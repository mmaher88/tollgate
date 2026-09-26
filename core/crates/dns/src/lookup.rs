//! Host name lookups for the proxy's upstream connections over DNS over HTTPS, so they use
//! the same encrypted resolver as the tunnel's DNS instead of the network's.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use lru::LruCache;
use tokio::sync::{Semaphore, watch};
use tollgate_common::resolve::{LookupFuture, Resolve};

use crate::cache::MIN_CACHE_TTL;
use crate::doh::DohResolver;
use crate::local::is_local_name;

/// Host names whose addresses are kept.
pub const LOOKUP_CACHE_CAPACITY: usize = 256;
/// Longest time addresses are kept, in seconds, even when their records say more.
pub const MAX_LOOKUP_TTL: u32 = 300;
/// Longest wait for both lookups of one name, including the wait for a turn; after it the
/// caller falls back to the system resolver.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
/// The share of [`crate::MAX_IN_FLIGHT`] DoH queries kept for proxy name lookups: at most
/// `LOOKUP_PERMITS / 2` names are looked up at once (A and AAAA run together), and further
/// names wait for a turn. The DNS forwarder must keep to the rest (`MAX_IN_FLIGHT -
/// LOOKUP_PERMITS`), so neither ever finds the resolver busy.
pub const LOOKUP_PERMITS: usize = 32;

/// The result of a lookup in progress, for callers asking for the same name meanwhile.
type Pending = watch::Receiver<Option<Arc<[IpAddr]>>>;

/// Removes a lookup from the ones in progress when it ends, even when its caller gave up.
struct InProgress<'a> {
    resolver: &'a HostResolver,
    host: String,
    id: u64,
}

impl Drop for InProgress<'_> {
    fn drop(&mut self) {
        let mut pending = self.resolver.pending();
        if pending
            .get(&self.host)
            .is_some_and(|(id, _)| *id == self.id)
        {
            pending.remove(&self.host);
        }
    }
}

struct Entry {
    addresses: Arc<[IpAddr]>,
    expires: u64,
}

/// Looks up A and AAAA records through a [`DohResolver`], IPv4 first, and keeps the
/// addresses for their smallest TTL (10 s to 5 min). Failures are not kept. At most
/// `LOOKUP_PERMITS / 2` names are looked up at once, and callers asking for a name that is
/// already being looked up wait for that lookup. Local network
/// names ([`crate::is_local_name`]) are never sent to DoH: their lookup is empty, so the
/// proxy uses the system resolver.
pub struct HostResolver {
    doh: DohResolver,
    cache: Mutex<LruCache<String, Entry>>,
    clock: fn() -> u64,
    /// Turns for names looked up at once.
    turns: Semaphore,
    in_progress: Mutex<Lookups>,
}

impl std::fmt::Debug for HostResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostResolver")
    }
}

impl HostResolver {
    /// Uses `doh`, which must run on the same tokio runtime as the lookups.
    pub fn new(doh: DohResolver) -> HostResolver {
        HostResolver::with_clock(doh, tollgate_common::clock::now_secs)
    }

    /// [`HostResolver::new`] with `clock` (seconds, counting through sleep) for cache
    /// expiry. For tests.
    pub fn with_clock(doh: DohResolver, clock: fn() -> u64) -> HostResolver {
        let capacity = NonZeroUsize::new(LOOKUP_CACHE_CAPACITY).expect("capacity is not zero");
        HostResolver {
            doh,
            cache: Mutex::new(LruCache::new(capacity)),
            clock,
            turns: Semaphore::new(LOOKUP_PERMITS / 2),
            in_progress: Mutex::new(Lookups::default()),
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Lookups> {
        self.in_progress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The live cached addresses of `host`.
    fn cached(&self, host: &str, now: u64) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        match cache.get(host) {
            Some(entry) if entry.expires > now => Some(entry.addresses.to_vec()),
            Some(_) => {
                cache.pop(host);
                None
            }
            None => None,
        }
    }

    async fn resolve(&self, host: &str) -> Vec<IpAddr> {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ip];
        }
        if is_local_name(&host) {
            // Only the network's resolver knows it; the caller falls back to the system
            // resolver, whose query the tunnel sends there.
            return Vec::new();
        }
        loop {
            if let Some(addresses) = self.cached(&host, (self.clock)()) {
                return addresses;
            }
            let joined = {
                let mut pending = self.pending();
                match pending.get(&host) {
                    Some((_, receiver)) => Err(receiver.clone()),
                    None => {
                        let (sender, receiver) = watch::channel(None);
                        let id = pending.insert(host.clone(), receiver);
                        Ok((sender, id))
                    }
                }
            };
            match joined {
                Ok((sender, id)) => {
                    let _in_progress = InProgress {
                        resolver: self,
                        host: host.clone(),
                        id,
                    };
                    let addresses = self.look_up(&host).await;
                    sender.send_replace(Some(addresses.clone().into()));
                    return addresses;
                }
                Err(mut receiver) => {
                    // An error means that lookup's caller gave up: try again.
                    if let Ok(result) = receiver.wait_for(Option::is_some).await {
                        return result.as_deref().unwrap_or_default().to_vec();
                    }
                }
            }
        }
    }

    /// Looks `host` up over DoH once a turn is free, and keeps what it finds.
    async fn look_up(&self, host: &str) -> Vec<IpAddr> {
        let Ok(_turn) = self.turns.acquire().await else {
            return Vec::new();
        };
        let now = (self.clock)();
        let (v4, v6) = tokio::join!(
            self.query(host, RecordType::A),
            self.query(host, RecordType::AAAA)
        );
        let mut addresses = Vec::new();
        let mut ttl = None::<u32>;
        for (found, found_ttl) in [v4, v6].into_iter().flatten() {
            for ip in found {
                if !addresses.contains(&ip) {
                    addresses.push(ip);
                }
            }
            ttl = Some(ttl.map_or(found_ttl, |t| t.min(found_ttl)));
        }
        if !addresses.is_empty() {
            let lifetime = ttl.unwrap_or(0).clamp(MIN_CACHE_TTL, MAX_LOOKUP_TTL);
            let entry = Entry {
                addresses: addresses.clone().into(),
                expires: now + u64::from(lifetime),
            };
            self.cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .put(host.to_string(), entry);
        }
        addresses
    }

    /// The addresses of one type and their smallest TTL; `None` when the lookup failed.
    async fn query(&self, host: &str, rtype: RecordType) -> Option<(Vec<IpAddr>, u32)> {
        let name = Name::from_ascii(format!("{host}.")).ok()?;
        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(name, rtype));
        let wire = message.to_vec().ok()?;
        let answer = match self.doh.resolve(&wire).await {
            Ok(answer) => answer,
            Err(e) => {
                log::debug!("DoH lookup of {host} ({rtype}) failed: {e}");
                return None;
            }
        };
        let answer = Message::from_vec(&answer).ok()?;
        if answer.metadata.response_code != ResponseCode::NoError {
            return Some((Vec::new(), 0));
        }
        let mut addresses = Vec::new();
        let mut ttl = u32::MAX;
        for record in &answer.answers {
            let ip = match &record.data {
                RData::A(a) if rtype == RecordType::A => IpAddr::V4(a.0),
                RData::AAAA(aaaa) if rtype == RecordType::AAAA => IpAddr::V6(aaaa.0),
                _ => continue,
            };
            addresses.push(ip);
            ttl = ttl.min(record.ttl);
        }
        Some((addresses, ttl))
    }
}

impl Resolve for HostResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(LOOKUP_TIMEOUT, self.resolve(host))
                .await
                .unwrap_or_else(|_| {
                    log::debug!("DoH lookup of {host} timed out");
                    Vec::new()
                })
        })
    }
}

/// The lookups in progress by name, each with an id so a finished one removes only itself.
#[derive(Default)]
struct Lookups {
    last_id: u64,
    by_host: HashMap<String, (u64, Pending)>,
}

impl Lookups {
    fn get(&self, host: &str) -> Option<&(u64, Pending)> {
        self.by_host.get(host)
    }

    fn remove(&mut self, host: &str) {
        self.by_host.remove(host);
    }

    /// Records a new lookup of `host` and returns its id.
    fn insert(&mut self, host: String, receiver: Pending) -> u64 {
        self.last_id += 1;
        self.by_host.insert(host, (self.last_id, receiver));
        self.last_id
    }
}
