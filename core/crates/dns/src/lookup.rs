//! Host name lookups for the proxy's upstream connections over DNS over HTTPS, so they use
//! the same encrypted resolver as the tunnel's DNS instead of the network's.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use lru::LruCache;
use tollgate_common::resolve::{LookupFuture, Resolve};

use crate::cache::MIN_CACHE_TTL;
use crate::doh::DohResolver;

/// Host names whose addresses are kept.
pub const LOOKUP_CACHE_CAPACITY: usize = 256;
/// Longest time addresses are kept, in seconds, even when their records say more.
pub const MAX_LOOKUP_TTL: u32 = 300;
/// Longest wait for both lookups of one name; after it the caller falls back to the system
/// resolver.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

struct Entry {
    addresses: Arc<[IpAddr]>,
    expires: u64,
}

/// Looks up A and AAAA records through a [`DohResolver`], IPv4 first, and keeps the
/// addresses for their smallest TTL (10 s to 5 min). Failures are not kept.
pub struct HostResolver {
    doh: DohResolver,
    cache: Mutex<LruCache<String, Entry>>,
    clock: fn() -> u64,
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
        }
    }

    async fn resolve(&self, host: &str) -> Vec<IpAddr> {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ip];
        }
        let now = (self.clock)();
        {
            let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            match cache.get(&host) {
                Some(entry) if entry.expires > now => return entry.addresses.to_vec(),
                Some(_) => {
                    cache.pop(&host);
                }
                None => {}
            }
        }
        let (v4, v6) = tokio::join!(
            self.query(&host, RecordType::A),
            self.query(&host, RecordType::AAAA)
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
                .put(host, entry);
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
