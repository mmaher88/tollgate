//! Turning query packets into reply packets or forwarding jobs.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::{ArcSwap, ArcSwapOption};
use hickory_proto::op::{Message, OpCode};
use tollgate_common::clock::unix_secs;
use tollgate_common::events::{BlockEvent, EventKind, EventLog};
use tollgate_common::stats::Stats;
use tollgate_filter::DomainSet;
use tollgate_policy::HostPattern;

use crate::answer::{self, FORMERR, NOERROR, NOTIMP, Requester, SERVFAIL, UpstreamAnswer};
use crate::cache::AnswerCache;
use crate::doh::DohError;
use crate::packet::{build_udp, parse_udp};
use crate::wire::{self, HEADER_LEN};
use crate::{TUNNEL_DNS_V4, TUNNEL_DNS_V6};

const TYPE_SVCB: u16 = 64;
const TYPE_HTTPS: u16 = 65;

/// What to do with one packet from the tunnel.
#[derive(Debug)]
pub enum Outcome {
    /// Write this packet back to the tunnel now.
    Reply(Vec<u8>),
    /// Resolve [`ForwardJob::query`] upstream, then pass the result to
    /// [`DnsHandler::complete`].
    Forward(ForwardJob),
    /// Not a DNS query for the tunnel; counted in `packets_dropped`.
    Drop,
}

/// A query that needs the upstream resolver, with what is needed to answer it.
#[derive(Debug)]
pub struct ForwardJob {
    query: Vec<u8>,
    client: SocketAddr,
    server: SocketAddr,
    requester: Requester,
    key: Box<[u8]>,
}

/// The cache key for a question: [`wire::question_key`] followed by the requester's DO bit.
/// Answers to queries with DO carry DNSSEC records that RFC 3225 does not allow in replies
/// to requesters without it, and the query goes upstream as the requester sent it, so the
/// two kinds are cached apart.
fn cache_key(key: &[u8], requester: &Requester) -> Box<[u8]> {
    let dnssec_ok = requester.edns.is_some_and(|edns| edns.dnssec_ok);
    let mut out = Vec::with_capacity(key.len() + 1);
    out.extend_from_slice(key);
    out.push(u8::from(dnssec_ok));
    out.into_boxed_slice()
}

impl ForwardJob {
    /// The DNS message as the client sent it.
    pub fn query(&self) -> &[u8] {
        &self.query
    }
}

/// Answers DNS queries addressed to the tunnel. Send + Sync; every method returns without
/// waiting on the network.
pub struct DnsHandler {
    blocklist: ArcSwapOption<DomainSet>,
    /// Names matching one of these are never blocked.
    allowlist: ArcSwap<Vec<HostPattern>>,
    events: ArcSwapOption<EventLog>,
    cache: Mutex<AnswerCache>,
    stats: Arc<Stats>,
}

fn is_tunnel_dns(destination: SocketAddr) -> bool {
    destination.port() == 53
        && match destination.ip() {
            IpAddr::V4(ip) => ip == TUNNEL_DNS_V4,
            IpAddr::V6(ip) => ip == TUNNEL_DNS_V6,
        }
}

fn reply_packet(server: SocketAddr, client: SocketAddr, payload: &[u8]) -> Vec<u8> {
    // Replies are at most 1,232 bytes and keep the query's address family.
    build_udp(server, client, payload).expect("a reply always fits in one packet")
}

impl DnsHandler {
    pub fn new(blocklist: Option<Arc<DomainSet>>, stats: Arc<Stats>) -> DnsHandler {
        DnsHandler {
            blocklist: ArcSwapOption::new(blocklist),
            allowlist: ArcSwap::from_pointee(Vec::new()),
            events: ArcSwapOption::empty(),
            cache: Mutex::new(AnswerCache::new()),
            stats,
        }
    }

    /// Replaces the blocklist; queries handled afterwards use the new one.
    pub fn set_blocklist(&self, blocklist: Option<Arc<DomainSet>>) {
        self.blocklist.store(blocklist);
    }

    /// Replaces the allowlist: names matching a pattern are resolved normally (forwarded or
    /// answered from the cache) even when the blocklist has them.
    pub fn set_allowlist(&self, patterns: Vec<HostPattern>) {
        self.allowlist.store(Arc::new(patterns));
    }

    /// Where blocks are recorded; `None` records nothing.
    pub fn set_events(&self, events: Option<Arc<EventLog>>) {
        self.events.store(events);
    }

    fn is_blocked(&self, name: &str) -> bool {
        self.blocklist
            .load()
            .as_ref()
            .is_some_and(|set| set.is_blocked(name))
            && !self.allowlist.load().iter().any(|p| p.matches(name))
    }

    fn record_block(&self, name: &str) {
        if let Some(events) = self.events.load().as_ref() {
            let host = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
            events.record(BlockEvent {
                unix_secs: unix_secs(),
                kind: EventKind::Dns,
                host,
                url: None,
                source_host: None,
            });
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, AnswerCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Handles one raw IP packet from the tunnel. `now` is
    /// [`tollgate_common::clock::now_secs`]. Never blocks or awaits.
    pub fn handle_packet(&self, packet: &[u8], now: u64) -> Outcome {
        let Some(datagram) = parse_udp(packet) else {
            Stats::inc(&self.stats.packets_dropped);
            return Outcome::Drop;
        };
        let query = datagram.payload;
        if !is_tunnel_dns(datagram.destination)
            || query.len() < HEADER_LEN
            || wire::is_response(query)
        {
            Stats::inc(&self.stats.packets_dropped);
            return Outcome::Drop;
        }
        Stats::inc(&self.stats.dns_queries);
        let (client, server) = (datagram.source, datagram.destination);
        let reply = |payload: Vec<u8>| Outcome::Reply(reply_packet(server, client, &payload));

        let Ok(message) = Message::from_vec(query) else {
            return reply(answer::header_only(query, FORMERR));
        };
        if message.metadata.op_code != OpCode::Query {
            return reply(answer::header_only(query, NOTIMP));
        }
        let Some(question_end) = wire::question_end(query) else {
            return reply(answer::header_only(query, FORMERR));
        };
        let requester = Requester::from_query(query, &message, question_end);
        let question = &message.queries[0];

        if matches!(u16::from(question.query_type()), TYPE_SVCB | TYPE_HTTPS) {
            return reply(requester.empty(NOERROR));
        }
        let name = question.name().to_ascii();
        if self.is_blocked(&name) {
            Stats::inc(&self.stats.dns_blocked);
            self.record_block(&name);
            return reply(requester.blocked());
        }
        let key = wire::question_key(query, question_end);
        if let Some((cached, elapsed)) = self.cache().get(&cache_key(&key, &requester), now) {
            Stats::inc(&self.stats.dns_cache_hits);
            return reply(cached.render(&requester, elapsed));
        }
        Stats::inc(&self.stats.dns_forwarded);
        Outcome::Forward(ForwardJob {
            query: query.to_vec(),
            client,
            server,
            requester,
            key,
        })
    }

    /// Builds the reply packet for a forwarded query from the upstream result. A usable
    /// answer is adapted to the client and, if it is NOERROR or NXDOMAIN, cached; an error
    /// or an unusable answer becomes SERVFAIL and counts in `dns_failed`.
    pub fn complete(
        &self,
        job: ForwardJob,
        answer: Result<Vec<u8>, DohError>,
        now: u64,
    ) -> Vec<u8> {
        let ForwardJob {
            client,
            server,
            requester,
            key,
            ..
        } = job;
        let checked = answer
            .map_err(|e| e.to_string())
            .and_then(|wire| UpstreamAnswer::parse(&wire, &key).map_err(str::to_string));
        let payload = match checked {
            Ok(upstream) => {
                let payload = upstream.render(&requester, 0);
                if upstream.cacheable() {
                    let key = cache_key(&key, &requester);
                    self.cache().insert(key, upstream, now);
                }
                payload
            }
            Err(reason) => {
                log::debug!("DNS query failed: {reason}");
                Stats::inc(&self.stats.dns_failed);
                requester.empty(SERVFAIL)
            }
        };
        reply_packet(server, client, &payload)
    }
}
