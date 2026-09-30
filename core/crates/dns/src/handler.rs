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
use crate::local::is_local_name;
use crate::packet::{build_udp, parse_udp};
use crate::wire::{self, HEADER_LEN};
use crate::{TUNNEL_DNS_V4, TUNNEL_DNS_V6};

const TYPE_SVCB: u16 = 64;
const TYPE_HTTPS: u16 = 65;
const TYPE_ANY: u16 = 255;

/// Answers from the local network's resolver kept at most, apart from the upstream ones.
pub const LOCAL_CACHE_CAPACITY: usize = 128;
/// Longest time an answer from the local network's resolver is kept, and the highest TTL
/// its records are given, in seconds. The cache is also emptied when the network changes
/// (see [`DnsHandler::set_network`]).
pub const MAX_LOCAL_TTL: u32 = 60;

/// What to do with one packet from the tunnel.
#[derive(Debug)]
pub enum Outcome {
    /// Write this packet back to the tunnel now.
    Reply(Vec<u8>),
    /// Resolve [`ForwardJob::query`] upstream, then pass the result to
    /// [`DnsHandler::complete`].
    Forward(ForwardJob),
    /// A name only the local network's resolver knows (see [`crate::is_local_name`]): look
    /// up [`ForwardJob::name`] with that resolver, never with the DoH upstreams, then pass
    /// the records to [`DnsHandler::complete_local`]. Never blocked.
    Local(ForwardJob),
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
    /// The question name as sent, in presentation form with the final dot.
    name: Box<str>,
    /// For local jobs: the network generation when the query arrived.
    network: u64,
}

/// One record from the local network's resolver: type, class, TTL and the record data in
/// wire form (names in it uncompressed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRecord {
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

/// The answers of the local network's resolver, for the network they came from.
struct LocalState {
    network: String,
    /// Changes with `network`, so an answer that arrives after a change is not kept.
    generation: u64,
    cache: AnswerCache,
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

    /// The question name in presentation form with the final dot, as the client sent it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The question's type and class.
    pub fn record_type_and_class(&self) -> (u16, u16) {
        self.requester.qtype_and_class()
    }
}

/// An answer message for the question `key` (see [`wire::question_key`]) holding the
/// `records` of the queried type and class, TTLs capped at [`MAX_LOCAL_TTL`]. Records that
/// would make the message longer than 64 KiB are left out.
fn local_answer(key: &[u8], records: &[LocalRecord]) -> Vec<u8> {
    let n = key.len();
    let qtype = u16::from_be_bytes([key[n - 4], key[n - 3]]);
    let qclass = u16::from_be_bytes([key[n - 2], key[n - 1]]);
    let mut out = vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(key);
    let mut count: u16 = 0;
    for record in records {
        let wanted = (record.rtype == qtype || qtype == TYPE_ANY) && record.rclass == qclass;
        let Ok(len) = u16::try_from(record.data.len()) else {
            continue;
        };
        if !wanted || out.len() + 12 + record.data.len() > usize::from(u16::MAX) {
            continue;
        }
        // Owner name: a pointer to the question name at offset 12.
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&record.rclass.to_be_bytes());
        out.extend_from_slice(&record.ttl.min(MAX_LOCAL_TTL).to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&record.data);
        count += 1;
        if count == u16::MAX {
            break;
        }
    }
    wire::set_u16(&mut out, 6, count);
    out
}

/// Answers DNS queries addressed to the tunnel. Send + Sync; every method returns without
/// waiting on the network.
pub struct DnsHandler {
    blocklist: ArcSwapOption<DomainSet>,
    /// Names matching one of these are never blocked.
    allowlist: ArcSwap<Vec<HostPattern>>,
    events: ArcSwapOption<EventLog>,
    cache: Mutex<AnswerCache>,
    local: Mutex<LocalState>,
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
            local: Mutex::new(LocalState {
                network: String::new(),
                generation: 0,
                cache: AnswerCache::with_limits(LOCAL_CACHE_CAPACITY, MAX_LOCAL_TTL),
            }),
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

    fn local(&self) -> std::sync::MutexGuard<'_, LocalState> {
        self.local.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Names the network the local resolver answers for (any string that changes when the
    /// network does, such as the interface and its gateways). When it differs from the last
    /// one, the local answers kept so far are dropped, and answers to queries that arrived
    /// before the change are not kept.
    pub fn set_network(&self, network: &str) {
        let mut local = self.local();
        if local.network != network {
            local.network = network.to_string();
            local.generation += 1;
            local.cache = AnswerCache::with_limits(LOCAL_CACHE_CAPACITY, MAX_LOCAL_TTL);
        }
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
        if is_local_name(&name) {
            let key = wire::question_key(query, question_end);
            let mut local = self.local();
            if let Some((cached, elapsed)) = local.cache.get(&cache_key(&key, &requester), now) {
                Stats::inc(&self.stats.dns_cache_hits);
                return reply(cached.render(&requester, elapsed));
            }
            let network = local.generation;
            drop(local);
            Stats::inc(&self.stats.dns_forwarded);
            return Outcome::Local(ForwardJob {
                query: query.to_vec(),
                client,
                server,
                requester,
                key,
                name: name.into(),
                network,
            });
        }
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
            name: name.into(),
            network: 0,
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

impl DnsHandler {
    /// Builds the reply packet for a [`Outcome::Local`] job from the local resolver's
    /// records: `Some` with the records of the queried type (none when the name or the
    /// type does not exist there), or `None` when the lookup failed or timed out, which
    /// becomes SERVFAIL and counts in `dns_failed`. Answers with records are kept for at
    /// most [`MAX_LOCAL_TTL`] seconds, unless the network changed meanwhile; empty answers
    /// and failures are never kept.
    pub fn complete_local(
        &self,
        job: ForwardJob,
        records: Option<&[LocalRecord]>,
        now: u64,
    ) -> Vec<u8> {
        let ForwardJob {
            client,
            server,
            requester,
            key,
            network,
            ..
        } = job;
        let checked = match records {
            None => Err("the local resolver gave no answer"),
            Some(records) => UpstreamAnswer::parse(&local_answer(&key, records), &key),
        };
        let payload = match checked {
            Ok(answer) => {
                let payload = answer.render(&requester, 0);
                if answer.has_answers() && answer.cacheable() {
                    let mut local = self.local();
                    if local.generation == network {
                        local.cache.insert(cache_key(&key, &requester), answer, now);
                    }
                }
                payload
            }
            Err(reason) => {
                log::debug!("local DNS query failed: {reason}");
                Stats::inc(&self.stats.dns_failed);
                requester.empty(SERVFAIL)
            }
        };
        reply_packet(server, client, &payload)
    }
}
