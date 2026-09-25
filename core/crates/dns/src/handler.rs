//! Turning query packets into reply packets or forwarding jobs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use hickory_proto::op::{Message, OpCode};
use tollgate_common::stats::Stats;
use tollgate_filter::DomainSet;

use crate::answer::{self, FORMERR, NOERROR, NOTIMP, Requester};
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
    /// Resolve [`ForwardJob::query`] upstream.
    Forward(ForwardJob),
    /// Not a DNS query for the tunnel; counted in `packets_dropped`.
    Drop,
}

/// A query that needs the upstream resolver.
#[derive(Debug)]
pub struct ForwardJob {
    query: Vec<u8>,
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
            stats,
        }
    }

    /// Replaces the blocklist; queries handled afterwards use the new one.
    pub fn set_blocklist(&self, blocklist: Option<Arc<DomainSet>>) {
        self.blocklist.store(blocklist);
    }

    fn is_blocked(&self, name: &str) -> bool {
        self.blocklist
            .load()
            .as_ref()
            .is_some_and(|set| set.is_blocked(name))
    }

    /// Handles one raw IP packet from the tunnel. `now` is
    /// [`tollgate_common::clock::now_secs`]. Never blocks or awaits.
    pub fn handle_packet(&self, packet: &[u8], _now: u64) -> Outcome {
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
        if self.is_blocked(&question.name().to_ascii()) {
            Stats::inc(&self.stats.dns_blocked);
            return reply(requester.blocked());
        }
        Stats::inc(&self.stats.dns_forwarded);
        Outcome::Forward(ForwardJob {
            query: query.to_vec(),
        })
    }
}
