mod support;

use std::net::Ipv4Addr;
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, RecordType};
use support::doh_server::{TestServer, closed_upstream, trusting};
use support::{checked_reply, decode, expect_forward, expect_reply, query_packet};
use tollgate_common::stats::{Stats, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohResolver};

const NOW: u64 = 7_000;

#[tokio::test]
async fn packet_to_upstream_to_reply_then_cache() {
    let server = TestServer::start().await;
    let resolver = trusting(vec![server.upstream()], &[&server]);
    let stats = Arc::new(Stats::default());
    let handler = Arc::new(DnsHandler::new(None, stats.clone()));

    let packet = query_packet(0x5151, "Example.COM.", RecordType::A, Some((1232, false)));
    let job = expect_forward(handler.handle_packet(&packet, NOW));
    // The way the tunnel runs it: one task per forwarded query.
    let reply = tokio::spawn({
        let handler = handler.clone();
        async move {
            let answer = resolver.resolve(job.query()).await;
            handler.complete(job, answer, NOW)
        }
    })
    .await
    .unwrap();
    let message = decode(&checked_reply(&reply).payload);
    assert_eq!(message.metadata.id, 0x5151);
    assert_eq!(message.queries[0].name().to_ascii(), "Example.COM.");
    assert_eq!(
        message.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
    );
    assert!(message.edns.is_some());

    let again = query_packet(0x5252, "example.com.", RecordType::A, None);
    let message = decode(&expect_reply(handler.handle_packet(&again, NOW + 5)).payload);
    assert_eq!(message.metadata.id, 0x5252);
    assert_eq!(message.answers[0].ttl, 295);
    assert_eq!(server.requests(), 1);
    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            dns_queries: 2,
            dns_forwarded: 1,
            dns_cache_hits: 1,
            ..StatsSnapshot::default()
        }
    );
}

#[tokio::test]
async fn unreachable_upstreams_give_servfail() {
    let resolver = DohResolver::new(vec![closed_upstream().await, closed_upstream().await]);
    let stats = Arc::new(Stats::default());
    let handler = DnsHandler::new(None, stats.clone());
    let packet = query_packet(3, "example.com.", RecordType::A, None);
    let job = expect_forward(handler.handle_packet(&packet, NOW));
    let answer = resolver.resolve(job.query()).await;
    assert!(answer.is_err());
    let message = decode(&checked_reply(&handler.complete(job, answer, NOW)).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(stats.snapshot().dns_failed, 1);
}
