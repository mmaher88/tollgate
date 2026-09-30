mod support;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hickory_proto::op::{MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, RecordType};
use support::{
    client_v6, decode, dns_v6, expect_forward, expect_reply, query, query_packet, udp_packet,
};
use tollgate_common::stats::Stats;
use tollgate_dns::{BLOCK_TTL, DnsHandler};
use tollgate_filter::{DomainSet, ListFormat, ListSource};

const NOW: u64 = 1_000;

fn blocklist() -> Arc<DomainSet> {
    let rules = "||ads.example^\n||tracker.test^\n@@||ok.ads.example^\n";
    let bytes = DomainSet::build(&[ListSource {
        name: "test",
        text: rules,
        format: ListFormat::Adblock,
    }]);
    Arc::new(DomainSet::from_bytes(bytes).unwrap())
}

fn handler() -> (DnsHandler, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    (DnsHandler::new(Some(blocklist()), stats.clone()), stats)
}

#[test]
fn blocked_a_gets_zero_address() {
    let (handler, stats) = handler();
    let packet = query_packet(0x1234, "ads.example.", RecordType::A, None);
    let reply = expect_reply(handler.handle_packet(&packet, NOW));
    // Header, question (13 + 4 bytes), one A record with a compressed name (16 bytes).
    assert_eq!(reply.payload.len(), 12 + 17 + 16);
    let message = decode(&reply.payload);
    assert_eq!(message.metadata.id, 0x1234);
    assert_eq!(message.metadata.message_type, MessageType::Response);
    assert!(message.metadata.recursion_desired);
    assert!(message.metadata.recursion_available);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.queries.len(), 1);
    assert_eq!(message.queries[0].name().to_ascii(), "ads.example.");
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].ttl, BLOCK_TTL);
    assert_eq!(BLOCK_TTL, 60);
    assert_eq!(message.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    assert!(message.edns.is_none());
    assert_eq!(stats.snapshot().dns_queries, 1);
    assert_eq!(stats.snapshot().dns_blocked, 1);
}

#[test]
fn blocked_aaaa_for_a_subdomain_keeps_the_letter_case() {
    let (handler, _) = handler();
    let packet = query_packet(9, "cdn.ADS.Example.", RecordType::AAAA, None);
    let message = decode(&expect_reply(handler.handle_packet(&packet, NOW)).payload);
    assert_eq!(message.queries[0].name().to_ascii(), "cdn.ADS.Example.");
    assert_eq!(message.answers[0].name.to_ascii(), "cdn.ADS.Example.");
    assert_eq!(
        message.answers[0].data,
        RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))
    );
    assert_eq!(message.answers[0].ttl, 60);
}

#[test]
fn blocked_names_get_no_records_for_other_types() {
    let (handler, stats) = handler();
    for rtype in [RecordType::MX, RecordType::TXT, RecordType::CNAME] {
        let packet = query_packet(2, "tracker.test.", rtype, None);
        let message = decode(&expect_reply(handler.handle_packet(&packet, NOW)).payload);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert_eq!(message.queries[0].query_type(), rtype);
        assert!(message.answers.is_empty());
    }
    assert_eq!(stats.snapshot().dns_blocked, 3);
}

#[test]
fn exceptions_and_other_names_are_forwarded() {
    let (handler, stats) = handler();
    for name in ["ok.ads.example.", "example.com.", "notads.example."] {
        expect_forward(handler.handle_packet(&query_packet(1, name, RecordType::A, None), NOW));
    }
    assert_eq!(stats.snapshot().dns_blocked, 0);
    assert_eq!(stats.snapshot().dns_forwarded, 3);
}

#[test]
fn opt_is_echoed_only_when_the_query_had_one() {
    let (handler, _) = handler();
    for dnssec_ok in [true, false] {
        let packet = query_packet(5, "ads.example.", RecordType::A, Some((4096, dnssec_ok)));
        let message = decode(&expect_reply(handler.handle_packet(&packet, NOW)).payload);
        let edns = message.edns.expect("OPT echoed");
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(edns.flags().dnssec_ok, dnssec_ok);
        assert!(edns.options().as_ref().is_empty());
        assert_eq!(message.answers.len(), 1);
    }
    let packet = query_packet(5, "ads.example.", RecordType::A, None);
    let message = decode(&expect_reply(handler.handle_packet(&packet, NOW)).payload);
    assert!(message.edns.is_none());
}

#[test]
fn https_and_svcb_get_an_empty_noerror() {
    let stats = Arc::new(Stats::default());
    let handler = DnsHandler::new(None, stats.clone());
    for (rtype, code) in [(RecordType::HTTPS, 65), (RecordType::SVCB, 64)] {
        let packet = query_packet(3, "www.Example.org.", rtype, Some((1232, false)));
        let message = decode(&expect_reply(handler.handle_packet(&packet, NOW)).payload);
        assert_eq!(message.metadata.id, 3);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert_eq!(u16::from(message.queries[0].query_type()), code);
        assert_eq!(message.queries[0].name().to_ascii(), "www.Example.org.");
        assert!(message.answers.is_empty());
        assert!(message.authorities.is_empty());
        assert!(message.edns.is_some());
    }
    assert_eq!(stats.snapshot().dns_queries, 2);
    assert_eq!(stats.snapshot().dns_blocked, 0);
    assert_eq!(stats.snapshot().dns_forwarded, 0);
}

#[test]
fn recursion_desired_is_copied() {
    let (handler, _) = handler();
    let mut payload = query(4, "ads.example.", RecordType::A, None);
    payload[2] &= !0x01;
    let packet = udp_packet(support::client_v4(), support::dns_v4(), &payload);
    let message = decode(&expect_reply(handler.handle_packet(&packet, NOW)).payload);
    assert!(!message.metadata.recursion_desired);
    assert!(message.metadata.recursion_available);
}

#[test]
fn blocklist_can_be_replaced_and_removed() {
    let stats = Arc::new(Stats::default());
    let handler = DnsHandler::new(None, stats);
    let packet = query_packet(1, "ads.example.", RecordType::A, None);
    expect_forward(handler.handle_packet(&packet, NOW));
    handler.set_blocklist(Some(blocklist()));
    expect_reply(handler.handle_packet(&packet, NOW));
    handler.set_blocklist(None);
    expect_forward(handler.handle_packet(&packet, NOW));
}

#[test]
fn ipv6_queries_get_ipv6_replies() {
    let (handler, _) = handler();
    let payload = query(8, "ads.example.", RecordType::AAAA, None);
    let packet = udp_packet(client_v6(), dns_v6(), &payload);
    let reply = expect_reply(handler.handle_packet(&packet, NOW));
    assert_eq!(reply.source, dns_v6());
    assert_eq!(reply.destination, client_v6());
    let message = decode(&reply.payload);
    assert_eq!(
        message.answers[0].data,
        RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))
    );
}
