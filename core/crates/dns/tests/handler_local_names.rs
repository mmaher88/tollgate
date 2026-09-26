//! Names only the local network's resolver knows (`nas.lan`, private reverse zones, bare
//! device names) never go to the public DoH upstreams.

mod support;

use std::net::Ipv4Addr;
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, PTR};
use hickory_proto::rr::{Name, RData, RecordType};
use support::{decode, expect_forward, expect_reply, query_packet};
use tollgate_common::stats::Stats;
use tollgate_dns::{DnsHandler, ForwardJob, LocalRecord, MAX_LOCAL_TTL, Outcome};
use tollgate_filter::{DomainSet, ListFormat, ListSource};

const NOW: u64 = 1_000;
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

fn handler() -> (DnsHandler, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    (DnsHandler::new(None, stats.clone()), stats)
}

fn expect_local(outcome: Outcome) -> ForwardJob {
    match outcome {
        Outcome::Local(job) => job,
        other => panic!("expected a local job, got {other:?}"),
    }
}

fn a(ip: [u8; 4], ttl: u32) -> LocalRecord {
    LocalRecord {
        rtype: TYPE_A,
        rclass: CLASS_IN,
        ttl,
        data: ip.to_vec(),
    }
}

#[test]
fn local_names_are_never_forwarded_to_doh() {
    let (handler, _) = handler();
    for (name, rtype) in [
        ("nas.lan.", RecordType::A),
        ("x.home.arpa.", RecordType::AAAA),
        ("1.1.168.192.in-addr.arpa.", RecordType::PTR),
        ("nas.", RecordType::A),
        ("fritz.box.", RecordType::A),
    ] {
        let outcome = handler.handle_packet(&query_packet(1, name, rtype, None), NOW);
        assert!(
            !matches!(outcome, Outcome::Forward(_)),
            "{name} {rtype} went to DoH"
        );
        let job = expect_local(outcome);
        assert_eq!(job.name(), name);
        assert_eq!(job.record_type_and_class(), (u16::from(rtype), CLASS_IN));
    }
    expect_forward(
        handler.handle_packet(&query_packet(2, "example.com.", RecordType::A, None), NOW),
    );
    expect_forward(
        handler.handle_packet(&query_packet(3, "planet.box.", RecordType::A, None), NOW),
    );
}

#[test]
fn local_names_are_never_blocked() {
    let bytes = DomainSet::build(&[ListSource {
        name: "test",
        text: "||lan^\n||nas.home.arpa^\n",
        format: ListFormat::Adblock,
    }]);
    let stats = Arc::new(Stats::default());
    let handler = DnsHandler::new(
        Some(Arc::new(DomainSet::from_bytes(bytes).unwrap())),
        stats.clone(),
    );
    expect_local(handler.handle_packet(&query_packet(1, "nas.lan.", RecordType::A, None), NOW));
    expect_local(
        handler.handle_packet(&query_packet(2, "nas.home.arpa.", RecordType::A, None), NOW),
    );
    assert_eq!(stats.snapshot().dns_blocked, 0);
}

#[test]
fn local_records_answer_the_query_and_are_kept_briefly() {
    let (handler, stats) = handler();
    handler.set_network("en0 192.168.1.1");
    let packet = query_packet(0x4242, "NAS.lan.", RecordType::A, Some((1232, false)));
    let job = expect_local(handler.handle_packet(&packet, NOW));
    // A CNAME-less answer; a record of another type is left out, a long TTL is capped.
    let records = [
        a([192, 168, 1, 20], 3600),
        LocalRecord {
            rtype: TYPE_AAAA,
            rclass: CLASS_IN,
            ttl: 5,
            data: vec![0; 16],
        },
    ];
    let reply =
        decode(&support::checked_reply(&handler.complete_local(job, Some(&records), NOW)).payload);
    assert_eq!(reply.metadata.id, 0x4242);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.queries[0].name().to_ascii(), "NAS.lan.");
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].ttl, MAX_LOCAL_TTL);
    assert_eq!(
        reply.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 168, 1, 20)))
    );
    assert!(reply.edns.is_some());

    // Answered from the cache until the TTL runs out.
    let again = query_packet(7, "nas.lan.", RecordType::A, Some((1232, false)));
    let cached = decode(&expect_reply(handler.handle_packet(&again, NOW + 10)).payload);
    assert_eq!(cached.metadata.id, 7);
    assert_eq!(cached.answers[0].ttl, MAX_LOCAL_TTL - 10);
    assert_eq!(stats.snapshot().dns_cache_hits, 1);
    expect_local(handler.handle_packet(&again, NOW + u64::from(MAX_LOCAL_TTL)));
}

#[test]
fn a_network_change_drops_local_answers() {
    let (handler, _) = handler();
    handler.set_network("en0 192.168.1.1");
    let packet = query_packet(1, "nas.lan.", RecordType::A, None);
    let job = expect_local(handler.handle_packet(&packet, NOW));
    handler.complete_local(job, Some(&[a([192, 168, 1, 20], 30)]), NOW);
    expect_reply(handler.handle_packet(&packet, NOW + 1));

    // The same network again keeps the answer; another one drops it.
    handler.set_network("en0 192.168.1.1");
    expect_reply(handler.handle_packet(&packet, NOW + 1));
    handler.set_network("en0 10.0.0.1");
    let job = expect_local(handler.handle_packet(&packet, NOW + 1));

    // An answer that arrives after another change is not kept for the new network.
    handler.set_network("pdp_ip0");
    handler.complete_local(job, Some(&[a([192, 168, 1, 20], 30)]), NOW + 2);
    expect_local(handler.handle_packet(&packet, NOW + 3));
}

#[test]
fn failures_and_empty_answers_are_not_kept() {
    let (handler, stats) = handler();
    let packet = query_packet(9, "printer.lan.", RecordType::AAAA, None);
    let job = expect_local(handler.handle_packet(&packet, NOW));
    let reply = decode(&support::checked_reply(&handler.complete_local(job, None, NOW)).payload);
    assert_eq!(reply.metadata.id, 9);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(stats.snapshot().dns_failed, 1);

    let job = expect_local(handler.handle_packet(&packet, NOW + 1));
    let reply =
        decode(&support::checked_reply(&handler.complete_local(job, Some(&[]), NOW + 1)).payload);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    expect_local(handler.handle_packet(&packet, NOW + 2));
    assert_eq!(stats.snapshot().dns_failed, 1);
}

#[test]
fn reverse_lookups_of_lan_addresses_get_ptr_records() {
    let (handler, _) = handler();
    let packet = query_packet(3, "20.1.168.192.in-addr.arpa.", RecordType::PTR, None);
    let job = expect_local(handler.handle_packet(&packet, NOW));
    // PTR data from the local resolver: an uncompressed name.
    let target = b"\x03nas\x03lan\x00".to_vec();
    let records = [LocalRecord {
        rtype: TYPE_PTR,
        rclass: CLASS_IN,
        ttl: 20,
        data: target,
    }];
    let reply =
        decode(&support::checked_reply(&handler.complete_local(job, Some(&records), NOW)).payload);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].data,
        RData::PTR(PTR(Name::from_ascii("nas.lan.").unwrap()))
    );
    assert_eq!(reply.answers[0].ttl, 20);
}

#[test]
fn malformed_record_data_becomes_servfail() {
    let (handler, stats) = handler();
    let packet = query_packet(4, "nas.lan.", RecordType::A, None);
    let job = expect_local(handler.handle_packet(&packet, NOW));
    let bad = LocalRecord {
        rtype: TYPE_A,
        rclass: CLASS_IN,
        ttl: 20,
        data: vec![1, 2, 3],
    };
    let reply =
        decode(&support::checked_reply(&handler.complete_local(job, Some(&[bad]), NOW)).payload);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(stats.snapshot().dns_failed, 1);
}
