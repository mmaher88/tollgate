mod support;

use std::net::Ipv4Addr;
use std::sync::Arc;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use support::{
    a_record, checked_reply, client_v4, decode, dns_v4, expect_forward, expect_reply, query,
    query_packet, udp_packet, upstream_answer,
};
use tollgate_common::stats::Stats;
use tollgate_dns::{CACHE_CAPACITY, DnsHandler, DohError, MAX_CACHE_TTL, MIN_CACHE_TTL};

const T0: u64 = 50_000;

fn handler() -> (DnsHandler, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    (DnsHandler::new(None, stats.clone()), stats)
}

/// Forwards `name` at `now` and completes it with the answer `build` makes.
fn fill(
    handler: &DnsHandler,
    name: &str,
    rtype: RecordType,
    now: u64,
    build: impl FnOnce(&mut Message),
) {
    let job = expect_forward(handler.handle_packet(&query_packet(1, name, rtype, None), now));
    let answer = upstream_answer(job.query(), build);
    checked_reply(&handler.complete(job, Ok(answer), now));
}

fn ttls(message: &Message) -> Vec<u32> {
    message.all_sections().map(|r| r.ttl).collect()
}

fn ns_record(name: &str, ttl: u32, host: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        ttl,
        RData::NS(NS(Name::from_ascii(host).unwrap())),
    )
}

#[test]
fn hit_patches_id_letter_case_and_ttls() {
    let (handler, stats) = handler();
    fill(&handler, "Example.COM.", RecordType::A, T0, |answer| {
        answer.add_answer(a_record("example.com.", 300, [192, 0, 2, 1]));
        answer.add_answer(a_record("example.com.", 400, [192, 0, 2, 2]));
        answer.add_authority(ns_record("example.com.", 900, "ns.example.com."));
        answer.add_additional(a_record("ns.example.com.", 500, [192, 0, 2, 53]));
    });

    let packet = query_packet(0x7777, "eXAMPLE.com.", RecordType::A, None);
    let reply = expect_reply(handler.handle_packet(&packet, T0 + 100));
    assert_eq!(reply.source, dns_v4());
    assert_eq!(reply.destination, client_v4());
    let message = decode(&reply.payload);
    assert_eq!(message.metadata.id, 0x7777);
    assert_eq!(message.queries[0].name().to_ascii(), "eXAMPLE.com.");
    assert_eq!(message.answers[0].name.to_ascii(), "eXAMPLE.com.");
    assert_eq!(ttls(&message), [200, 300, 800, 400]);
    assert_eq!(
        message.answers[1].data,
        RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 2)))
    );
    let snapshot = stats.snapshot();
    assert_eq!(
        (
            snapshot.dns_queries,
            snapshot.dns_forwarded,
            snapshot.dns_cache_hits
        ),
        (2, 1, 1)
    );
}

#[test]
fn answers_expire_at_their_smallest_ttl() {
    let (handler, _) = handler();
    fill(&handler, "example.com.", RecordType::A, T0, |answer| {
        answer.add_answer(a_record("example.com.", 300, [192, 0, 2, 1]));
        answer.add_answer(a_record("example.com.", 400, [192, 0, 2, 2]));
    });
    let packet = query_packet(2, "example.com.", RecordType::A, None);
    let message = decode(&expect_reply(handler.handle_packet(&packet, T0 + 299)).payload);
    assert_eq!(ttls(&message), [1, 101]);
    expect_forward(handler.handle_packet(&packet, T0 + 300));
    // The expired entry is gone, so it stays a miss.
    expect_forward(handler.handle_packet(&packet, T0 + 1));
}

#[test]
fn lifetime_is_clamped_to_10_seconds_and_1_hour() {
    assert_eq!((MIN_CACHE_TTL, MAX_CACHE_TTL), (10, 3600));
    let (handler, _) = handler();
    fill(&handler, "zero.example.", RecordType::A, T0, |answer| {
        answer.add_answer(a_record("zero.example.", 0, [192, 0, 2, 1]));
    });
    fill(&handler, "day.example.", RecordType::A, T0, |answer| {
        answer.add_answer(a_record("day.example.", 86_400, [192, 0, 2, 1]));
    });
    let zero = query_packet(2, "zero.example.", RecordType::A, None);
    let day = query_packet(2, "day.example.", RecordType::A, None);
    let message = decode(&expect_reply(handler.handle_packet(&zero, T0 + 9)).payload);
    assert_eq!(ttls(&message), [0]);
    let message = decode(&expect_reply(handler.handle_packet(&day, T0 + 3599)).payload);
    assert_eq!(ttls(&message), [86_400 - 3599]);
    expect_forward(handler.handle_packet(&zero, T0 + 10));
    expect_forward(handler.handle_packet(&day, T0 + 3600));
}

#[test]
fn negative_answers_are_cached() {
    let (handler, _) = handler();
    fill(&handler, "missing.example.", RecordType::A, T0, |answer| {
        answer.metadata.response_code = ResponseCode::NXDomain;
        let soa = SOA::new(
            Name::from_ascii("example.").unwrap(),
            Name::from_ascii("hostmaster.example.").unwrap(),
            1,
            3600,
            600,
            86_400,
            60,
        );
        answer.add_authority(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            120,
            RData::SOA(soa),
        ));
    });
    // NOERROR without records (NODATA) is kept for the 10 second minimum.
    fill(&handler, "nodata.example.", RecordType::AAAA, T0, |_| {});

    let missing = query_packet(3, "missing.example.", RecordType::A, None);
    let message = decode(&expect_reply(handler.handle_packet(&missing, T0 + 20)).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(ttls(&message), [100]);
    expect_forward(handler.handle_packet(&missing, T0 + 120));

    let nodata = query_packet(3, "nodata.example.", RecordType::AAAA, None);
    let message = decode(&expect_reply(handler.handle_packet(&nodata, T0 + 9)).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
    expect_forward(handler.handle_packet(&nodata, T0 + 10));
}

#[test]
fn failures_and_truncated_answers_are_not_cached() {
    let (handler, _) = handler();
    fill(&handler, "servfail.example.", RecordType::A, T0, |answer| {
        answer.metadata.response_code = ResponseCode::ServFail;
    });
    fill(&handler, "refused.example.", RecordType::A, T0, |answer| {
        answer.metadata.response_code = ResponseCode::Refused;
    });
    fill(&handler, "tc.example.", RecordType::A, T0, |answer| {
        answer.metadata.truncation = true;
    });
    let job = expect_forward(handler.handle_packet(
        &query_packet(1, "timeout.example.", RecordType::A, None),
        T0,
    ));
    handler.complete(job, Err(DohError::Timeout), T0);

    for name in [
        "servfail.example.",
        "refused.example.",
        "tc.example.",
        "timeout.example.",
    ] {
        expect_forward(handler.handle_packet(&query_packet(4, name, RecordType::A, None), T0 + 1));
    }
}

#[test]
fn key_is_name_type_and_class() {
    let (handler, _) = handler();
    fill(&handler, "example.com.", RecordType::A, T0, |answer| {
        answer.add_answer(a_record("example.com.", 300, [192, 0, 2, 1]));
    });
    expect_reply(handler.handle_packet(&query_packet(5, "EXAMPLE.COM.", RecordType::A, None), T0));
    expect_forward(
        handler.handle_packet(&query_packet(5, "example.com.", RecordType::AAAA, None), T0),
    );
    expect_forward(handler.handle_packet(
        &query_packet(5, "www.example.com.", RecordType::A, None),
        T0,
    ));
    let mut chaos = query(5, "example.com.", RecordType::A, None);
    let class_at = chaos.len() - 1;
    chaos[class_at] = 3;
    expect_forward(handler.handle_packet(&udp_packet(client_v4(), dns_v4(), &chaos), T0));
}

#[test]
fn hits_are_adapted_to_each_requester() {
    let (handler, _) = handler();
    let job = expect_forward(handler.handle_packet(
        &query_packet(1, "big.example.", RecordType::A, Some((4096, false))),
        T0,
    ));
    // 40 records: 669 bytes, over 512 and under 1232.
    let answer = upstream_answer(job.query(), |answer| {
        for i in 0..40 {
            answer.add_answer(a_record("big.example.", 300, [10, 0, 0, i]));
        }
    });
    handler.complete(job, Ok(answer), T0);

    let plain = query_packet(2, "big.example.", RecordType::A, None);
    let reply = expect_reply(handler.handle_packet(&plain, T0 + 1));
    assert!(reply.payload.len() <= 512);
    let message = decode(&reply.payload);
    assert!(!message.metadata.truncation);
    assert!(!message.answers.is_empty() && message.answers.len() < 40);
    assert!(message.edns.is_none());

    let edns = query_packet(3, "big.example.", RecordType::A, Some((1232, false)));
    let message = decode(&expect_reply(handler.handle_packet(&edns, T0 + 1)).payload);
    assert!(!message.metadata.truncation);
    assert_eq!(message.answers.len(), 40);
    let opt = message.edns.expect("OPT");
    assert!(!opt.flags().dnssec_ok);

    let mut no_rd = query(4, "big.example.", RecordType::A, Some((1232, false)));
    no_rd[2] &= !0x01;
    let packet = udp_packet(client_v4(), dns_v4(), &no_rd);
    let message = decode(&expect_reply(handler.handle_packet(&packet, T0 + 1)).payload);
    assert!(!message.metadata.recursion_desired);
    assert!(message.edns.is_some());
}

/// Appends an RRSIG over the A records of the question name to a built answer.
fn with_rrsig(mut answer: Vec<u8>) -> Vec<u8> {
    let mut rdata = vec![
        0, 1, 13, 2, 0, 0, 1, 44, 0x70, 0, 0, 0, 0x60, 0, 0, 0, 0x12, 0x34,
    ];
    rdata.extend_from_slice(b"\x07example\x00");
    rdata.extend_from_slice(&[0xab; 64]);
    answer.extend_from_slice(&[0xc0, 12, 0, 46, 0, 1, 0, 0, 1, 44]);
    answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    answer.extend_from_slice(&rdata);
    let count = u16::from_be_bytes([answer[6], answer[7]]) + 1;
    answer[6..8].copy_from_slice(&count.to_be_bytes());
    answer
}

fn has_rrsig(message: &Message) -> bool {
    message
        .all_sections()
        .any(|r| r.record_type() == RecordType::RRSIG)
}

#[test]
fn dnssec_answers_are_only_served_to_requesters_that_set_do() {
    let (handler, _) = handler();
    let signed = query_packet(1, "signed.example.", RecordType::A, Some((1232, true)));
    let job = expect_forward(handler.handle_packet(&signed, T0));
    let answer = with_rrsig(upstream_answer(job.query(), |answer| {
        answer.add_answer(a_record("signed.example.", 300, [192, 0, 2, 1]));
    }));
    let message = decode(&checked_reply(&handler.complete(job, Ok(answer), T0)).payload);
    assert!(has_rrsig(&message));

    // A requester without DO never gets DNSSEC records (RFC 3225): not from this entry.
    for edns in [None, Some((1232, false))] {
        let plain = query_packet(2, "signed.example.", RecordType::A, edns);
        match handler.handle_packet(&plain, T0 + 1) {
            tollgate_dns::Outcome::Reply(packet) => {
                let message = decode(&checked_reply(&packet).payload);
                assert!(!has_rrsig(&message), "{edns:?}");
            }
            tollgate_dns::Outcome::Forward(job) => {
                let answer = upstream_answer(job.query(), |answer| {
                    answer.add_answer(a_record("signed.example.", 300, [192, 0, 2, 1]));
                });
                let message =
                    decode(&checked_reply(&handler.complete(job, Ok(answer), T0 + 1)).payload);
                assert!(!has_rrsig(&message), "{edns:?}");
            }
            tollgate_dns::Outcome::Drop => panic!("dropped"),
            tollgate_dns::Outcome::Local(_) => panic!("sent to the local resolver"),
        }
    }

    // Both kinds are cached side by side.
    let message = decode(&expect_reply(handler.handle_packet(&signed, T0 + 2)).payload);
    assert!(has_rrsig(&message));
    let plain = query_packet(3, "signed.example.", RecordType::A, None);
    let message = decode(&expect_reply(handler.handle_packet(&plain, T0 + 2)).payload);
    assert!(!has_rrsig(&message));
}

#[test]
fn least_recently_used_answer_is_evicted_at_capacity() {
    assert_eq!(CACHE_CAPACITY, 2000);
    let (handler, _) = handler();
    let name = |i: usize| format!("n{i}.example.");
    for i in 0..CACHE_CAPACITY {
        fill(&handler, &name(i), RecordType::A, T0, |answer| {
            answer.add_answer(a_record(&name(i), 300, [192, 0, 2, 1]));
        });
    }
    // Touch the oldest entry, then add one more: the second oldest goes.
    expect_reply(handler.handle_packet(&query_packet(1, &name(0), RecordType::A, None), T0));
    fill(&handler, "extra.example.", RecordType::A, T0, |answer| {
        answer.add_answer(a_record("extra.example.", 300, [192, 0, 2, 1]));
    });
    expect_reply(handler.handle_packet(&query_packet(1, &name(0), RecordType::A, None), T0));
    expect_forward(handler.handle_packet(&query_packet(1, &name(1), RecordType::A, None), T0));
    expect_reply(handler.handle_packet(&query_packet(1, &name(2), RecordType::A, None), T0));
    expect_reply(
        handler.handle_packet(&query_packet(1, "extra.example.", RecordType::A, None), T0),
    );
}

#[test]
fn answers_too_big_for_any_reply_are_not_cached() {
    let (handler, stats) = handler();
    // 100 records: about 1,600 bytes, more than any requester accepts whole. Keeping it
    // would only spend memory (DoH answers can be up to 64 KiB).
    fill(&handler, "huge.example.", RecordType::A, T0, |answer| {
        for i in 0..100 {
            answer.add_answer(a_record("huge.example.", 300, [10, 0, 0, i]));
        }
    });
    let packet = query_packet(2, "huge.example.", RecordType::A, Some((4096, false)));
    expect_forward(handler.handle_packet(&packet, T0 + 1));
    assert_eq!(stats.snapshot().dns_cache_hits, 0);
}
