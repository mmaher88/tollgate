mod support;

use std::net::Ipv4Addr;
use std::sync::Arc;

use hickory_proto::op::{Edns, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use support::{
    a_record, checked_reply, client_v4, client_v6, decode, dns_v4, dns_v6, expect_forward, query,
    query_packet, udp_packet, upstream_answer,
};
use tollgate_common::stats::Stats;
use tollgate_dns::{DnsHandler, DohError, ForwardJob};

const NOW: u64 = 1_000;

fn handler() -> (DnsHandler, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    (DnsHandler::new(None, stats.clone()), stats)
}

fn forward(handler: &DnsHandler, id: u16, name: &str, edns: Option<(u16, bool)>) -> ForwardJob {
    expect_forward(handler.handle_packet(&query_packet(id, name, RecordType::A, edns), NOW))
}

fn many_a_records(count: u8) -> impl FnOnce(&mut hickory_proto::op::Message) {
    move |answer| {
        for i in 0..count {
            answer.add_answer(a_record("big.example.", 300, [10, 0, 0, i]));
        }
    }
}

#[test]
fn relays_the_answer_with_the_client_id_and_letter_case() {
    let (handler, stats) = handler();
    let job = forward(&handler, 0x4242, "WwW.Example.COM.", None);
    let answer = upstream_answer(job.query(), |answer| {
        answer.add_answer(a_record("www.example.com.", 300, [192, 0, 2, 7]));
    });
    let reply = checked_reply(&handler.complete(job, Ok(answer), NOW));
    assert_eq!(reply.source, dns_v4());
    assert_eq!(reply.destination, client_v4());
    let message = decode(&reply.payload);
    assert_eq!(message.metadata.id, 0x4242);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.queries[0].name().to_ascii(), "WwW.Example.COM.");
    // The record's owner name points at the question, so it shows the client's case too.
    assert_eq!(message.answers[0].name.to_ascii(), "WwW.Example.COM.");
    assert_eq!(message.answers[0].ttl, 300);
    assert_eq!(
        message.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 7)))
    );
    assert_eq!(stats.snapshot().dns_failed, 0);
}

#[test]
fn ipv6_clients_get_ipv6_replies() {
    let (handler, _) = handler();
    let payload = query(6, "example.net.", RecordType::A, None);
    let job =
        expect_forward(handler.handle_packet(&udp_packet(client_v6(), dns_v6(), &payload), NOW));
    let answer = upstream_answer(job.query(), |answer| {
        answer.add_answer(a_record("example.net.", 60, [192, 0, 2, 8]));
    });
    let reply = checked_reply(&handler.complete(job, Ok(answer), NOW));
    assert_eq!(reply.source, dns_v6());
    assert_eq!(reply.destination, client_v6());
    assert_eq!(decode(&reply.payload).answers.len(), 1);
}

fn padded_opt(dnssec_ok: bool) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(4096).set_dnssec_ok(dnssec_ok);
    edns.options_mut()
        .insert(EdnsOption::Unknown(12, vec![0; 200]));
    edns
}

#[test]
fn upstream_opt_is_removed_for_a_client_without_edns() {
    let (handler, _) = handler();
    let job = forward(&handler, 1, "example.com.", None);
    let answer = upstream_answer(job.query(), |answer| {
        answer.add_answer(a_record("example.com.", 300, [192, 0, 2, 1]));
        answer.set_edns(padded_opt(true));
    });
    let upstream_len = answer.len();
    let reply = checked_reply(&handler.complete(job, Ok(answer), NOW));
    // OPT: 11 fixed bytes plus the 204-byte padding option.
    assert_eq!(reply.payload.len(), upstream_len - 215);
    let message = decode(&reply.payload);
    assert!(message.edns.is_none());
    assert_eq!(message.answers.len(), 1);
}

#[test]
fn upstream_opt_is_replaced_by_ours_for_a_client_with_edns() {
    let (handler, _) = handler();
    let job = forward(&handler, 1, "example.com.", Some((4096, false)));
    let answer = upstream_answer(job.query(), |answer| {
        answer.add_answer(a_record("example.com.", 300, [192, 0, 2, 1]));
        answer.set_edns(padded_opt(true));
    });
    let message = decode(&checked_reply(&handler.complete(job, Ok(answer), NOW)).payload);
    let edns = message.edns.expect("OPT");
    assert_eq!(edns.max_payload(), 1232);
    assert!(!edns.flags().dnssec_ok);
    assert!(edns.options().as_ref().is_empty());
    assert_eq!(message.additionals.len(), 0);
}

#[test]
fn opt_is_added_when_the_upstream_sent_none() {
    let (handler, _) = handler();
    let job = forward(&handler, 1, "example.com.", Some((1232, true)));
    let answer = upstream_answer(job.query(), |answer| {
        answer.add_answer(a_record("example.com.", 300, [192, 0, 2, 1]));
    });
    let message = decode(&checked_reply(&handler.complete(job, Ok(answer), NOW)).payload);
    let edns = message.edns.expect("OPT");
    assert_eq!(edns.max_payload(), 1232);
    assert!(edns.flags().dnssec_ok);
}

#[test]
fn large_answers_are_truncated_to_the_client_udp_size() {
    // 40 A records: 12 + 17 + 40 * 16 = 669 bytes without OPT.
    let cases = [
        (None, true),
        (Some((512, false)), true),
        (Some((600, false)), true),
        (Some((1232, false)), false),
        (Some((4096, false)), false),
    ];
    for (edns, truncated) in cases {
        let (handler, _) = handler();
        let job = forward(&handler, 77, "Big.Example.", edns);
        let answer = upstream_answer(job.query(), many_a_records(40));
        let reply = checked_reply(&handler.complete(job, Ok(answer), NOW));
        let message = decode(&reply.payload);
        assert_eq!(message.metadata.truncation, truncated, "{edns:?}");
        assert_eq!(message.metadata.id, 77);
        assert_eq!(message.queries[0].name().to_ascii(), "Big.Example.");
        assert_eq!(message.edns.is_some(), edns.is_some());
        if truncated {
            assert!(message.answers.is_empty());
            let limit = edns.map_or(512, |(size, _)| usize::from(size.clamp(512, 1232)));
            assert!(reply.payload.len() <= limit);
        } else {
            assert_eq!(message.answers.len(), 40);
        }
    }
}

#[test]
fn replies_never_exceed_1232_bytes() {
    let (handler, _) = handler();
    let job = forward(&handler, 5, "big.example.", Some((65000, false)));
    // 12 + 17 + 100 * 16 + 11 = 1640 bytes.
    let answer = upstream_answer(job.query(), many_a_records(100));
    let reply = checked_reply(&handler.complete(job, Ok(answer), NOW));
    let message = decode(&reply.payload);
    assert!(message.metadata.truncation);
    assert!(message.answers.is_empty());
    assert_eq!(message.edns.map(|e| e.max_payload()), Some(1232));
}

#[test]
fn upstream_error_codes_are_passed_through() {
    let (handler, stats) = handler();
    let job = forward(&handler, 3, "missing.example.", None);
    let answer = upstream_answer(job.query(), |answer| {
        answer.metadata.response_code = ResponseCode::NXDomain;
        let soa = SOA::new(
            Name::from_ascii("example.").unwrap(),
            Name::from_ascii("hostmaster.example.").unwrap(),
            1,
            3600,
            600,
            86400,
            120,
        );
        answer.add_authority(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            900,
            RData::SOA(soa),
        ));
    });
    let message = decode(&checked_reply(&handler.complete(job, Ok(answer), NOW)).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(message.authorities.len(), 1);
    assert_eq!(message.authorities[0].ttl, 900);

    let job = forward(&handler, 4, "refused.example.", None);
    let answer = upstream_answer(job.query(), |answer| {
        answer.metadata.response_code = ResponseCode::Refused;
    });
    let message = decode(&checked_reply(&handler.complete(job, Ok(answer), NOW)).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::Refused);
    assert_eq!(stats.snapshot().dns_failed, 0);
}

#[test]
fn upstream_failure_becomes_servfail() {
    let (handler, stats) = handler();
    let job = forward(&handler, 0x0bad, "Example.org.", Some((1232, true)));
    let reply = checked_reply(&handler.complete(job, Err(DohError::Timeout), NOW));
    let message = decode(&reply.payload);
    assert_eq!(message.metadata.id, 0x0bad);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    assert!(message.metadata.recursion_available);
    assert_eq!(message.queries[0].name().to_ascii(), "Example.org.");
    assert!(message.answers.is_empty());
    assert!(message.edns.is_some_and(|e| e.flags().dnssec_ok));

    let job = forward(&handler, 2, "example.org.", None);
    let message = decode(&checked_reply(&handler.complete(job, Err(DohError::Busy), NOW)).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    assert!(message.edns.is_none());
    assert_eq!(stats.snapshot().dns_failed, 2);
}

/// Header, question for `example.com.` A, then the given records, with the given counts.
fn raw_answer(answers: u16, additionals: u16, records: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 1, 0x81, 0x80, 0, 1];
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&additionals.to_be_bytes());
    out.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    out.extend_from_slice(records);
    out
}

const A_RECORD: [u8; 16] = [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1];
const OPT_RECORD: [u8; 11] = [0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0];

#[test]
fn unusable_answers_become_servfail() {
    let (handler, stats) = handler();
    let wrong_question = {
        let job = forward(&handler, 1, "other.example.", None);
        upstream_answer(job.query(), |_| {})
    };
    let not_a_response = query(1, "example.com.", RecordType::A, None);
    let opt_not_last = {
        let mut records = OPT_RECORD.to_vec();
        records.extend_from_slice(&A_RECORD);
        raw_answer(0, 2, &records)
    };
    let extended_rcode = {
        let mut opt = OPT_RECORD;
        // Extended RCODE bits: BADVERS.
        opt[5] = 1;
        raw_answer(0, 1, &opt)
    };
    let record_past_the_end = raw_answer(1, 0, &A_RECORD[..10]);
    let bad = [
        vec![1, 2, 3, 4, 5],
        wrong_question,
        not_a_response,
        opt_not_last,
        extended_rcode,
        record_past_the_end,
    ];
    let count = bad.len() as u64;
    for answer in bad {
        let job = forward(&handler, 9, "example.com.", None);
        let message = decode(&checked_reply(&handler.complete(job, Ok(answer), NOW)).payload);
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(message.metadata.id, 9);
    }
    assert_eq!(stats.snapshot().dns_failed, count);
}

#[test]
fn a_well_formed_raw_answer_is_accepted() {
    let (handler, _) = handler();
    let job = forward(&handler, 9, "EXAMPLE.com.", None);
    let mut records = A_RECORD.to_vec();
    records.extend_from_slice(&OPT_RECORD);
    let answer = raw_answer(1, 1, &records);
    let message = decode(&checked_reply(&handler.complete(job, Ok(answer), NOW)).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers[0].name.to_ascii(), "EXAMPLE.com.");
    assert!(message.edns.is_none());
}
