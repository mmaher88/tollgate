//! The allowlist and the blocked log on the DNS path.

mod support;

use std::sync::Arc;

use hickory_proto::rr::RecordType;
use support::{
    a_record, checked_reply, expect_forward, expect_reply, query_packet, upstream_answer,
};
use tollgate_common::clock::unix_secs;
use tollgate_common::events::{BlockEvent, EventKind, EventLog};
use tollgate_common::stats::Stats;
use tollgate_dns::DnsHandler;
use tollgate_filter::{DomainSet, ListFormat, ListSource};
use tollgate_policy::HostPattern;

const NOW: u64 = 1_000;

fn blocklist() -> Arc<DomainSet> {
    let rules = "||ads.example^\n||tracker.test^\n";
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

fn patterns(list: &[&str]) -> Vec<HostPattern> {
    list.iter()
        .map(|p| HostPattern::parse(p).unwrap())
        .collect()
}

fn a_query(name: &str) -> Vec<u8> {
    query_packet(7, name, RecordType::A, None)
}

#[test]
fn allowlisted_blocked_names_are_forwarded() {
    let (handler, stats) = handler();
    handler.set_allowlist(patterns(&["ads.example"]));
    expect_forward(handler.handle_packet(&a_query("ads.example."), NOW));
    expect_forward(handler.handle_packet(&a_query("ADS.Example."), NOW));
    // Exact patterns do not cover subdomains, and other blocked names stay blocked.
    expect_reply(handler.handle_packet(&a_query("cdn.ads.example."), NOW));
    expect_reply(handler.handle_packet(&a_query("tracker.test."), NOW));
    assert_eq!(stats.snapshot().dns_forwarded, 2);
    assert_eq!(stats.snapshot().dns_blocked, 2);
}

#[test]
fn wildcard_allowlist_covers_subdomains() {
    let (handler, stats) = handler();
    handler.set_allowlist(patterns(&["*.ads.example"]));
    for name in ["ads.example.", "cdn.ads.example.", "a.b.ADS.example."] {
        expect_forward(handler.handle_packet(&a_query(name), NOW));
    }
    assert_eq!(stats.snapshot().dns_blocked, 0);
}

#[test]
fn allowlisted_names_are_answered_from_the_cache() {
    let (handler, stats) = handler();
    handler.set_allowlist(patterns(&["*.ads.example"]));
    let job = expect_forward(handler.handle_packet(&a_query("ads.example."), NOW));
    let answer = upstream_answer(job.query(), |m| {
        m.add_answer(a_record("ads.example.", 300, [192, 0, 2, 7]));
    });
    checked_reply(&handler.complete(job, Ok(answer), NOW));

    let reply = expect_reply(handler.handle_packet(&a_query("ads.example."), NOW + 10));
    let message = support::decode(&reply.payload);
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].ttl, 290);
    assert_eq!(stats.snapshot().dns_cache_hits, 1);
    assert_eq!(stats.snapshot().dns_blocked, 0);
}

#[test]
fn allowlist_can_be_replaced_and_cleared() {
    let (handler, _) = handler();
    let packet = a_query("ads.example.");
    expect_reply(handler.handle_packet(&packet, NOW));
    handler.set_allowlist(patterns(&["ads.example"]));
    expect_forward(handler.handle_packet(&packet, NOW));
    handler.set_allowlist(patterns(&["other.example"]));
    expect_reply(handler.handle_packet(&packet, NOW));
    handler.set_allowlist(patterns(&["ads.example"]));
    handler.set_allowlist(Vec::new());
    expect_reply(handler.handle_packet(&packet, NOW));
}

#[test]
fn blocks_are_recorded_lowercased_without_trailing_dot() {
    let (handler, _) = handler();
    let events = Arc::new(EventLog::new());
    handler.set_events(Some(events.clone()));
    let before = unix_secs();
    expect_reply(handler.handle_packet(&a_query("Cdn.ADS.Example."), NOW));
    let after = unix_secs();

    let recorded = events.recent(10);
    assert_eq!(recorded.len(), 1);
    let event = &recorded[0];
    assert!((before..=after).contains(&event.unix_secs), "{event:?}");
    assert_eq!(
        *event,
        BlockEvent {
            unix_secs: event.unix_secs,
            kind: EventKind::Dns,
            host: "cdn.ads.example".into(),
            url: None,
            source_host: None,
        }
    );
}

#[test]
fn only_blocks_are_recorded() {
    let (handler, _) = handler();
    let events = Arc::new(EventLog::new());
    handler.set_events(Some(events.clone()));
    handler.set_allowlist(patterns(&["tracker.test"]));
    expect_forward(handler.handle_packet(&a_query("example.com."), NOW));
    expect_forward(handler.handle_packet(&a_query("tracker.test."), NOW));
    expect_reply(handler.handle_packet(
        &query_packet(1, "ads.example.", RecordType::HTTPS, None),
        NOW,
    ));
    assert!(events.recent(10).is_empty());

    expect_reply(handler.handle_packet(&a_query("ads.example."), NOW));
    expect_reply(handler.handle_packet(
        &query_packet(2, "ads.example.", RecordType::AAAA, None),
        NOW,
    ));
    let hosts: Vec<_> = events.recent(10).into_iter().map(|e| e.host).collect();
    assert_eq!(hosts, ["ads.example", "ads.example"]);
}

#[test]
fn events_can_be_detached() {
    let (handler, stats) = handler();
    let events = Arc::new(EventLog::new());
    handler.set_events(Some(events.clone()));
    handler.set_events(None);
    expect_reply(handler.handle_packet(&a_query("ads.example."), NOW));
    assert!(events.recent(10).is_empty());
    assert_eq!(stats.snapshot().dns_blocked, 1);
}
