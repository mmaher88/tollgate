//! The engine without its runtime: construction, local DNS answers, list reloads.

mod support;

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, RecordType};
use support::{client, compile_into, data_dir, path, query, reply};
use tollgate_dns::packet::build_udp;
use tollgate_ffi::{Engine, LEARNED_PINS_FILE, Stats, TollgateError, generate_ca};

const EMPTY_PINS: &str = r#"{"version":1,"pins":[]}"#;

fn engine(dir: &tempfile::TempDir) -> std::sync::Arc<Engine> {
    Engine::new("{}".to_string(), path(dir)).unwrap()
}

#[test]
fn invalid_config_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = Engine::new("not json".to_string(), path(&dir))
        .err()
        .unwrap();
    assert!(
        matches!(&error, TollgateError::Config { message } if message.starts_with("invalid configuration: ")),
        "{error:?}"
    );
    let error = Engine::new(
        r#"{"passthrough":["exa mple.com"]}"#.to_string(),
        path(&dir),
    )
    .err()
    .unwrap();
    assert!(
        matches!(&error, TollgateError::Config { message } if message.starts_with("invalid host pattern \"exa mple.com\"")),
        "{error:?}"
    );
}

#[test]
fn an_empty_data_dir_gives_a_dns_only_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    assert!(!engine.mitm_active());
    assert_eq!(engine.stats(), Stats::default());
    assert_eq!(engine.learned_pins_json(), EMPTY_PINS);
}

#[test]
fn blocked_names_get_unspecified_addresses() {
    let dir = data_dir("", "||ads.example^\n");
    let engine = engine(&dir);
    let replies = engine
        .handle_packets(vec![
            query(0x0101, "ads.example.", RecordType::A),
            query(0x0202, "cdn.ads.example.", RecordType::AAAA),
        ])
        .unwrap();
    assert_eq!(replies.len(), 2);
    let v4 = reply(&replies[0]);
    assert_eq!(v4.metadata.id, 0x0101);
    assert_eq!(v4.metadata.response_code, ResponseCode::NoError);
    assert_eq!(v4.answers.len(), 1);
    assert_eq!(v4.answers[0].ttl, 60);
    assert_eq!(v4.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    let v6 = reply(&replies[1]);
    assert_eq!(v6.metadata.id, 0x0202);
    assert_eq!(v6.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 2,
            dns_blocked: 2,
            ..Stats::default()
        }
    );
}

#[test]
fn https_queries_get_an_empty_answer() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    let replies = engine
        .handle_packets(vec![query(7, "example.com.", RecordType::HTTPS)])
        .unwrap();
    let message = reply(&replies[0]);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
}

#[test]
fn forwarded_queries_get_servfail_while_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    let replies = engine
        .handle_packets(vec![query(0x3333, "example.com.", RecordType::A)])
        .unwrap();
    assert_eq!(replies.len(), 1);
    let message = reply(&replies[0]);
    assert_eq!(message.metadata.id, 0x3333);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 1,
            dns_forwarded: 1,
            dns_failed: 1,
            ..Stats::default()
        }
    );
}

#[test]
fn other_packets_are_dropped_and_order_is_kept() {
    let dir = data_dir("", "||ads.example^\n");
    let engine = engine(&dir);
    let not_dns = build_udp(client(), "198.18.0.1:80".parse().unwrap(), &[0u8; 20]).unwrap();
    let replies = engine
        .handle_packets(vec![
            query(1, "ads.example.", RecordType::A),
            not_dns,
            vec![0x45, 0x00, 0x01],
            query(2, "example.com.", RecordType::HTTPS),
        ])
        .unwrap();
    let ids: Vec<u16> = replies.iter().map(|r| reply(r).metadata.id).collect();
    assert_eq!(ids, vec![1, 2]);
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 2,
            dns_blocked: 1,
            packets_dropped: 2,
            ..Stats::default()
        }
    );
}

#[test]
fn reload_swaps_both_lists_or_neither() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(&dir);
    let blocked = |engine: &Engine| {
        let replies = engine
            .handle_packets(vec![query(9, "ads.example.", RecordType::A)])
            .unwrap();
        reply(&replies[0]).metadata.response_code == ResponseCode::NoError
    };
    assert!(!blocked(&engine), "no blocklist yet: forwarded, SERVFAIL");

    compile_into(&dir, "||ads.example^\n", "||ads.example^\n");
    engine.reload_lists().unwrap();
    assert!(blocked(&engine));

    // Replaced by rename, like compile does: the loaded set maps the old file.
    let junk = dir.path().join("junk.tmp");
    fs::write(&junk, b"junk").unwrap();
    fs::rename(&junk, dir.path().join("domains.bin")).unwrap();
    let error = engine.reload_lists().unwrap_err();
    assert!(matches!(&error, TollgateError::Lists { .. }), "{error:?}");
    assert!(blocked(&engine), "the old lists stay after a failed reload");

    fs::remove_file(dir.path().join("domains.bin")).unwrap();
    fs::remove_file(dir.path().join("engine.dat")).unwrap();
    engine.reload_lists().unwrap();
    assert!(!blocked(&engine), "missing files clear the lists");
}

#[test]
fn interception_needs_the_flag_the_ca_and_the_engine() {
    let dir = data_dir("||ads.example^\n", "");
    assert!(!engine(&dir).mitm_active(), "no CA");
    generate_ca(path(&dir)).unwrap();
    assert!(engine(&dir).mitm_active());
    let off = Engine::new(r#"{"mitm_enabled":false}"#.to_string(), path(&dir)).unwrap();
    assert!(!off.mitm_active());
    fs::remove_file(dir.path().join("engine.dat")).unwrap();
    assert!(!engine(&dir).mitm_active(), "no engine.dat");
}

#[test]
fn unreadable_files_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("engine.dat"), b"junk").unwrap();
    fs::write(dir.path().join("domains.bin"), b"junk").unwrap();
    fs::write(dir.path().join("ca.pem"), b"junk").unwrap();
    fs::write(dir.path().join("ca.key"), b"junk").unwrap();
    fs::write(dir.path().join(LEARNED_PINS_FILE), b"junk").unwrap();
    let engine = engine(&dir);
    assert!(!engine.mitm_active());
    assert_eq!(engine.learned_pins_json(), EMPTY_PINS);
}

#[test]
fn learned_pins_are_loaded_from_the_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let now = tollgate_common::clock::unix_secs();
    let pins =
        format!(r#"{{"version":1,"pins":[{{"host":"pinned.example","learned_at":{now}}}]}}"#);
    fs::write(dir.path().join(LEARNED_PINS_FILE), &pins).unwrap();
    assert_eq!(engine(&dir).learned_pins_json(), pins);
}
