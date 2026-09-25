//! M3 user controls through the Swift-facing API: the blocked log, the allowlist, learned
//! pin management and host pattern validation.

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use support::{closed_upstream_config, data_dir, path, query, reply, sink};
use tollgate_ffi::{
    BlockEvent, Engine, EventKind, LEARNED_PINS_FILE, LearnedPin, TollgateError,
    forget_stored_pins, stored_learned_pins, validate_host_pattern,
};

const PINS: &str = r#"{"version":1,"pins":[{"host":"b.example","learned_at":5},{"host":"a.example","learned_at":7}]}"#;

fn pin(host: &str, learned_at: u64) -> LearnedPin {
    LearnedPin {
        host: host.to_string(),
        learned_at,
    }
}

fn hosts(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Sends one request to the proxy in absolute form and returns the whole response.
fn proxy_get(port: u16, url: &str, host: &str, extra: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET {url} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[cfg(unix)]
fn assert_private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "{}", path.display());
}

#[cfg(not(unix))]
fn assert_private(_path: &std::path::Path) {}

#[test]
fn dns_blocks_are_in_recent_events_newest_first() {
    let dir = data_dir("", "||ads.example^\n||tracker.test^\n");
    let engine = Engine::new("{}".to_string(), path(&dir)).unwrap();
    assert!(engine.recent_events(10).is_empty());

    engine
        .handle_packets(vec![
            query(1, "Ads.Example.", RecordType::A),
            query(2, "example.com.", RecordType::A),
            query(3, "tracker.test.", RecordType::AAAA),
        ])
        .unwrap();

    let events = engine.recent_events(10);
    let summary: Vec<_> = events
        .iter()
        .map(|e| {
            (
                e.kind,
                e.host.as_str(),
                e.url.clone(),
                e.source_host.clone(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (EventKind::Dns, "tracker.test", None, None),
            (EventKind::Dns, "ads.example", None, None),
        ]
    );
    let now = tollgate_common::clock::unix_secs();
    assert!(
        events
            .iter()
            .all(|e| e.unix_secs <= now && e.unix_secs + 60 > now)
    );
    assert_eq!(engine.recent_events(1).len(), 1);
    assert_eq!(engine.recent_events(1)[0].host, "tracker.test");
    assert!(engine.recent_events(0).is_empty());
}

#[test]
fn clear_events_empties_the_log() {
    let dir = data_dir("", "||ads.example^\n");
    let engine = Engine::new("{}".to_string(), path(&dir)).unwrap();
    engine
        .handle_packets(vec![query(1, "ads.example.", RecordType::A)])
        .unwrap();
    assert_eq!(engine.recent_events(10).len(), 1);
    engine.clear_events();
    assert!(engine.recent_events(10).is_empty());
    assert_eq!(engine.stats().dns_blocked, 1, "counters are kept");
}

#[test]
fn the_config_allowlist_applies_to_dns() {
    let dir = data_dir("", "||ads.example^\n");
    let config = r#"{"allowlist":["*.ads.example"]}"#.to_string();
    let engine = Engine::new(config, path(&dir)).unwrap();
    // Not running, so a forwarded query gets SERVFAIL at once instead of a block.
    let replies = engine
        .handle_packets(vec![query(1, "cdn.ads.example.", RecordType::A)])
        .unwrap();
    assert_eq!(
        reply(&replies[0]).metadata.response_code,
        ResponseCode::ServFail
    );
    let stats = engine.stats();
    assert_eq!((stats.dns_blocked, stats.dns_forwarded), (0, 1));
    assert!(engine.recent_events(10).is_empty());
}

#[test]
fn an_invalid_allowlist_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = Engine::new(r#"{"allowlist":["a b"]}"#.to_string(), path(&dir))
        .err()
        .unwrap();
    assert!(
        matches!(&error, TollgateError::Config { message } if message.starts_with("invalid host pattern \"a b\"")),
        "{error:?}"
    );
}

#[test]
fn request_blocks_share_the_log_and_the_allowlist_applies() {
    let dir = data_dir("||blocked.example^\n/ads/*\n", "||ads.example^\n");
    let config = closed_upstream_config().replacen('{', r#"{"allowlist":["127.0.0.1"],"#, 1);
    let engine = Engine::new(config, path(&dir)).unwrap();
    let port = engine.start(sink().0).unwrap();

    engine
        .handle_packets(vec![query(1, "ads.example.", RecordType::A)])
        .unwrap();
    let response = proxy_get(
        port,
        "http://blocked.example/ad.js?x=1",
        "blocked.example",
        "Referer: https://news.test/page\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");

    // Allowlisted request host: not blocked, so it is forwarded and fails upstream.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let url = format!("http://127.0.0.1:{closed_port}/ads/banner.js");
    let response = proxy_get(port, &url, &format!("127.0.0.1:{closed_port}"), "");
    assert!(!response.starts_with("HTTP/1.1 403 "), "{response}");

    let events = engine.recent_events(10);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(
        events[0],
        BlockEvent {
            unix_secs: events[0].unix_secs,
            kind: EventKind::Request,
            host: "blocked.example".to_string(),
            url: Some("http://blocked.example/ad.js?x=1".to_string()),
            source_host: Some("news.test".to_string()),
        }
    );
    assert_eq!(events[1].kind, EventKind::Dns);
    assert_eq!(events[1].host, "ads.example");
    let stats = engine.stats();
    assert_eq!((stats.http_requests, stats.http_blocked), (2, 1));
    engine.stop();
}

#[test]
fn learned_pins_come_sorted_from_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        Engine::new("{}".to_string(), path(&dir))
            .unwrap()
            .learned_pins()
            .is_empty()
    );
    std::fs::write(dir.path().join(LEARNED_PINS_FILE), PINS).unwrap();
    let engine = Engine::new("{}".to_string(), path(&dir)).unwrap();
    assert_eq!(
        engine.learned_pins(),
        [pin("a.example", 7), pin("b.example", 5)]
    );
}

#[test]
fn forget_pins_saves_the_file_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(LEARNED_PINS_FILE);
    std::fs::write(&file, PINS).unwrap();
    let engine = Engine::new("{}".to_string(), path(&dir)).unwrap();

    assert_eq!(engine.forget_pins(hosts(&["A.Example.", "x.example"])), 1);
    assert_eq!(engine.learned_pins(), [pin("b.example", 5)]);
    let saved = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        saved,
        r#"{"version":1,"pins":[{"host":"b.example","learned_at":5}]}"#
    );
    assert_eq!(saved, engine.learned_pins_json());
    assert_private(&file);

    assert_eq!(engine.forget_pins(hosts(&["a.example"])), 0);
    assert_eq!(engine.forget_pins(Vec::new()), 0);
}

#[test]
fn forget_pins_works_while_running() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(LEARNED_PINS_FILE);
    std::fs::write(&file, PINS).unwrap();
    let engine = Engine::new(closed_upstream_config(), path(&dir)).unwrap();
    engine.start(sink().0).unwrap();
    assert_eq!(engine.forget_pins(hosts(&["a.example", "b.example"])), 2);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        r#"{"version":1,"pins":[]}"#
    );
    engine.stop();
    assert!(engine.learned_pins().is_empty());
}

#[test]
fn validate_host_pattern_uses_the_core_parser() {
    for good in ["example.com", "*.example.com", "Example.COM.", "127.0.0.1"] {
        assert_eq!(validate_host_pattern(good.to_string()), Ok(()), "{good}");
    }
    for bad in ["", "*.", "a b.example", "a.*.example", "exa..mple"] {
        let error = validate_host_pattern(bad.to_string()).unwrap_err();
        let prefix = format!("invalid host pattern {bad:?}: ");
        assert!(
            matches!(&error, TollgateError::Config { message } if message.starts_with(&prefix)),
            "{bad:?} gave {error:?}"
        );
    }
}

#[test]
fn stored_learned_pins_reads_the_file() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(stored_learned_pins(path(&dir)), Ok(Vec::new()));
    let missing = dir.path().join("missing").to_str().unwrap().to_string();
    assert_eq!(stored_learned_pins(missing), Ok(Vec::new()));

    std::fs::write(dir.path().join(LEARNED_PINS_FILE), PINS).unwrap();
    assert_eq!(
        stored_learned_pins(path(&dir)),
        Ok(vec![pin("a.example", 7), pin("b.example", 5)])
    );

    std::fs::write(dir.path().join(LEARNED_PINS_FILE), "not json").unwrap();
    assert_eq!(stored_learned_pins(path(&dir)), Ok(Vec::new()));
}

#[test]
fn forget_stored_pins_rewrites_the_file_like_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(LEARNED_PINS_FILE);

    assert_eq!(forget_stored_pins(path(&dir), hosts(&["a.example"])), Ok(0));
    assert!(!file.exists(), "a missing file is not created");

    std::fs::write(&file, PINS).unwrap();
    assert_eq!(
        forget_stored_pins(path(&dir), hosts(&["B.EXAMPLE.", "none.example"])),
        Ok(1)
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        r#"{"version":1,"pins":[{"host":"a.example","learned_at":7}]}"#
    );
    assert_private(&file);
    assert_eq!(
        stored_learned_pins(path(&dir)),
        Ok(vec![pin("a.example", 7)])
    );
    let engine = Engine::new("{}".to_string(), path(&dir)).unwrap();
    assert_eq!(engine.learned_pins(), [pin("a.example", 7)]);

    assert_eq!(forget_stored_pins(path(&dir), hosts(&["b.example"])), Ok(0));
    assert_eq!(forget_stored_pins(path(&dir), hosts(&["a.example"])), Ok(1));
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        r#"{"version":1,"pins":[]}"#
    );
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name != LEARNED_PINS_FILE)
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn forget_stored_pins_reports_write_errors() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(LEARNED_PINS_FILE);
    std::fs::write(&file, PINS).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        // Root ignores directory permissions; nothing to check then.
        let writable = std::fs::File::create(dir.path().join("probe")).is_ok();
        if !writable {
            let error = forget_stored_pins(path(&dir), hosts(&["a.example"])).unwrap_err();
            assert!(matches!(error, TollgateError::Io { .. }), "{error:?}");
            assert_eq!(std::fs::read_to_string(&file).unwrap(), PINS);
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
