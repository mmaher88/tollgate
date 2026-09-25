use std::sync::Arc;

use tollgate_common::events::{BlockEvent, EventKind, EventLog};

fn dns(host: &str, unix_secs: u64) -> BlockEvent {
    BlockEvent {
        unix_secs,
        kind: EventKind::Dns,
        host: host.to_owned(),
        url: None,
        source_host: None,
    }
}

fn request(url: String) -> BlockEvent {
    BlockEvent {
        unix_secs: 1,
        kind: EventKind::Request,
        host: "ads.example".to_owned(),
        url: Some(url),
        source_host: Some("news.example".to_owned()),
    }
}

#[test]
fn new_log_is_empty() {
    let log = EventLog::new();
    assert!(log.recent(10).is_empty());
    assert!(EventLog::default().recent(10).is_empty());
}

#[test]
fn recent_returns_newest_first() {
    let log = EventLog::new();
    for i in 0..3 {
        log.record(dns(&format!("h{i}.example"), i));
    }
    let hosts: Vec<_> = log.recent(10).into_iter().map(|e| e.host).collect();
    assert_eq!(hosts, ["h2.example", "h1.example", "h0.example"]);
}

#[test]
fn recent_respects_limit() {
    let log = EventLog::new();
    for i in 0..5 {
        log.record(dns(&format!("h{i}.example"), i));
    }
    let recent = log.recent(2);
    assert_eq!(recent, [dns("h4.example", 4), dns("h3.example", 3)]);
    assert!(log.recent(0).is_empty());
}

#[test]
fn keeps_only_the_newest_capacity_events() {
    assert_eq!(EventLog::CAPACITY, 500);
    let log = EventLog::new();
    for i in 0..(EventLog::CAPACITY as u64 + 7) {
        log.record(dns(&format!("h{i}.example"), i));
    }
    let recent = log.recent(usize::MAX);
    assert_eq!(recent.len(), EventLog::CAPACITY);
    assert_eq!(recent[0].unix_secs, EventLog::CAPACITY as u64 + 6);
    assert_eq!(recent[EventLog::CAPACITY - 1].unix_secs, 7);
}

#[test]
fn clear_removes_every_event() {
    let log = EventLog::new();
    log.record(dns("a.example", 1));
    log.record(dns("b.example", 2));
    log.clear();
    assert!(log.recent(10).is_empty());
    log.record(dns("c.example", 3));
    assert_eq!(log.recent(10), [dns("c.example", 3)]);
}

#[test]
fn short_urls_are_kept_whole() {
    assert_eq!(EventLog::MAX_URL_BYTES, 512);
    let log = EventLog::new();
    let url = format!("https://ads.example/{}", "a".repeat(512 - 20));
    assert_eq!(url.len(), 512);
    log.record(request(url.clone()));
    assert_eq!(log.recent(1)[0], request(url));
}

#[test]
fn long_urls_are_truncated_to_max_bytes() {
    let log = EventLog::new();
    let url = format!("https://ads.example/{}", "a".repeat(1000));
    log.record(request(url.clone()));
    let stored = log.recent(1).remove(0).url.unwrap();
    assert_eq!(stored.len(), EventLog::MAX_URL_BYTES);
    assert_eq!(stored, url[..EventLog::MAX_URL_BYTES]);
}

#[test]
fn truncation_stops_at_a_character_boundary() {
    let log = EventLog::new();
    // "https://ads.example/" is 20 bytes; each "é" is 2 bytes, so byte 512 falls in the
    // middle of a character when the prefix is 21 bytes.
    let url = format!("https://ads.example/x{}", "é".repeat(400));
    assert!(!url.is_char_boundary(EventLog::MAX_URL_BYTES));
    log.record(request(url.clone()));
    let stored = log.recent(1).remove(0).url.unwrap();
    assert_eq!(stored.len(), EventLog::MAX_URL_BYTES - 1);
    assert!(url.starts_with(&stored));

    // Four-byte characters: the cut may drop up to three bytes.
    let url = format!("https://ads.example/{}", "😀".repeat(200));
    log.record(request(url.clone()));
    let stored = log.recent(1).remove(0).url.unwrap();
    assert!(stored.len() <= EventLog::MAX_URL_BYTES);
    assert!(stored.len() > EventLog::MAX_URL_BYTES - 4);
    assert!(url.starts_with(&stored));
    assert!(stored.ends_with('😀'));
}

#[test]
fn events_without_url_stay_without_url() {
    let log = EventLog::new();
    log.record(dns("a.example", 1));
    assert_eq!(log.recent(1)[0].url, None);
}

#[test]
fn records_from_many_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EventLog>();

    let log = Arc::new(EventLog::new());
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                for i in 0..100 {
                    log.record(dns(&format!("t{t}-{i}.example"), i));
                    let _ = log.recent(5);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let recent = log.recent(usize::MAX);
    assert_eq!(recent.len(), 500);
    // Every thread's events appear in the order that thread recorded them.
    for t in 0..8 {
        let prefix = format!("t{t}-");
        let secs: Vec<_> = recent
            .iter()
            .filter(|e| e.host.starts_with(&prefix))
            .map(|e| e.unix_secs)
            .collect();
        assert!(secs.windows(2).all(|w| w[0] > w[1]), "thread {t}: {secs:?}");
    }
}
