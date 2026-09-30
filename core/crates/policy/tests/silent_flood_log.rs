//! The info lines, which the tunnel's log shows, that name a host whose silent refusals
//! the success guard holds back, and a host learned from a flood. One test function: the
//! logger is process-wide, so the steps must not run in parallel.

use std::sync::Mutex;

use log::{Level, LevelFilter, Log, Metadata, Record};
use tollgate_policy::{Config, Policy, SILENT_HELD_BACK_LOG_SECS};

const T0: u64 = 1_790_000_000;

/// Keeps the messages this crate logs at info level or above.
struct Capture(Mutex<Vec<String>>);

impl Log for Capture {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info && metadata.target().starts_with("tollgate_policy")
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            self.0.lock().unwrap().push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));

fn take() -> Vec<String> {
    std::mem::take(&mut *CAPTURE.0.lock().unwrap())
}

/// The line for held-back refusals of `host`.
fn held_back(host: &str, refusals: u32, seconds: u32, ago: u64, handshakes: u32) -> String {
    format!(
        "not learning a certificate pin for {host} yet: {refusals} silent refusals in {seconds} \
         different seconds within 60 s, but a client trusted our certificate for it {ago} s \
         ago, with {handshakes} handshakes within 60 s (a flood of refusals in 10 different \
         seconds, 5 times the handshakes, would make it a pin)"
    )
}

#[test]
fn held_back_refusals_and_floods_are_logged() {
    log::set_logger(&CAPTURE).unwrap();
    log::set_max_level(LevelFilter::Debug);
    let p = Policy::new(&Config::default(), None).unwrap();

    // A browser's hang-ups of a moment on a host it trusts us for: nothing at info level.
    let browser = "www.news.example";
    for _ in 0..18 {
        p.record_intercepted_handshake(browser, T0);
    }
    for _ in 0..4 {
        assert!(!p.record_silent_refusal(browser, T0));
    }
    for _ in 0..3 {
        assert!(!p.record_silent_refusal(browser, T0 + 1));
    }
    assert!(take().is_empty());

    // An app that pins a host another client trusts us for: named once its refusals fall
    // in three different seconds within a minute, with the counts.
    let app = "upload.messenger.example";
    p.record_intercepted_handshake(app, T0);
    for _ in 0..5 {
        assert!(!p.record_silent_refusal(app, T0 + 10));
    }
    assert!(!p.record_silent_refusal(app, T0 + 11));
    assert!(take().is_empty());
    assert!(!p.record_silent_refusal(app, T0 + 12));
    assert_eq!(take(), [held_back(app, 7, 3, 12, 1)]);
    // Not again while it goes on, short of a flood.
    for now in T0 + 12..T0 + 19 {
        assert!(!p.record_silent_refusal(app, now));
    }
    assert!(take().is_empty());
    // Another host is named on its own.
    let other = "graph.meta.example";
    p.record_intercepted_handshake(other, T0 + 20);
    for now in T0 + 20..T0 + 23 {
        assert!(!p.record_silent_refusal(other, now));
    }
    assert_eq!(take(), [held_back(other, 3, 3, 2, 1)]);

    // The app again SILENT_HELD_BACK_LOG_SECS after its line, not a second sooner.
    let again = T0 + 12 + SILENT_HELD_BACK_LOG_SECS;
    for now in again - 3..again {
        assert!(!p.record_silent_refusal(app, now));
    }
    assert!(take().is_empty());
    assert!(!p.record_silent_refusal(app, again));
    assert_eq!(take(), [held_back(app, 4, 4, 312, 0)]);

    // Then a flood: six more different seconds make ten.
    for now in again + 1..again + 6 {
        assert!(!p.record_silent_refusal(app, now));
    }
    assert!(p.record_silent_refusal(app, again + 6));
    assert_eq!(
        take(),
        [format!(
            "learned certificate pin for {app} after a flood of 10 silent refusals in 10 \
             different seconds within 60 s, against 0 handshakes; a client trusted our \
             certificate for it 318 s ago"
        )]
    );
}
