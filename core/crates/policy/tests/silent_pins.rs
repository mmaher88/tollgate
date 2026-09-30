//! Pin learning from silent refusals: clients that hang up during the handshake after
//! receiving our certificate, without an alert. The rule is stricter than for alerts,
//! because clients also hang up for reasons that have nothing to do with the certificate.

use tollgate_policy::{
    Config, Decision, PassthroughReason, Policy, REJECTION_WINDOW_SECS, RejectionKind,
    SILENT_BURST_HOSTS, SILENT_BURST_SECS, SILENT_FLOOD_RATIO, SILENT_FLOOD_SECONDS,
    SILENT_FLOOD_SECS, SILENT_HELD_BACK_LOG_SECS, SILENT_RECENT_SECS, SILENT_REFUSALS,
    SILENT_SUPPRESS_SECS,
};

const T0: u64 = 1_790_000_000;

fn policy() -> Policy {
    Policy::new(&Config::default(), None).unwrap()
}

fn hosts(p: &Policy) -> Vec<String> {
    p.learned_pins().into_iter().map(|(host, _)| host).collect()
}

fn pinned(p: &Policy, host: &str, now: u64) -> bool {
    p.classify(host, now) == Decision::Passthrough(PassthroughReason::LearnedPin)
}

/// Silent refusals of `host` at `start`, `start + 1` and `start + 2`; the last one learns.
fn silent_pin(p: &Policy, host: &str, start: u64) {
    assert!(!p.record_silent_refusal(host, start));
    assert!(!p.record_silent_refusal(host, start + 1));
    assert!(p.record_silent_refusal(host, start + 2));
}

#[test]
fn the_rule_is_three_refusals_in_different_seconds_within_ten_minutes() {
    assert_eq!(SILENT_REFUSALS, 3);
    assert_eq!(REJECTION_WINDOW_SECS, 600);
    assert_eq!(SILENT_RECENT_SECS, 60);
    assert_eq!(SILENT_BURST_HOSTS, 4);
    assert_eq!(SILENT_BURST_SECS, 10);
    assert_eq!(SILENT_SUPPRESS_SECS, 60);
    assert_eq!(SILENT_FLOOD_SECS, 60);
    assert_eq!(SILENT_FLOOD_SECONDS, 10);
    assert_eq!(SILENT_FLOOD_RATIO, 5);
    assert_eq!(SILENT_HELD_BACK_LOG_SECS, 300);
}

#[test]
fn refusals_in_three_different_seconds_learn_a_pin() {
    let p = policy();
    assert!(!p.record_silent_refusal("api.pinned.example", T0));
    assert!(!p.record_silent_refusal("API.Pinned.Example.", T0 + 1));
    assert!(!pinned(&p, "api.pinned.example", T0 + 1));
    assert!(p.record_silent_refusal("api.pinned.example", T0 + 2));
    assert!(pinned(&p, "api.pinned.example", T0 + 2));
    assert_eq!(
        p.learned_pins(),
        [("api.pinned.example".to_string(), T0 + 2)]
    );
    // Already a pin: further refusals report nothing new.
    assert!(!p.record_silent_refusal("api.pinned.example", T0 + 3));
    // Per host, not per domain.
    assert!(!pinned(&p, "www.pinned.example", T0 + 3));
}

#[test]
fn refusals_within_one_second_count_once() {
    // Connections that were set up together and hung up together, like the losers of a
    // race to another network, are one refusal.
    let p = policy();
    for _ in 0..10 {
        assert!(!p.record_silent_refusal("race.example", T0));
    }
    for _ in 0..10 {
        assert!(!p.record_silent_refusal("race.example", T0 + 1));
    }
    assert!(hosts(&p).is_empty());
    assert!(p.record_silent_refusal("race.example", T0 + 2));
}

#[test]
fn refusals_must_fall_within_the_window() {
    let p = policy();
    assert!(!p.record_silent_refusal("slow.example", T0));
    assert!(!p.record_silent_refusal("slow.example", T0 + 300));
    assert!(!p.record_silent_refusal("slow.example", T0 + REJECTION_WINDOW_SECS + 1));
    assert!(hosts(&p).is_empty());
    // The window slides: the last three are within ten minutes.
    assert!(p.record_silent_refusal("slow.example", T0 + REJECTION_WINDOW_SECS + 2));
}

#[test]
fn a_host_refused_in_two_seconds_per_use_is_learned_on_the_next_use() {
    // The X app's second pinned host on 2026-09-30, from the device log: refused at
    // 08:48:46 and 08:48:50 during one use of the app, and in no other second. The same
    // use two minutes later brings the third second.
    let p = policy();
    let host = "upload.x.example";
    assert!(!p.record_silent_refusal(host, T0 + 46));
    assert!(!p.record_silent_refusal(host, T0 + 50));
    assert!(hosts(&p).is_empty());
    let next = T0 + 120;
    assert!(p.record_silent_refusal(host, next + 46));
    assert_eq!(hosts(&p), [host]);
}

#[test]
fn uses_further_apart_than_the_window_teach_nothing() {
    let p = policy();
    let host = "upload.x.example";
    for n in 0..5 {
        let start = T0 + n * 11 * 60;
        assert!(!p.record_silent_refusal(host, start + 46));
        assert!(!p.record_silent_refusal(host, start + 50));
    }
    assert!(hosts(&p).is_empty());
}

#[test]
fn a_trusted_handshake_keeps_the_host_from_being_learned_for_the_window() {
    let p = policy();
    p.record_intercepted_handshake("www.site.example", T0);
    // Refusals in as many different seconds as a minute can hold without a flood, many
    // each, then every ten seconds for the rest of the window.
    for at in T0 + 1..T0 + SILENT_FLOOD_SECONDS as u64 {
        for _ in 0..20 {
            assert!(!p.record_silent_refusal("www.site.example", at));
        }
    }
    for at in (T0 + 70..T0 + REJECTION_WINDOW_SECS).step_by(10) {
        assert!(!p.record_silent_refusal("www.site.example", at));
    }
    assert!(hosts(&p).is_empty());
    // Ten minutes after the last success, refusals count again.
    let later = T0 + REJECTION_WINDOW_SECS + 1;
    silent_pin(&p, "www.site.example", later);
}

#[test]
fn a_trusted_handshake_guards_the_whole_window() {
    // A browser completed one handshake and keeps using that connection, so it makes no
    // new handshakes; hang-ups of its other connections minutes apart must not add up.
    let p = policy();
    p.record_intercepted_handshake("news.example", T0);
    for at in [T0 + 100, T0 + 400, T0 + 650] {
        assert!(!p.record_silent_refusal("news.example", at));
    }
    assert!(hosts(&p).is_empty());
}

#[test]
fn a_trusted_handshake_forgets_pending_refusals() {
    let p = policy();
    assert!(!p.record_silent_refusal("www.site.example", T0));
    assert!(!p.record_silent_refusal("www.site.example", T0 + 1));
    p.record_intercepted_handshake("WWW.SITE.EXAMPLE.", T0 + 1);
    assert!(!p.record_silent_refusal("www.site.example", T0 + 2));
    assert!(!p.record_silent_refusal("www.site.example", T0 + 3));
    assert!(hosts(&p).is_empty());
    // Other hosts are not affected.
    silent_pin(&p, "api.pinned.example", T0 + 4);
}

#[test]
fn a_browser_that_trusts_us_is_never_learned() {
    // A browser completes handshakes for a site, and hangs up some connections early
    // (preconnects it did not need, races lost to another network). The worst moment in a
    // device log: 7 hang-ups within 2 seconds on two hosts that completed 18 and 2
    // handshakes then. Here each host has 7 hang-ups every 5 seconds for ten minutes,
    // before its handshakes of that moment: refusals in far more than
    // SILENT_FLOOD_SECONDS different seconds a minute.
    let p = policy();
    for burst in 0..120 {
        let now = T0 + burst * 5;
        for (host, handshakes) in [("www.news.example", 18), ("img.news.example", 2)] {
            for _ in 0..4 {
                assert!(!p.record_silent_refusal(host, now));
            }
            for _ in 0..3 {
                assert!(!p.record_silent_refusal(host, now + 1));
            }
            for _ in 0..handshakes {
                p.record_intercepted_handshake(host, now + 1);
            }
        }
    }
    // One that hangs up a connection every second and completes one every second.
    for second in 0..600 {
        let now = T0 + 1_000 + second;
        assert!(!p.record_silent_refusal("api.news.example", now));
        p.record_intercepted_handshake("api.news.example", now);
    }
    assert!(hosts(&p).is_empty());
}

#[test]
fn refusals_on_many_hosts_at_once_are_a_burst_and_teach_nothing() {
    let p = policy();
    assert!(!p.record_silent_refusal("a.example", T0));
    assert!(!p.record_silent_refusal("a.example", T0 + 1));
    assert!(!p.record_silent_refusal("b.example", T0 + 2));
    assert!(!p.record_silent_refusal("c.example", T0 + 3));
    // The fourth host within ten seconds: a burst. a.example's two refusals are forgotten.
    assert!(!p.record_silent_refusal("d.example", T0 + 4));
    // Suppressed for a minute, whatever the host.
    assert!(!p.record_silent_refusal("a.example", T0 + 20));
    assert!(!p.record_silent_refusal("a.example", T0 + 21));
    assert!(!p.record_silent_refusal("a.example", T0 + 22));
    assert!(!p.record_silent_refusal("a.example", T0 + 4 + SILENT_SUPPRESS_SECS - 1));
    assert!(hosts(&p).is_empty());
    // Then learning works again, from new refusals only.
    let after = T0 + 4 + SILENT_SUPPRESS_SECS;
    silent_pin(&p, "a.example", after);
    assert_eq!(hosts(&p), ["a.example"]);
}

#[test]
fn hosts_refused_further_apart_are_not_a_burst() {
    let p = policy();
    silent_pin(&p, "a.example", T0);
    assert!(!p.record_silent_refusal("b.example", T0 + 5));
    assert!(!p.record_silent_refusal("c.example", T0 + 11));
    silent_pin(&p, "d.example", T0 + 13);
    assert_eq!(hosts(&p), ["a.example", "d.example"]);
}

#[test]
fn a_burst_takes_back_silent_pins_from_its_window_and_keeps_other_pins() {
    let p = policy();
    silent_pin(&p, "old.example", T0);
    // Learned from an alert and from the upstream server, within the burst window.
    assert!(!p.record_client_rejection("alert.example", RejectionKind::UnknownCa, T0 + 20));
    assert!(p.record_client_rejection("alert.example", RejectionKind::UnknownCa, T0 + 21));
    assert!(p.learn_upstream_untrusted("legacy.example", T0 + 21));
    silent_pin(&p, "new.example", T0 + 20);
    assert!(!p.record_silent_refusal("b.example", T0 + 24));
    assert!(!p.record_silent_refusal("c.example", T0 + 25));
    // new.example, b, c and d within ten seconds.
    assert!(!p.record_silent_refusal("d.example", T0 + 26));
    assert_eq!(
        hosts(&p),
        ["alert.example", "legacy.example", "old.example"]
    );
    assert!(!pinned(&p, "new.example", T0 + 27));
}

#[test]
fn a_burst_lasts_while_many_hosts_keep_refusing() {
    // The Tollgate certificate is no longer trusted: every client fails, all the time.
    let p = policy();
    for (i, host) in ["a", "b", "c", "d"].iter().enumerate() {
        p.record_silent_refusal(&format!("{host}.example"), T0 + i as u64);
    }
    // Still failing on many hosts 50 seconds later: suppressed a minute from then.
    for (i, host) in ["e", "f", "g", "h"].iter().enumerate() {
        p.record_silent_refusal(&format!("{host}.example"), T0 + 50 + i as u64);
    }
    for at in [
        T0 + 80,
        T0 + 81,
        T0 + 82,
        T0 + 53 + SILENT_SUPPRESS_SECS - 1,
    ] {
        assert!(!p.record_silent_refusal("app.example", at));
    }
    assert!(hosts(&p).is_empty());
    silent_pin(&p, "app.example", T0 + 53 + SILENT_SUPPRESS_SECS);
}

#[test]
fn the_x_app_timeline_learns_its_api_host() {
    // The X app for iOS on 2026-09-30, from the device log, in whole seconds. Its API
    // host was refused 13 times within 5 seconds, a second host twice, and a third host,
    // which the app had trusted 7 seconds before, once.
    let p = policy();
    let api = "api.x.example";
    let upload = "upload.x.example";
    let media = "media.x.example";
    let start = T0 + 45;
    assert!(!p.record_silent_refusal(api, start));
    assert!(!p.record_silent_refusal(api, start));
    assert!(!p.record_silent_refusal(upload, start + 1));
    assert!(!p.record_silent_refusal(api, start + 1));
    p.record_intercepted_handshake(media, start + 2);
    assert!(p.record_silent_refusal(api, start + 2));
    // Passed through from now on, so no more refusals from it.
    assert!(!p.record_silent_refusal(upload, start + 5));
    assert!(!p.record_silent_refusal(media, start + 9));
    assert_eq!(hosts(&p), [api]);
}

#[test]
fn a_network_change_drops_recent_silent_pins_and_pending_refusals() {
    let p = policy();
    silent_pin(&p, "old.example", T0);
    assert!(!p.record_client_rejection("alert.example", RejectionKind::UnknownCa, T0 + 100));
    assert!(p.record_client_rejection("alert.example", RejectionKind::UnknownCa, T0 + 101));
    silent_pin(&p, "new.example", T0 + 100);
    assert!(!p.record_silent_refusal("pending.example", T0 + 110));
    assert!(!p.record_silent_refusal("pending.example", T0 + 111));
    p.on_network_change(T0 + 120);
    assert_eq!(hosts(&p), ["alert.example", "old.example"]);
    // The pending refusals are gone: one more does not learn.
    assert!(!p.record_silent_refusal("pending.example", T0 + 121));
    // A dropped host is learned again from new refusals.
    silent_pin(&p, "new.example", T0 + 130);
    // Nothing else changes on a second call later.
    p.on_network_change(T0 + 200);
    assert_eq!(hosts(&p), ["alert.example", "new.example", "old.example"]);
}

#[test]
fn silent_pins_are_saved_and_pending_refusals_are_not() {
    let p = policy();
    silent_pin(&p, "pinned.example", T0);
    assert!(!p.record_silent_refusal("pending.example", T0 + 10));
    assert!(!p.record_silent_refusal("pending.example", T0 + 11));
    let json = p.learned_pins_json();
    assert_eq!(
        json,
        format!(
            r#"{{"version":1,"pins":[{{"host":"pinned.example","learned_at":{}}}]}}"#,
            T0 + 2
        )
    );
    let restored = Policy::new(&Config::default(), Some(&json)).unwrap();
    assert!(pinned(&restored, "pinned.example", T0 + 12));
    assert!(!restored.record_silent_refusal("pending.example", T0 + 12));
    assert_eq!(hosts(&restored), ["pinned.example"]);
    // A restored pin is not taken back by a network change: only fresh ones are.
    restored.on_network_change(T0 + 13);
    assert!(pinned(&restored, "pinned.example", T0 + 13));
}

#[test]
fn forgetting_a_host_forgets_its_pending_refusals() {
    let p = policy();
    silent_pin(&p, "pinned.example", T0);
    assert!(!p.record_silent_refusal("pending.example", T0 + 10));
    assert!(!p.record_silent_refusal("pending.example", T0 + 11));
    let forgotten = ["pinned.example".to_string(), "pending.example".to_string()];
    assert_eq!(p.forget_pins(&forgotten), 1);
    assert!(hosts(&p).is_empty());
    assert!(!p.record_silent_refusal("pending.example", T0 + 12));
    silent_pin(&p, "pinned.example", T0 + 20);
}

#[test]
fn alerts_and_silent_refusals_are_counted_apart() {
    let p = policy();
    assert!(!p.record_client_rejection("mixed.example", RejectionKind::UnknownCa, T0));
    assert!(!p.record_silent_refusal("mixed.example", T0 + 1));
    assert!(!p.record_silent_refusal("mixed.example", T0 + 2));
    assert!(hosts(&p).is_empty());
    // The alert rule is unchanged: a second alert learns.
    assert!(p.record_client_rejection("mixed.example", RejectionKind::BadCertificate, T0 + 3));
}

#[test]
fn empty_hosts_teach_nothing() {
    let p = policy();
    p.record_intercepted_handshake("", T0);
    for at in T0..T0 + 5 {
        assert!(!p.record_silent_refusal("", at));
        assert!(!p.record_silent_refusal(".", at));
    }
    assert!(hosts(&p).is_empty());
}

#[test]
fn many_hosts_stay_bounded() {
    let p = policy();
    // Far enough apart that no ten seconds see four hosts.
    for i in 0..5_000u64 {
        let host = format!("h{i}.example");
        let at = T0 + i * 11;
        p.record_intercepted_handshake(&format!("t{i}.example"), at);
        assert!(!p.record_silent_refusal(&host, at));
        assert!(!p.record_silent_refusal(&host, at + 1));
    }
    // The most recent host is still remembered, so its third refusal learns.
    let last = T0 + 4_999 * 11;
    assert!(p.record_silent_refusal("h4999.example", last + 2));
    // And the most recent success still counts.
    assert!(!p.record_silent_refusal("t4999.example", last + 3));
    assert!(!p.record_silent_refusal("t4999.example", last + 4));
    assert!(!p.record_silent_refusal("t4999.example", last + 5));
    assert_eq!(hosts(&p), ["h4999.example"]);
}
