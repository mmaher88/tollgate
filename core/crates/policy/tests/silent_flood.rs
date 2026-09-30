//! Pin learning from a flood of silent refusals: a pinning app that keeps retrying on a
//! host that other clients trust us for is learned although a client completed a handshake
//! for the host within the success guard's window. A browser that mostly succeeds never is
//! (see `a_browser_that_trusts_us_is_never_learned` in `silent_pins.rs`).

use tollgate_policy::{
    Config, Decision, PassthroughReason, Policy, SILENT_BURST_SECS, SILENT_FLOOD_RATIO,
    SILENT_FLOOD_SECONDS, SILENT_FLOOD_SECS, SILENT_RECENT_SECS, SILENT_SUPPRESS_SECS,
};

const T0: u64 = 1_790_000_000;

/// The host Messenger pinned, whose name the device log does not show.
const PINNED: &str = "upload.messenger.example";

/// Messenger's silent refusals of one host in the device log of 2026-09-30, from 13:59:39
/// on: (second, connections refused in it), 286 in 39 different seconds within a minute.
/// Each connection was cancelled in the app's certificate check about 9 ms after it
/// received our leaf.
#[rustfmt::skip]
const MESSENGER: [(u64, u32); 39] = [
    (0, 6), (1, 10), (2, 25), (3, 29), (4, 1), (5, 16), (6, 12), (17, 1), (18, 8), (19, 25),
    (21, 7), (23, 3), (24, 1), (25, 1), (26, 1), (27, 24), (29, 1), (31, 2), (32, 1),
    (33, 1), (35, 16), (36, 9), (37, 1), (39, 2), (40, 7), (41, 4), (42, 5), (43, 2), (45, 2),
    (46, 3), (47, 3), (49, 2), (50, 1), (51, 2), (52, 33), (53, 1), (54, 2), (56, 2),
    (58, 14),
];

/// The handshakes other clients completed with our certificate for Meta hosts in the same
/// log, in seconds from 13:59:39: the Facebook app at 13:48:18, 13:50:59, 14:00:32 and
/// 14:01:33, Messenger's notification extension at 13:57:11 and 13:59:28.
const OTHERS: [i64; 6] = [-681, -520, -148, -11, 53, 114];

fn policy() -> Policy {
    Policy::new(&Config::default(), None).unwrap()
}

fn hosts(p: &Policy) -> Vec<String> {
    p.learned_pins().into_iter().map(|(host, _)| host).collect()
}

fn pinned(p: &Policy, host: &str, now: u64) -> bool {
    p.classify(host, now) == Decision::Passthrough(PassthroughReason::LearnedPin)
}

/// `start` plus `offset` seconds.
fn at(start: u64, offset: i64) -> u64 {
    start.checked_add_signed(offset).unwrap()
}

/// Replays Messenger's refusals of `host` from `start`, with a handshake for the same host
/// at each of `handshakes` (in order, each before the refusals of its second), and returns
/// the second at which the host was learned. Once it is, its connections are passed
/// through and refused no more.
fn replay(p: &Policy, host: &str, start: u64, handshakes: &[u64]) -> Option<u64> {
    let mut handshakes = handshakes.iter().copied().peekable();
    for (second, refusals) in MESSENGER {
        let now = start + second;
        while let Some(then) = handshakes.next_if(|then| *then <= now) {
            p.record_intercepted_handshake(host, then);
        }
        for _ in 0..refusals {
            if p.record_silent_refusal(host, now) {
                assert!(pinned(p, host, now));
                return Some(now);
            }
        }
    }
    None
}

/// `each` refusals of `host` in every one of `seconds`, none of which may learn it.
fn refuse(p: &Policy, host: &str, seconds: std::ops::Range<u64>, each: u32) {
    for now in seconds {
        for _ in 0..each {
            assert!(!p.record_silent_refusal(host, now), "{host} at {now}");
        }
    }
}

#[test]
fn messenger_is_learned_although_other_clients_trust_its_host() {
    // Other clients' handshakes on the pinned host itself: the worst case, since the log
    // hashes host names and does not tell which Meta hosts they were.
    let p = policy();
    let start = T0 + 1_000;
    let others: Vec<u64> = OTHERS.iter().map(|offset| at(start, *offset)).collect();
    // 13:59:58, its tenth different second, 133 refusals against the notification
    // extension's one handshake within the minute. Without the flood rule the handshake at
    // 13:59:28 would have kept it from being learned until 14:09:28.
    assert_eq!(replay(&p, PINNED, start, &others), Some(start + 19));
    assert_eq!(hosts(&p), [PINNED]);
}

#[test]
fn messenger_is_learned_however_often_other_clients_complete_handshakes() {
    // Another client completing a handshake for the same host every `every` seconds, from
    // ten minutes before the refusals until after them.
    for (every, learned) in [(60, 19), (10, 19), (2, 27)] {
        let p = policy();
        let start = T0 + 1_000;
        let others: Vec<u64> = (start - 600..start + 120).step_by(every).collect();
        let got = replay(&p, PINNED, start, &others);
        // Every 2 seconds is 30 handshakes in a minute: learned once the refusals reach 150.
        assert_eq!(got, Some(start + learned), "every {every} s");
    }
}

#[test]
fn a_flood_needs_refusals_in_ten_different_seconds() {
    let p = policy();
    let host = "api.pinned.example";
    p.record_intercepted_handshake(host, T0);
    // Many refusals, but in one second fewer than SILENT_FLOOD_SECONDS.
    let edge = T0 + SILENT_FLOOD_SECONDS as u64;
    refuse(&p, host, T0 + 1..edge, 50);
    assert!(hosts(&p).is_empty());
    assert!(p.record_silent_refusal(host, edge));
    assert_eq!(hosts(&p), [host]);
}

#[test]
fn a_flood_needs_ratio_times_the_handshakes_of_the_same_minute() {
    let p = policy();
    let host = "api.pinned.example";
    for _ in 0..4 {
        p.record_intercepted_handshake(host, T0);
    }
    // Ten different seconds, but 10 refusals against 4 handshakes.
    let edge = T0 + SILENT_FLOOD_SECONDS as u64;
    refuse(&p, host, T0 + 1..edge + 1, 1);
    let needed = 4 * SILENT_FLOOD_RATIO;
    refuse(&p, host, edge..edge + 1, needed - 1 - 10);
    assert!(hosts(&p).is_empty());
    // The refusal that makes SILENT_FLOOD_RATIO times the handshakes.
    assert!(p.record_silent_refusal(host, edge));
}

#[test]
fn a_flood_counts_the_refusals_of_the_last_minute_only() {
    let host = "api.pinned.example";
    // A refusal SILENT_FLOOD_SECS before the tenth second still counts...
    let p = policy();
    p.record_intercepted_handshake(host, T0 - 1);
    let last = T0 + SILENT_FLOOD_SECS;
    refuse(&p, host, T0..T0 + 1, 1);
    refuse(&p, host, last - 8..last, 1);
    assert!(p.record_silent_refusal(host, last));
    // ...and one second earlier it does not.
    let p = policy();
    p.record_intercepted_handshake(host, T0 - 1);
    refuse(&p, host, T0..T0 + 1, 1);
    refuse(&p, host, last - 7..last + 2, 1);
    assert!(hosts(&p).is_empty());
}

#[test]
fn a_flood_counts_the_handshakes_of_the_last_minute_only() {
    // Handshakes older than SILENT_FLOOD_SECS no longer count against a flood, although
    // they still guard the host from the rule for a few refusals.
    let p = policy();
    let host = "api.pinned.example";
    for _ in 0..5 {
        p.record_intercepted_handshake(host, T0);
    }
    // 20 refusals in 10 seconds against 5 handshakes, which need 25.
    let last = T0 + SILENT_FLOOD_SECS;
    refuse(&p, host, last - 9..last + 1, 2);
    assert!(hosts(&p).is_empty());
    // A second later the handshakes are out of the minute.
    assert!(p.record_silent_refusal(host, last + 1));
}

#[test]
fn a_flood_overrides_trust_from_minutes_before() {
    let p = policy();
    let host = "api.pinned.example";
    p.record_intercepted_handshake(host, T0);
    // Five minutes later the success guard still holds, but a flood wins.
    let start = T0 + 300;
    refuse(&p, host, start..start + 9, 1);
    assert!(p.record_silent_refusal(host, start + 9));
}

#[test]
fn a_flood_on_one_host_is_not_a_burst() {
    // Two other hosts that clients trust are refused in the same seconds: three hosts
    // within SILENT_BURST_SECS, which is not a burst either.
    let p = policy();
    let start = T0 + 1_000;
    let others: Vec<u64> = OTHERS.iter().map(|offset| at(start, *offset)).collect();
    for host in ["graph.meta.example", "edge.meta.example"] {
        p.record_intercepted_handshake(host, start - 1);
        for second in [0, 17, 18] {
            assert!(!p.record_silent_refusal(host, start + second));
        }
    }
    assert_eq!(replay(&p, PINNED, start, &others), Some(start + 19));
    // Silent refusals were not suppressed: another host is learned by the usual rule.
    let later = start + 30;
    for second in 0..2 {
        assert!(!p.record_silent_refusal("api.pinned.example", later + second));
    }
    assert!(p.record_silent_refusal("api.pinned.example", later + 2));
    assert_eq!(hosts(&p), ["api.pinned.example", PINNED]);
}

#[test]
fn a_burst_forgets_a_flood_in_progress() {
    let p = policy();
    p.record_intercepted_handshake(PINNED, T0 - 1);
    refuse(&p, PINNED, T0..T0 + 9, 20);
    // Three more hosts within SILENT_BURST_SECS: a burst.
    for host in ["b.example", "c.example", "d.example"] {
        assert!(!p.record_silent_refusal(host, T0 + 8));
    }
    // The flood's refusals go on every second. Within SILENT_BURST_SECS of the other
    // hosts' they are part of the burst, which lasts until T0 + 18; then silent refusals
    // are suppressed for SILENT_SUPPRESS_SECS, however many.
    let until = T0 + 8 + SILENT_BURST_SECS + SILENT_SUPPRESS_SECS;
    refuse(&p, PINNED, T0 + 9..until, 20);
    // Then the flood's earlier seconds are forgotten: ten new ones are needed.
    refuse(&p, PINNED, until..until + 9, 20);
    assert!(hosts(&p).is_empty());
    assert!(p.record_silent_refusal(PINNED, until + 9));
}

#[test]
fn a_burst_takes_back_a_pin_learned_from_a_flood() {
    let p = policy();
    p.record_intercepted_handshake(PINNED, T0 - 1);
    refuse(&p, PINNED, T0..T0 + 9, 20);
    assert!(p.record_silent_refusal(PINNED, T0 + 9));
    // Three more hosts within SILENT_BURST_SECS of the flood's last refusal.
    assert!(!p.record_silent_refusal("b.example", T0 + 10));
    assert!(!p.record_silent_refusal("c.example", T0 + 11));
    assert!(!p.record_silent_refusal("d.example", T0 + 12));
    assert!(hosts(&p).is_empty());
    assert!(!pinned(&p, PINNED, T0 + 13));
}

#[test]
fn a_network_change_takes_back_a_fresh_flood_pin_and_forgets_a_flood() {
    let p = policy();
    p.record_intercepted_handshake(PINNED, T0 - 1);
    refuse(&p, PINNED, T0..T0 + 9, 20);
    assert!(p.record_silent_refusal(PINNED, T0 + 9));
    p.on_network_change(T0 + 9 + SILENT_RECENT_SECS);
    assert!(hosts(&p).is_empty());

    // A flood in progress is forgotten: ten new seconds are needed.
    let start = T0 + 100;
    refuse(&p, PINNED, start..start + 9, 20);
    p.on_network_change(start + 9);
    refuse(&p, PINNED, start + 9..start + 18, 20);
    assert!(hosts(&p).is_empty());
    assert!(p.record_silent_refusal(PINNED, start + 18));

    // An older one is kept.
    p.on_network_change(start + 18 + SILENT_RECENT_SECS + 1);
    assert_eq!(hosts(&p), [PINNED]);
}

/// The tunnel saves its pins when it stops (airplane mode can stop it), and the restarted
/// tunnel's policy keeps a fresh flood pin through a network change, so only a path change
/// while the tunnel runs takes one back.
#[test]
fn a_flood_pin_saved_when_the_tunnel_stops_is_kept_after_a_network_change() {
    let p = policy();
    p.record_intercepted_handshake(PINNED, T0 - 1);
    refuse(&p, PINNED, T0..T0 + 9, 20);
    assert!(p.record_silent_refusal(PINNED, T0 + 9));
    let restored = Policy::new(&Config::default(), Some(&p.learned_pins_json())).unwrap();
    restored.on_network_change(T0 + 10);
    assert_eq!(hosts(&restored), [PINNED]);
    assert!(pinned(&restored, PINNED, T0 + 10));
}

#[test]
fn forgetting_a_host_forgets_its_flood() {
    let p = policy();
    p.record_intercepted_handshake(PINNED, T0 - 1);
    refuse(&p, PINNED, T0..T0 + 9, 20);
    assert_eq!(p.forget_pins(&[PINNED.to_string()]), 0);
    refuse(&p, PINNED, T0 + 9..T0 + 18, 20);
    assert!(p.record_silent_refusal(PINNED, T0 + 18));
}

#[test]
fn many_flooded_hosts_stay_bounded() {
    // Far enough apart that no ten seconds see four hosts, each trusted and refused in
    // nine different seconds.
    let p = policy();
    for i in 0..3_000u64 {
        let host = format!("h{i}.example");
        let start = T0 + i * 11;
        p.record_intercepted_handshake(&host, start);
        refuse(&p, &host, start..start + 9, 1);
    }
    // The most recent host's refusals are still counted, so its tenth second learns.
    let last = T0 + 2_999 * 11;
    assert!(p.record_silent_refusal("h2999.example", last + 9));
    assert_eq!(hosts(&p), ["h2999.example"]);
}
