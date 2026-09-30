//! Upstream TLS failures on many hosts at once come from the network (a captive portal, a
//! filter that intercepts HTTPS), not from the servers, so they must not leave pins.

use tollgate_policy::{Config, Decision, PassthroughReason, Policy, RejectionKind};

const T0: u64 = 1_790_000_000;

fn policy() -> Policy {
    Policy::new(&Config::default(), None).unwrap()
}

fn hosts(p: &Policy) -> Vec<String> {
    p.learned_pins().into_iter().map(|(host, _)| host).collect()
}

fn client_pin(p: &Policy, host: &str, at: u64) {
    assert!(!p.record_client_rejection(host, RejectionKind::UnknownCa, at));
    assert!(p.record_client_rejection(host, RejectionKind::UnknownCa, at + 1));
}

#[test]
fn a_single_host_still_becomes_a_pin_at_once() {
    let p = policy();
    assert!(p.learn_upstream_untrusted("legacy.example", T0));
    assert_eq!(
        p.classify("legacy.example", T0 + 1),
        Decision::Passthrough(PassthroughReason::LearnedPin)
    );
}

#[test]
fn three_hosts_within_a_minute_leave_no_pins_and_stop_learning() {
    let p = policy();
    assert!(p.learn_upstream_untrusted("news.example", T0));
    assert!(p.learn_upstream_untrusted("mail.example", T0 + 20));
    assert!(!p.learn_upstream_untrusted("social.example", T0 + 40));
    assert!(hosts(&p).is_empty(), "{:?}", hosts(&p));
    assert_eq!(p.classify("news.example", T0 + 41), Decision::Intercept);
    assert!(!p.learned_pins_json().contains("example"));

    // Suppressed for ten minutes, then learning works again.
    assert!(!p.learn_upstream_untrusted("shop.example", T0 + 100));
    assert!(!p.learn_upstream_untrusted("shop.example", T0 + 40 + 599));
    assert!(hosts(&p).is_empty());
    assert!(p.learn_upstream_untrusted("shop.example", T0 + 40 + 600));
    assert_eq!(hosts(&p), ["shop.example"]);
}

#[test]
fn hosts_learned_further_apart_are_kept() {
    let p = policy();
    assert!(p.learn_upstream_untrusted("a.example", T0));
    assert!(p.learn_upstream_untrusted("b.example", T0 + 30));
    assert!(p.learn_upstream_untrusted("c.example", T0 + 61));
    assert_eq!(hosts(&p), ["a.example", "b.example", "c.example"]);
}

#[test]
fn a_burst_keeps_pins_learned_from_client_rejections() {
    let p = policy();
    client_pin(&p, "pinned-app.example", T0);
    assert!(p.learn_upstream_untrusted("news.example", T0 + 5));
    assert!(p.learn_upstream_untrusted("mail.example", T0 + 6));
    assert!(!p.learn_upstream_untrusted("social.example", T0 + 7));
    assert_eq!(hosts(&p), ["pinned-app.example"]);
}

#[test]
fn a_network_change_drops_upstream_pins_from_the_last_five_minutes() {
    let p = policy();
    assert!(p.learn_upstream_untrusted("old.example", T0));
    client_pin(&p, "pinned-app.example", T0 + 200);
    assert!(p.learn_upstream_untrusted("new.example", T0 + 250));
    p.on_network_change(T0 + 301);
    assert_eq!(hosts(&p), ["old.example", "pinned-app.example"]);
    // Nothing else changes on a second call.
    p.on_network_change(T0 + 302);
    assert_eq!(hosts(&p), ["old.example", "pinned-app.example"]);
}

#[test]
fn a_forgotten_upstream_pin_relearned_from_client_rejections_survives() {
    let p = policy();
    assert!(p.learn_upstream_untrusted("app.example", T0));
    assert_eq!(p.forget_pins(&["app.example".to_string()]), 1);
    client_pin(&p, "app.example", T0 + 10);
    p.on_network_change(T0 + 20);
    assert_eq!(hosts(&p), ["app.example"]);
}
