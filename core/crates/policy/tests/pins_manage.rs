use tollgate_policy::{Config, Decision, PassthroughReason, Policy, RejectionKind};

const T0: u64 = 1_790_000_000;

fn policy() -> Policy {
    Policy::new(&Config::default(), None).unwrap()
}

fn learn(p: &Policy, host: &str, at: u64) {
    assert!(!p.record_client_rejection(host, RejectionKind::UnknownCa, at));
    assert!(p.record_client_rejection(host, RejectionKind::BadCertificate, at + 1));
}

#[test]
fn learned_pins_are_sorted_by_host_with_their_time() {
    let p = policy();
    assert!(p.learned_pins().is_empty());
    learn(&p, "zeta.example", T0);
    learn(&p, "Alpha.Example", T0 + 100);
    learn(&p, "mid.example", T0 + 50);
    assert_eq!(
        p.learned_pins(),
        [
            ("alpha.example".to_string(), T0 + 101),
            ("mid.example".to_string(), T0 + 51),
            ("zeta.example".to_string(), T0 + 1),
        ]
    );
}

#[test]
fn learned_pins_include_pins_loaded_from_json() {
    let json = r#"{"version":1,"pins":[{"host":"b.example","learned_at":5},{"host":"a.example","learned_at":7}]}"#;
    let p = Policy::new(&Config::default(), Some(json)).unwrap();
    assert_eq!(
        p.learned_pins(),
        [("a.example".to_string(), 7), ("b.example".to_string(), 5)]
    );
}

#[test]
fn forget_pins_removes_them_and_counts() {
    let p = policy();
    learn(&p, "a.example", T0);
    learn(&p, "b.example", T0);
    learn(&p, "c.example", T0);
    let removed = p.forget_pins(&["a.example".into(), "c.example".into(), "x.example".into()]);
    assert_eq!(removed, 2);
    assert_eq!(p.learned_pins(), [("b.example".to_string(), T0 + 1)]);
    assert_eq!(p.classify("a.example", T0 + 10), Decision::Intercept);
    assert_eq!(
        p.classify("b.example", T0 + 10),
        Decision::Passthrough(PassthroughReason::LearnedPin)
    );
    assert!(!p.learned_pins_json().contains("a.example"));
}

#[test]
fn forget_pins_ignores_case_and_trailing_dot() {
    let p = policy();
    learn(&p, "pinned.example", T0);
    assert_eq!(p.forget_pins(&["PINNED.Example.".into()]), 1);
    assert!(p.learned_pins().is_empty());
}

#[test]
fn forget_pins_counts_each_pin_once() {
    let p = policy();
    learn(&p, "pinned.example", T0);
    assert_eq!(
        p.forget_pins(&["pinned.example".into(), "Pinned.example".into()]),
        1
    );
    assert_eq!(p.forget_pins(&["pinned.example".into()]), 0);
    assert_eq!(p.forget_pins(&[]), 0);
}

#[test]
fn forget_pins_drops_a_pending_single_rejection() {
    let p = policy();
    assert!(!p.record_client_rejection("pending.example", RejectionKind::UnknownCa, T0));
    assert_eq!(p.forget_pins(&["Pending.Example.".into()]), 0);
    // Without the forgotten first rejection, the next one starts a new count.
    assert!(!p.record_client_rejection("pending.example", RejectionKind::UnknownCa, T0 + 1));
    assert!(p.learned_pins().is_empty());
    assert!(p.record_client_rejection("pending.example", RejectionKind::UnknownCa, T0 + 2));
}

#[test]
fn a_forgotten_pin_can_be_learned_again() {
    let p = policy();
    learn(&p, "pinned.example", T0);
    assert_eq!(p.forget_pins(&["pinned.example".into()]), 1);
    learn(&p, "pinned.example", T0 + 100);
    assert_eq!(p.learned_pins(), [("pinned.example".to_string(), T0 + 101)]);
}

#[test]
fn one_unverifiable_upstream_certificate_makes_a_pin() {
    let p = policy();
    assert!(p.learn_upstream_untrusted("Legacy.Example.", T0));
    assert_eq!(p.learned_pins(), [("legacy.example".to_string(), T0)]);
    assert_eq!(
        p.classify("legacy.example", T0 + 1),
        Decision::Passthrough(PassthroughReason::LearnedPin)
    );
    // Already a pin: nothing new is learned, and the time is kept.
    assert!(!p.learn_upstream_untrusted("legacy.example", T0 + 5));
    assert_eq!(p.learned_pins(), [("legacy.example".to_string(), T0)]);
    assert!(!p.learn_upstream_untrusted("", T0));
    assert!(p.learned_pins_json().contains("legacy.example"));
}
