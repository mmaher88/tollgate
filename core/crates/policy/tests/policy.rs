use tollgate_policy::{
    Config, Decision, PIN_LIFETIME_SECS, PassthroughReason, Policy, PolicyError,
    REJECTION_WINDOW_SECS, RejectionKind,
};

const T0: u64 = 1_790_000_000;

fn policy(passthrough: &[&str]) -> Policy {
    let config = Config {
        passthrough: passthrough.iter().map(|s| s.to_string()).collect(),
        ..Config::default()
    };
    Policy::new(&config, None).unwrap()
}

fn passthrough(reason: PassthroughReason) -> Decision {
    Decision::Passthrough(reason)
}

#[test]
fn ordinary_hosts_are_intercepted() {
    let p = policy(&[]);
    assert_eq!(p.classify("example.com", T0), Decision::Intercept);
    assert_eq!(p.classify("[2001:db8::1]", T0), Decision::Intercept);
}

#[test]
fn mitm_disabled_passes_everything_through() {
    let config = Config {
        mitm_enabled: false,
        passthrough: vec!["user.example".into()],
        ..Config::default()
    };
    let p = Policy::new(&config, None).unwrap();
    for host in ["example.com", "user.example", "gateway.icloud.com"] {
        assert_eq!(
            p.classify(host, T0),
            passthrough(PassthroughReason::MitmDisabled)
        );
    }
}

#[test]
fn user_patterns_come_first() {
    let p = policy(&["*.apple.com", "Bank.Example."]);
    assert_eq!(
        p.classify("www.apple.com", T0),
        passthrough(PassthroughReason::User)
    );
    assert_eq!(
        p.classify("bank.example", T0),
        passthrough(PassthroughReason::User)
    );
    assert_eq!(p.classify("www.bank.example", T0), Decision::Intercept);
    assert_eq!(
        p.classify("gateway.icloud.com", T0),
        passthrough(PassthroughReason::Bundled)
    );
}

#[test]
fn bundled_hosts_pass_through_case_and_dot_insensitively() {
    let p = policy(&[]);
    assert_eq!(
        p.classify("WWW.Chase.COM.", T0),
        passthrough(PassthroughReason::Bundled)
    );
    assert_eq!(
        p.classify("chase.com.evil.example", T0),
        Decision::Intercept
    );
}

#[test]
fn invalid_user_pattern_fails_construction() {
    let config = Config {
        passthrough: vec!["ok.example".into(), "bad pattern".into()],
        ..Config::default()
    };
    let err = Policy::new(&config, None).err().unwrap();
    assert!(
        matches!(&err, PolicyError::InvalidPattern { pattern, .. } if pattern == "bad pattern"),
        "{err:?}"
    );
}

#[test]
fn two_rejections_within_ten_minutes_learn_a_pin() {
    let p = policy(&[]);
    assert!(!p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, T0));
    assert_eq!(p.classify("pinned.example", T0), Decision::Intercept);
    assert!(p.record_client_rejection(
        "Pinned.Example.",
        RejectionKind::DecryptError,
        T0 + REJECTION_WINDOW_SECS
    ));
    assert_eq!(
        p.classify("pinned.example", T0 + 601),
        passthrough(PassthroughReason::LearnedPin)
    );
    // Already a pin: further rejections do not report a new pin.
    assert!(!p.record_client_rejection("pinned.example", RejectionKind::BadCertificate, T0 + 700));
    // Pins are per host, not per domain.
    assert_eq!(
        p.classify("www.pinned.example", T0 + 700),
        Decision::Intercept
    );
}

#[test]
fn rejections_further_apart_do_not_learn() {
    let p = policy(&[]);
    assert!(!p.record_client_rejection("slow.example", RejectionKind::UnknownCa, T0));
    assert!(!p.record_client_rejection(
        "slow.example",
        RejectionKind::UnknownCa,
        T0 + REJECTION_WINDOW_SECS + 1
    ));
    // The window restarts at the second rejection.
    assert!(p.record_client_rejection(
        "slow.example",
        RejectionKind::CertificateUnknown,
        T0 + REJECTION_WINDOW_SECS + 1 + 500
    ));
}

#[test]
fn different_hosts_are_counted_separately() {
    let p = policy(&[]);
    assert!(!p.record_client_rejection("a.example", RejectionKind::UnknownCa, T0));
    assert!(!p.record_client_rejection("b.example", RejectionKind::UnknownCa, T0 + 1));
    assert_eq!(p.classify("a.example", T0 + 2), Decision::Intercept);
    assert!(!p.record_client_rejection("", RejectionKind::UnknownCa, T0 + 3));
    assert!(!p.record_client_rejection("", RejectionKind::UnknownCa, T0 + 4));
}

#[test]
fn pins_expire_after_thirty_days() {
    let p = policy(&[]);
    p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, T0);
    assert!(p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, T0 + 10));
    let learned_at = T0 + 10;
    assert_eq!(PIN_LIFETIME_SECS, 2_592_000);
    assert_eq!(
        p.classify("pinned.example", learned_at + PIN_LIFETIME_SECS - 1),
        passthrough(PassthroughReason::LearnedPin)
    );
    assert_eq!(
        p.classify("pinned.example", learned_at + PIN_LIFETIME_SECS),
        Decision::Intercept
    );
    // After expiry the host can be learned again.
    let later = learned_at + PIN_LIFETIME_SECS;
    assert!(!p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, later));
    assert!(p.record_client_rejection("pinned.example", RejectionKind::UnknownCa, later + 1));
}

#[test]
fn user_and_bundled_rank_above_learned_pins() {
    let p = policy(&["user.example"]);
    for host in ["user.example", "gateway.icloud.com"] {
        p.record_client_rejection(host, RejectionKind::UnknownCa, T0);
        assert!(p.record_client_rejection(host, RejectionKind::UnknownCa, T0 + 1));
    }
    assert_eq!(
        p.classify("user.example", T0 + 2),
        passthrough(PassthroughReason::User)
    );
    assert_eq!(
        p.classify("gateway.icloud.com", T0 + 2),
        passthrough(PassthroughReason::Bundled)
    );
}

#[test]
fn learned_pins_round_trip_through_json() {
    let p = policy(&[]);
    assert_eq!(p.learned_pins_json(), r#"{"version":1,"pins":[]}"#);
    for host in ["b.example", "a.example"] {
        p.record_client_rejection(host, RejectionKind::UnknownCa, 100);
        p.record_client_rejection(host, RejectionKind::UnknownCa, 160);
    }
    let json = p.learned_pins_json();
    assert_eq!(
        json,
        r#"{"version":1,"pins":[{"host":"a.example","learned_at":160},{"host":"b.example","learned_at":160}]}"#
    );
    let restored = Policy::new(&Config::default(), Some(&json)).unwrap();
    assert_eq!(
        restored.classify("a.example", 200),
        passthrough(PassthroughReason::LearnedPin)
    );
    assert_eq!(
        restored.classify("B.EXAMPLE.", 200),
        passthrough(PassthroughReason::LearnedPin)
    );
    assert_eq!(
        restored.classify("a.example", 160 + PIN_LIFETIME_SECS),
        Decision::Intercept
    );
    assert_eq!(restored.learned_pins_json(), json);
}

#[test]
fn unreadable_pins_are_ignored() {
    for bad in [
        "",
        "not json",
        r#"{"version":2,"pins":[{"host":"a.example","learned_at":1}]}"#,
        r#"{"pins":[]}"#,
    ] {
        let p = Policy::new(&Config::default(), Some(bad)).unwrap();
        assert_eq!(p.classify("a.example", 2), Decision::Intercept, "{bad:?}");
        assert_eq!(
            p.learned_pins_json(),
            r#"{"version":1,"pins":[]}"#,
            "{bad:?}"
        );
    }
}

#[test]
fn expired_pins_are_dropped_when_the_next_rejection_is_recorded() {
    let json = r#"{"version":1,"pins":[{"host":"new.example","learned_at":1000},{"host":"old.example","learned_at":0}]}"#;
    let p = Policy::new(&Config::default(), Some(json)).unwrap();
    assert_eq!(p.learned_pins_json(), json);
    p.record_client_rejection(
        "other.example",
        RejectionKind::UnknownCa,
        PIN_LIFETIME_SECS + 10,
    );
    assert_eq!(
        p.learned_pins_json(),
        r#"{"version":1,"pins":[{"host":"new.example","learned_at":1000}]}"#
    );
}

#[test]
fn many_single_rejections_stay_bounded_and_do_not_learn() {
    let p = policy(&[]);
    for i in 0..5_000u64 {
        assert!(!p.record_client_rejection(
            &format!("h{i}.example"),
            RejectionKind::UnknownCa,
            T0 + i
        ));
    }
    // The most recent host is still remembered, so its second rejection learns.
    assert!(p.record_client_rejection("h4999.example", RejectionKind::UnknownCa, T0 + 5_000));
}

#[test]
fn policy_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Policy>();
}
