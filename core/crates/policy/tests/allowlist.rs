use tollgate_policy::{Config, Decision, Policy, PolicyError};

const T0: u64 = 1_790_000_000;

fn policy(allowlist: &[&str]) -> Policy {
    let config = Config {
        allowlist: allowlist.iter().map(|s| s.to_string()).collect(),
        ..Config::default()
    };
    Policy::new(&config, None).unwrap()
}

#[test]
fn nothing_is_allowlisted_by_default() {
    let p = Policy::new(&Config::default(), None).unwrap();
    assert!(!p.is_allowlisted("example.com"));
    assert!(!p.is_allowlisted(""));
}

#[test]
fn exact_patterns_match_only_that_host() {
    let p = policy(&["shop.example"]);
    assert!(p.is_allowlisted("shop.example"));
    assert!(p.is_allowlisted("SHOP.Example."));
    assert!(!p.is_allowlisted("www.shop.example"));
    assert!(!p.is_allowlisted("shop.example.org"));
}

#[test]
fn wildcard_patterns_match_the_domain_and_subdomains() {
    let p = policy(&["*.news.example"]);
    assert!(p.is_allowlisted("news.example"));
    assert!(p.is_allowlisted("static.cdn.News.Example"));
    assert!(!p.is_allowlisted("fakenews.example"));
    assert!(!p.is_allowlisted("example"));
}

#[test]
fn allowlist_does_not_change_interception() {
    let p = policy(&["*.shop.example"]);
    assert_eq!(p.classify("www.shop.example", T0), Decision::Intercept);
}

#[test]
fn invalid_allowlist_pattern_fails_construction() {
    let config = Config {
        allowlist: vec!["ok.example".into(), "bad*pattern".into()],
        ..Config::default()
    };
    let err = Policy::new(&config, None).err().unwrap();
    assert!(
        matches!(&err, PolicyError::InvalidPattern { pattern, .. } if pattern == "bad*pattern"),
        "{err:?}"
    );
}
