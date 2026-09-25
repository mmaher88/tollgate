use std::collections::HashSet;

use tollgate_policy::{HostPattern, bundled_passthrough};

fn bundled_matches(host: &str) -> bool {
    bundled_passthrough()
        .iter()
        .any(|p| HostPattern::parse(p).unwrap().matches(host))
}

#[test]
fn every_entry_is_a_canonical_pattern() {
    for entry in bundled_passthrough() {
        let parsed = HostPattern::parse(entry).unwrap();
        assert_eq!(parsed.to_string(), *entry);
    }
}

#[test]
fn entries_are_unique_and_the_snapshot_is_complete() {
    let unique: HashSet<&str> = bundled_passthrough().iter().copied().collect();
    assert_eq!(unique.len(), bundled_passthrough().len());
    assert_eq!(bundled_passthrough().len(), 627);
}

#[test]
fn covers_apple_services() {
    for host in [
        "gateway.icloud.com",
        "p42-contacts.icloud.com",
        "mesu.apple.com",
        "api.apple-cloudkit.com",
        "cvws.icloud-content.com",
        "is1-ssl.mzstatic.com",
        "updates.cdn-apple.com",
        "token.safebrowsing.apple",
        "apple-relay.cloudflare.com",
        "ocsp.digicert.com",
        "www.icloud.com.cn",
    ] {
        assert!(bundled_matches(host), "{host}");
    }
}

#[test]
fn covers_banking_and_sensitive_services() {
    for host in [
        "www.chase.com",
        "secure.bankofamerica.com",
        "www.paypal.com",
        "api.stripe.com",
        "accounts.google.com",
        "vault.bitwarden.com",
        "my.1password.com",
        "login.live.com",
    ] {
        assert!(bundled_matches(host), "{host}");
    }
}

#[test]
fn leaves_ordinary_hosts_alone() {
    for host in [
        "www.google.com",
        "example.com",
        "securepubads.g.doubleclick.net",
        "apple.com.evil.example",
        "cloudflare.com",
    ] {
        assert!(!bundled_matches(host), "{host}");
    }
}
