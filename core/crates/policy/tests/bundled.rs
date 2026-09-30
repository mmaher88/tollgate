use std::collections::HashSet;

use tollgate_policy::{BundledGroup, HostPattern, bundled_passthrough};

fn bundled_matches(host: &str) -> bool {
    bundled_passthrough()
        .iter()
        .any(|p| HostPattern::parse(p).unwrap().matches(host))
}

fn group_matches(group: BundledGroup, host: &str) -> bool {
    group
        .patterns()
        .iter()
        .any(|p| HostPattern::parse(p).unwrap().matches(host))
}

#[test]
fn the_groups_make_up_the_bundled_list_in_order() {
    let joined: Vec<&str> = BundledGroup::ALL
        .iter()
        .flat_map(|group| group.patterns().iter().copied())
        .collect();
    assert_eq!(joined, bundled_passthrough());
    let sizes = BundledGroup::ALL.map(|group| group.patterns().len());
    assert_eq!(sizes, [24, 183, 420, 3]);
}

#[test]
fn each_group_is_sorted() {
    for group in BundledGroup::ALL {
        let patterns = group.patterns();
        assert!(patterns.is_sorted(), "{group:?}");
    }
}

#[test]
fn each_host_falls_in_the_group_of_its_source() {
    for (group, host) in [
        (BundledGroup::Apple, "gateway.icloud.com"),
        (BundledGroup::Sensitive, "accounts.google.com"),
        (BundledGroup::Sensitive, "vault.bitwarden.com"),
        (BundledGroup::Sensitive, "www.army.mil"),
        (BundledGroup::Banks, "secure.chase.com"),
        (BundledGroup::Banks, "api.stripe.com"),
        (BundledGroup::SilentRefusers, "api.x.com"),
    ] {
        for other in BundledGroup::ALL {
            assert_eq!(
                group_matches(other, host),
                other == group,
                "{host} in {other:?}"
            );
        }
    }
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
    assert_eq!(bundled_passthrough().len(), 630);
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
fn covers_apps_that_refuse_our_certificate_silently() {
    for host in [
        "api.x.com",
        "x.com",
        "api.twitter.com",
        "pbs.twimg.com",
        "video.twimg.com",
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
        "fox.com",
        "notx.com",
    ] {
        assert!(!bundled_matches(host), "{host}");
    }
}
