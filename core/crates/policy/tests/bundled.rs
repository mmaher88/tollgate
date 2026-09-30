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
    assert_eq!(sizes, [24, 183, 423, 3, 6, 6, 3, 1]);
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
        (BundledGroup::Banks, "pay.google.com"),
        (BundledGroup::Banks, "api.braintreegateway.com"),
        (BundledGroup::SilentRefusers, "api.x.com"),
        (BundledGroup::DeviceManagement, "i.manage.microsoft.com"),
        (BundledGroup::DeclaredPins, "api.atlassian.com"),
        (BundledGroup::ReportedPins, "mmg.whatsapp.net"),
        (
            BundledGroup::LearnedPins,
            "meta-ohttp-relay-prod.fastly-edge.com",
        ),
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
    assert_eq!(bundled_passthrough().len(), 649);
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
        "pay.google.com",
        "payments.braintree-api.com",
        "api.braintreegateway.com",
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
fn covers_device_management_hosts() {
    for host in [
        "i.manage.microsoft.com",
        "enrollment.manage.microsoft.com",
        "r.manage.microsoft.com",
        "fef.msuc03.manage.microsoft.com",
        "checkin.dm.microsoft.com",
        "enterpriseregistration.windows.net",
        "certauth.enterpriseregistration.windows.net",
        "device.login.microsoftonline.com",
        "t.certauth.login.microsoftonline.com",
        "config.edge.skype.com",
    ] {
        assert!(bundled_matches(host), "{host}");
    }
}

#[test]
fn covers_pinned_hosts_of_apps() {
    for host in [
        // Declared in Info.plist.
        "api.atlassian.com",
        "api-private.atlassian.com",
        "auth.atlassian.com",
        "media-cdn.atlassian.com",
        "api.media.atlassian.com",
        "jira.atlassian-isolated.net",
        // Listed by vendors.
        "mmg.whatsapp.net",
        "media-iad3-1.cdn.whatsapp.net",
        "wd5.myworkday.com",
        "www.eventbriteapi.com",
        // Learned in a device log.
        "meta-ohttp-relay-prod.fastly-edge.com",
    ] {
        assert!(bundled_matches(host), "{host}");
    }
}

#[test]
fn leaves_trackers_next_to_the_newer_groups_alone() {
    // Tracker hosts under the same domains as entries added for payment services, device
    // management and pins, which the default lists block.
    for host in [
        "client-analytics.braintreegateway.com",
        "xp.atlassian.com",
        "clicks.eventbrite.com",
    ] {
        assert!(!bundled_matches(host), "{host}");
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
        // Next to the newer groups: their domains' public sites and other hosts, and hosts
        // left out because they cost filtering or rest on no evidence.
        "login.microsoftonline.com",
        "www.microsoft.com",
        "www.atlassian.com",
        "zoom.us",
        "api.viber.com",
        "graph.facebook.com",
        "googlehomefoyer-pa.googleapis.com",
        "fastly-edge.com",
    ] {
        assert!(!bundled_matches(host), "{host}");
    }
}
