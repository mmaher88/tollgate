use tollgate_policy::{HostPattern, PolicyError};

fn pattern(s: &str) -> HostPattern {
    HostPattern::parse(s).unwrap()
}

#[test]
fn exact_pattern_matches_only_that_host() {
    let p = pattern("example.com");
    assert!(!p.is_wildcard());
    for host in ["example.com", "EXAMPLE.com", "Example.Com.", "example.com."] {
        assert!(p.matches(host), "{host}");
    }
    for host in [
        "www.example.com",
        "notexample.com",
        "example.co",
        "example.com..",
        "",
        "com",
    ] {
        assert!(!p.matches(host), "{host}");
    }
}

#[test]
fn wildcard_matches_the_domain_and_every_subdomain() {
    let p = pattern("*.example.com");
    assert!(p.is_wildcard());
    for host in [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "A.Example.COM.",
    ] {
        assert!(p.matches(host), "{host}");
    }
    for host in [
        "badexample.com",
        "example.com.evil.net",
        "example.org",
        ".example.co",
        "",
    ] {
        assert!(!p.matches(host), "{host}");
    }
}

#[test]
fn parse_normalizes_case_trailing_dot_and_whitespace() {
    let p = pattern("  *.Example.COM.  ");
    assert_eq!(p.name(), "example.com");
    assert_eq!(p.to_string(), "*.example.com");
    assert_eq!(pattern("Host.Example.").to_string(), "host.example");
    assert_eq!(pattern("*.Example.COM"), pattern("*.example.com"));
}

#[test]
fn single_labels_and_ip_literals_are_hosts_too() {
    assert!(pattern("localhost").matches("LOCALHOST"));
    assert!(pattern("*.test").matches("a.test"));
    assert!(pattern("192.168.1.1").matches("192.168.1.1"));
    assert!(pattern("under_score.example").matches("under_score.example"));
}

#[test]
fn non_ascii_hosts_do_not_panic() {
    assert!(pattern("*.example.com").matches("ü.example.com"));
    assert!(!pattern("example.com").matches("exämple.com"));
}

fn reason(s: &str) -> &'static str {
    match HostPattern::parse(s) {
        Err(PolicyError::InvalidPattern { pattern, reason }) => {
            assert_eq!(pattern, s);
            reason
        }
        other => panic!("{s:?} parsed as {other:?}"),
    }
}

#[test]
fn invalid_patterns_are_rejected_with_a_reason() {
    for s in ["", "   ", "*.", ".", "*..", "."] {
        assert!(!reason(s).is_empty(), "{s:?}");
    }
    assert_eq!(reason(""), "empty host name");
    assert_eq!(reason("*."), "empty host name");
    assert_eq!(
        reason("*"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(
        reason("*example.com"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(
        reason("a.*.com"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(
        reason("*.*.example.com"),
        "a wildcard is only allowed as a leading \"*.\""
    );
    assert_eq!(reason("a..b"), "empty label");
    assert_eq!(reason(".example.com"), "empty label");
    assert_eq!(reason("example.com.."), "empty label");
    let letters = "only letters, digits, '-', '_' and '.' are allowed";
    for s in [
        "exa mple.com",
        "http://example.com",
        "example.com/path",
        "[::1]",
        "ex$mple.com",
        "exämple.com",
    ] {
        assert_eq!(reason(s), letters, "{s:?}");
    }
    let long_label = format!("{}.com", "a".repeat(64));
    assert_eq!(reason(&long_label), "label longer than 63 bytes");
    let ok_label = format!("{}.com", "a".repeat(63));
    assert!(HostPattern::parse(&ok_label).is_ok());
    let long_name = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62),
    ]
    .join(".");
    assert_eq!(long_name.len(), 254);
    assert_eq!(reason(&long_name), "host name longer than 253 bytes");
}
