use std::net::IpAddr;

use serde_json::json;
use tollgate_policy::{Config, DohUpstream, PolicyError};

#[test]
fn defaults_match_the_spec() {
    let config = Config::default();
    assert_eq!(
        config.doh_upstreams,
        vec![
            DohUpstream {
                ip: "1.1.1.1".parse().unwrap(),
                port: 443,
                tls_name: "cloudflare-dns.com".into(),
                path: "/dns-query".into(),
            },
            DohUpstream {
                ip: "9.9.9.9".parse().unwrap(),
                port: 443,
                tls_name: "dns.quad9.net".into(),
                path: "/dns-query".into(),
            },
        ]
    );
    assert!(config.passthrough.is_empty());
    assert!(config.mitm_enabled);
    assert_eq!(config.max_intercepted_connections, 32);
}

#[test]
fn default_json_has_stable_field_names() {
    let value: serde_json::Value = serde_json::from_str(&Config::default().to_json()).unwrap();
    assert_eq!(
        value,
        json!({
            "doh_upstreams": [
                {"ip": "1.1.1.1", "port": 443, "tls_name": "cloudflare-dns.com", "path": "/dns-query"},
                {"ip": "9.9.9.9", "port": 443, "tls_name": "dns.quad9.net", "path": "/dns-query"}
            ],
            "passthrough": [],
            "mitm_enabled": true,
            "max_intercepted_connections": 32
        })
    );
}

#[test]
fn empty_object_gives_defaults() {
    assert_eq!(Config::from_json("{}").unwrap(), Config::default());
}

#[test]
fn missing_fields_keep_their_defaults() {
    let config = Config::from_json(r#"{"mitm_enabled": false}"#).unwrap();
    assert_eq!(
        config,
        Config {
            mitm_enabled: false,
            ..Config::default()
        }
    );
}

#[test]
fn upstream_port_and_path_default() {
    let config = Config::from_json(
        r#"{"doh_upstreams": [{"ip": "2606:4700:4700::1111", "tls_name": "one.one.one.one"}]}"#,
    )
    .unwrap();
    assert_eq!(
        config.doh_upstreams,
        vec![DohUpstream {
            ip: "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            port: 443,
            tls_name: "one.one.one.one".into(),
            path: "/dns-query".into(),
        }]
    );
}

#[test]
fn unknown_fields_are_ignored() {
    let config =
        Config::from_json(r#"{"future_option": [1, 2], "max_intercepted_connections": 8}"#)
            .unwrap();
    assert_eq!(config.max_intercepted_connections, 8);
}

#[test]
fn round_trip() {
    let config = Config {
        doh_upstreams: vec![DohUpstream {
            ip: "192.0.2.53".parse().unwrap(),
            port: 8443,
            tls_name: "dns.example".into(),
            path: "/q".into(),
        }],
        passthrough: vec!["*.bank.example".into(), "pinned.example.org".into()],
        mitm_enabled: false,
        max_intercepted_connections: 5,
    };
    assert_eq!(Config::from_json(&config.to_json()).unwrap(), config);
}

#[test]
fn invalid_json_is_an_error() {
    for bad in [
        "",
        "not json",
        r#"{"mitm_enabled": "yes"}"#,
        r#"{"max_intercepted_connections": -1}"#,
        r#"{"doh_upstreams": [{"ip": "not-an-ip", "tls_name": "x"}]}"#,
        r#"{"doh_upstreams": [{"ip": "1.1.1.1"}]}"#,
    ] {
        let err = Config::from_json(bad).unwrap_err();
        assert!(
            matches!(err, PolicyError::Config(_)),
            "{bad:?} gave {err:?}"
        );
    }
}
