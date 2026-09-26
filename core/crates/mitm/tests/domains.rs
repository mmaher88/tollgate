//! The DNS blocklist applies to proxied connections too: with the proxy settings on,
//! clients send `CONNECT host` and never look the name up through the tunnel's DNS.

mod support;

use std::sync::Arc;

use hyper::StatusCode;
use tollgate_common::events::{EventKind, EventLog};
use tollgate_filter::{DomainSet, ListFormat, ListSource};
use tollgate_mitm::{CertAuthority, ProxyContext};
use tollgate_policy::Config;

use support::client::proxy_get;
use support::tunnel::{connect, connect_status, tls, tls_config};
use support::{proxy, tls_origin};

fn domains(text: &str) -> Arc<DomainSet> {
    let list = ListSource {
        name: "dns",
        text,
        format: ListFormat::Adblock,
    };
    Arc::new(DomainSet::from_bytes(DomainSet::build(&[list])).unwrap())
}

struct Setup {
    ca: Arc<CertAuthority>,
    origin: support::origin::Origin,
    proxy: proxy::TestProxy,
    events: Arc<EventLog>,
}

async fn setup(config: Config) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let events = Arc::new(EventLog::new());
    let ctx = ProxyContext {
        events: Some(events.clone()),
        ..proxy::context(ca.clone(), &config, None)
    };
    ctx.domains
        .store(Some(domains("||ads.example^\n@@||ok.ads.example^\n")));
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    Setup {
        ca,
        origin,
        proxy,
        events,
    }
}

fn dns_blocks(events: &EventLog) -> Vec<String> {
    events
        .recent(10)
        .into_iter()
        .filter(|e| e.kind == EventKind::Dns)
        .map(|e| e.host)
        .collect()
}

#[tokio::test]
async fn connect_to_a_dns_blocked_host_gets_403() {
    let s = setup(Config::default()).await;
    let (status, _) = connect_status(s.proxy.addr, "Tracker.Ads.Example.:443").await;
    assert_eq!(status, 403);
    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_eq!(s.proxy.stats().connections_intercepted, 0);
    assert_eq!(dns_blocks(&s.events), ["tracker.ads.example"]);

    // The list's own exception, and hosts it does not name, are not blocked.
    let (status, _) = connect_status(s.proxy.addr, "ok.ads.example:443").await;
    assert_eq!(status, 200);
    let (status, _) = connect_status(s.proxy.addr, "www.example:443").await;
    assert_eq!(status, 200);
    assert_eq!(s.proxy.stats().dns_blocked, 1);
}

#[tokio::test]
async fn passthrough_hosts_are_checked_too() {
    let config = Config {
        passthrough: vec!["*.ads.example".to_string()],
        ..Config::default()
    };
    let s = setup(config).await;
    let (status, _) = connect_status(s.proxy.addr, "sdk.ads.example:443").await;
    assert_eq!(status, 403);
    assert_eq!(s.proxy.stats().connections_passthrough, 0);
    assert_eq!(s.proxy.stats().dns_blocked, 1);
}

#[tokio::test]
async fn allowlisted_hosts_are_not_blocked() {
    let config = Config {
        allowlist: vec!["*.ads.example".to_string()],
        ..Config::default()
    };
    let s = setup(config).await;
    let (status, _) = connect_status(s.proxy.addr, "ads.example:443").await;
    assert_eq!(status, 200);
    assert_eq!(s.proxy.stats().dns_blocked, 0);
}

#[tokio::test]
async fn absolute_form_requests_to_a_blocked_host_get_403() {
    let s = setup(Config::default()).await;
    let reply = proxy_get(s.proxy.addr, "http://ads.example/pixel.gif", &[]).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = proxy_get(s.proxy.addr, "https://ads.example/pixel.gif", &[]).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(s.proxy.stats().dns_blocked, 2);
}

#[tokio::test]
async fn a_blocked_server_name_behind_an_address_is_not_intercepted() {
    let s = setup(Config::default()).await;
    let target = format!("127.0.0.1:{}", s.origin.port());
    let tcp = connect(s.proxy.addr, &target).await;
    let handshake = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "ads.example").await;
    assert!(handshake.is_err(), "the connection was intercepted");
    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_eq!(s.proxy.stats().connections_intercepted, 0);

    let tcp = connect(s.proxy.addr, &target).await;
    let handshake = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "www.tollgate.test").await;
    assert!(handshake.is_ok());
}
