//! The DNS blocklist applies to proxied connections too: with the proxy settings on,
//! clients send `CONNECT host` and never look the name up through the tunnel's DNS.
//!
//! A blocked host's `CONNECT` gets `200` and a connection that completes TLS and then fails
//! every request, because iOS retries a refused connection over another network without
//! the proxy. Blocked hosts the policy passes through get `403`, and so does any blocked
//! host when memory is low, or when every blocked-connection slot is taken and no blocked
//! connection becomes idle in time to be closed.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::StatusCode;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tollgate_common::clock::unix_secs;
use tollgate_common::events::{EventKind, EventLog};
use tollgate_common::resolve::{LookupFuture, Resolve};
use tollgate_filter::{DomainSet, ListFormat, ListSource};
use tollgate_mitm::{CertAuthority, ProxyContext, ServeOptions};
use tollgate_policy::{Config, Decision, RejectionKind};

use support::client::{get, proxy_get, proxy_try_get, read_to_close, wait_for};
use support::tunnel::{
    alpn, connect, connect_status, http2, peer_issuer, reset_reason, send2, tls, tls_config,
};
use support::{proxy, tls_origin};

const TOLLGATE: &str = "CN=Tollgate Test CA, O=Tollgate";

fn domains(text: &str) -> Arc<DomainSet> {
    let list = ListSource {
        name: "dns",
        text,
        format: ListFormat::Adblock,
    };
    Arc::new(DomainSet::from_bytes(DomainSet::build(&[list])).unwrap())
}

/// Resolves every name to 127.0.0.1, where the origin listens, so a `CONNECT` to a blocked
/// host that were dialed would reach it.
#[derive(Debug)]
struct Loopback;

impl Resolve for Loopback {
    fn lookup<'a>(&'a self, _host: &'a str) -> LookupFuture<'a> {
        Box::pin(async { vec![IpAddr::V4(Ipv4Addr::LOCALHOST)] })
    }
}

struct Setup {
    ca: Arc<CertAuthority>,
    origin_ca: Arc<CertAuthority>,
    origin: support::origin::Origin,
    proxy: proxy::TestProxy,
    events: Arc<EventLog>,
}

impl Setup {
    /// `name:<origin port>`, which reaches the origin when dialed.
    fn target(&self, name: &str) -> String {
        format!("{name}:{}", self.origin.port())
    }

    /// `127.0.0.1:<origin port>`.
    fn address(&self) -> String {
        format!("127.0.0.1:{}", self.origin.port())
    }

    /// `https://<name>:<origin port><path>`.
    fn url(&self, name: &str, path: &str) -> String {
        format!("https://{name}:{}{path}", self.origin.port())
    }

    fn classify(&self, host: &str) -> Decision {
        self.proxy.ctx.policy.classify(host, unix_secs())
    }

    /// `CONNECT target`, expecting `200`, then TLS for `name` trusting the Tollgate CA and
    /// offering `alpn`.
    async fn tls(&self, target: &str, name: &str, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        let tcp = connect(self.proxy.addr, target).await;
        tls(tcp, tls_config(&[&self.ca], alpn), name).await.unwrap()
    }

    /// `CONNECT target` until it gets `200` (for up to 5 s), for a slot to be free again.
    async fn connect_eventually(&self, target: &str) {
        for _ in 0..500 {
            if connect_status(self.proxy.addr, target).await.0 == 200 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("CONNECT {target} never got 200");
    }
}

async fn setup(config: Config) -> Setup {
    setup_with(config, |_, _| {}).await
}

/// The DNS list blocks `ads.example` and its subdomains except `ok.ads.example`; every
/// name resolves to the origin.
async fn setup_with(
    config: Config,
    edit: impl FnOnce(&mut ProxyContext, &mut ServeOptions),
) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let events = Arc::new(EventLog::new());
    let mut ctx = ProxyContext {
        events: Some(events.clone()),
        ..proxy::context(ca.clone(), &config, None)
    };
    ctx.domains
        .store(Some(domains("||ads.example^\n@@||ok.ads.example^\n")));
    let mut options = tls_origin::trusting(&origin_ca);
    options.resolver = Some(Arc::new(Loopback));
    edit(&mut ctx, &mut options);
    let proxy = proxy::start(ctx, options).await;
    Setup {
        ca,
        origin_ca,
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

/// Asserts that nothing counted the blocked connections as intercepted or passed through,
/// and that nothing reached the origin.
fn assert_not_intercepted(s: &Setup) {
    let stats = s.proxy.stats();
    assert_eq!(stats.connections_intercepted, 0);
    assert_eq!(stats.connections_passthrough, 0);
    assert_eq!(stats.tls_client_rejections, 0);
    assert_eq!(stats.tls_abandoned_after_handshake, 0);
    assert_eq!(stats.http_requests, 0);
    assert_eq!(s.origin.connections(), 0);
}

#[tokio::test]
async fn a_dns_blocked_host_gets_a_connection_whose_http2_requests_are_reset() {
    let s = setup(Config::default()).await;
    let (status, tcp) = connect_status(s.proxy.addr, &s.target("Tracker.Ads.Example.")).await;
    assert_eq!(status, 200);
    let config = tls_config(&[&s.ca], &[b"h2", b"http/1.1"]);
    let tls = tls(tcp, config, "tracker.ads.example").await.unwrap();
    assert_eq!(peer_issuer(&tls), TOLLGATE);
    assert_eq!(alpn(&tls).as_deref(), Some(&b"h2"[..]));

    let mut h2 = http2(tls).await;
    for path in ["/pixel.gif", "/track.js"] {
        let url = s.url("tracker.ads.example", path);
        let error = h2.send_request(get(&url, &[])).await.unwrap_err();
        assert_eq!(
            reset_reason(&error),
            Some(h2::Reason::INTERNAL_ERROR),
            "{error}"
        );
        // Only the stream is reset: the connection stays open for the next request.
        assert!(!h2.is_closed(), "{path}");
    }

    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_eq!(dns_blocks(&s.events), ["tracker.ads.example"]);
    assert_not_intercepted(&s);

    // A connection closed right after its handshake is not counted as abandoned.
    drop(
        s.tls(&s.target("ads.example"), "ads.example", &[b"h2"])
            .await,
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.proxy.stats().dns_blocked, 2);
    assert_not_intercepted(&s);
}

#[tokio::test]
async fn an_http1_request_to_a_blocked_host_gets_no_response_and_the_connection_closes() {
    let s = setup(Config::default()).await;
    let mut tls = s
        .tls(&s.target("ads.example"), "ads.example", &[b"http/1.1"])
        .await;
    assert_eq!(peer_issuer(&tls), TOLLGATE);
    assert_eq!(alpn(&tls).as_deref(), Some(&b"http/1.1"[..]));

    tls.write_all(b"GET /pixel.gif HTTP/1.1\r\nHost: ads.example\r\n\r\n")
        .await
        .unwrap();
    let received = read_to_close(&mut tls, Duration::from_secs(5)).await;
    assert_eq!(received, Some(Vec::new()), "closed without a response");

    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_eq!(dns_blocks(&s.events), ["ads.example"]);
    assert_not_intercepted(&s);
}

/// A wildcard block in the DNS list (`||log*.example^`) blocks the hosts it matches like
/// any other block, and its exceptions still win.
#[tokio::test]
async fn hosts_a_wildcard_block_matches_get_a_blocked_connection() {
    let s = setup_with(Config::default(), |ctx, _| {
        ctx.domains.store(Some(domains(
            "||log*.ads.example^\n@@||log-ok*.ads.example^\n",
        )));
    })
    .await;
    let tls = s
        .tls(&s.target("log1.ads.example"), "log1.ads.example", &[b"h2"])
        .await;
    assert_eq!(peer_issuer(&tls), TOLLGATE);
    drop(tls);
    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_eq!(dns_blocks(&s.events), ["log1.ads.example"]);
    assert_not_intercepted(&s);

    for name in ["blog.ads.example", "log-ok1.ads.example"] {
        let tls = s.tls(&s.target(name), name, &[b"h2"]).await;
        let mut h2 = http2(tls).await;
        let reply = send2(&mut h2, get(&s.url(name, "/"), &[])).await;
        assert_eq!(reply.status, StatusCode::OK, "{name}");
    }
    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_eq!(s.proxy.stats().connections_intercepted, 2);
}

#[tokio::test]
async fn hosts_the_list_does_not_block_are_intercepted() {
    let s = setup(Config::default()).await;
    // The list's own exception, and a host it does not name.
    for name in ["ok.ads.example", "www.example"] {
        let tls = s.tls(&s.target(name), name, &[b"h2"]).await;
        let mut h2 = http2(tls).await;
        let reply = send2(&mut h2, get(&s.url(name, "/"), &[])).await;
        assert_eq!(reply.status, StatusCode::OK, "{name}");
    }
    let stats = s.proxy.stats();
    assert_eq!(stats.dns_blocked, 0);
    assert_eq!(stats.connections_intercepted, 2);
    assert_eq!(s.origin.requests(), 2);
    assert!(dns_blocks(&s.events).is_empty());
}

#[tokio::test]
async fn blocked_hosts_the_policy_passes_through_get_403() {
    let config = Config {
        passthrough: vec!["*.sdk.ads.example".to_string()],
        ..Config::default()
    };
    let s = setup(config).await;
    let policy = &s.proxy.ctx.policy;
    for _ in 0..2 {
        policy.record_client_rejection("pinned.ads.example", RejectionKind::UnknownCa, unix_secs());
    }
    assert_eq!(
        s.classify("pinned.ads.example"),
        Decision::Passthrough(tollgate_policy::PassthroughReason::LearnedPin)
    );

    for name in ["a.sdk.ads.example", "pinned.ads.example"] {
        let (status, _) = connect_status(s.proxy.addr, &s.target(name)).await;
        assert_eq!(status, 403, "{name}");
    }
    // The same names behind an address are closed.
    for name in ["a.sdk.ads.example", "pinned.ads.example"] {
        let tcp = connect(s.proxy.addr, &s.address()).await;
        let handshake = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), name).await;
        assert!(handshake.is_err(), "{name}");
    }
    assert_eq!(s.proxy.stats().dns_blocked, 4);
    assert_not_intercepted(&s);

    // With HTTPS filtering off every host is passed through, so a blocked one gets 403.
    let config = Config {
        mitm_enabled: false,
        ..Config::default()
    };
    let s = setup(config).await;
    let (status, _) = connect_status(s.proxy.addr, &s.target("ads.example")).await;
    assert_eq!(status, 403);
    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_not_intercepted(&s);
}

#[tokio::test]
async fn blocked_hosts_get_403_when_memory_is_low() {
    let s = setup_with(Config::default(), |ctx, _| {
        ctx.available_memory = || Some(1024 * 1024);
    })
    .await;
    let (status, _) = connect_status(s.proxy.addr, &s.target("ads.example")).await;
    assert_eq!(status, 403);
    let tcp = connect(s.proxy.addr, &s.address()).await;
    let handshake = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "ads.example").await;
    assert!(handshake.is_err(), "a blocked server name is closed");
    assert_eq!(s.proxy.stats().dns_blocked, 2);
    assert_not_intercepted(&s);
}

#[tokio::test]
async fn blocked_hosts_over_the_cap_get_403_while_no_blocked_connection_can_be_closed() {
    let s = setup_with(Config::default(), |_, options| options.max_blocked = 1).await;
    // Answered 200, but no ClientHello yet: before its handshake a blocked connection
    // cannot be closed to make room, since the client's attempt is not ready.
    let held = connect(s.proxy.addr, &s.target("a.ads.example")).await;

    let asked = Instant::now();
    let (status, _) = connect_status(s.proxy.addr, &s.target("b.ads.example")).await;
    assert_eq!(status, 403);
    assert!(
        asked.elapsed() >= Duration::from_millis(100),
        "answered before waiting for a slot"
    );
    let tcp = connect(s.proxy.addr, &s.address()).await;
    let handshake = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "c.ads.example").await;
    assert!(
        handshake.is_err(),
        "a blocked server name over the cap is closed"
    );

    drop(held);
    s.connect_eventually(&s.target("b.ads.example")).await;
    assert_not_intercepted(&s);
}

#[tokio::test]
async fn an_idle_blocked_connection_gives_its_slot_to_a_new_blocked_host() {
    let s = setup_with(Config::default(), |_, options| options.max_blocked = 1).await;
    let tls_a = s
        .tls(&s.target("a.ads.example"), "a.ads.example", &[b"h2"])
        .await;
    let mut held = http2(tls_a).await;
    let url = s.url("a.ads.example", "/");
    assert!(held.send_request(get(&url, &[])).await.is_err());

    // Idle only for a moment, which is enough: closing it costs its client nothing.
    let (status, tcp) = connect_status(s.proxy.addr, &s.target("b.ads.example")).await;
    assert_eq!(status, 200);
    let config = tls_config(&[&s.ca], &[b"h2"]);
    let mut tls_b = tls(tcp, config, "b.ads.example").await.unwrap();
    assert_eq!(peer_issuer(&tls_b), TOLLGATE);
    wait_for("the idle blocked connection to close", || held.is_closed()).await;

    // The same for a blocked server name behind an address: the connection to
    // b.ads.example, idle since its handshake, gives up the slot.
    let tls_c = s.tls(&s.address(), "c.ads.example", &[b"h2"]).await;
    assert_eq!(peer_issuer(&tls_c), TOLLGATE);
    let closed = read_to_close(&mut tls_b, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "the idle blocked connection was closed");

    assert_eq!(s.proxy.stats().dns_blocked, 3);
    assert_not_intercepted(&s);
}

#[tokio::test]
async fn a_blocked_host_waits_for_a_blocked_connection_to_become_idle() {
    let s = setup_with(Config::default(), |_, options| options.max_blocked = 1).await;
    // Issued ahead, so the handshake below is quick.
    s.ca.leaf("a.ads.example").unwrap();
    let held = connect(s.proxy.addr, &s.target("a.ads.example")).await;

    // As in a burst: the connection holding the only slot has not done its handshake
    // when the next blocked host asks for one.
    let addr = s.proxy.addr;
    let target = s.target("b.ads.example");
    let waiting = tokio::spawn(async move { connect_status(addr, &target).await.0 });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut tls_a = tls(held, tls_config(&[&s.ca], &[b"h2"]), "a.ads.example")
        .await
        .unwrap();

    assert_eq!(waiting.await.unwrap(), 200);
    let closed = read_to_close(&mut tls_a, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "the idle blocked connection was closed");
    assert_not_intercepted(&s);
}

#[tokio::test]
async fn a_blocked_connection_closes_once_the_lists_change() {
    let s = setup(Config::default()).await;
    let tls = s
        .tls(&s.target("cdn.ads.example"), "cdn.ads.example", &[b"h2"])
        .await;
    let mut h2 = http2(tls).await;
    let url = s.url("cdn.ads.example", "/");
    let error = h2.send_request(get(&url, &[])).await.unwrap_err();
    assert_eq!(reset_reason(&error), Some(h2::Reason::INTERNAL_ERROR));

    // The lists are reloaded without the rule that blocked the host: the next request is
    // refused, so the client may retry it, and the connection closes.
    s.proxy
        .ctx
        .domains
        .store(Some(domains("||other.example^\n")));
    let error = h2.send_request(get(&url, &[])).await.unwrap_err();
    assert_eq!(
        reset_reason(&error),
        Some(h2::Reason::REFUSED_STREAM),
        "{error}"
    );
    wait_for("the blocked connection to close", || h2.is_closed()).await;
    assert_eq!(s.origin.connections(), 0);

    // The retry's CONNECT is classified with the new lists.
    let tls = s
        .tls(&s.target("cdn.ads.example"), "cdn.ads.example", &[b"h2"])
        .await;
    let mut h2 = http2(tls).await;
    let reply = send2(&mut h2, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
    let stats = s.proxy.stats();
    assert_eq!(stats.dns_blocked, 1);
    assert_eq!(stats.connections_intercepted, 1);
}

#[tokio::test]
async fn a_blocked_host_offered_no_http_completes_its_handshake_and_is_closed() {
    let s = setup(Config::default()).await;
    // An app's own protocol over TLS, to the blocked host and behind an address.
    for target in [s.target("telemetry.ads.example"), s.address()] {
        let mut tls = s.tls(&target, "telemetry.ads.example", &[b"mqtt"]).await;
        assert_eq!(peer_issuer(&tls), TOLLGATE, "{target}");
        assert_eq!(alpn(&tls), None, "{target}");
        let closed = read_to_close(&mut tls, Duration::from_secs(5)).await;
        assert_eq!(closed, Some(Vec::new()), "{target}");
    }

    assert_eq!(s.proxy.stats().dns_blocked, 2);
    assert_not_intercepted(&s);
    assert_eq!(s.classify("telemetry.ads.example"), Decision::Intercept);
    assert!(
        !s.proxy
            .ctx
            .policy
            .learned_pins_json()
            .contains("telemetry.ads.example")
    );
}

#[tokio::test]
async fn a_client_that_rejects_a_blocked_hosts_leaf_teaches_no_pin() {
    let s = setup(Config::default()).await;
    // Like a pinning app: it trusts only the real origin's CA.
    let pinned = tls_config(&[&s.origin_ca], &[b"h2", b"http/1.1"]);
    for _ in 0..2 {
        let tcp = connect(s.proxy.addr, &s.target("sdk.ads.example")).await;
        let error = tls(tcp, pinned.clone(), "sdk.ads.example")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("UnknownIssuer"), "{error}");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.classify("sdk.ads.example"), Decision::Intercept);
    assert!(
        !s.proxy
            .ctx
            .policy
            .learned_pins_json()
            .contains("sdk.ads.example")
    );
    assert_not_intercepted(&s);
    // Still a blocked connection rather than a 403.
    let (status, _) = connect_status(s.proxy.addr, &s.target("sdk.ads.example")).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_blocked_server_name_behind_an_address_gets_a_blocked_connection() {
    let s = setup(Config::default()).await;
    let tls = s.tls(&s.address(), "ads.example", &[b"h2"]).await;
    assert_eq!(peer_issuer(&tls), TOLLGATE);
    let mut h2 = http2(tls).await;
    let error = h2
        .send_request(get(&s.url("ads.example", "/"), &[]))
        .await
        .unwrap_err();
    assert_eq!(reset_reason(&error), Some(h2::Reason::INTERNAL_ERROR));
    assert!(!h2.is_closed());
    assert_eq!(s.proxy.stats().dns_blocked, 1);
    assert_eq!(dns_blocks(&s.events), ["ads.example"]);
    assert_not_intercepted(&s);

    // Other names behind the address are intercepted.
    let tls = s.tls(&s.address(), "www.tollgate.test", &[b"h2"]).await;
    let mut h2 = http2(tls).await;
    let reply = send2(&mut h2, get(&s.url("www.tollgate.test", "/"), &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(s.proxy.stats().connections_intercepted, 1);
    assert_eq!(s.proxy.stats().dns_blocked, 1);
}

#[tokio::test]
async fn an_idle_blocked_connection_is_closed_and_gives_back_its_slot() {
    let idle = Duration::from_millis(300);
    let s = setup_with(Config::default(), |_, options| {
        options.max_blocked = 1;
        options.blocked_idle_timeout = idle;
    })
    .await;
    let tls = s
        .tls(&s.target("ads.example"), "ads.example", &[b"h2"])
        .await;
    let mut h2 = http2(tls).await;
    let url = s.url("ads.example", "/");
    let before_request = Instant::now();
    assert!(h2.send_request(get(&url, &[])).await.is_err());

    wait_for("the idle connection to close", || h2.is_closed()).await;
    assert!(
        before_request.elapsed() >= idle,
        "closed before the idle timeout"
    );
    s.connect_eventually(&s.target("ads.example")).await;
    assert_not_intercepted(&s);
}

#[tokio::test]
async fn blocked_connections_end_when_the_proxy_stops() {
    let s = setup(Config::default()).await;
    let mut tls = s
        .tls(&s.target("ads.example"), "ads.example", &[b"h2"])
        .await;
    s.proxy.stop().await;
    let closed = read_to_close(&mut tls, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "the blocked connection was closed");
}

#[tokio::test]
async fn allowlisted_hosts_are_not_blocked() {
    let config = Config {
        allowlist: vec!["*.ads.example".to_string()],
        ..Config::default()
    };
    let s = setup(config).await;
    let (status, _) = connect_status(s.proxy.addr, &s.target("ads.example")).await;
    assert_eq!(status, 200);
    assert_eq!(s.proxy.stats().dns_blocked, 0);
}

#[tokio::test]
async fn absolute_form_requests_to_a_blocked_host_get_403() {
    let s = setup(Config::default()).await;
    let reply = proxy_get(s.proxy.addr, "http://ads.example/pixel.gif", &[]).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.headers["access-control-allow-origin"], "*");
    let reply = proxy_get(s.proxy.addr, "https://ads.example/pixel.gif", &[]).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(s.proxy.stats().dns_blocked, 2);
    assert_eq!(s.origin.connections(), 0);
}

/// Like a request the filter engine blocks: a browser's navigation gets a page saying that
/// Tollgate blocked it, and its other requests no response.
#[tokio::test]
async fn absolute_form_requests_to_a_blocked_host_from_a_browser() {
    let s = setup(Config::default()).await;
    for url in ["http://ads.example/", "https://ads.example/"] {
        let page = proxy_get(s.proxy.addr, url, &[("sec-fetch-dest", "document")]).await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{url}");
        assert!(
            page.body.starts_with("Tollgate blocked this page."),
            "{url}"
        );
        let script = proxy_try_get(s.proxy.addr, url, &[("sec-fetch-dest", "script")]).await;
        assert!(script.is_none(), "{url}: {script:?}");
    }
    assert_eq!(s.proxy.stats().dns_blocked, 4);
    assert_eq!(dns_blocks(&s.events).len(), 4);
    assert_eq!(s.origin.connections(), 0);
}
