//! `CONNECT` tunnels that the proxy intercepts: TLS with a Tollgate leaf, HTTP/2 or
//! HTTP/1.1 to the client, filtering, and forwarding through the shared pool.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyper::{StatusCode, Version};
use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tollgate_mitm::{CertAuthority, limits};
use tollgate_policy::Config;

use support::client::{get, http1, read_to_close, send1, wait_for};
use support::tunnel::{alpn, connect, http2, issuer_via, peer_issuer, send2, tls, tls_config};
use support::{proxy, tls_origin};

const RULES: &str = "\
||ads.tollgate.test^
/pixel/*$image
||tracker.tollgate.test^$third-party
";

struct Setup {
    ca: Arc<CertAuthority>,
    origin: support::origin::Origin,
    proxy: proxy::TestProxy,
}

impl Setup {
    /// `CONNECT 127.0.0.1:<origin port>`.
    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.origin.port())
    }

    /// `https://<name>:<origin port><path>`.
    fn url(&self, name: &str, path: &str) -> String {
        format!("https://{name}:{}{path}", self.origin.port())
    }
}

async fn setup_with(alpn: &[&[u8]], edit: impl FnOnce(&mut tollgate_mitm::ProxyContext)) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), alpn).await;
    let mut ctx = proxy::context(ca.clone(), &Config::default(), Some(RULES));
    edit(&mut ctx);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    Setup { ca, origin, proxy }
}

async fn setup() -> Setup {
    setup_with(&[b"h2", b"http/1.1"], |_| {}).await
}

#[tokio::test]
async fn http2_client_is_intercepted_and_forwarded() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.ca], &[b"h2", b"http/1.1"]);
    let tls = tls(tcp, config, "www.tollgate.test").await.unwrap();
    assert_eq!(peer_issuer(&tls), "CN=Tollgate Test CA, O=Tollgate");
    assert_eq!(alpn(&tls).as_deref(), Some(&b"h2"[..]));

    let mut h2 = http2(tls).await;
    let reply = send2(&mut h2, get(&s.url("www.tollgate.test", "/page?x=1"), &[])).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.version, Version::HTTP_2);
    assert_eq!(
        reply.body,
        format!(
            "GET /page?x=1 authority=www.tollgate.test:{} version=HTTP/2.0 conn=1 cookie=",
            s.origin.port()
        )
    );
    let stats = s.proxy.stats();
    assert_eq!(stats.connections_intercepted, 1);
    assert_eq!(stats.connections_passthrough, 0);
    assert_eq!(stats.http_requests, 1);
}

#[tokio::test]
async fn http1_client_is_intercepted_and_forwarded() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.ca], &[b"http/1.1"]);
    let tls = tls(tcp, config, "www.tollgate.test").await.unwrap();
    assert_eq!(alpn(&tls).as_deref(), Some(&b"http/1.1"[..]));

    let mut h1 = http1(tls).await;
    let request = get("/page", &[("host", "www.tollgate.test"), ("cookie", "a=1")]);
    let reply = send1(&mut h1, request).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.version, Version::HTTP_11);
    // The URL comes from the SNI and the CONNECT port, not from the Host header.
    assert_eq!(
        reply.body,
        format!(
            "GET /page authority=www.tollgate.test:{} version=HTTP/2.0 conn=1 cookie=a=1",
            s.origin.port()
        )
    );
}

#[tokio::test]
async fn blocked_requests_get_403_with_cors_header() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "ads.tollgate.test")
        .await
        .unwrap();
    let mut h2 = http2(tls).await;

    let reply = send2(&mut h2, get(&s.url("ads.tollgate.test", "/banner.js"), &[])).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.headers["access-control-allow-origin"], "*");
    assert_eq!(reply.body, "");
    assert_eq!(s.origin.requests(), 0);
    assert_eq!(s.proxy.stats().http_blocked, 1);
}

/// Opens an intercepted HTTP/2 connection for `name` and checks each case.
/// A path, its request headers and the status the client should get.
type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], StatusCode);

async fn check_statuses(s: &Setup, name: &str, cases: &[Case<'_>]) {
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), name)
        .await
        .unwrap();
    let mut h2 = http2(tls).await;
    for (path, headers, expected) in cases {
        let reply = send2(&mut h2, get(&s.url(name, path), headers)).await;
        assert_eq!(reply.status, *expected, "{name}{path} {headers:?}");
    }
}

#[tokio::test]
async fn request_type_comes_from_fetch_dest_then_accept_then_extension() {
    let s = setup().await;
    // `/pixel/*$image`
    let cases: &[Case] = &[
        (
            "/pixel/a",
            &[("sec-fetch-dest", "image")],
            StatusCode::FORBIDDEN,
        ),
        (
            "/pixel/a",
            &[("accept", "image/avif,*/*")],
            StatusCode::FORBIDDEN,
        ),
        ("/pixel/a.png", &[], StatusCode::FORBIDDEN),
        (
            "/pixel/a.png",
            &[("sec-fetch-dest", "script"), ("accept", "image/avif")],
            StatusCode::OK,
        ),
        ("/pixel/a", &[], StatusCode::OK),
    ];
    check_statuses(&s, "www.tollgate.test", cases).await;
}

#[tokio::test]
async fn documents_are_their_own_source() {
    let s = setup().await;
    // `||tracker.tollgate.test^$third-party`: a top-level document is first party; the
    // same URL embedded by another site, or with no source at all, is third party.
    let cases: &[Case] = &[
        ("/", &[("sec-fetch-dest", "document")], StatusCode::OK),
        (
            "/",
            &[
                ("sec-fetch-dest", "iframe"),
                ("referer", "https://news.test/"),
            ],
            StatusCode::FORBIDDEN,
        ),
        (
            "/app.js",
            &[("referer", "https://tracker.tollgate.test/")],
            StatusCode::OK,
        ),
        (
            "/app.js",
            &[("origin", "https://tracker.tollgate.test")],
            StatusCode::OK,
        ),
        ("/app.js", &[], StatusCode::FORBIDDEN),
    ];
    check_statuses(&s, "tracker.tollgate.test", cases).await;
}

#[tokio::test]
async fn http2_request_for_another_authority_gets_421() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "a.tollgate.test")
        .await
        .unwrap();
    let mut h2 = http2(tls).await;

    let other_host = send2(&mut h2, get(&s.url("b.tollgate.test", "/"), &[])).await;
    assert_eq!(other_host.status, StatusCode::MISDIRECTED_REQUEST);
    let other_port = send2(&mut h2, get("https://a.tollgate.test:1/", &[])).await;
    assert_eq!(other_port.status, StatusCode::MISDIRECTED_REQUEST);
    let same = send2(&mut h2, get(&s.url("A.Tollgate.Test", "/"), &[])).await;
    assert_eq!(same.status, StatusCode::OK);
    assert_eq!(s.origin.requests(), 1);
}

#[tokio::test]
async fn client_without_sni_gets_a_leaf_for_the_connect_ip() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(peer_issuer(&tls), "CN=Tollgate Test CA, O=Tollgate");
    let mut h2 = http2(tls).await;

    let reply = send2(&mut h2, get(&s.url("127.0.0.1", "/ip"), &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.body.starts_with("GET /ip authority=127.0.0.1:"),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn upstream_is_shared_across_client_connections_and_converted_to_http1() {
    let s = setup_with(&[b"http/1.1"], |_| {}).await;
    for _ in 0..2 {
        let tcp = connect(s.proxy.addr, &s.target()).await;
        let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "www.tollgate.test")
            .await
            .unwrap();
        let mut h2 = http2(tls).await;
        let cookies = [("cookie", "a=1"), ("cookie", "b=2")];
        let reply = send2(&mut h2, get(&s.url("www.tollgate.test", "/"), &cookies)).await;
        assert_eq!(
            reply.body,
            format!(
                "GET / authority=www.tollgate.test:{} version=HTTP/1.1 conn=1 cookie=a=1; b=2",
                s.origin.port()
            )
        );
    }
    assert_eq!(s.origin.connections(), 1);
}

#[tokio::test]
async fn untrusted_upstream_certificate_gets_502() {
    let s = setup().await;
    // An origin whose certificate comes from a CA the proxy does not trust.
    let rogue = tls_origin::https(
        Arc::new(CertAuthority::generate("Rogue CA").unwrap()),
        &[b"h2"],
    )
    .await;
    let tcp = connect(s.proxy.addr, &format!("127.0.0.1:{}", rogue.port())).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "www.tollgate.test")
        .await
        .unwrap();
    let mut h2 = http2(tls).await;
    let url = format!("https://www.tollgate.test:{}/", rogue.port());

    let reply = send2(&mut h2, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(rogue.requests(), 0);
}

#[tokio::test]
async fn idle_intercepted_connections_give_back_their_slot() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let mut ctx = proxy::context(ca.clone(), &Config::default(), None);
    ctx.max_intercepted = 1;
    let mut options = tls_origin::trusting(&origin_ca);
    options.idle_timeout = Duration::from_millis(300);
    let proxy = proxy::start(ctx, options).await;
    let target = format!("127.0.0.1:{}", origin.port());

    let tcp = connect(proxy.addr, &target).await;
    let mut idle = tls(tcp, tls_config(&[&ca], &[b"h2"]), "www.tollgate.test")
        .await
        .unwrap();
    let closed = read_to_close(&mut idle, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "the idle connection was closed");

    wait_for("the slot to be free", || {
        proxy.stats().connections_intercepted == 1
    })
    .await;
    let tcp = connect(proxy.addr, &target).await;
    let tls = tls(tcp, tls_config(&[&ca], &[b"h2"]), "www.tollgate.test").await;
    assert_eq!(
        peer_issuer(&tls.unwrap()),
        "CN=Tollgate Test CA, O=Tollgate"
    );
    assert_eq!(proxy.stats().connections_intercepted, 2);
}

#[tokio::test]
async fn a_full_table_closes_the_longest_idle_connection_for_a_new_one() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let mut ctx = proxy::context(ca.clone(), &Config::default(), None);
    ctx.max_intercepted = 2;
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    let target = format!("127.0.0.1:{}", origin.port());
    let url = |path: &str| format!("https://www.tollgate.test:{}{path}", origin.port());
    let client = || async {
        let tcp = connect(proxy.addr, &target).await;
        let tls = tls(tcp, tls_config(&[&ca], &[b"h2"]), "www.tollgate.test")
            .await
            .unwrap();
        http2(tls).await
    };

    // One client has a slow request in flight the whole time; the other is done.
    let mut busy = client().await;
    let slow = url("/?delay=6000");
    let in_flight = tokio::spawn(async move { send2(&mut busy, get(&slow, &[])).await });
    let mut idle = client().await;
    assert_eq!(
        send2(&mut idle, get(&url("/"), &[])).await.status,
        StatusCode::OK
    );
    tokio::time::sleep(limits::MIN_IDLE_TO_RECLAIM + Duration::from_millis(300)).await;

    // The table is full: the idle connection is closed to make room.
    let tcp = connect(proxy.addr, &target).await;
    let tls = tls(tcp, tls_config(&[&ca], &[b"h2"]), "www.tollgate.test")
        .await
        .unwrap();
    assert_eq!(peer_issuer(&tls), "CN=Tollgate Test CA, O=Tollgate");
    let mut third = http2(tls).await;
    assert_eq!(
        send2(&mut third, get(&url("/"), &[])).await.status,
        StatusCode::OK
    );
    wait_for("the idle connection to close", || idle.is_closed()).await;
    assert_eq!(proxy.stats().connections_intercepted, 3);
    assert_eq!(proxy.stats().connections_passthrough, 0);

    // Now one connection is busy and the other was idle only briefly: neither is closed,
    // and a new connection is passed through.
    let issuer = issuer_via(proxy.addr, &target, &[&ca, &origin_ca], "www.tollgate.test").await;
    assert_eq!(issuer, "CN=Origin CA, O=Tollgate");
    assert_eq!(proxy.stats().connections_passthrough, 1);
    assert!(!third.is_closed());
    let reply = in_flight.await.unwrap();
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.body.starts_with("GET /?delay=6000 "),
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn incomplete_client_hello_times_out() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let ctx = proxy::context(ca, &Config::default(), None);
    let options = tollgate_mitm::ServeOptions {
        handshake_timeout: Duration::from_millis(300),
        ..tollgate_mitm::ServeOptions::default()
    };
    let proxy = proxy::start(ctx, options).await;
    let origin = support::origin::http().await;

    let mut tcp = connect(proxy.addr, &format!("127.0.0.1:{}", origin.port())).await;
    // A TLS record header announcing 512 bytes, then nothing.
    tcp.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00])
        .await
        .unwrap();
    let closed = read_to_close(&mut tcp, Duration::from_secs(5)).await;
    assert_eq!(closed, Some(Vec::new()));
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn stalled_handshake_times_out_and_frees_the_slot() {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let mut ctx = proxy::context(ca.clone(), &Config::default(), None);
    ctx.max_intercepted = 1;
    let mut options = tls_origin::trusting(&origin_ca);
    options.handshake_timeout = Duration::from_secs(1);
    let proxy = proxy::start(ctx, options).await;
    let target = format!("127.0.0.1:{}", origin.port());

    // A real ClientHello, then silence: the proxy answers with its flight and waits for a
    // client Finished that never comes. Reading the ClientHello took no time at all, so
    // only the limit on the handshake itself can end this.
    let mut stalled = connect(proxy.addr, &target).await;
    let name = ServerName::try_from("www.tollgate.test").unwrap();
    let mut client = ClientConnection::new(tls_config(&[&ca], &[b"h2"]), name).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    stalled.write_all(&hello).await.unwrap();
    wait_for("the stalled connection to be intercepted", || {
        proxy.stats().connections_intercepted == 1
    })
    .await;

    // The stalled handshake holds the only slot.
    let issuer = issuer_via(
        proxy.addr,
        &target,
        &[&ca, &origin_ca],
        "full.tollgate.test",
    )
    .await;
    assert_eq!(issuer, "CN=Origin CA, O=Tollgate");
    assert_eq!(proxy.stats().connections_passthrough, 1);

    let closed = read_to_close(&mut stalled, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "the stalled handshake was closed");
    let issuer = issuer_via(proxy.addr, &target, &[&ca], "www.tollgate.test").await;
    assert_eq!(issuer, "CN=Tollgate Test CA, O=Tollgate");
    let stats = proxy.stats();
    assert_eq!(stats.connections_intercepted, 2);
    assert_eq!(stats.connections_passthrough, 1);
    assert_eq!(stats.tls_client_rejections, 0);
}

/// Opens an intercepted HTTP/2 connection to the test origin.
async fn intercepted_h2(s: &Setup) -> support::tunnel::Sender2 {
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, tls_config(&[&s.ca], &[b"h2"]), "www.tollgate.test")
        .await
        .unwrap();
    http2(tls).await
}

#[tokio::test]
async fn large_http2_response_headers_are_forwarded() {
    let s = setup().await;
    let mut h2 = intercepted_h2(&s).await;
    // About 24 KB of Set-Cookie, over hyper's 16 KiB default.
    let url = s.url("www.tollgate.test", "/headers?count=3&size=8000");
    let reply = send2(&mut h2, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.headers.get_all("set-cookie").iter().count(), 3);
}

#[tokio::test]
async fn many_http1_response_headers_are_forwarded() {
    let s = setup_with(&[b"http/1.1"], |_| {}).await;
    let mut h2 = intercepted_h2(&s).await;
    // 120 header lines, over hyper's default of 100.
    let url = s.url("www.tollgate.test", "/headers?count=120&size=10");
    let reply = send2(&mut h2, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.headers.get_all("set-cookie").iter().count(), 120);
}

#[tokio::test]
async fn response_headers_over_the_limit_get_a_clean_502() {
    let s = setup().await;
    let mut h2 = intercepted_h2(&s).await;
    let size = 7400;
    let count = limits::MAX_HEADER_LIST as usize / size + 1;
    let url = s.url(
        "www.tollgate.test",
        &format!("/headers?count={count}&size={size}"),
    );
    let reply = send2(&mut h2, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    // The proxy is still serving: the same client connection works afterwards.
    let reply = send2(&mut h2, get(&s.url("www.tollgate.test", "/"), &[])).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn large_http2_request_cookie_is_forwarded() {
    let s = setup().await;
    let mut h2 = intercepted_h2(&s).await;
    let cookie = format!("a={}", "x".repeat(24 * 1024));
    let reply = send2(
        &mut h2,
        get(&s.url("www.tollgate.test", "/"), &[("cookie", &cookie)]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.ends_with(&cookie));
}

#[tokio::test]
async fn many_http1_request_headers_are_forwarded() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(
        tcp,
        tls_config(&[&s.ca], &[b"http/1.1"]),
        "www.tollgate.test",
    )
    .await
    .unwrap();
    let mut h1 = http1(tls).await;
    let names: Vec<String> = (0..120).map(|i| format!("x-extra-{i}")).collect();
    let mut headers: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "1")).collect();
    headers.push(("host", "www.tollgate.test"));
    let reply = send1(&mut h1, get("/", &headers)).await;
    assert_eq!(reply.status, StatusCode::OK);
}
