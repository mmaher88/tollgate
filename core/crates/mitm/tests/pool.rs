//! Pooled upstream connections after the device slept or changed networks: they are aged
//! with a clock that keeps counting during sleep, can be dropped all at once, and a safe
//! request that fails on a reused connection is retried once on a new one.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use hyper::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tollgate_mitm::{CertAuthority, ServeOptions};
use tollgate_policy::Config;

use support::client::{get, http1, proxy_get, read_reply};
use support::tunnel::{Sender2, connect, http2, send2, tls, tls_config};
use support::{proxy, tls_origin};

fn ca(name: &str) -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate(name).unwrap())
}

async fn start(options: ServeOptions) -> proxy::TestProxy {
    let ctx = proxy::context(ca("Tollgate Test CA"), &Config::default(), None);
    proxy::start(ctx, options).await
}

/// Lets an idle HTTP/1.1 connection get back to the pool.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

static H2_CLOCK: AtomicU64 = AtomicU64::new(1_000);
fn h2_clock() -> u64 {
    H2_CLOCK.load(Ordering::SeqCst)
}

#[tokio::test]
async fn an_http2_connection_idle_through_sleep_is_not_reused() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let mut options = tls_origin::trusting(&origin_ca);
    options.clock = h2_clock;
    let proxy = start(options).await;
    let url = format!("https://localhost:{}/", origin.port());

    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert!(reply.body.contains(" conn=1 "), "{}", reply.body);
    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert!(reply.body.contains(" conn=1 "), "{}", reply.body);

    // Two minutes asleep: tokio's clock, like Instant on iOS, did not move.
    H2_CLOCK.fetch_add(120, Ordering::SeqCst);
    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains(" conn=2 "), "{}", reply.body);
    assert_eq!(origin.connections(), 2);
}

static H1_CLOCK: AtomicU64 = AtomicU64::new(1_000);
fn h1_clock() -> u64 {
    H1_CLOCK.load(Ordering::SeqCst)
}

#[tokio::test]
async fn an_http1_connection_idle_through_sleep_is_not_reused() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"http/1.1"]).await;
    let mut options = tls_origin::trusting(&origin_ca);
    options.clock = h1_clock;
    let proxy = start(options).await;
    let url = format!("https://localhost:{}/", origin.port());

    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert!(reply.body.contains(" conn=1 "), "{}", reply.body);
    settle().await;
    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert!(reply.body.contains(" conn=1 "), "{}", reply.body);
    settle().await;

    H1_CLOCK.fetch_add(120, Ordering::SeqCst);
    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains(" conn=2 "), "{}", reply.body);
}

#[tokio::test]
async fn resetting_upstream_connections_drops_the_pooled_ones() {
    let origin_ca = ca("Origin CA");
    let h2 = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let h1 = tls_origin::https(origin_ca.clone(), &[b"http/1.1"]).await;
    let proxy = start(tls_origin::trusting(&origin_ca)).await;
    let h2_url = format!("https://localhost:{}/", h2.port());
    let h1_url = format!("https://localhost:{}/", h1.port());

    proxy_get(proxy.addr, &h2_url, &[]).await;
    proxy_get(proxy.addr, &h1_url, &[]).await;
    settle().await;
    proxy.ctx.reset_upstream_connections();

    let reply = proxy_get(proxy.addr, &h2_url, &[]).await;
    assert!(reply.body.contains(" conn=2 "), "{}", reply.body);
    let reply = proxy_get(proxy.addr, &h1_url, &[]).await;
    assert!(reply.body.contains(" conn=2 "), "{}", reply.body);
}

/// A plain HTTP origin that answers the first request on each connection with
/// `conn=<n>`, then reads the next request and closes the connection without an answer,
/// like a server behind a network path that went away.
async fn one_answer_per_connection() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    tokio::spawn(async move {
        let mut connections = 0;
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            connections += 1;
            let conn = connections;
            let seen = seen.clone();
            tokio::spawn(async move {
                if !read_head(&mut tcp).await {
                    return;
                }
                seen.fetch_add(1, Ordering::SeqCst);
                let body = format!("conn={conn}");
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
                let _ = tcp.write_all(format!("{head}{body}").as_bytes()).await;
                if read_head(&mut tcp).await {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    (addr, requests)
}

/// Reads up to the end of a request head; false if the connection ended first.
async fn read_head(tcp: &mut TcpStream) -> bool {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tcp.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return false,
        }
    }
    true
}

#[tokio::test]
async fn a_get_that_fails_on_a_reused_connection_is_retried_once() {
    let (origin, requests) = one_answer_per_connection().await;
    let proxy = start(ServeOptions::default()).await;
    let url = format!("http://{origin}/");

    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert_eq!(reply.body, "conn=1");
    settle().await;
    let reply = proxy_get(proxy.addr, &url, &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, "conn=2");
    assert_eq!(requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_request_with_a_body_is_not_retried() {
    let (origin, requests) = one_answer_per_connection().await;
    let proxy = start(ServeOptions::default()).await;
    let url = format!("http://{origin}/");

    proxy_get(proxy.addr, &url, &[]).await;
    settle().await;
    let tcp = TcpStream::connect(proxy.addr).await.unwrap();
    let mut sender = http1(tcp).await;
    let mut request = get(&url, &[("content-length", "0")]);
    *request.method_mut() = hyper::Method::POST;
    request
        .headers_mut()
        .insert("host", origin.to_string().parse().unwrap());
    let reply = read_reply(sender.send_request(request).await.unwrap()).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

/// Opens an intercepted HTTP/2 connection to `target` through the proxy, sends `GET url`
/// and returns once the response headers are in, without reading the body. The connection
/// stays open while the returned values live.
async fn start_unread(
    proxy: SocketAddr,
    proxy_ca: &CertAuthority,
    target: &str,
    url: &str,
) -> (Sender2, hyper::Response<hyper::body::Incoming>) {
    let tcp = connect(proxy, target).await;
    let tls = tls(tcp, tls_config(&[proxy_ca], &[b"h2"]), "localhost")
        .await
        .unwrap();
    let mut sender = http2(tls).await;
    let response = sender.send_request(get(url, &[])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    (sender, response)
}

#[tokio::test]
async fn clients_that_stop_reading_do_not_freeze_the_shared_http2_connection() {
    let proxy_ca = ca("Tollgate Test CA");
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let ctx = proxy::context(proxy_ca.clone(), &Config::default(), None);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    let target = format!("localhost:{}", origin.port());
    let big = format!("https://{target}/big?bytes=268435456");

    // Two clients stop reading large responses. Their upstream streams share one
    // connection, and together they can hold its whole receive window.
    let _first = start_unread(proxy.addr, &proxy_ca, &target, &big).await;
    let _second = start_unread(proxy.addr, &proxy_ca, &target, &big).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let small = format!("https://{target}/small");
    let third = async {
        let tcp = connect(proxy.addr, &target).await;
        let tls = tls(tcp, tls_config(&[&proxy_ca], &[b"h2"]), "localhost")
            .await
            .unwrap();
        let mut sender = http2(tls).await;
        send2(&mut sender, get(&small, &[])).await
    };
    let reply = tokio::time::timeout(Duration::from_secs(5), third)
        .await
        .expect("a request to the same origin was stuck behind the stalled ones");
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.starts_with("GET /small "), "{}", reply.body);
}
