//! An intercepted connection whose upstream cannot be reached, or closes the connection
//! without answering: the proxy answered the `CONNECT` and finished TLS before dialing, so
//! it must not answer the request itself. Closing the connection (HTTP/1.1) or resetting
//! the stream (HTTP/2) lets the browser show its own error page, or fall back from
//! `https://` to `http://`.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hyper::StatusCode;
use tokio::net::TcpListener;
use tollgate_mitm::CertAuthority;
use tollgate_policy::Config;

use support::client::{get, http1};
use support::origin::{Origin, closed_port};
use support::tls_origin::{ClientAuth, HangUp};
use support::tunnel::{connect, http2, send2, tls, tls_config};
use support::{proxy, tls_origin};

fn ca(name: &str) -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate(name).unwrap())
}

async fn start(options: tollgate_mitm::ServeOptions) -> (Arc<CertAuthority>, proxy::TestProxy) {
    let tollgate_ca = ca("Tollgate Test CA");
    let ctx = proxy::context(tollgate_ca.clone(), &Config::default(), None);
    (tollgate_ca, proxy::start(ctx, options).await)
}

#[tokio::test]
async fn an_unreachable_upstream_closes_an_http1_connection_without_a_response() {
    let (tollgate_ca, proxy) = start(tls_origin::trusting(&ca("Origin CA"))).await;
    let port = closed_port().await;
    let tcp = connect(proxy.addr, &format!("127.0.0.1:{port}")).await;
    let tls = tls(
        tcp,
        tls_config(&[&tollgate_ca], &[b"http/1.1"]),
        "www.tollgate.test",
    )
    .await
    .unwrap();
    let mut sender = http1(tls).await;
    let url = format!("https://www.tollgate.test:{port}/");
    let host = format!("www.tollgate.test:{port}");
    let result = sender.send_request(get(&url, &[("host", &host)])).await;
    assert!(result.is_err(), "expected no response, got {result:?}");
    assert!(proxy.ctx.policy.learned_pins().is_empty());
}

#[tokio::test]
async fn an_unreachable_upstream_resets_the_http2_stream() {
    let (tollgate_ca, proxy) = start(tls_origin::trusting(&ca("Origin CA"))).await;
    let port = closed_port().await;
    let tcp = connect(proxy.addr, &format!("127.0.0.1:{port}")).await;
    let tls = tls(
        tcp,
        tls_config(&[&tollgate_ca], &[b"h2"]),
        "www.tollgate.test",
    )
    .await
    .unwrap();
    let mut sender = http2(tls).await;
    let url = format!("https://www.tollgate.test:{port}/");
    let result = sender.send_request(get(&url, &[])).await;
    assert!(result.is_err(), "expected a stream reset, got {result:?}");
    assert!(proxy.ctx.policy.learned_pins().is_empty());
}

/// Sends one request through an intercepted connection to `origin` (its certificates from
/// `origin_ca`), with the client speaking `front` (`h2` or `http/1.1`), and returns
/// whether the client got a response.
async fn answered(origin_ca: &Arc<CertAuthority>, origin: &Origin, front: &[u8]) -> bool {
    let (tollgate_ca, proxy) = start(tls_origin::trusting(origin_ca)).await;
    let tcp = connect(proxy.addr, &format!("localhost:{}", origin.port())).await;
    let tls = tls(tcp, tls_config(&[&tollgate_ca], &[front]), "localhost")
        .await
        .unwrap();
    let url = format!("https://localhost:{}/", origin.port());
    let result = if front == b"h2" {
        http2(tls).await.send_request(get(&url, &[])).await
    } else {
        let host = format!("localhost:{}", origin.port());
        http1(tls)
            .await
            .send_request(get(&url, &[("host", &host)]))
            .await
    };
    assert!(proxy.ctx.policy.learned_pins().is_empty());
    if let Ok(response) = &result {
        eprintln!("answered {}", response.status());
    }
    result.is_ok()
}

#[tokio::test]
async fn an_upstream_that_hangs_up_gets_no_response() {
    for how in [HangUp::CloseNotify, HangUp::Reset] {
        for upstream in [&b"http/1.1"[..], b"h2"] {
            for front in [&b"http/1.1"[..], b"h2"] {
                let origin_ca = ca("Origin CA");
                let origin = tls_origin::hang_up(
                    origin_ca.clone(),
                    &[upstream],
                    rustls::DEFAULT_VERSIONS,
                    ClientAuth::None,
                    how,
                )
                .await;
                let answered = answered(&origin_ca, &origin, front).await;
                assert!(
                    !answered,
                    "{how:?}, upstream {:?}, front {:?}",
                    String::from_utf8_lossy(upstream),
                    String::from_utf8_lossy(front)
                );
                assert_eq!(origin.requests(), 1);
            }
        }
    }
}

#[tokio::test]
async fn an_http2_upstream_that_resets_the_stream_gets_no_response() {
    for front in [&b"http/1.1"[..], b"h2"] {
        let origin_ca = ca("Origin CA");
        let origin = tls_origin::failing(origin_ca.clone(), &[b"h2"]).await;
        assert!(!answered(&origin_ca, &origin, front).await);
        assert_eq!(origin.requests(), 1);
    }
}

#[tokio::test]
async fn no_free_upstream_connection_gets_503() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2"]).await;
    let mut options = tls_origin::trusting(&origin_ca);
    options.max_upstream_connections = 0;
    options.connect_timeout = Duration::from_millis(200);
    let (tollgate_ca, proxy) = start(options).await;
    let tcp = connect(proxy.addr, &format!("127.0.0.1:{}", origin.port())).await;
    let tls = tls(
        tcp,
        tls_config(&[&tollgate_ca], &[b"h2"]),
        "www.tollgate.test",
    )
    .await
    .unwrap();
    let mut sender = http2(tls).await;
    let url = format!("https://www.tollgate.test:{}/", origin.port());
    let reply = send2(&mut sender, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    // The connection still works for the next request.
    let reply = send2(&mut sender, get(&url, &[])).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
}

/// A port that completes TCP handshakes and then never says anything, and the number of
/// connections it accepted.
async fn silent_port() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            held.push(tcp);
        }
    });
    (port, accepted)
}

/// An intercepted HTTP/2 connection through a proxy whose connect timeout is `limit`, to
/// `port` on 127.0.0.1, and the URL to ask for there.
async fn h2_to(port: u16, limit: Duration) -> (proxy::TestProxy, support::tunnel::Sender2, String) {
    let mut options = tls_origin::trusting(&ca("Origin CA"));
    options.connect_timeout = limit;
    let (tollgate_ca, proxy) = start(options).await;
    let tcp = connect(proxy.addr, &format!("127.0.0.1:{port}")).await;
    let tls = tls(
        tcp,
        tls_config(&[&tollgate_ca], &[b"h2"]),
        "www.tollgate.test",
    )
    .await
    .unwrap();
    let sender = http2(tls).await;
    (proxy, sender, format!("https://www.tollgate.test:{port}/"))
}

#[tokio::test]
async fn requests_waiting_on_a_dial_that_times_out_fail_with_it() {
    let limit = Duration::from_secs(1);
    let (port, accepted) = silent_port().await;
    let (_proxy, sender, url) = h2_to(port, limit).await;
    let start = Instant::now();
    let requests: Vec<_> = (0..5)
        .map(|_| {
            let mut sender = sender.clone();
            let request = get(&url, &[]);
            tokio::spawn(async move {
                let result = sender.send_request(request).await;
                (result.is_err(), start.elapsed())
            })
        })
        .collect();
    for request in requests {
        let (failed, elapsed) = request.await.unwrap();
        assert!(failed);
        assert!(
            elapsed < limit.mul_f32(1.3),
            "a request failed after {elapsed:?}"
        );
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_request_waiting_on_a_cancelled_dial_dials_itself() {
    let limit = Duration::from_secs(1);
    let (port, accepted) = silent_port().await;
    let (_proxy, sender, url) = h2_to(port, limit).await;
    let start = Instant::now();
    let first = tokio::spawn({
        let mut sender = sender.clone();
        let request = get(&url, &[]);
        async move { sender.send_request(request).await.is_err() }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = tokio::spawn({
        let mut sender = sender.clone();
        let request = get(&url, &[]);
        async move { sender.send_request(request).await.is_err() }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The client gives up on the first request while its dial is still running.
    first.abort();
    assert!(second.await.unwrap());
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300) + limit.mul_f32(0.9),
        "the second request failed after {elapsed:?}, before a dial of its own could time out"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}
