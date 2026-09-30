//! Upstream TLS failures that the client, talking to the server directly, would not have:
//! the host is learned as a pin and passed through from then on. Failures the client would
//! have too are not learned. A failure that is not learned fails a browser's request for
//! part of a page, as it would without the proxy, while a navigation and an app get a
//! `502`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyper::StatusCode;
use rustls::SupportedProtocolVersion;
use rustls::version::{TLS12, TLS13};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tollgate_common::clock::unix_secs;
use tollgate_mitm::CertAuthority;
use tollgate_policy::{Config, Decision, PassthroughReason};

use support::client::{get, http1, proxy_get, proxy_get_raw, read_reply, read_to_close, wait_for};
use support::tls_origin::{self, ClientAuth, HangUp};
use support::tunnel::{connect, http2, peer_issuer, reset_reason, tls, tls_config};
use support::{origin, proxy};

fn ca(name: &str) -> Arc<CertAuthority> {
    Arc::new(CertAuthority::generate(name).unwrap())
}

fn learned(proxy: &proxy::TestProxy) -> Vec<String> {
    proxy
        .ctx
        .policy
        .learned_pins()
        .into_iter()
        .map(|(host, _)| host)
        .collect()
}

/// A plain `https://` request through the proxy to `localhost:port`.
async fn status_via(proxy: &proxy::TestProxy, port: u16) -> StatusCode {
    proxy_get(proxy.addr, &format!("https://localhost:{port}/"), &[])
        .await
        .status
}

async fn start(origin_ca: &CertAuthority) -> proxy::TestProxy {
    start_with(ca("Tollgate Test CA"), origin_ca).await
}

/// A proxy with `tollgate_ca`, whose upstream TLS trusts only `origin_ca`.
async fn start_with(
    tollgate_ca: Arc<CertAuthority>,
    origin_ca: &CertAuthority,
) -> proxy::TestProxy {
    let ctx = proxy::context(tollgate_ca, &Config::default(), None);
    proxy::start(ctx, tls_origin::trusting(origin_ca)).await
}

/// What a request on an intercepted HTTP/2 connection got.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Answer {
    /// A response: its status and body.
    Response(StatusCode, String),
    /// No response: the stream was reset with this reason.
    Reset(Option<h2::Reason>),
}

/// A browser's request that is not a navigation, failed as an upstream failure is.
const NO_RESPONSE: Answer = Answer::Reset(Some(h2::Reason::INTERNAL_ERROR));

/// Sends `GET /` to the origin at `port` for each `Sec-Fetch-Dest` in `dests` (`None`: no
/// header, as an app sends), in order, on one intercepted HTTP/2 connection for
/// `localhost` that trusts `tollgate_ca`, and returns what each got.
async fn answers(
    proxy: &proxy::TestProxy,
    tollgate_ca: &CertAuthority,
    port: u16,
    dests: &[Option<&str>],
) -> Vec<Answer> {
    let tcp = connect(proxy.addr, &format!("localhost:{port}")).await;
    let tls = tls(tcp, tls_config(&[tollgate_ca], &[b"h2"]), "localhost")
        .await
        .unwrap();
    let mut sender = http2(tls).await;
    let url = format!("https://localhost:{port}/");
    let mut out = Vec::new();
    for dest in dests {
        let headers: Vec<(&str, &str)> = dest.iter().map(|d| ("sec-fetch-dest", *d)).collect();
        out.push(match sender.send_request(get(&url, &headers)).await {
            Ok(response) => {
                let reply = read_reply(response).await;
                Answer::Response(reply.status, reply.body)
            }
            Err(e) => Answer::Reset(reset_reason(&e)),
        });
    }
    out
}

/// A `502` whose text starts with `start`.
fn text_502(answer: &Answer, start: &str) -> bool {
    matches!(answer, Answer::Response(StatusCode::BAD_GATEWAY, body) if body.starts_with(start))
}

/// A certificate the client would reject too, here one for another name, is not learned. A
/// browser's request for part of a page (`fetch()` among them) fails, as the browser's own
/// check of the certificate would fail it, so a page that tests whether the host is
/// reachable sees it unreachable; a navigation gets a `502` whose text says what is wrong,
/// and so does an app, which sends no `Sec-Fetch-Dest`.
#[tokio::test]
async fn a_certificate_the_client_would_reject_fails_a_browsers_fetch() {
    let origin_ca = ca("Origin CA");
    let origin = tls_origin::for_name(origin_ca.clone(), "elsewhere.tollgate.test").await;
    let tollgate_ca = ca("Tollgate Test CA");
    let proxy = start_with(tollgate_ca.clone(), &origin_ca).await;
    let got = answers(
        &proxy,
        &tollgate_ca,
        origin.port(),
        &[
            Some("empty"),
            Some("document"),
            None,
            Some("image"),
            Some("Document"),
            Some("script"),
        ],
    )
    .await;
    let says = "Tollgate: the server's certificate is for another name";
    assert_eq!(got[0], NO_RESPONSE);
    assert!(text_502(&got[1], says), "{:?}", got[1]);
    assert!(text_502(&got[2], says), "{:?}", got[2]);
    assert_eq!(got[3], NO_RESPONSE);
    assert!(text_502(&got[4], says), "{:?}", got[4]);
    assert_eq!(got[5], NO_RESPONSE);
    assert!(learned(&proxy).is_empty());
    assert_eq!(origin.requests(), 0);

    // Over HTTP/1.1 the connection closes without a response.
    let tcp = connect(proxy.addr, &format!("localhost:{}", origin.port())).await;
    let mut tls = tls(
        tcp,
        tls_config(&[&tollgate_ca], &[b"http/1.1"]),
        "localhost",
    )
    .await
    .unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Dest: empty\r\n\r\n")
        .await
        .unwrap();
    let received = read_to_close(&mut tls, Duration::from_secs(5)).await;
    assert_eq!(received, Some(Vec::new()), "closed without a response");
}

/// A certificate the proxy cannot verify, not learned because upstream TLS failed for
/// several hosts at once (see `Policy::learn_upstream_untrusted`): a browser's fetch fails,
/// and its failure still counts toward the burst; a navigation and an app get a `502` that
/// says so.
#[tokio::test]
async fn an_unverified_certificate_that_was_not_learned_fails_a_browsers_fetch() {
    // The proxy trusts only the Origin CA; this origin's certificate comes from another.
    let origin = tls_origin::https(ca("Rogue CA"), &[b"h2", b"http/1.1"]).await;
    let tollgate_ca = ca("Tollgate Test CA");
    let proxy = start_with(tollgate_ca.clone(), &ca("Origin CA")).await;
    let policy = &proxy.ctx.policy;
    let now = unix_secs();
    assert!(policy.learn_upstream_untrusted("a.tollgate.test", now));
    assert!(policy.learn_upstream_untrusted("b.tollgate.test", now));
    let got = answers(&proxy, &tollgate_ca, origin.port(), &[Some("empty")]).await;
    assert_eq!(got, [NO_RESPONSE]);
    // The fetch's failure made three hosts: a burst, which takes the other two back.
    assert!(learned(&proxy).is_empty());

    let got = answers(
        &proxy,
        &tollgate_ca,
        origin.port(),
        &[Some("document"), None, Some("image")],
    )
    .await;
    let says = "Tollgate: the server's certificate could not be verified";
    assert!(text_502(&got[0], says), "{:?}", got[0]);
    assert!(text_502(&got[1], says), "{:?}", got[1]);
    assert_eq!(got[2], NO_RESPONSE);
    assert!(learned(&proxy).is_empty());
    assert_eq!(origin.requests(), 0);
}

/// A failure that makes the host a learned pin gets the same answer whoever sent the
/// request: no response, and the connection closes, so the browser retries on a new
/// `CONNECT`, which is passed through.
#[tokio::test]
async fn a_browsers_fetch_still_learns_an_unverified_certificate() {
    let origin = tls_origin::https(ca("Rogue CA"), &[b"h2"]).await;
    let tollgate_ca = ca("Tollgate Test CA");
    let proxy = start_with(tollgate_ca.clone(), &ca("Origin CA")).await;
    let got = answers(&proxy, &tollgate_ca, origin.port(), &[Some("empty")]).await;
    assert_eq!(got, [Answer::Reset(Some(h2::Reason::REFUSED_STREAM))]);
    assert_eq!(learned(&proxy), ["localhost"]);
}

/// Any other upstream failure that gets a `502`, here a TLS alert (internal_error) the
/// client would get too: a browser's fetch fails, and a navigation and an app get an empty
/// `502`.
#[tokio::test]
async fn other_failures_fail_a_browsers_fetch() {
    let origin = tls_origin::tls_alert(80).await;
    let tollgate_ca = ca("Tollgate Test CA");
    let proxy = start_with(tollgate_ca.clone(), &ca("Origin CA")).await;
    let got = answers(
        &proxy,
        &tollgate_ca,
        origin.port(),
        &[Some("empty"), Some("document"), None],
    )
    .await;
    let empty_502 = Answer::Response(StatusCode::BAD_GATEWAY, String::new());
    assert_eq!(got, [NO_RESPONSE, empty_502.clone(), empty_502]);
    assert!(learned(&proxy).is_empty());
}

#[tokio::test]
async fn servers_the_proxy_shares_no_cipher_suite_or_version_with_are_learned() {
    // 40 handshake_failure (no common cipher suite), 70 protocol_version (TLS 1.0 only),
    // 71 insufficient_security.
    for alert in [40, 70, 71] {
        let origin = tls_origin::tls_alert(alert).await;
        let proxy = start(&ca("Origin CA")).await;
        assert_eq!(
            status_via(&proxy, origin.port()).await,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(learned(&proxy), ["localhost"], "alert {alert}");
    }
}

#[tokio::test]
async fn other_alerts_are_not_learned() {
    // 42 bad_certificate without a certificate request, 80 internal_error, 112
    // unrecognized_name: the client would get the same answer.
    for alert in [42, 80, 112] {
        let origin = tls_origin::tls_alert(alert).await;
        let proxy = start(&ca("Origin CA")).await;
        assert_eq!(
            status_via(&proxy, origin.port()).await,
            StatusCode::BAD_GATEWAY
        );
        assert!(learned(&proxy).is_empty(), "alert {alert}");
    }
}

async fn required_client_certificate_is_learned(
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[&[u8]],
) {
    let origin_ca = ca("Origin CA");
    let origin =
        tls_origin::https_with(origin_ca.clone(), alpn, versions, ClientAuth::Required).await;
    let proxy = start(&origin_ca).await;
    assert_eq!(
        status_via(&proxy, origin.port()).await,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(learned(&proxy), ["localhost"]);
    assert_eq!(origin.requests(), 0);
    // The client (an app with its own certificate) now talks to the server directly.
    let target = format!("localhost:{}", origin.port());
    let tcp = connect(proxy.addr, &target).await;
    let config = tls_config(&[&origin_ca], &[b"h2", b"http/1.1"]);
    match tls(tcp, config, "localhost").await {
        Ok(stream) => assert_eq!(peer_issuer(&stream), "CN=Origin CA, O=Tollgate"),
        // Over TLS 1.2 the origin itself turns this test client, which has no certificate
        // either, away during the handshake. Intercepted, it would fail on our leaf.
        Err(e) => assert!(e.to_string().contains("CertificateRequired"), "{e}"),
    }
}

#[tokio::test]
async fn a_server_requiring_a_client_certificate_is_learned_over_tls12() {
    required_client_certificate_is_learned(&[&TLS12], &[b"h2", b"http/1.1"]).await;
}

#[tokio::test]
async fn a_server_requiring_a_client_certificate_is_learned_over_tls13_and_http1() {
    required_client_certificate_is_learned(&[&TLS13], &[b"http/1.1"]).await;
}

#[tokio::test]
async fn a_server_requiring_a_client_certificate_is_learned_over_tls13_and_http2() {
    required_client_certificate_is_learned(&[&TLS13], &[b"h2"]).await;
}

#[tokio::test]
async fn an_intercepted_request_to_a_server_requiring_a_client_certificate_is_learned() {
    let tollgate_ca = ca("Tollgate Test CA");
    let origin_ca = ca("Origin CA");
    let origin =
        tls_origin::https_with(origin_ca.clone(), &[b"h2"], &[&TLS13], ClientAuth::Required).await;
    let ctx = proxy::context(tollgate_ca.clone(), &Config::default(), None);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    let target = format!("localhost:{}", origin.port());
    let tcp = connect(proxy.addr, &target).await;
    let tls = tls(tcp, tls_config(&[&tollgate_ca], &[b"h2"]), "localhost")
        .await
        .unwrap();
    let mut sender = http2(tls).await;
    // No response: the stream is refused and the connection closes, so the client retries
    // on a new CONNECT, which is passed through.
    let error = sender
        .send_request(get(&format!("https://localhost:{}/", origin.port()), &[]))
        .await
        .unwrap_err();
    assert_eq!(reset_reason(&error), Some(h2::Reason::REFUSED_STREAM));
    assert_eq!(learned(&proxy), ["localhost"]);
    wait_for("the connection to close", || sender.is_closed()).await;
}

#[tokio::test]
async fn a_server_asking_for_an_optional_client_certificate_stays_intercepted() {
    for versions in [&[&TLS12], &[&TLS13]] {
        let origin_ca = ca("Origin CA");
        let origin = tls_origin::https_with(
            origin_ca.clone(),
            &[b"h2", b"http/1.1"],
            versions,
            ClientAuth::Optional,
        )
        .await;
        let proxy = start(&origin_ca).await;
        for _ in 0..2 {
            assert_eq!(status_via(&proxy, origin.port()).await, StatusCode::OK);
        }
        assert!(learned(&proxy).is_empty());
    }
}

/// A server that asks for an optional client certificate proves over TLS 1.2 that it does
/// not require one, and over TLS 1.3 sends no alert when it drops a request for another
/// reason: neither is learned.
#[tokio::test]
async fn a_server_asking_for_an_optional_client_certificate_that_hangs_up_is_not_learned() {
    for versions in [&[&TLS12], &[&TLS13]] {
        for alpn in [&b"http/1.1"[..], b"h2"] {
            for how in [HangUp::CloseNotify, HangUp::Reset] {
                let origin_ca = ca("Origin CA");
                let origin = tls_origin::hang_up(
                    origin_ca.clone(),
                    &[alpn],
                    versions,
                    ClientAuth::Optional,
                    how,
                )
                .await;
                let tollgate_ca = ca("Tollgate Test CA");
                let ctx = proxy::context(tollgate_ca.clone(), &Config::default(), None);
                let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
                let case = format!("{versions:?} {:?} {how:?}", String::from_utf8_lossy(alpn));
                // Absolute form: no response (the server hung up), or 502.
                let tcp = TcpStream::connect(proxy.addr).await.unwrap();
                let url = format!("https://localhost:{}/", origin.port());
                let host = format!("localhost:{}", origin.port());
                let request = get(&url, &[("host", &host)]);
                if let Ok(response) = http1(tcp).await.send_request(request).await {
                    assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{case}");
                }
                assert!(learned(&proxy).is_empty(), "{case}");
                // Intercepted: no response, or 502.
                let target = format!("localhost:{}", origin.port());
                let tcp = connect(proxy.addr, &target).await;
                let tls = tls(tcp, tls_config(&[&tollgate_ca], &[b"h2"]), "localhost")
                    .await
                    .unwrap();
                let url = format!("https://localhost:{}/", origin.port());
                if let Ok(response) = http2(tls).await.send_request(get(&url, &[])).await {
                    assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{case}");
                }
                assert_eq!(origin.requests(), 2, "{case}");
                assert!(learned(&proxy).is_empty(), "{case}");
            }
        }
    }
}

#[tokio::test]
async fn a_closed_port_is_still_not_learned() {
    let proxy = start(&ca("Origin CA")).await;
    let port = origin::closed_port().await;
    let response = proxy_get_raw(proxy.addr, &format!("https://localhost:{port}/")).await;
    assert_eq!(String::from_utf8_lossy(&response), "");
    assert!(learned(&proxy).is_empty());
}

/// IIS resets a request's stream with HTTP_1_1_REQUIRED when it needs HTTP/1.1, for
/// Windows authentication or a client certificate. The pool cannot carry that
/// connection-bound state, so the host is passed through and the client falls back to
/// HTTP/1.1 itself; the reason is passed on to it. Other resets are not learned.
#[tokio::test]
async fn an_http2_server_that_requires_http1_is_learned() {
    for (reason, learn) in [
        (h2::Reason::HTTP_1_1_REQUIRED, true),
        (h2::Reason::PROTOCOL_ERROR, false),
        (h2::Reason::REFUSED_STREAM, false),
    ] {
        let origin_ca = ca("Origin CA");
        let origin = tls_origin::h2_reset(origin_ca.clone(), reason).await;
        let tollgate_ca = ca("Tollgate Test CA");
        let ctx = proxy::context(tollgate_ca.clone(), &Config::default(), None);
        let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
        let target = format!("localhost:{}", origin.port());
        let tcp = connect(proxy.addr, &target).await;
        let tls = tls(tcp, tls_config(&[&tollgate_ca], &[b"h2"]), "localhost")
            .await
            .unwrap();
        let mut sender = http2(tls).await;
        let url = format!("https://localhost:{}/", origin.port());
        let result = sender.send_request(get(&url, &[])).await;
        let decision = proxy.ctx.policy.classify("localhost", unix_secs());
        if learn {
            let error = result.expect_err("no response");
            assert_eq!(reset_reason(&error), Some(reason));
            assert_eq!(
                decision,
                Decision::Passthrough(PassthroughReason::LearnedPin)
            );
            wait_for("the connection to close", || sender.is_closed()).await;
        } else {
            assert_eq!(decision, Decision::Intercept, "{reason:?}");
            assert!(learned(&proxy).is_empty(), "{reason:?}");
        }
    }
}
