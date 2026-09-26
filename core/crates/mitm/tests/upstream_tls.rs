//! Upstream TLS failures that the client, talking to the server directly, would not have:
//! the host is learned as a pin and passed through from then on. Failures the client would
//! have too are not learned.

mod support;

use std::sync::Arc;

use hyper::StatusCode;
use rustls::SupportedProtocolVersion;
use rustls::version::{TLS12, TLS13};
use tollgate_mitm::CertAuthority;
use tollgate_policy::Config;

use support::client::{get, proxy_get};
use support::tls_origin::{self, ClientAuth, HangUp};
use support::tunnel::{connect, http2, peer_issuer, send2, tls, tls_config};
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
    let ctx = proxy::context(ca("Tollgate Test CA"), &Config::default(), None);
    proxy::start(ctx, tls_origin::trusting(origin_ca)).await
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
    let reply = send2(
        &mut sender,
        get(&format!("https://localhost:{}/", origin.port()), &[]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(learned(&proxy), ["localhost"]);
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
                // Absolute form: 502.
                assert_eq!(
                    status_via(&proxy, origin.port()).await,
                    StatusCode::BAD_GATEWAY,
                    "{case}"
                );
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
    assert_eq!(status_via(&proxy, port).await, StatusCode::BAD_GATEWAY);
    assert!(learned(&proxy).is_empty());
}
