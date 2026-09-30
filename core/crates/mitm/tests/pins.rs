//! Pin learning: only TLS alerts that reject our certificate count, and two of them within
//! ten minutes make the host a learned pin that is passed through from then on.

mod support;

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tollgate_mitm::CertAuthority;
use tollgate_policy::{Config, Decision, PassthroughReason};

use support::client::{get, http1, read_to_close, send1, wait_for};
use support::tunnel::{connect, peer_issuer, tls, tls_config};
use support::{proxy, tls_origin};

const ORIGIN: &str = "CN=Origin CA, O=Tollgate";

struct Setup {
    ca: Arc<CertAuthority>,
    origin_ca: Arc<CertAuthority>,
    origin: support::origin::Origin,
    proxy: proxy::TestProxy,
}

impl Setup {
    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.origin.port())
    }

    fn classify(&self, host: &str) -> Decision {
        let now = tollgate_common::clock::unix_secs();
        self.proxy.ctx.policy.classify(host, now)
    }
}

async fn setup(idle_timeout: Duration) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let ctx = proxy::context(ca.clone(), &Config::default(), None);
    let mut options = tls_origin::trusting(&origin_ca);
    options.idle_timeout = idle_timeout;
    let proxy = proxy::start(ctx, options).await;
    Setup {
        ca,
        origin_ca,
        origin,
        proxy,
    }
}

#[tokio::test]
async fn two_certificate_rejections_make_a_learned_pin() {
    let s = setup(Duration::from_secs(60)).await;
    // Like a pinning app: it trusts only the real origin's CA.
    let pinned = tls_config(&[&s.origin_ca], &[b"h2", b"http/1.1"]);

    for attempt in 1..=2 {
        let tcp = connect(s.proxy.addr, &s.target()).await;
        let error = tls(tcp, pinned.clone(), "app.tollgate.test")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("UnknownIssuer"), "{error}");
        wait_for("the rejection to be recorded", || {
            s.proxy.stats().tls_client_rejections == attempt
        })
        .await;
    }

    assert_eq!(
        s.classify("app.tollgate.test"),
        Decision::Passthrough(PassthroughReason::LearnedPin)
    );
    assert!(
        s.proxy
            .ctx
            .policy
            .learned_pins_json()
            .contains("\"host\":\"app.tollgate.test\"")
    );
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, pinned, "app.tollgate.test").await.unwrap();
    assert_eq!(peer_issuer(&tls), ORIGIN);
    assert_eq!(s.classify("other.tollgate.test"), Decision::Intercept);
}

#[tokio::test]
async fn closing_after_the_handshake_is_only_counted() {
    let s = setup(Duration::from_secs(60)).await;
    let trusted = tls_config(&[&s.ca], &[b"h2", b"http/1.1"]);

    for attempt in 1..=3 {
        let tcp = connect(s.proxy.addr, &s.target()).await;
        let tls = tls(tcp, trusted.clone(), "quiet.tollgate.test")
            .await
            .unwrap();
        drop(tls);
        wait_for("the abandoned connection to be counted", || {
            s.proxy.stats().tls_abandoned_after_handshake == attempt
        })
        .await;
    }

    assert_eq!(s.proxy.stats().tls_client_rejections, 0);
    assert_eq!(s.classify("quiet.tollgate.test"), Decision::Intercept);
}

#[tokio::test]
async fn connections_that_made_a_request_are_not_abandoned() {
    let s = setup(Duration::from_secs(60)).await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.ca], &[b"http/1.1"]);
    let tls = tls(tcp, config, "www.tollgate.test").await.unwrap();
    let mut h1 = http1(tls).await;
    let reply = send1(&mut h1, get("/", &[("host", "www.tollgate.test")])).await;
    assert_eq!(reply.status, 200);
    drop(h1);

    wait_for("the origin request", || s.origin.requests() == 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.proxy.stats().tls_abandoned_after_handshake, 0);
}

#[tokio::test]
async fn idle_timeout_is_not_counted_as_abandoned() {
    let s = setup(Duration::from_millis(200)).await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let config = tls_config(&[&s.ca], &[b"h2"]);
    let mut tls = tls(tcp, config, "www.tollgate.test").await.unwrap();

    let closed = read_to_close(&mut tls, Duration::from_secs(5)).await;
    assert!(closed.is_some(), "closed by the idle timeout");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(s.proxy.stats().tls_abandoned_after_handshake, 0);
}

#[tokio::test]
async fn handshake_failures_that_are_not_rejections_do_not_count() {
    let s = setup(Duration::from_secs(60)).await;
    // TLS 1.2 with an RSA-only cipher suite: our ECDSA leaf cannot serve it.
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(s.ca.cert_der())).unwrap();
    let incompatible = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    for _ in 0..2 {
        let tcp = connect(s.proxy.addr, &s.target()).await;
        let error = tls(tcp, incompatible.clone(), "old.tollgate.test")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("HandshakeFailure"), "{error}");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.proxy.stats().tls_client_rejections, 0);
    assert_eq!(s.classify("old.tollgate.test"), Decision::Intercept);
}
