//! Silent refusals: a client that hangs up during the handshake after our certificate
//! reached it, without an alert, as the X app for iOS does when it pins. Each way a client
//! can end the handshake is told apart, and the policy learns a pin from silent refusals
//! only under its own rule (see `tollgate_policy::Policy::record_silent_refusal`).

mod support;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, NamedGroup, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tollgate_mitm::CertAuthority;
use tollgate_policy::{Config, Decision, PassthroughReason};

use support::client::{get, http1, read_to_close, send1, wait_for};
use support::tunnel::{connect, peer_issuer, tls, tls_config};
use support::{proxy, tls_origin};

const ORIGIN: &str = "CN=Origin CA, O=Tollgate";
const TLS_APPLICATION_DATA: u8 = 23;

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

    /// A client that trusts the proxy's CA, like a browser once the Tollgate certificate
    /// is trusted.
    fn trusting(&self) -> Arc<ClientConfig> {
        tls_config(&[&self.ca], &[b"h2", b"http/1.1"])
    }

    /// Waits until the proxy has intercepted `n` connections in all, then a moment for the
    /// last handshake to end, so a counter that stays unchanged can be checked.
    async fn settle(&self, n: u64) {
        wait_for("the connection to be intercepted", || {
            self.proxy.stats().connections_intercepted == n
        })
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn setup() -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), &[b"h2", b"http/1.1"]).await;
    let ctx = proxy::context(ca.clone(), &Config::default(), None);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    Setup {
        ca,
        origin_ca,
        origin,
        proxy,
    }
}

/// How far into the proxy's answer a client goes before it hangs up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Until {
    /// Reads the first record of the answer only: the ServerHello, or a HelloRetryRequest.
    FirstRecord,
    /// Reads and checks the whole flight, certificate included, and sends nothing more: a
    /// client whose own certificate check cancels the connection.
    Flight,
    /// Reads the whole flight but processes it only up to the ServerHello, so it holds the
    /// handshake keys and can still send an encrypted alert.
    FlightUnread,
}

/// Opens a `CONNECT` tunnel, sends a ClientHello for `name` with `config` and follows the
/// proxy's answer `until` the point given, answering a HelloRetryRequest on the way.
/// Returns the tunnel and the client's TLS state.
async fn start_handshake(
    s: &Setup,
    config: Arc<ClientConfig>,
    name: &str,
    until: Until,
) -> (TcpStream, ClientConnection) {
    let mut tcp = connect(s.proxy.addr, &s.target()).await;
    let name = ServerName::try_from(name.to_string()).unwrap();
    let mut client = ClientConnection::new(config, name).unwrap();
    send_pending(&mut tcp, &mut client).await;
    loop {
        let record = read_record(&mut tcp).await;
        if until == Until::FlightUnread && record[0] == TLS_APPLICATION_DATA {
            return (tcp, client);
        }
        client.read_tls(&mut record.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        if until == Until::FirstRecord || client.peer_certificates().is_some() {
            // What the client would send next (its Finished, or with TLS 1.2 its key
            // exchange) is never sent.
            return (tcp, client);
        }
        send_pending(&mut tcp, &mut client).await;
    }
}

/// Writes what the client has to send: a ClientHello, or a ChangeCipherSpec.
async fn send_pending(tcp: &mut TcpStream, client: &mut ClientConnection) {
    let mut out = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut out).unwrap();
    }
    tcp.write_all(&out).await.unwrap();
}

/// Reads one TLS record, header included.
async fn read_record(tcp: &mut TcpStream) -> Vec<u8> {
    let mut record = vec![0; 5];
    let read = tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut record)).await;
    read.expect("the proxy answered in time").unwrap();
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + len, 0);
    tcp.read_exact(&mut record[5..]).await.unwrap();
    record
}

/// Closes `tcp` with a reset instead of a FIN.
fn reset(tcp: TcpStream) {
    #[allow(deprecated)]
    tcp.set_linger(Some(Duration::ZERO)).unwrap();
    drop(tcp);
}

/// A key exchange group the proxy does not support, offered first, so the proxy answers
/// with a HelloRetryRequest for one it does. The X app offers X25519MLKEM768 first.
#[derive(Debug)]
struct UnsupportedGroup;

struct UnsupportedShare(Vec<u8>);

impl SupportedKxGroup for UnsupportedGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(UnsupportedShare(vec![7; 1216])))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

impl ActiveKeyExchange for UnsupportedShare {
    fn complete(self: Box<Self>, _: &[u8]) -> Result<SharedSecret, rustls::Error> {
        Err(rustls::Error::General("never negotiated".into()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.0
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// Like the X app: offers a key share the proxy does not support first, so the handshake
/// goes through a HelloRetryRequest, and checks the certificate against `roots` only.
fn x_like(roots: &[&CertAuthority]) -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups.insert(0, &UnsupportedGroup);
    let mut store = rustls::RootCertStore::empty();
    for ca in roots {
        store.add(CertificateDer::from(ca.cert_der())).unwrap();
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Accepts any certificate, so a test client can read the proxy's whole flight and then
/// hang up, as a pinning app does when its own check fails.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS 1.2 client that accepts any certificate.
fn tls12_accepting_any() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Sleeps into the next wall-clock second, so the next refusal falls in a second of its
/// own.
async fn next_second() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let into = Duration::from_nanos(u64::from(now.subsec_nanos()));
    tokio::time::sleep(Duration::from_secs(1) - into + Duration::from_millis(50)).await;
}

#[tokio::test]
async fn an_alert_is_a_rejection_not_a_silent_refusal() {
    let s = setup().await;
    let pinned = tls_config(&[&s.origin_ca], &[b"h2", b"http/1.1"]);
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let error = tls(tcp, pinned, "app.tollgate.test").await.unwrap_err();
    assert!(error.to_string().contains("UnknownIssuer"), "{error}");
    wait_for("the rejection", || {
        s.proxy.stats().tls_client_rejections == 1
    })
    .await;
    s.settle(1).await;
    assert_eq!(s.proxy.stats().tls_silent_refusals, 0);
}

#[tokio::test]
async fn hanging_up_after_the_certificate_is_a_silent_refusal() {
    let s = setup().await;
    let (tcp, _) = start_handshake(&s, s.trusting(), "app.tollgate.test", Until::Flight).await;
    drop(tcp);
    wait_for("the silent refusal", || {
        s.proxy.stats().tls_silent_refusals == 1
    })
    .await;
    let stats = s.proxy.stats();
    assert_eq!(stats.tls_client_rejections, 0);
    assert_eq!(stats.tls_abandoned_after_handshake, 0);
    // One refusal teaches nothing yet.
    assert_eq!(s.classify("app.tollgate.test"), Decision::Intercept);
}

#[tokio::test]
async fn a_reset_after_the_certificate_is_a_silent_refusal() {
    let s = setup().await;
    let (tcp, _) = start_handshake(&s, s.trusting(), "app.tollgate.test", Until::Flight).await;
    reset(tcp);
    wait_for("the silent refusal", || {
        s.proxy.stats().tls_silent_refusals == 1
    })
    .await;
    assert_eq!(s.proxy.stats().tls_client_rejections, 0);
}

#[tokio::test]
async fn close_notify_during_the_handshake_is_a_silent_refusal() {
    let s = setup().await;
    let config = s.trusting();
    let (mut tcp, mut client) =
        start_handshake(&s, config, "app.tollgate.test", Until::FlightUnread).await;
    client.send_close_notify();
    send_pending(&mut tcp, &mut client).await;
    wait_for("the silent refusal", || {
        s.proxy.stats().tls_silent_refusals == 1
    })
    .await;
    assert_eq!(s.proxy.stats().tls_client_rejections, 0);
    drop(tcp);
}

#[tokio::test]
async fn a_tls12_client_hanging_up_after_the_certificate_is_a_silent_refusal() {
    let s = setup().await;
    let config = tls12_accepting_any();
    let (tcp, _) = start_handshake(&s, config, "app.tollgate.test", Until::Flight).await;
    drop(tcp);
    wait_for("the silent refusal", || {
        s.proxy.stats().tls_silent_refusals == 1
    })
    .await;
}

#[tokio::test]
async fn hanging_up_before_the_certificate_is_not_counted() {
    let s = setup().await;

    // Closes right after its ClientHello, before the proxy answered.
    let mut tcp = connect(s.proxy.addr, &s.target()).await;
    let name = ServerName::try_from("app.tollgate.test").unwrap();
    let mut client = ClientConnection::new(s.trusting(), name).unwrap();
    send_pending(&mut tcp, &mut client).await;
    tcp.shutdown().await.unwrap();
    assert!(
        read_to_close(&mut tcp, Duration::from_secs(5))
            .await
            .is_some()
    );
    s.settle(1).await;

    // Hangs up after a HelloRetryRequest, which carries no certificate.
    let config = x_like(&[&s.ca]);
    let (mut tcp, client) =
        start_handshake(&s, config.clone(), "app.tollgate.test", Until::FirstRecord).await;
    assert!(client.wants_write(), "a second ClientHello is due");
    drop(client);
    tcp.shutdown().await.unwrap();
    s.settle(2).await;
    let (tcp, _) = start_handshake(&s, config, "app.tollgate.test", Until::FirstRecord).await;
    reset(tcp);
    s.settle(3).await;

    let stats = s.proxy.stats();
    assert_eq!(stats.tls_silent_refusals, 0);
    assert_eq!(stats.tls_client_rejections, 0);
}

#[tokio::test]
async fn a_completed_handshake_then_closed_is_not_a_refusal() {
    let s = setup().await;
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, s.trusting(), "www.tollgate.test").await.unwrap();
    drop(tls);
    wait_for("the abandoned connection", || {
        s.proxy.stats().tls_abandoned_after_handshake == 1
    })
    .await;
    let stats = s.proxy.stats();
    assert_eq!(stats.tls_silent_refusals, 0);
    assert_eq!(stats.tls_client_rejections, 0);
}

#[tokio::test]
async fn hanging_up_on_a_resumed_session_is_not_counted() {
    let s = setup().await;
    let host = "www.tollgate.test";
    // A full handshake and a request, whose response brings the session tickets along.
    let config = s.trusting();
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let mut h1 = http1(tls(tcp, config.clone(), host).await.unwrap()).await;
    assert_eq!(
        send1(&mut h1, get("/", &[("host", host)])).await.status,
        200
    );
    drop(h1);

    // Resumed: the proxy sends no certificate, so hanging up refuses nothing.
    let (tcp, _) = start_handshake(&s, config, host, Until::FlightUnread).await;
    drop(tcp);
    s.settle(2).await;
    assert_eq!(s.proxy.stats().tls_silent_refusals, 0);

    // The same without a session to resume is a silent refusal.
    let (tcp, _) = start_handshake(&s, s.trusting(), host, Until::FlightUnread).await;
    drop(tcp);
    wait_for("the silent refusal", || {
        s.proxy.stats().tls_silent_refusals == 1
    })
    .await;
}

#[tokio::test]
async fn an_x_like_app_is_learned_from_refusals_in_three_seconds() {
    let s = setup().await;
    let host = "api.tollgate.test";
    // Trusts only the real origin, and hangs up inside its certificate check.
    let config = x_like(&[&s.origin_ca]);
    for refusal in 1..=3 {
        next_second().await;
        let (tcp, _) = start_handshake(&s, config.clone(), host, Until::FlightUnread).await;
        drop(tcp);
        wait_for("the silent refusal", || {
            s.proxy.stats().tls_silent_refusals == refusal
        })
        .await;
        if refusal < 3 {
            assert_eq!(s.classify(host), Decision::Intercept);
        }
    }
    assert_eq!(
        s.classify(host),
        Decision::Passthrough(PassthroughReason::LearnedPin)
    );
    let json = s.proxy.ctx.policy.learned_pins_json();
    assert!(json.contains("\"host\":\"api.tollgate.test\""), "{json}");

    // Passed through from now on: the app sees the real certificate and trusts it.
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let tls = tls(tcp, config, host).await.unwrap();
    assert_eq!(peer_issuer(&tls), ORIGIN);
    assert_eq!(s.proxy.stats().tls_client_rejections, 0);
}

#[tokio::test]
async fn a_client_that_trusts_us_is_never_learned() {
    let s = setup().await;
    let host = "www.tollgate.test";
    // A browser completes a handshake for the site...
    let tcp = connect(s.proxy.addr, &s.target()).await;
    let _open = tls(tcp, s.trusting(), host).await.unwrap();
    // ...and hangs up other connections to it early, in three different seconds.
    for refusal in 1..=3 {
        next_second().await;
        let (tcp, _) = start_handshake(&s, s.trusting(), host, Until::Flight).await;
        drop(tcp);
        wait_for("the silent refusal", || {
            s.proxy.stats().tls_silent_refusals == refusal
        })
        .await;
    }
    assert_eq!(s.classify(host), Decision::Intercept);
    assert!(s.proxy.ctx.policy.learned_pins().is_empty());
}
