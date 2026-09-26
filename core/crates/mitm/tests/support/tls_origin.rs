//! A local TLS origin with its own CA, and proxy options that trust it.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tollgate_mitm::{CertAuthority, ServeOptions};

use super::origin::{Counters, Live, Origin, serve_http};

/// Presents a leaf from the origin's CA for whatever name the client sends, and for
/// 127.0.0.1 when it sends none.
#[derive(Debug)]
struct AnyName(Arc<CertAuthority>);

impl ResolvesServerCert for AnyName {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.leaf(hello.server_name().unwrap_or("127.0.0.1")).ok()
    }
}

/// Whether a TLS origin asks for a client certificate.
#[derive(Clone, Copy, Debug)]
pub enum ClientAuth {
    None,
    /// Asks, and accepts a client without one.
    Optional,
    /// Asks, and fails the connection without one.
    Required,
}

/// A TLS origin on 127.0.0.1 with certificates from `ca`, offering `alpn`.
pub async fn https(ca: Arc<CertAuthority>, alpn: &[&[u8]]) -> Origin {
    https_with(ca, alpn, rustls::DEFAULT_VERSIONS, ClientAuth::None).await
}

/// [`https`] limited to `versions`, asking for client certificates as `client_auth` says.
pub async fn https_with(
    ca: Arc<CertAuthority>,
    alpn: &[&[u8]],
    versions: &[&'static SupportedProtocolVersion],
    client_auth: ClientAuth,
) -> Origin {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.cert_der())).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    let builder = match client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Optional => {
            builder.with_client_cert_verifier(verifier.allow_unauthenticated().build().unwrap())
        }
        ClientAuth::Required => builder.with_client_cert_verifier(verifier.build().unwrap()),
    };
    let mut config = builder.with_cert_resolver(Arc::new(AnyName(ca)));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counters = Arc::new(Counters::default());
    let shared = counters.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let live = Live::new(&shared);
            let conn = shared.connections.load(Ordering::SeqCst);
            let counters = shared.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _live = live;
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_http(tls, conn, counters).await;
                }
            });
        }
    });
    Origin { addr, counters }
}

/// A server on 127.0.0.1 that answers every ClientHello with the fatal TLS alert
/// `description` (for example 40, handshake_failure, as a server with no cipher suite in
/// common sends) and closes.
pub async fn tls_alert(description: u8) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counters = Arc::new(Counters::default());
    let shared = counters.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            shared.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut hello = [0u8; 512];
                let _ = tcp.read(&mut hello).await;
                let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description];
                let _ = tcp.write_all(&alert).await;
                let _ = tcp.shutdown().await;
            });
        }
    });
    Origin { addr, counters }
}

/// Production options, except that upstream TLS trusts only `origin_ca`.
pub fn trusting(origin_ca: &CertAuthority) -> ServeOptions {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(origin_ca.cert_der()))
        .unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    ServeOptions {
        upstream_tls: Arc::new(config),
        ..ServeOptions::default()
    }
}
