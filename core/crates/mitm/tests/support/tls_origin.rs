//! A local TLS origin with its own CA, and proxy options that trust it.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;

use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
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
    let acceptor = acceptor(ca, alpn, versions, client_auth);
    serve_tls(acceptor, |tls, conn, counters| async move {
        serve_http(tls, conn, counters).await;
    })
    .await
}

/// How [`hang_up`] ends a connection.
#[derive(Clone, Copy, Debug)]
pub enum HangUp {
    /// TLS close_notify, then FIN.
    CloseNotify,
    /// A TCP reset (`SO_LINGER` 0), without close_notify.
    Reset,
}

/// A TLS origin like [`https_with`] that reads the request and then closes the connection
/// as `how` says, without answering, as a server or a firewall that drops a request does.
pub async fn hang_up(
    ca: Arc<CertAuthority>,
    alpn: &[&[u8]],
    versions: &[&'static SupportedProtocolVersion],
    client_auth: ClientAuth,
    how: HangUp,
) -> Origin {
    let acceptor = acceptor(ca, alpn, versions, client_auth);
    serve_tls(acceptor, move |mut tls, _, counters| async move {
        // The request, and for HTTP/2 the preface and settings before it: read until the
        // client has been quiet for a moment.
        let mut buf = [0u8; 16 * 1024];
        let mut read = 0;
        loop {
            match tokio::time::timeout(Duration::from_millis(200), tls.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => read += n,
                Ok(_) => return,
                Err(_) if read > 0 => break,
                Err(_) => {}
            }
        }
        counters.requests.fetch_add(1, Ordering::SeqCst);
        match how {
            HangUp::CloseNotify => {
                let _ = tls.shutdown().await;
            }
            HangUp::Reset => {
                let (tcp, _) = tls.into_inner();
                let _ = tcp.set_zero_linger();
            }
        }
    })
    .await
}

/// A TLS origin like [`https`] whose server fails every request: HTTP/2 resets the stream
/// (INTERNAL_ERROR) before any response headers, HTTP/1.1 closes the connection.
pub async fn failing(ca: Arc<CertAuthority>, alpn: &[&[u8]]) -> Origin {
    let acceptor = acceptor(ca, alpn, rustls::DEFAULT_VERSIONS, ClientAuth::None);
    serve_tls(acceptor, |tls, _, counters| async move {
        let service = service_fn(move |_: Request<Incoming>| {
            counters.requests.fetch_add(1, Ordering::SeqCst);
            async { Err::<Response<Empty<Bytes>>, _>(std::io::Error::other("refused")) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls), service)
            .await;
    })
    .await
}

fn acceptor(
    ca: Arc<CertAuthority>,
    alpn: &[&[u8]],
    versions: &[&'static SupportedProtocolVersion],
    client_auth: ClientAuth,
) -> TlsAcceptor {
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
    TlsAcceptor::from(Arc::new(config))
}

/// Accepts TLS connections on 127.0.0.1 with `acceptor` and hands each to `serve` with its
/// connection number.
async fn serve_tls<F, Fut>(acceptor: TlsAcceptor, serve: F) -> Origin
where
    F: Fn(TlsStream<TcpStream>, usize, Arc<Counters>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
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
            let serve = serve.clone();
            tokio::spawn(async move {
                let _live = live;
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve(tls, conn, counters).await;
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
