//! A client that opens `CONNECT` tunnels through the proxy and speaks TLS inside them.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::Request;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tollgate_mitm::CertAuthority;

use super::client::{Reply, read_reply};

pub type Sender2 = http2::SendRequest<Empty<Bytes>>;

/// Sends `CONNECT target` and returns the status code and the stream after the response
/// headers. Reads byte by byte so nothing after the headers is consumed.
pub async fn connect_status(proxy: SocketAddr, target: &str) -> (u16, TcpStream) {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, tcp)
}

/// `CONNECT target`, expecting `200`.
pub async fn connect(proxy: SocketAddr, target: &str) -> TcpStream {
    let (status, tcp) = connect_status(proxy, target).await;
    assert_eq!(status, 200, "CONNECT {target}");
    tcp
}

/// A client configuration trusting only `roots`, offering `alpn`.
pub fn tls_config(roots: &[&CertAuthority], alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for ca in roots {
        store.add(CertificateDer::from(ca.cert_der())).unwrap();
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// TLS over `io`. An IP address as `server_name` sends no SNI.
pub async fn tls<T>(
    io: T,
    config: Arc<ClientConfig>,
    server_name: &str,
) -> std::io::Result<TlsStream<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(server_name.to_string()).unwrap();
    TlsConnector::from(config).connect(name, io).await
}

/// The issuer of the certificate the server presented, for example `CN=..., O=Tollgate`.
pub fn peer_issuer<T>(tls: &TlsStream<T>) -> String {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let chain = tls.get_ref().1.peer_certificates().unwrap();
    let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
    cert.issuer().to_string()
}

/// CONNECTs to `target`, completes TLS trusting `roots` and returns the issuer of the
/// certificate the client saw: the Tollgate CA when intercepted, the origin's otherwise.
pub async fn issuer_via(
    proxy: SocketAddr,
    target: &str,
    roots: &[&CertAuthority],
    name: &str,
) -> String {
    let tcp = connect(proxy, target).await;
    let config = tls_config(roots, &[b"h2", b"http/1.1"]);
    peer_issuer(&tls(tcp, config, name).await.unwrap())
}

/// The ALPN protocol the server chose.
pub fn alpn<T>(tls: &TlsStream<T>) -> Option<Vec<u8>> {
    tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
}

pub async fn http2<T>(io: T) -> Sender2
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Like Safari, accept far larger response headers than hyper's 16 KiB default.
    let (sender, conn) = http2::Builder::new(TokioExecutor::new())
        .max_header_list_size(1024 * 1024)
        .handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

pub async fn send2(sender: &mut Sender2, request: Request<Empty<Bytes>>) -> Reply {
    read_reply(sender.send_request(request).await.unwrap()).await
}

/// The reason of the HTTP/2 stream reset or GOAWAY behind a failed request, if any.
pub fn reset_reason(error: &hyper::Error) -> Option<h2::Reason> {
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = next {
        if let Some(h2) = error.downcast_ref::<h2::Error>() {
            return h2.reason();
        }
        next = error.source();
    }
    None
}
