//! Bodies through intercepted connections: request bodies reach the origin intact across
//! the HTTP/2 and HTTP/1.1 conversion, and response bodies stream with backpressure
//! instead of being buffered whole.

mod support;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::{Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tollgate_mitm::CertAuthority;
use tollgate_policy::Config;

use support::client::read_reply;
use support::origin::{digest_line, pattern_byte};
use support::tunnel::{alpn, connect, tls, tls_config};
use support::{proxy, tls_origin};

const NAME: &str = "www.tollgate.test";
const UPLOAD: usize = 1024 * 1024;
const BIG: usize = 8 * 1024 * 1024;
const FIRST_READ: usize = 64 * 1024;

struct Setup {
    ca: Arc<CertAuthority>,
    origin: support::origin::Origin,
    proxy: proxy::TestProxy,
}

impl Setup {
    fn url(&self, path: &str) -> String {
        format!("https://{NAME}:{}{path}", self.origin.port())
    }

    /// An intercepted TLS connection to the origin, offering `protocols`.
    async fn client(&self, protocols: &[&[u8]]) -> TlsStream<TcpStream> {
        let target = format!("127.0.0.1:{}", self.origin.port());
        let tcp = connect(self.proxy.addr, &target).await;
        let tls = tls(tcp, tls_config(&[&self.ca], protocols), NAME)
            .await
            .unwrap();
        assert_eq!(alpn(&tls).as_deref(), Some(protocols[0]));
        tls
    }
}

/// A TLS origin offering only `protocols`, behind a proxy that intercepts everything.
async fn setup(protocols: &[&[u8]]) -> Setup {
    let ca = Arc::new(CertAuthority::generate("Tollgate Test CA").unwrap());
    let origin_ca = Arc::new(CertAuthority::generate("Origin CA").unwrap());
    let origin = tls_origin::https(origin_ca.clone(), protocols).await;
    let ctx = proxy::context(ca.clone(), &Config::default(), None);
    let proxy = proxy::start(ctx, tls_origin::trusting(&origin_ca)).await;
    Setup { ca, origin, proxy }
}

fn upload() -> Bytes {
    (0..UPLOAD).map(|i| (i * 7 % 256) as u8).collect()
}

/// Reads data frames until at least `limit` bytes have arrived (all of them for
/// `usize::MAX`), checking each byte against the origin's pattern from `offset` on.
/// Returns the number of bytes read.
async fn read_body(body: &mut Incoming, offset: usize, limit: usize) -> usize {
    let mut read = 0;
    while read < limit {
        let Some(frame) = body.frame().await else {
            break;
        };
        if let Ok(data) = frame.unwrap().into_data() {
            for (i, byte) in data.iter().enumerate() {
                assert_eq!(
                    *byte,
                    pattern_byte(offset + read + i),
                    "byte {}",
                    offset + read + i
                );
            }
            read += data.len();
        }
    }
    read
}

#[tokio::test]
async fn a_post_body_crosses_from_an_http2_client_to_an_http1_origin() {
    let s = setup(&[b"http/1.1"]).await;
    let tls = s.client(&[b"h2"]).await;
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);

    let data = upload();
    let request = Request::post(s.url("/echo"))
        .body(Full::new(data.clone()))
        .unwrap();
    let reply = read_reply(sender.send_request(request).await.unwrap()).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, digest_line(&data));
    assert_eq!(s.origin.requests(), 1);
}

#[tokio::test]
async fn a_post_body_crosses_from_an_http1_client_to_an_http2_origin() {
    let s = setup(&[b"h2"]).await;
    let tls = s.client(&[b"http/1.1"]).await;
    let (mut sender, conn) = http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);

    let data = upload();
    let request = Request::post("/echo")
        .header("host", NAME)
        .body(Full::new(data.clone()))
        .unwrap();
    let reply = read_reply(sender.send_request(request).await.unwrap()).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, digest_line(&data));
    assert_eq!(s.origin.requests(), 1);
}

/// Reads 64 KiB of an 8 MiB body, pauses, and returns how many bytes the origin had
/// produced by then and how many the kernel held in the sockets on `ports`; then reads the
/// rest and checks it.
async fn read_with_a_pause(
    s: &Setup,
    response: hyper::Response<Incoming>,
    ports: &[u16],
) -> (usize, usize) {
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = read_body(&mut body, 0, FIRST_READ).await;
    assert!(first >= FIRST_READ);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let produced = s.origin.produced() - first;
    let in_kernel = kernel_queued(ports);

    let rest = read_body(&mut body, first, usize::MAX).await;
    assert_eq!(first + rest, BIG);
    assert_eq!(s.origin.produced(), BIG);
    (produced, in_kernel)
}

/// Bytes queued in the kernel (send and receive queues) of TCP sockets whose local or
/// remote port is one of `ports`, from `/proc/net/tcp`. 0 where that file does not exist.
fn kernel_queued(ports: &[u16]) -> usize {
    let hex = |field: &str| usize::from_str_radix(field, 16).unwrap();
    let mut total = 0;
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let port = |address: &str| hex(address.rsplit(':').next().unwrap()) as u16;
            if !ports.contains(&port(fields[1])) && !ports.contains(&port(fields[2])) {
                continue;
            }
            let (tx, rx) = fields[4].split_once(':').unwrap();
            total += hex(tx) + hex(rx);
        }
    }
    total
}

#[tokio::test]
async fn a_large_response_streams_to_an_http2_client_with_backpressure() {
    let s = setup(&[b"h2"]).await;
    let tls = s.client(&[b"h2"]).await;
    // The client's own windows are small, so what it has not read stays upstream of it.
    let (mut sender, conn) = http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(FIRST_READ as u32)
        .initial_connection_window_size(FIRST_READ as u32)
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);

    let request = Request::get(s.url(&format!("/big?bytes={BIG}")))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let ports = [s.origin.port(), s.proxy.addr.port()];
    let (produced, _) = read_with_a_pause(&s, response, &ports).await;
    // Flow control bounds every buffer on the way, the kernel's included.
    assert!(
        produced < 2 * 1024 * 1024,
        "the origin produced {produced} bytes more than the client read"
    );
}

/// HTTP/1.1 has no flow control of its own, so on loopback the kernel's socket buffers
/// (autotuned up to several MiB) take much of the body. What the kernel holds is
/// subtracted; the rest is what the origin, the proxy and the client hold in memory.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_large_response_streams_to_an_http1_client_with_backpressure() {
    let s = setup(&[b"http/1.1"]).await;
    let tls = s.client(&[b"http/1.1"]).await;
    let (mut sender, conn) = http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);

    let request = Request::get(format!("/big?bytes={BIG}"))
        .header("host", NAME)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let ports = [s.origin.port(), s.proxy.addr.port()];
    let (produced, in_kernel) = read_with_a_pause(&s, response, &ports).await;
    let in_memory = produced.saturating_sub(in_kernel);
    assert!(
        in_memory < 1024 * 1024,
        "{in_memory} bytes held in memory ({produced} unread, {in_kernel} in the kernel)"
    );
}
