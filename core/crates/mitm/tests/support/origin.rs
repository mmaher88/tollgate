//! Local origin servers. Nothing here touches the network beyond 127.0.0.1.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

/// What an origin has seen so far.
#[derive(Default)]
pub struct Counters {
    pub connections: AtomicUsize,
    pub live: AtomicUsize,
    pub max_live: AtomicUsize,
    pub requests: AtomicUsize,
    /// Bytes of `/big` bodies handed to the server so far.
    pub produced: AtomicUsize,
}

pub struct Origin {
    pub addr: SocketAddr,
    pub counters: Arc<Counters>,
}

impl Origin {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn connections(&self) -> usize {
        self.counters.connections.load(Ordering::SeqCst)
    }

    pub fn live(&self) -> usize {
        self.counters.live.load(Ordering::SeqCst)
    }

    pub fn max_live(&self) -> usize {
        self.counters.max_live.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> usize {
        self.counters.requests.load(Ordering::SeqCst)
    }

    pub fn produced(&self) -> usize {
        self.counters.produced.load(Ordering::SeqCst)
    }
}

/// Chunk size of `/big` bodies.
pub const CHUNK: usize = 16 * 1024;

/// The bytes of `/big` bodies: byte `i` is `i % 251`.
pub fn pattern_byte(i: usize) -> u8 {
    (i % 251) as u8
}

/// `len=<n> sha256=<hex>` for `data`, as `/echo` answers.
pub fn digest_line(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut hex = String::new();
    for byte in digest.as_ref() {
        write!(hex, "{byte:02x}").unwrap();
    }
    format!("len={} sha256={hex}", data.len())
}

/// `/big` bodies: [`CHUNK`]-byte data frames made only when the server asks for the next
/// one, each counted in `produced` as it is handed over.
struct Chunks {
    sent: usize,
    total: usize,
    counters: Arc<Counters>,
}

impl Stream for Chunks {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.sent >= self.total {
            return Poll::Ready(None);
        }
        let len = CHUNK.min(self.total - self.sent);
        let chunk: Vec<u8> = (self.sent..self.sent + len).map(pattern_byte).collect();
        self.sent += len;
        self.counters.produced.fetch_add(len, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))))
    }
}

/// `/drip` bodies: a line right away, then another every `every`, never ending.
struct Drip {
    sent: usize,
    every: tokio::time::Interval,
}

impl Stream for Drip {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.every.poll_tick(cx).is_pending() {
            return Poll::Pending;
        }
        self.sent += 1;
        let line = format!("data: {}\n\n", self.sent);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(line)))))
    }
}

type OriginBody = BoxBody<Bytes, Infallible>;

fn full(text: impl Into<Bytes>) -> OriginBody {
    Full::new(text.into()).boxed()
}

/// `/echo`: reads the whole request body and answers with its [`digest_line`].
async fn echo(request: Request<Incoming>) -> Response<OriginBody> {
    match request.into_body().collect().await {
        Ok(body) => Response::new(full(digest_line(&body.to_bytes()))),
        Err(e) => {
            let mut response = Response::new(full(e.to_string()));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            response
        }
    }
}

/// `/big?bytes=N`: `N` bytes of [`pattern_byte`] in [`CHUNK`]-byte frames.
fn big(request: &Request<Incoming>, counters: Arc<Counters>) -> Response<OriginBody> {
    let total = request
        .uri()
        .query()
        .and_then(|q| q.strip_prefix("bytes="))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let chunks = Chunks {
        sent: 0,
        total,
        counters,
    };
    Response::new(StreamBody::new(chunks).boxed())
}

/// `/drip?every=<ms>`: a server-sent events stream that never ends, one event right away
/// and another every `ms` milliseconds (default one hour, so it holds after the first).
fn drip(request: &Request<Incoming>) -> Response<OriginBody> {
    let ms = request
        .uri()
        .query()
        .and_then(|q| q.strip_prefix("every="))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3_600_000);
    let drip = Drip {
        sent: 0,
        every: tokio::time::interval(Duration::from_millis(ms)),
    };
    let mut response = Response::new(StreamBody::new(drip).boxed());
    response
        .headers_mut()
        .insert("content-type", "text/event-stream".parse().unwrap());
    response
}

/// `/headers?count=N&size=S`: `N` `set-cookie` headers, each with an `S`-byte value.
fn headers(request: &Request<Incoming>) -> Response<OriginBody> {
    let query = request.uri().query().unwrap_or("");
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
    };
    let mut response = Response::new(full("headers"));
    for i in 0..param("count") {
        let value = format!("c{i}={}", "x".repeat(param("size")));
        response
            .headers_mut()
            .append("set-cookie", value.parse().unwrap());
    }
    response
}

/// Decrements `live` when a connection ends.
pub struct Live(Arc<Counters>);

impl Live {
    pub fn new(counters: &Arc<Counters>) -> Live {
        counters.connections.fetch_add(1, Ordering::SeqCst);
        let live = counters.live.fetch_add(1, Ordering::SeqCst) + 1;
        counters.max_live.fetch_max(live, Ordering::SeqCst);
        Live(counters.clone())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Answers `/echo` with [`echo`], `/big` with [`big`], `/headers` with [`headers`], `/drip`
/// with [`drip`], and
/// every other request with a line
/// describing it: `GET /path?q authority=host:port version=HTTP/1.1 conn=1 cookie=a=1|b=2`.
/// `?delay=<ms>` waits before answering.
async fn handle(
    conn: usize,
    counters: Arc<Counters>,
    request: Request<Incoming>,
) -> Result<Response<OriginBody>, Infallible> {
    counters.requests.fetch_add(1, Ordering::SeqCst);
    match request.uri().path() {
        "/echo" => return Ok(echo(request).await),
        "/big" => return Ok(big(&request, counters)),
        "/headers" => return Ok(headers(&request)),
        "/drip" => return Ok(drip(&request)),
        _ => {}
    }
    if let Some(ms) = request
        .uri()
        .query()
        .and_then(|q| q.strip_prefix("delay="))
        .and_then(|v| v.parse::<u64>().ok())
    {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    let authority = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let cookie = request
        .headers()
        .get_all("cookie")
        .iter()
        .map(|v| v.to_str().unwrap_or("?"))
        .collect::<Vec<_>>()
        .join("|");
    let line = format!(
        "{} {} authority={authority} version={:?} conn={conn} cookie={cookie}",
        request.method(),
        request.uri().path_and_query().map_or("/", |pq| pq.as_str()),
        request.version(),
    );
    Ok(Response::new(full(line)))
}

/// Serves HTTP/1.1 or HTTP/2 on `io` with [`handle`]. Like real servers, it accepts far
/// larger request headers than hyper's defaults.
pub async fn serve_http<T>(io: T, conn: usize, counters: Arc<Counters>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| handle(conn, counters.clone(), request));
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().max_headers(1000);
    builder.http2().max_header_list_size(1024 * 1024);
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(io), service)
        .await;
}

/// A plain HTTP origin on 127.0.0.1.
pub async fn http() -> Origin {
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
            tokio::spawn(async move {
                let _live = live;
                serve_http(tcp, conn, counters).await;
            });
        }
    });
    Origin { addr, counters }
}

/// A port with nothing listening on it.
pub async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}
