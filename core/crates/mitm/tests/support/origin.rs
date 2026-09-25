//! Local origin servers. Nothing here touches the network beyond 127.0.0.1.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Request, Response};
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

/// Answers every request with a line describing it:
/// `GET /path?q authority=host:port version=HTTP/1.1 conn=1 cookie=a=1|b=2`.
/// `?delay=<ms>` waits before answering.
async fn handle(
    conn: usize,
    counters: Arc<Counters>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    counters.requests.fetch_add(1, Ordering::SeqCst);
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
    Ok(Response::new(Full::new(Bytes::from(line))))
}

/// Serves HTTP/1.1 or HTTP/2 on `io` with [`handle`].
pub async fn serve_http<T>(io: T, conn: usize, counters: Arc<Counters>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| handle(conn, counters.clone(), request));
    let _ = auto::Builder::new(TokioExecutor::new())
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
