//! Upstream connections, pooled per origin and shared by every client connection.
//!
//! One HTTP/2 connection per origin carries all of its requests. HTTP/1.1 origins get at
//! most `max_h1_per_host` connections; further requests wait for one to become idle. All
//! origins together hold at most `max_connections`; when that is reached, the oldest idle
//! connection is closed to make room.
//!
//! Idle connections are aged with the continuous clock (`PoolOptions::clock`), because
//! tokio's clock stops while the device sleeps, and are checked again when they are taken
//! from the pool. `ProxyContext::reset_upstream_connections` drops them all after a wake or
//! a network change, and a safe request that fails on a reused connection before its
//! response starts is sent once more on a new connection.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::{Body as _, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::header::{self, HeaderValue};
use hyper::rt::{Read, Write};
use hyper::{Method, Request, Response, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::ProxyContext;
use crate::body::{Body, DoneBody};
use crate::http::{authority, join_cookies, strip_hop_by_hop};
use crate::limits::{
    H1_MAX_BUF, H2_CONNECTION_WINDOW, H2_MAX_SEND_BUF, H2_STREAM_WINDOW, KEEP_ALIVE_TIMEOUT,
};
use crate::shutdown::Shutdown;

/// How often a request waiting for an upstream connection looks for an idle one to close.
const EVICT_RETRY: Duration = Duration::from_millis(50);

/// Where a request goes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Target {
    pub(crate) tls: bool,
    /// Name or IP address to dial, without IPv6 brackets.
    pub(crate) host: String,
    pub(crate) port: u16,
    /// TLS server name and the host in the request's authority. It differs from `host`
    /// when a client connects to an IP address and names the site in its SNI.
    pub(crate) server_name: String,
}

impl Target {
    pub(crate) fn authority(&self) -> String {
        authority(
            &self.server_name,
            self.port,
            if self.tls { 443 } else { 80 },
        )
    }

    fn scheme(&self) -> &'static str {
        if self.tls { "https" } else { "http" }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamError {
    #[error("connecting: {0}")]
    Connect(#[from] io::Error),
    #[error("timed out connecting")]
    Timeout,
    #[error("invalid TLS server name {0:?}")]
    ServerName(String),
    #[error("too many upstream connections")]
    Exhausted,
    #[error(transparent)]
    Http(#[from] hyper::Error),
}

pub(crate) struct PoolOptions {
    pub(crate) connect_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) keep_alive_interval: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_h1_per_host: usize,
    /// Seconds from a clock that keeps counting while the device sleeps.
    pub(crate) clock: fn() -> u64,
}

impl PoolOptions {
    /// The idle timeout in whole seconds of `clock`, at least 1.
    fn idle_secs(&self) -> u64 {
        self.idle_timeout.as_secs().max(1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Http1,
    Http2,
}

struct Host {
    /// Unknown until the first TLS handshake has negotiated ALPN.
    protocol: Option<Protocol>,
    h2: Option<http2::SendRequest<Body>>,
    /// Idle HTTP/1.1 connections and when they became idle (`PoolOptions::clock`).
    idle: Vec<(http1::SendRequest<Body>, u64)>,
    /// One permit per live HTTP/1.1 connection.
    slots: Arc<Semaphore>,
    /// Signalled when an HTTP/1.1 connection becomes idle.
    ready: Arc<Notify>,
    /// Held while dialing an origin whose protocol may be HTTP/2, so it gets one connection.
    dial: Arc<tokio::sync::Mutex<()>>,
    /// Responses whose bodies are still streaming.
    active: Arc<AtomicUsize>,
    /// When a request last started on this origin (`PoolOptions::clock`).
    last_used: u64,
}

impl Host {
    fn new(tls: bool, max_h1: usize, now: u64) -> Host {
        Host {
            protocol: if tls { None } else { Some(Protocol::Http1) },
            h2: None,
            idle: Vec::new(),
            slots: Arc::new(Semaphore::new(max_h1)),
            ready: Arc::new(Notify::new()),
            dial: Arc::new(tokio::sync::Mutex::new(())),
            active: Arc::new(AtomicUsize::new(0)),
            last_used: now,
        }
    }

    /// A pooled connection that is open and was not idle for `idle` seconds or more at
    /// `now`. Older ones are dropped: after sleep or a network change their path may be
    /// gone without the connection noticing.
    fn reuse(&mut self, now: u64, idle: u64) -> Option<Sender> {
        if let Some(h2) = &self.h2 {
            let idle_too_long = self.active.load(Ordering::Relaxed) == 0
                && now.saturating_sub(self.last_used) >= idle;
            if h2.is_ready() && !idle_too_long {
                return Some(Sender::Http2(h2.clone()));
            }
            self.h2 = None;
        }
        while let Some((h1, since)) = self.idle.pop() {
            if h1.is_ready() && now.saturating_sub(since) < idle {
                return Some(Sender::Http1(h1));
            }
        }
        None
    }

    /// Drops every pooled connection. In-flight requests keep their connections, and the
    /// slots and counters stay, since those connections still use them.
    fn clear(&mut self) {
        self.h2 = None;
        self.idle.clear();
    }
}

enum Sender {
    Http1(http1::SendRequest<Body>),
    Http2(http2::SendRequest<Body>),
}

pub(crate) struct Pool(Arc<Inner>);

struct Inner {
    hosts: Mutex<HashMap<Target, Host>>,
    global: Arc<Semaphore>,
    tls: TlsConnector,
    options: PoolOptions,
    shutdown: Shutdown,
    /// Where `reset_upstream_connections` is counted.
    ctx: Arc<ProxyContext>,
    /// The reset count the pool has acted on.
    resets_seen: AtomicU64,
}

impl Inner {
    /// The hosts, after dropping every pooled connection if a reset was asked for since
    /// the last look.
    fn hosts(&self) -> MutexGuard<'_, HashMap<Target, Host>> {
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        let resets = self.ctx.upstream_resets.load(Ordering::Acquire);
        if self.resets_seen.swap(resets, Ordering::AcqRel) != resets {
            log::info!("dropping pooled upstream connections");
            hosts.values_mut().for_each(Host::clear);
        }
        hosts
    }

    fn now(&self) -> u64 {
        (self.options.clock)()
    }

    /// Returns an HTTP/1.1 connection to the idle list once its last response is done.
    fn give_back(self: &Arc<Self>, target: Target, mut sender: http1::SendRequest<Body>) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let inner = self.clone();
        self.shutdown.spawn(async move {
            if sender.ready().await.is_err() {
                return;
            }
            let now = inner.now();
            let mut hosts = inner.hosts();
            if let Some(host) = hosts.get_mut(&target) {
                host.idle.push((sender, now));
                host.ready.notify_one();
            }
        });
    }
}

impl Pool {
    /// `tls` supplies the trusted roots; the pool offers ALPN `h2` and `http/1.1`.
    /// `ctx` is where resets are asked for.
    pub(crate) fn new(
        tls: &ClientConfig,
        options: PoolOptions,
        shutdown: Shutdown,
        ctx: Arc<ProxyContext>,
    ) -> Pool {
        let mut config = tls.clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let resets_seen = AtomicU64::new(ctx.upstream_resets.load(Ordering::Acquire));
        Pool(Arc::new(Inner {
            hosts: Mutex::new(HashMap::new()),
            global: Arc::new(Semaphore::new(options.max_connections)),
            tls: TlsConnector::from(Arc::new(config)),
            options,
            shutdown,
            ctx,
            resets_seen,
        }))
    }

    /// Sends `request` (any URI form) to `target`. A request that a reused connection
    /// refused before sending it is retried once on a new connection. So is a GET, HEAD
    /// or OPTIONS without a body that a reused connection failed before its response
    /// started: the connection may have been cut off by sleep or a network change, and
    /// repeating such a request is safe.
    pub(crate) async fn send(
        &self,
        target: &Target,
        mut request: Request<Body>,
    ) -> Result<Response<Body>, UpstreamError> {
        let mut fresh_only = false;
        let mut replay = replayable(&request);
        loop {
            let (sender, fresh) = self.checkout(target, fresh_only).await?;
            let mut error = match sender {
                Sender::Http2(mut h2) => {
                    match h2.try_send_request(for_http2(request, target)).await {
                        Ok(response) => return Ok(self.wrap(target, response, None)),
                        Err(e) => e,
                    }
                }
                Sender::Http1(mut h1) => {
                    match h1.try_send_request(for_http1(request, target)).await {
                        Ok(response) => return Ok(self.wrap(target, response, Some(h1))),
                        Err(e) => e,
                    }
                }
            };
            match error.take_message() {
                Some(unsent) if !fresh => {
                    request = unsent;
                    fresh_only = true;
                }
                None if !fresh && let Some(copy) = replay.take() => {
                    log::debug!(
                        "upstream {}: {} on a reused connection; retrying on a new one",
                        target.authority(),
                        error.error()
                    );
                    request =
                        copy.map(|()| Empty::new().map_err(|never| match never {}).boxed_unsync());
                    fresh_only = true;
                }
                _ => return Err(error.into_error().into()),
            }
        }
    }

    /// A permit for one more upstream connection. When none is left, the oldest idle
    /// connection is closed and the freed permit awaited; this repeats every 50 ms, since
    /// busy connections become idle, until the connect timeout.
    pub(crate) async fn global_permit(&self) -> Result<OwnedSemaphorePermit, UpstreamError> {
        let deadline = Instant::now() + self.0.options.connect_timeout;
        loop {
            if let Ok(permit) = self.0.global.clone().try_acquire_owned() {
                return Ok(permit);
            }
            self.evict_one();
            let retry = (Instant::now() + EVICT_RETRY).min(deadline);
            let freed = tokio::time::timeout_at(retry, self.0.global.clone().acquire_owned()).await;
            match freed {
                Ok(Ok(permit)) => return Ok(permit),
                Ok(Err(_)) => return Err(UpstreamError::Exhausted),
                Err(_) if Instant::now() >= deadline => return Err(UpstreamError::Exhausted),
                Err(_) => {}
            }
        }
    }

    /// Closes connections idle for longer than the idle timeout and forgets unused origins.
    pub(crate) fn reap(&self) {
        let now = self.0.now();
        let idle = self.0.options.idle_secs();
        let max_h1 = self.0.options.max_h1_per_host;
        self.0.hosts().retain(|_, host| {
            host.idle
                .retain(|(h1, since)| now.saturating_sub(*since) < idle && !h1.is_closed());
            let active = host.active.load(Ordering::Relaxed);
            let h2_idle = active == 0 && now.saturating_sub(host.last_used) >= idle;
            if host.h2.as_ref().is_some_and(|h2| h2.is_closed() || h2_idle) {
                host.h2 = None;
            }
            let unused = host.idle.is_empty()
                && host.h2.is_none()
                && active == 0
                && host.slots.available_permits() == max_h1
                && Arc::strong_count(&host.slots) == 1
                && Arc::strong_count(&host.dial) == 1;
            !unused
        });
    }

    async fn checkout(
        &self,
        target: &Target,
        fresh_only: bool,
    ) -> Result<(Sender, bool), UpstreamError> {
        loop {
            let (protocol, slots, ready, dial) = {
                let now = self.0.now();
                let idle = self.0.options.idle_secs();
                let max_h1 = self.0.options.max_h1_per_host;
                let mut hosts = self.0.hosts();
                let host = hosts
                    .entry(target.clone())
                    .or_insert_with(|| Host::new(target.tls, max_h1, now));
                // Checked before last_used moves, so an HTTP/2 connection idle for too long
                // is not mistaken for a busy one.
                let reused = if fresh_only {
                    None
                } else {
                    host.reuse(now, idle)
                };
                host.last_used = now;
                if let Some(sender) = reused {
                    return Ok((sender, false));
                }
                (
                    host.protocol,
                    host.slots.clone(),
                    host.ready.clone(),
                    host.dial.clone(),
                )
            };
            if protocol == Some(Protocol::Http1) {
                tokio::select! {
                    permit = slots.acquire_owned() => {
                        let permit = permit.expect("host slots are never closed");
                        return Ok((self.connect(target, Some(permit)).await?, true));
                    }
                    () = ready.notified(), if !fresh_only => continue,
                }
            }
            let _dialing = dial.lock().await;
            let now_protocol = {
                let now = self.0.now();
                let idle = self.0.options.idle_secs();
                let max_h1 = self.0.options.max_h1_per_host;
                let mut hosts = self.0.hosts();
                let host = hosts
                    .entry(target.clone())
                    .or_insert_with(|| Host::new(target.tls, max_h1, now));
                if !fresh_only && let Some(sender) = host.reuse(now, idle) {
                    host.last_used = now;
                    return Ok((sender, false));
                }
                host.protocol
            };
            if protocol.is_none() && now_protocol == Some(Protocol::Http1) {
                continue;
            }
            let permit = slots.try_acquire_owned().ok();
            return Ok((self.connect(target, permit).await?, true));
        }
    }

    async fn connect(
        &self,
        target: &Target,
        h1_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<Sender, UpstreamError> {
        let global = self.global_permit().await?;
        tokio::time::timeout(
            self.0.options.connect_timeout,
            self.handshake(target, global, h1_permit),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
    }

    async fn handshake(
        &self,
        target: &Target,
        global: OwnedSemaphorePermit,
        h1_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<Sender, UpstreamError> {
        let tcp = connect_tcp(&target.host, target.port).await?;
        if !target.tls {
            let h1 = self
                .start_http1(TokioIo::new(tcp), global, h1_permit)
                .await?;
            return Ok(Sender::Http1(h1));
        }
        let name = ServerName::try_from(target.server_name.clone())
            .map_err(|_| UpstreamError::ServerName(target.server_name.clone()))?;
        let tls = self.0.tls.connect(name, tcp).await?;
        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let io = TokioIo::new(tls);
        if !is_h2 {
            self.set_protocol(target, Protocol::Http1, None);
            let h1 = self.start_http1(io, global, h1_permit).await?;
            return Ok(Sender::Http1(h1));
        }
        drop(h1_permit);
        let (h2, conn) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .initial_stream_window_size(H2_STREAM_WINDOW)
            .initial_connection_window_size(H2_CONNECTION_WINDOW)
            .max_send_buf_size(H2_MAX_SEND_BUF)
            .keep_alive_interval(self.0.options.keep_alive_interval)
            .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
            // Ping idle connections too, so one whose path died is found and dropped
            // before a request is sent on it. Pooled connections live 60 s at most.
            .keep_alive_while_idle(true)
            .handshake(io)
            .await?;
        let authority = target.authority();
        self.0.shutdown.spawn(async move {
            let _global = global;
            if let Err(e) = conn.await {
                log::debug!("upstream HTTP/2 connection to {authority}: {e}");
            }
        });
        self.set_protocol(target, Protocol::Http2, Some(h2.clone()));
        Ok(Sender::Http2(h2))
    }

    async fn start_http1<T>(
        &self,
        io: T,
        global: OwnedSemaphorePermit,
        h1_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<http1::SendRequest<Body>, UpstreamError>
    where
        T: Read + Write + Unpin + Send + 'static,
    {
        let (h1, conn) = http1::Builder::new()
            .max_buf_size(H1_MAX_BUF)
            .handshake(io)
            .await?;
        self.0.shutdown.spawn(async move {
            let _permits = (global, h1_permit);
            if let Err(e) = conn.await {
                log::debug!("upstream HTTP/1.1 connection: {e}");
            }
        });
        Ok(h1)
    }

    fn set_protocol(
        &self,
        target: &Target,
        protocol: Protocol,
        h2: Option<http2::SendRequest<Body>>,
    ) {
        if let Some(host) = self.0.hosts().get_mut(target) {
            host.protocol = Some(protocol);
            if h2.is_some() {
                host.h2 = h2;
            }
        }
    }

    /// Closes the least recently used idle connection, HTTP/1.1 first.
    fn evict_one(&self) {
        let mut hosts = self.0.hosts();
        let oldest_h1 = hosts
            .iter()
            .flat_map(|(target, host)| {
                host.idle
                    .iter()
                    .enumerate()
                    .map(move |(i, (_, since))| (target.clone(), i, *since))
            })
            .min_by_key(|(_, _, since)| *since);
        if let Some((target, i, _)) = oldest_h1 {
            if let Some(host) = hosts.get_mut(&target) {
                host.idle.remove(i);
            }
            return;
        }
        let idle_h2 = hosts
            .iter()
            .filter(|(_, host)| host.h2.is_some() && host.active.load(Ordering::Relaxed) == 0)
            .min_by_key(|(_, host)| host.last_used)
            .map(|(target, _)| target.clone());
        if let Some(target) = idle_h2
            && let Some(host) = hosts.get_mut(&target)
        {
            host.h2 = None;
        }
    }

    /// Counts the response as active until its body is done, strips hop-by-hop headers and
    /// hands an HTTP/1.1 connection back to the pool afterwards.
    fn wrap(
        &self,
        target: &Target,
        response: Response<Incoming>,
        h1: Option<http1::SendRequest<Body>>,
    ) -> Response<Body> {
        let active = self
            .0
            .hosts()
            .get(target)
            .map(|host| host.active.clone())
            .unwrap_or_default();
        active.fetch_add(1, Ordering::Relaxed);
        let inner = self.0.clone();
        let target = target.clone();
        let (mut parts, body) = response.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let body = DoneBody::new(body, move || {
            active.fetch_sub(1, Ordering::Relaxed);
            if let Some(h1) = h1 {
                inner.give_back(target, h1);
            }
        });
        Response::from_parts(parts, body.boxed_unsync())
    }
}

/// A copy of `request` without its body, if sending it twice is safe: GET, HEAD or
/// OPTIONS with an empty body.
fn replayable(request: &Request<Body>) -> Option<Request<()>> {
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return None;
    }
    let body = request.body();
    if !body.is_end_stream() && body.size_hint().exact() != Some(0) {
        return None;
    }
    let mut copy = Request::new(());
    *copy.method_mut() = request.method().clone();
    *copy.uri_mut() = request.uri().clone();
    *copy.version_mut() = request.version();
    *copy.headers_mut() = request.headers().clone();
    Some(copy)
}

/// Opens a TCP connection with Nagle's algorithm off.
pub(crate) async fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let tcp = TcpStream::connect((host, port)).await?;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

fn path_and_query(uri: &Uri) -> &str {
    uri.path_and_query().map_or("/", |pq| pq.as_str())
}

/// Origin-form URI, one `Host` header, one `Cookie` header.
fn for_http1(mut request: Request<Body>, target: &Target) -> Request<Body> {
    if let Ok(uri) = path_and_query(request.uri()).parse::<Uri>() {
        *request.uri_mut() = uri;
    }
    *request.version_mut() = Version::HTTP_11;
    let headers = request.headers_mut();
    strip_hop_by_hop(headers);
    join_cookies(headers);
    if let Ok(host) = HeaderValue::from_str(&target.authority()) {
        headers.insert(header::HOST, host);
    }
    request
}

/// Absolute URI (hyper sends it as `:scheme` and `:authority`), no `Host` header. `TE:
/// trailers` is kept because gRPC servers require it.
fn for_http2(mut request: Request<Body>, target: &Target) -> Request<Body> {
    let uri = format!(
        "{}://{}{}",
        target.scheme(),
        target.authority(),
        path_and_query(request.uri())
    );
    if let Ok(uri) = uri.parse::<Uri>() {
        *request.uri_mut() = uri;
    }
    *request.version_mut() = Version::HTTP_2;
    let headers = request.headers_mut();
    let trailers = headers
        .get(header::TE)
        .is_some_and(|te| te.as_bytes().eq_ignore_ascii_case(b"trailers"));
    strip_hop_by_hop(headers);
    headers.remove(header::HOST);
    if trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
    request
}
