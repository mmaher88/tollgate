//! Upstream connections, pooled per origin and shared by every client connection.
//!
//! One HTTP/2 connection per origin carries all of its requests. HTTP/1.1 origins get at
//! most `max_h1_per_host` connections; further requests wait for one to become idle. All
//! origins together hold at most `max_connections`; when that is reached, the oldest idle
//! connection is closed to make room.
//!
//! A client that stops reading a response leaves up to a stream window of data unread on
//! the shared HTTP/2 connection, and a few such streams use up the connection's window, so
//! no other response on it could move. Once stalled streams could hold half of that window,
//! the connection gets no new requests: the next one opens a new connection, and the old
//! one closes when its streams end.
//!
//! Idle connections are aged with the continuous clock (`PoolOptions::clock`), because
//! tokio's clock stops while the device sleeps, and are checked again when they are taken
//! from the pool. `ProxyContext::reset_upstream_connections` drops them all after a wake or
//! a network change, and a safe request that fails on a reused connection before its
//! response starts is sent once more on a new connection. A connection still carrying
//! requests is closed by the reset only when its source address is gone from the device
//! (see `cut`), so its responses fail instead of waiting on a dead path.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::{Body as _, Frame, Incoming, SizeHint};
use hyper::client::conn::{http1, http2};
use hyper::header::{self, HeaderValue};
use hyper::rt::{Read, Write};
use hyper::{Method, Request, Response, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::ServerName;
use rustls::sign::CertifiedKey;
use rustls::{AlertDescription, ClientConfig, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tollgate_common::resolve::Resolve;
use tollgate_policy::Decision;

use crate::ProxyContext;
use crate::body::{Body, DoneBody};
use crate::cut::{Cutter, cuttable};
use crate::http::{authority, join_cookies, strip_hop_by_hop};
use crate::limits::{
    H1_MAX_BUF, H2_CONNECTION_WINDOW, H2_MAX_SEND_BUF, H2_STREAM_WINDOW, KEEP_ALIVE_TIMEOUT,
    MAX_HEADER_LIST, MAX_HEADERS,
};
use crate::shutdown::Shutdown;
use crate::tunnel::until_path_gone;

/// How often a request waiting for an upstream connection looks for an idle one to close.
const EVICT_RETRY: Duration = Duration::from_millis(50);
/// Addresses from the resolver tried before falling back to the system resolver.
const MAX_ADDRESSES: usize = 2;
/// Limit for one connection attempt to an address from the resolver.
const ADDRESS_TIMEOUT: Duration = Duration::from_secs(2);
/// A response body that handed over data and was not asked for more for this long counts
/// as stalled: its client stopped reading.
const STALLED_AFTER: Duration = Duration::from_secs(1);
/// Stalled streams on one HTTP/2 connection that could hold half its receive window.
const MAX_STALLED_STREAMS: usize = (H2_CONNECTION_WINDOW / 2).div_ceil(H2_STREAM_WINDOW) as usize;

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

/// True when the upstream TLS failure is one the client, talking to the server itself,
/// probably would not have: the server's certificate could not be verified (unknown
/// issuer, missing intermediate, a root only the system trusts), the server shares no
/// protocol version or cipher suite with the proxy's TLS client (old TLS, CBC-only), or
/// it requires a client certificate the proxy cannot present. Timeouts, connection
/// failures, HTTP errors and other TLS alerts are not, and neither is a certificate for
/// another name, outside its validity dates, revoked or for another purpose: the client
/// would reject it too, and it is what a captive portal or a wrong device clock produces.
pub(crate) fn needs_passthrough(error: &UpstreamError) -> bool {
    if let UpstreamError::ClientCertificate(_) = error {
        return true;
    }
    if let Some(rustls::Error::InvalidCertificate(certificate)) = rustls_error(error) {
        return !client_rejects_too(certificate);
    }
    matches!(
        rustls_error(error),
        Some(
            rustls::Error::PeerIncompatible(_)
                | rustls::Error::AlertReceived(
                    AlertDescription::HandshakeFailure
                        | AlertDescription::ProtocolVersion
                        | AlertDescription::InsufficientSecurity
                        | AlertDescription::CertificateRequired
                )
        )
    )
}

/// Certificate errors that do not depend on which roots or intermediates the verifier
/// has: the name, the dates, revocation and the key usage.
fn client_rejects_too(error: &rustls::CertificateError) -> bool {
    use rustls::CertificateError as E;
    matches!(
        error,
        E::NotValidForName
            | E::NotValidForNameContext { .. }
            | E::Expired
            | E::ExpiredContext { .. }
            | E::NotValidYet
            | E::NotValidYetContext { .. }
            | E::Revoked
            | E::UnknownRevocationStatus
            | E::ExpiredRevocationList
            | E::ExpiredRevocationListContext { .. }
            | E::InvalidPurpose
            | E::InvalidPurposeContext { .. }
    )
}

/// True when no connection to the server could be made for this request: the name did not
/// resolve, the connection was refused, reset or timed out. TLS failures are not included;
/// neither is a failure on a connection that was already open, or a lack of permits.
pub(crate) fn is_unreachable(error: &UpstreamError) -> bool {
    match error {
        UpstreamError::Timeout => true,
        UpstreamError::Connect(_) => rustls_error(error).is_none(),
        _ => false,
    }
}

/// The rustls error behind `error`, if any. tokio-rustls reports TLS errors as an
/// `io::Error` wrapping the rustls error, and hyper wraps that `io::Error` in turn.
fn rustls_error(error: &UpstreamError) -> Option<&rustls::Error> {
    let mut next: Option<&(dyn std::error::Error + 'static)> = match error {
        UpstreamError::Connect(io) => Some(io),
        UpstreamError::Http(http) => Some(http),
        _ => None,
    };
    while let Some(error) = next {
        if let Some(tls) = error.downcast_ref::<rustls::Error>() {
            return Some(tls);
        }
        if let Some(tls) = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            return Some(tls);
        }
        next = error.source();
    }
    None
}

/// After a failed upstream request to the server named `name`: when the failure is one
/// the client would not have (see [`needs_passthrough`]), the host is passed through from
/// now on, so the client talks to the server itself. Returns true when the host is passed
/// through now, also when it already was a pin (another request may have learned it at the
/// same time), so the caller closes the client connection; false when the policy did not
/// learn it (a burst of failures that looks like the network's doing).
pub(crate) fn learn_from_failure(ctx: &ProxyContext, name: &str, error: &UpstreamError) -> bool {
    if !needs_passthrough(error) {
        return false;
    }
    let now = tollgate_common::clock::unix_secs();
    if ctx.policy.learn_upstream_untrusted(name, now) {
        log::info!("{name}: upstream TLS failed ({error}); passing it through from now on");
    }
    // Not a pin when the failure was part of a burst (see `learn_upstream_untrusted`).
    matches!(ctx.policy.classify(name, now), Decision::Passthrough(_))
}

/// Records whether the server asked for a client certificate. The proxy has none to
/// present, so it always answers with an empty one, as `with_no_client_auth` does.
#[derive(Debug, Default)]
struct ClientCertAsked(AtomicBool);

impl ResolvesClientCert for ClientCertAsked {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.0.store(true, Ordering::Relaxed);
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

/// A TLS connection to an upstream, and whether the server asked for a client certificate.
/// A server that requires one and rejects the empty certificate during the handshake
/// (TLS 1.2) fails here with [`UpstreamError::ClientCertificate`]; over TLS 1.3 the
/// rejection only arrives with the first request, so the caller checks the flag then.
pub(crate) async fn connect_tls<T>(
    config: &ClientConfig,
    name: ServerName<'static>,
    tcp: T,
) -> Result<(TlsStream<T>, bool), UpstreamError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let asked = Arc::new(ClientCertAsked::default());
    let mut config = config.clone();
    config.client_auth_cert_resolver = asked.clone();
    let result = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await;
    let asked = asked.0.load(Ordering::Relaxed);
    match result {
        Ok(tls) => Ok((tls, asked)),
        Err(e) => Err(connect_failure(e, asked)),
    }
}

/// A handshake failure; any alert after the server asked for a client certificate counts
/// as the server requiring one (servers send bad_certificate, handshake_failure or
/// certificate_required for it).
fn connect_failure(error: io::Error, client_cert_asked: bool) -> UpstreamError {
    let error = UpstreamError::Connect(error);
    if client_cert_asked && let Some(rustls::Error::AlertReceived(_)) = rustls_error(&error) {
        return UpstreamError::ClientCertificate(Box::new(error));
    }
    error
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
    /// The server asked for a client certificate and failed the connection or the first
    /// request without one.
    #[error("client certificate required: {0}")]
    ClientCertificate(Box<UpstreamError>),
}

pub(crate) struct PoolOptions {
    pub(crate) connect_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) keep_alive_interval: Duration,
    pub(crate) max_connections: usize,
    pub(crate) max_h1_per_host: usize,
    /// Seconds from a clock that keeps counting while the device sleeps.
    pub(crate) clock: fn() -> u64,
    /// Looks up upstream names before the system resolver is tried.
    pub(crate) resolver: Option<Arc<dyn Resolve>>,
    /// Whether a source address is still assigned to the device, checked on resets.
    pub(crate) local_address_present: fn(IpAddr) -> bool,
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

/// Whether a response body's client is still reading it.
struct Progress {
    /// Milliseconds after `base` plus 1 when the body last handed over data and has not been
    /// asked for more since; 0 while it waits for the upstream or has ended.
    handed_over: AtomicU64,
    base: Instant,
}

impl Progress {
    fn new() -> Progress {
        // Counted from the response headers: the body has not been asked for data yet.
        Progress {
            handed_over: AtomicU64::new(1),
            base: Instant::now(),
        }
    }

    fn handed_over(&self) {
        let millis = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.handed_over.store(millis + 1, Ordering::Relaxed);
    }

    fn waiting(&self) {
        self.handed_over.store(0, Ordering::Relaxed);
    }

    fn is_stalled(&self, now: Instant) -> bool {
        match self.handed_over.load(Ordering::Relaxed) {
            0 => false,
            at => {
                let since = self.base + Duration::from_millis(at - 1);
                now.saturating_duration_since(since) >= STALLED_AFTER
            }
        }
    }
}

/// The response bodies on one HTTP/2 connection.
#[derive(Default)]
struct Streams(Mutex<Vec<Weak<Progress>>>);

impl Streams {
    fn list(&self) -> MutexGuard<'_, Vec<Weak<Progress>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add(&self) -> Arc<Progress> {
        let progress = Arc::new(Progress::new());
        let mut list = self.list();
        list.retain(|p| p.strong_count() > 0);
        list.push(Arc::downgrade(&progress));
        progress
    }

    fn stalled(&self) -> usize {
        let now = Instant::now();
        let mut list = self.list();
        list.retain(|p| p.strong_count() > 0);
        list.iter()
            .filter_map(Weak::upgrade)
            .filter(|p| p.is_stalled(now))
            .count()
    }
}

/// An upstream response body that records in `progress` whether its client keeps asking
/// for data.
struct Watched {
    inner: Incoming,
    progress: Option<Arc<Progress>>,
}

impl hyper::body::Body for Watched {
    type Data = bytes::Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if let Some(progress) = &self.progress {
            match &polled {
                Poll::Ready(Some(Ok(_))) => progress.handed_over(),
                _ => progress.waiting(),
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The shared HTTP/2 connection of an origin.
#[derive(Clone)]
struct Shared {
    sender: http2::SendRequest<Body>,
    streams: Arc<Streams>,
}

struct Host {
    /// Unknown until the first TLS handshake has negotiated ALPN.
    protocol: Option<Protocol>,
    h2: Option<Shared>,
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
    /// gone without the connection noticing. So is an HTTP/2 connection whose stalled
    /// streams could hold half its window; it closes when they end.
    fn reuse(&mut self, now: u64, idle: u64) -> Option<Sender> {
        if let Some(h2) = &self.h2 {
            let idle_too_long = self.active.load(Ordering::Relaxed) == 0
                && now.saturating_sub(self.last_used) >= idle;
            let stalled = h2.streams.stalled();
            if h2.sender.is_ready() && !idle_too_long && stalled < MAX_STALLED_STREAMS {
                return Some(Sender::Http2(h2.clone()));
            }
            if stalled >= MAX_STALLED_STREAMS {
                log::debug!(
                    "{stalled} stalled streams on a shared HTTP/2 connection; opening another"
                );
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
    Http2(Shared),
}

/// Where `checkout` got a connection from.
#[derive(Clone, Copy, Debug)]
enum Checkout {
    Pooled,
    /// Opened for this request. `client_cert_asked` when the server asked for a client
    /// certificate during the handshake.
    New {
        client_cert_asked: bool,
    },
}

pub(crate) struct Pool(Arc<Inner>);

struct Inner {
    hosts: Mutex<HashMap<Target, Host>>,
    global: Arc<Semaphore>,
    /// Upstream TLS, with ALPN `h2` and `http/1.1`.
    tls: ClientConfig,
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
            tls: config,
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
            let (sender, checkout) = self.checkout(target, fresh_only).await?;
            let mut error = match sender {
                Sender::Http2(Shared {
                    mut sender,
                    streams,
                }) => match sender.try_send_request(for_http2(request, target)).await {
                    Ok(response) => {
                        return Ok(self.wrap(target, response, Connection::Http2(streams)));
                    }
                    Err(e) => e,
                },
                Sender::Http1(mut h1) => {
                    match h1.try_send_request(for_http1(request, target)).await {
                        Ok(response) => {
                            return Ok(self.wrap(target, response, Connection::Http1(h1)));
                        }
                        Err(e) => e,
                    }
                }
            };
            if let Checkout::Pooled = checkout {
                if let Some(unsent) = error.take_message() {
                    request = unsent;
                    fresh_only = true;
                    continue;
                }
                if let Some(copy) = replay.take() {
                    log::debug!(
                        "upstream {}: {} on a reused connection; retrying on a new one",
                        target.authority(),
                        error.error()
                    );
                    request =
                        copy.map(|()| Empty::new().map_err(|never| match never {}).boxed_unsync());
                    fresh_only = true;
                    continue;
                }
            }
            let error = UpstreamError::from(error.into_error());
            if let Checkout::New {
                client_cert_asked: true,
            } = checkout
            {
                // Over TLS 1.3 a server that requires a client certificate rejects the
                // empty one only after the handshake, so the first request fails.
                return Err(UpstreamError::ClientCertificate(Box::new(error)));
            }
            return Err(error);
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
            if host
                .h2
                .as_ref()
                .is_some_and(|h2| h2.sender.is_closed() || h2_idle)
            {
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
    ) -> Result<(Sender, Checkout), UpstreamError> {
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
                    return Ok((sender, Checkout::Pooled));
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
                        return self.connect(target, Some(permit)).await;
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
                    return Ok((sender, Checkout::Pooled));
                }
                host.protocol
            };
            if protocol.is_none() && now_protocol == Some(Protocol::Http1) {
                continue;
            }
            let permit = slots.try_acquire_owned().ok();
            return self.connect(target, permit).await;
        }
    }

    async fn connect(
        &self,
        target: &Target,
        h1_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<(Sender, Checkout), UpstreamError> {
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
    ) -> Result<(Sender, Checkout), UpstreamError> {
        let resolver = self.0.options.resolver.as_deref();
        let tcp = connect_tcp(resolver, &target.host, target.port).await?;
        let local = tcp.local_addr().ok().map(|a| a.ip());
        let (tcp, cutter) = cuttable(tcp);
        self.close_when_path_gone(cutter, local, target.authority());
        if !target.tls {
            let h1 = self
                .start_http1(TokioIo::new(tcp), global, h1_permit)
                .await?;
            let checkout = Checkout::New {
                client_cert_asked: false,
            };
            return Ok((Sender::Http1(h1), checkout));
        }
        let name = ServerName::try_from(target.server_name.clone())
            .map_err(|_| UpstreamError::ServerName(target.server_name.clone()))?;
        let (tls, client_cert_asked) = connect_tls(&self.0.tls, name, tcp).await?;
        let checkout = Checkout::New { client_cert_asked };
        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let io = TokioIo::new(tls);
        if !is_h2 {
            self.set_protocol(target, Protocol::Http1, None);
            let h1 = self.start_http1(io, global, h1_permit).await?;
            return Ok((Sender::Http1(h1), checkout));
        }
        drop(h1_permit);
        let (h2, conn) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .initial_stream_window_size(H2_STREAM_WINDOW)
            .initial_connection_window_size(H2_CONNECTION_WINDOW)
            .max_send_buf_size(H2_MAX_SEND_BUF)
            .max_header_list_size(MAX_HEADER_LIST)
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
        let shared = Shared {
            sender: h2,
            streams: Arc::default(),
        };
        self.set_protocol(target, Protocol::Http2, Some(shared.clone()));
        Ok((Sender::Http2(shared), checkout))
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
            .max_headers(MAX_HEADERS)
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

    /// Watches a new upstream connection until its socket is dropped. When the upstream
    /// connections are reset and `local`, its source address, is no longer assigned to the
    /// device, cuts the socket: the requests on it fail at once (releasing their permits)
    /// instead of waiting on a dead path, where an HTTP/1.1 response would wait forever and
    /// an HTTP/2 one until the keep-alive ping times out.
    fn close_when_path_gone(&self, mut cutter: Cutter, local: Option<IpAddr>, authority: String) {
        let resets = self.0.ctx.path_resets.subscribe();
        let present = self.0.options.local_address_present;
        self.0.shutdown.spawn(async move {
            let gone = until_path_gone(cutter.dropped(), resets, local, present)
                .await
                .is_none();
            if gone {
                log::debug!("upstream {authority}: network path gone; closing the connection");
                cutter.cut();
            }
        });
    }

    fn set_protocol(&self, target: &Target, protocol: Protocol, h2: Option<Shared>) {
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

    /// Counts the response as active until its body is done, strips hop-by-hop headers,
    /// watches an HTTP/2 body for a client that stops reading, and hands an HTTP/1.1
    /// connection back to the pool afterwards.
    fn wrap(
        &self,
        target: &Target,
        response: Response<Incoming>,
        via: Connection,
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
        let (h1, progress) = match via {
            Connection::Http1(h1) => (Some(h1), None),
            Connection::Http2(streams) => (None, Some(streams.add())),
        };
        let body = Watched {
            inner: body,
            progress,
        };
        let body = DoneBody::new(body, move || {
            active.fetch_sub(1, Ordering::Relaxed);
            if let Some(h1) = h1 {
                inner.give_back(target, h1);
            }
        });
        Response::from_parts(parts, body.boxed_unsync())
    }
}

/// The connection a response came on.
enum Connection {
    Http1(http1::SendRequest<Body>),
    Http2(Arc<Streams>),
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

/// Opens a TCP connection with Nagle's algorithm off. A host name is looked up with
/// `resolver` first and its first addresses are tried; when it finds nothing or none of
/// them answers, the system resolver (`getaddrinfo`) is used, so a DoH outage or a network
/// that needs synthesized addresses (NAT64) still works.
pub(crate) async fn connect_tcp(
    resolver: Option<&dyn Resolve>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    if let Some(resolver) = resolver
        && host.parse::<IpAddr>().is_err()
    {
        let addresses = resolver.lookup(host).await;
        for &ip in addresses.iter().take(MAX_ADDRESSES) {
            match tokio::time::timeout(ADDRESS_TIMEOUT, TcpStream::connect((ip, port))).await {
                Ok(Ok(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    return Ok(tcp);
                }
                Ok(Err(e)) => log::debug!("connecting to {host} at {ip}: {e}"),
                Err(_) => log::debug!("connecting to {host} at {ip}: timed out"),
            }
        }
        log::debug!("{host}: using the system resolver");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tls_failure(error: rustls::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    fn alert(description: AlertDescription) -> io::Error {
        tls_failure(rustls::Error::AlertReceived(description))
    }

    #[test]
    fn bad_certificate_counts_only_after_a_client_certificate_request() {
        let asked = connect_failure(alert(AlertDescription::BadCertificate), true);
        assert!(matches!(asked, UpstreamError::ClientCertificate(_)));
        assert!(needs_passthrough(&asked));
        let unasked = connect_failure(alert(AlertDescription::BadCertificate), false);
        assert!(!needs_passthrough(&unasked));
        // A reset after the request is not an alert, so not a certificate requirement.
        let reset = io::Error::from(io::ErrorKind::ConnectionReset);
        assert!(!needs_passthrough(&connect_failure(reset, true)));
    }

    #[test]
    fn certificates_the_client_would_reject_too_are_not_learned() {
        use rustls::CertificateError;
        for error in [
            CertificateError::NotValidForName,
            CertificateError::Expired,
            CertificateError::NotValidYet,
            CertificateError::Revoked,
            CertificateError::UnknownRevocationStatus,
            CertificateError::InvalidPurpose,
        ] {
            let failure = tls_failure(rustls::Error::InvalidCertificate(error.clone()));
            assert!(
                !needs_passthrough(&UpstreamError::Connect(failure)),
                "{error:?}"
            );
        }
        for error in [
            CertificateError::UnknownIssuer,
            CertificateError::BadSignature,
        ] {
            let failure = tls_failure(rustls::Error::InvalidCertificate(error.clone()));
            assert!(
                needs_passthrough(&UpstreamError::Connect(failure)),
                "{error:?}"
            );
        }
    }

    #[test]
    fn incompatible_servers_need_passthrough() {
        let incompatible = tls_failure(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::NoCipherSuitesInCommon,
        ));
        assert!(needs_passthrough(&UpstreamError::Connect(incompatible)));
        for description in [
            AlertDescription::HandshakeFailure,
            AlertDescription::ProtocolVersion,
            AlertDescription::InsufficientSecurity,
            AlertDescription::CertificateRequired,
        ] {
            assert!(needs_passthrough(&UpstreamError::Connect(alert(
                description
            ))));
        }
        for description in [
            AlertDescription::InternalError,
            AlertDescription::UnrecognisedName,
            AlertDescription::DecodeError,
        ] {
            assert!(!needs_passthrough(&UpstreamError::Connect(alert(
                description
            ))));
        }
        assert!(!needs_passthrough(&UpstreamError::Timeout));
        assert!(is_unreachable(&UpstreamError::Timeout));
        assert!(is_unreachable(&UpstreamError::Connect(io::Error::from(
            io::ErrorKind::ConnectionRefused
        ))));
        assert!(!is_unreachable(&UpstreamError::Connect(alert(
            AlertDescription::HandshakeFailure
        ))));
        assert!(!is_unreachable(&UpstreamError::Exhausted));
        assert!(!needs_passthrough(&UpstreamError::Connect(
            io::Error::from(io::ErrorKind::ConnectionRefused)
        )));
    }
}
