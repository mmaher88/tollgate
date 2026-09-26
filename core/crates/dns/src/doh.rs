//! DNS over HTTPS (RFC 8484): POST `application/dns-message` over HTTP/2 to upstreams
//! reached by IP address, with the TLS name set explicitly.
//!
//! Each upstream has one shared connection. Queries are independent futures that clone the
//! connection's sender, so any number of them run at once on the same connection.
//!
//! An upstream that times out or cannot be reached is marked down for [`DOWN_FOR`] and tried
//! only after the others, so a network that silently drops its packets does not cost every
//! query the cold deadline. When the time is up, one query is sent to it in the background;
//! its answer brings the upstream back, and a failure keeps it down for another period.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::client::conn::http2::{self, SendRequest};
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tollgate_policy::DohUpstream;

/// Deadline for one attempt that has to open a connection first.
pub const COLD_DEADLINE: Duration = Duration::from_millis(2000);
/// Deadline for one attempt on an open connection.
pub const WARM_DEADLINE: Duration = Duration::from_millis(1500);
/// A connection that has not completed a request for this long is not trusted to be
/// alive (the device may have slept, and NAT or the server dropped it): the next query
/// opens a new connection under the cold deadline instead of waiting out the warm one.
pub const MAX_IDLE: Duration = Duration::from_secs(30);
/// Queries resolving at once, across all clones; above it `resolve` fails at once with
/// [`DohError::Busy`]. The tunnel splits it: [`crate::LOOKUP_PERMITS`] for the proxy's name
/// lookups (`HostResolver` waits for a turn instead of exceeding it) and the rest for the
/// DNS forwarder, whose jobs wait in its queue, so neither sees `Busy`.
pub const MAX_IN_FLIGHT: usize = 128;
/// How long an upstream that timed out or could not be reached is tried only after the
/// others (all of them in order when every upstream is down).
pub const DOWN_FOR: Duration = Duration::from_secs(30);

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_ANSWER_LEN: usize = 65_535;
const DNS_HEADER_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DohError {
    #[error("no usable DoH upstream is configured")]
    NoUpstream,
    #[error("the query is shorter than a DNS header")]
    BadQuery,
    #[error("too many queries are in flight")]
    Busy,
    /// Not produced by the resolver: for callers that answer queued queries after stopping.
    #[error("the resolver is stopped")]
    Stopped,
    #[error("no answer before the deadline")]
    Timeout,
    #[error("connecting failed: {0}")]
    Connect(String),
    #[error("TLS failed: {0}")]
    Tls(String),
    #[error("HTTP/2 failed: {0}")]
    Http(String),
    #[error("upstream answered with HTTP status {0}")]
    Status(u16),
    #[error("unusable answer: {0}")]
    BadAnswer(String),
    #[error("invalid TLS configuration: {0}")]
    Config(String),
}

/// How one exchange on a connection failed.
enum Failure {
    /// The connection broke; worth one retry on a new connection.
    Connection(DohError),
    /// The upstream answered, but not usefully.
    Answer(DohError),
}

impl Failure {
    fn into_error(self) -> DohError {
        match self {
            Failure::Connection(e) | Failure::Answer(e) => e,
        }
    }
}

/// The shared connection of one upstream. `generation` changes with every new connection,
/// so a query only discards the connection it used itself.
#[derive(Default)]
struct Slot {
    sender: Option<SendRequest<Full<Bytes>>>,
    generation: u64,
    /// When the connection opened or last completed a request, from the resolver's clock.
    last_used: u64,
}

struct Upstream {
    name: String,
    addr: SocketAddr,
    server_name: ServerName<'static>,
    uri: Uri,
    slot: std::sync::Mutex<Slot>,
    /// Held while connecting, so concurrent cold queries open one connection, not many.
    connecting: tokio::sync::Mutex<()>,
    /// Until when (on the resolver's clock) the upstream is tried after the others; 0 when
    /// it is up.
    down_until: AtomicU64,
    /// Set while a background query checks whether a down upstream is back.
    probing: AtomicBool,
}

/// Whether an upstream is tried in order or after the others.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Health {
    Up,
    Down,
    /// Down, and its time is up: worth a query in the background.
    Due,
}

struct Inner {
    upstreams: Vec<Upstream>,
    tls: TlsConnector,
    in_flight: Semaphore,
}

/// Seconds from a clock that keeps counting while the device sleeps.
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// DNS over HTTPS client. Cheap to clone; clones share connections and the in-flight limit.
/// `resolve` must run on a tokio runtime (it spawns each connection's driver task), and its
/// future is `Send`, so callers can spawn one task per query.
#[derive(Clone)]
pub struct DohResolver {
    inner: Arc<Inner>,
    clock: Clock,
}

impl DohResolver {
    /// Resolver trusting the webpki roots. Upstreams are tried in order; one whose TLS name
    /// or path is invalid is logged and skipped.
    pub fn new(upstreams: Vec<DohUpstream>) -> DohResolver {
        DohResolver::with_tls_config(&upstreams, tollgate_common::tls::client_config(&[b"h2"]))
    }

    /// Resolver trusting the webpki roots plus `roots`, for tests against a local server
    /// with its own certificate authority.
    pub fn with_extra_roots(
        upstreams: Vec<DohUpstream>,
        roots: &[CertificateDer<'_>],
    ) -> Result<DohResolver, DohError> {
        let mut store = tollgate_common::tls::webpki_root_store();
        for root in roots {
            store
                .add(root.clone().into_owned())
                .map_err(|e| DohError::Config(e.to_string()))?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| DohError::Config(e.to_string()))?
            .with_root_certificates(store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(DohResolver::with_tls_config(&upstreams, Arc::new(config)))
    }

    fn with_tls_config(upstreams: &[DohUpstream], tls: Arc<ClientConfig>) -> DohResolver {
        let upstreams = upstreams
            .iter()
            .filter_map(|upstream| match Upstream::new(upstream) {
                Ok(upstream) => Some(upstream),
                Err(reason) => {
                    log::warn!("ignoring DoH upstream {}: {reason}", upstream.tls_name);
                    None
                }
            })
            .collect();
        DohResolver {
            inner: Arc::new(Inner {
                upstreams,
                tls: TlsConnector::from(tls),
                in_flight: Semaphore::new(MAX_IN_FLIGHT),
            }),
            clock: Arc::new(tollgate_common::clock::now_secs),
        }
    }

    /// This resolver with `clock` (seconds, counting through sleep) in place of
    /// `tollgate_common::clock::now_secs` for measuring how long connections were idle.
    /// Clones made earlier keep their clock. For tests.
    pub fn with_clock(self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> DohResolver {
        DohResolver {
            clock: Arc::new(clock),
            ..self
        }
    }

    /// Drops every upstream's open connection, so the next query to each opens a new one,
    /// and forgets which upstreams were down, so each gets another chance on the new path.
    /// For a network path change or a wake from sleep: a connection made on the old path
    /// would otherwise be reused for up to [`MAX_IDLE`] and cost each query the warm
    /// deadline before it fails. Queries already in flight on the old connection finish or
    /// time out as before. Safe to call from any thread, inside or outside the runtime.
    pub fn reset_connections(&self) {
        for upstream in &self.inner.upstreams {
            upstream.down_until.store(0, Ordering::SeqCst);
            let mut slot = upstream.slot();
            if slot.sender.take().is_some() {
                // A late touch or discard from a query on the old connection is a no-op.
                slot.generation += 1;
            }
        }
    }

    /// Sends `query` (a DNS message) to each upstream in turn until one answers, and returns
    /// the answer with the query's id. Upstreams that are down come after the others. The
    /// error is the last upstream's.
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, DohError> {
        if query.len() < DNS_HEADER_LEN {
            return Err(DohError::BadQuery);
        }
        let Ok(_permit) = self.inner.in_flight.try_acquire() else {
            return Err(DohError::Busy);
        };
        // RFC 8484 section 4.1: the id is 0 on the wire, so answers can be cached by HTTP.
        let mut body = query.to_vec();
        body[..2].fill(0);
        let body = Bytes::from(body);
        let mut last = DohError::NoUpstream;
        for index in self.order(&body) {
            let upstream = &self.inner.upstreams[index];
            match upstream.query(&self.inner.tls, &body, &*self.clock).await {
                Ok(mut answer) => {
                    answer[..2].copy_from_slice(&query[..2]);
                    return Ok(answer);
                }
                Err(e) => {
                    log::debug!("DoH upstream {} failed: {e}", upstream.name);
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// The upstreams to try, by index: those that are up in configured order, then those
    /// that are down in configured order. Starts a background query to each down upstream
    /// whose time is up.
    fn order(&self, body: &Bytes) -> Vec<usize> {
        let now = (self.clock)();
        let mut up = Vec::with_capacity(self.inner.upstreams.len());
        let mut down = Vec::new();
        for (index, upstream) in self.inner.upstreams.iter().enumerate() {
            match upstream.health(now) {
                Health::Up => up.push(index),
                Health::Down => down.push(index),
                Health::Due => {
                    self.probe(index, body);
                    down.push(index);
                }
            }
        }
        up.extend(down);
        up
    }

    /// Sends `body` to the down upstream `index` in a task of its own, unless one is already
    /// on its way, so no caller waits on it. The query marks the upstream up or down again.
    fn probe(&self, index: usize, body: &Bytes) {
        if self.inner.upstreams[index]
            .probing
            .swap(true, Ordering::SeqCst)
        {
            return;
        }
        let inner = self.inner.clone();
        let clock = self.clock.clone();
        let body = body.clone();
        tokio::spawn(async move {
            let upstream = &inner.upstreams[index];
            log::debug!("checking whether DoH upstream {} is back", upstream.name);
            if let Err(e) = upstream.query(&inner.tls, &body, &*clock).await {
                log::debug!("DoH upstream {} is still down: {e}", upstream.name);
            }
            upstream.probing.store(false, Ordering::SeqCst);
        });
    }
}

impl Upstream {
    fn new(config: &DohUpstream) -> Result<Upstream, String> {
        let server_name =
            ServerName::try_from(config.tls_name.clone()).map_err(|e| e.to_string())?;
        if !config.path.starts_with('/') {
            return Err(format!("path {:?} does not start with /", config.path));
        }
        // An IPv6 literal needs brackets in a URI.
        let host = match config.tls_name.parse::<std::net::Ipv6Addr>() {
            Ok(_) => format!("[{}]", config.tls_name),
            Err(_) => config.tls_name.clone(),
        };
        let authority = if config.port == 443 {
            host
        } else {
            format!("{host}:{}", config.port)
        };
        let uri = format!("https://{authority}{}", config.path)
            .parse::<Uri>()
            .map_err(|e| e.to_string())?;
        let addr = SocketAddr::new(config.ip, config.port);
        Ok(Upstream {
            name: format!("{} ({addr})", config.tls_name),
            addr,
            server_name,
            uri,
            slot: std::sync::Mutex::new(Slot::default()),
            connecting: tokio::sync::Mutex::new(()),
            down_until: AtomicU64::new(0),
            probing: AtomicBool::new(false),
        })
    }

    fn health(&self, now: u64) -> Health {
        match self.down_until.load(Ordering::SeqCst) {
            0 => Health::Up,
            until if now < until => Health::Down,
            _ if self.probing.load(Ordering::SeqCst) => Health::Down,
            _ => Health::Due,
        }
    }

    fn mark_up(&self) {
        if self.down_until.swap(0, Ordering::SeqCst) != 0 {
            log::debug!("DoH upstream {} is back", self.name);
        }
    }

    /// For an attempt that spent its deadline or failed below HTTP: not for an upstream
    /// that answered, even with an error status.
    fn mark_down(&self, now: u64) {
        // Never 0, which means up.
        let until = now.saturating_add(DOWN_FOR.as_secs()).max(1);
        if self.down_until.swap(until, Ordering::SeqCst) == 0 {
            log::debug!(
                "DoH upstream {} is down for {} s",
                self.name,
                DOWN_FOR.as_secs()
            );
        }
    }

    /// One query: an attempt on the open connection if there is one that was used within
    /// [`MAX_IDLE`] (retried once on a new connection if that connection turns out to be
    /// closed), otherwise an attempt on a new connection. An answer, even an unusable one,
    /// marks the upstream up; a timeout or a failure to connect or exchange marks it down.
    async fn query(
        &self,
        tls: &TlsConnector,
        body: &Bytes,
        now: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<Vec<u8>, DohError> {
        if let Some((generation, sender)) = self.open_sender(now()) {
            let result = timeout(WARM_DEADLINE, self.exchange(sender, body.clone())).await;
            if let Ok(Ok(_) | Err(Failure::Answer(_))) = &result {
                self.touch(generation, now());
                self.mark_up();
            }
            match result {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(Failure::Answer(e))) => return Err(e),
                Ok(Err(Failure::Connection(e))) => {
                    log::debug!("DoH connection to {} broke ({e}); retrying", self.name);
                    self.discard(generation);
                }
                Err(_) => {
                    // A connection that stops answering (for example after the device
                    // slept) is dropped, so the next query connects again.
                    self.discard(generation);
                    self.mark_down(now());
                    return Err(DohError::Timeout);
                }
            }
        }
        let attempt = async {
            let (generation, sender) = self
                .connected_sender(tls, now)
                .await
                .map_err(Failure::Connection)?;
            let result = self.exchange(sender, body.clone()).await;
            if let Ok(_) | Err(Failure::Answer(_)) = &result {
                self.touch(generation, now());
            }
            result
        };
        let result = timeout(COLD_DEADLINE, attempt)
            .await
            .unwrap_or(Err(Failure::Connection(DohError::Timeout)));
        match &result {
            Ok(_) | Err(Failure::Answer(_)) => self.mark_up(),
            Err(Failure::Connection(_)) => self.mark_down(now()),
        }
        result.map_err(Failure::into_error)
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The open connection, unless it has been idle for longer than [`MAX_IDLE`]: after the
    /// device sleeps it is probably dead, and finding out would cost the warm deadline.
    fn open_sender(&self, now: u64) -> Option<(u64, SendRequest<Full<Bytes>>)> {
        let mut slot = self.slot();
        let sender = slot.sender.as_ref().filter(|s| !s.is_closed())?.clone();
        let idle = now.saturating_sub(slot.last_used);
        if idle > MAX_IDLE.as_secs() {
            log::debug!(
                "DoH connection to {} was idle for {idle} s; reconnecting",
                self.name
            );
            slot.sender = None;
            return None;
        }
        Some((slot.generation, sender))
    }

    /// Records that the connection `generation` just completed a request.
    fn touch(&self, generation: u64, now: u64) {
        let mut slot = self.slot();
        if slot.generation == generation {
            slot.last_used = slot.last_used.max(now);
        }
    }

    fn discard(&self, generation: u64) {
        let mut slot = self.slot();
        if slot.generation == generation {
            slot.sender = None;
        }
    }

    /// The open connection, or a new one. Queries that arrive while a connection is being
    /// opened wait for it instead of opening their own.
    async fn connected_sender(
        &self,
        tls: &TlsConnector,
        now: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<(u64, SendRequest<Full<Bytes>>), DohError> {
        let _connecting = self.connecting.lock().await;
        if let Some(open) = self.open_sender(now()) {
            return Ok(open);
        }
        let sender = self.connect(tls).await?;
        let mut slot = self.slot();
        slot.generation += 1;
        slot.sender = Some(sender.clone());
        slot.last_used = now();
        Ok((slot.generation, sender))
    }

    async fn connect(&self, tls: &TlsConnector) -> Result<SendRequest<Full<Bytes>>, DohError> {
        let tcp = TcpStream::connect(self.addr)
            .await
            .map_err(|e| DohError::Connect(e.to_string()))?;
        tcp.set_nodelay(true)
            .map_err(|e| DohError::Connect(e.to_string()))?;
        let stream = tls
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| DohError::Tls(e.to_string()))?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(DohError::Tls("the upstream did not choose h2".to_string()));
        }
        let (sender, connection) = http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(64 * 1024)
            .initial_connection_window_size(256 * 1024)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|e| DohError::Http(e.to_string()))?;
        // The connection future drives the socket; nothing moves unless it is polled.
        let name = self.name.clone();
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                log::debug!("DoH connection to {name} closed: {e}");
            }
        });
        log::debug!("connected to DoH upstream {}", self.name);
        Ok(sender)
    }

    async fn exchange(
        &self,
        mut sender: SendRequest<Full<Bytes>>,
        body: Bytes,
    ) -> Result<Vec<u8>, Failure> {
        let broken = |e: hyper::Error| Failure::Connection(DohError::Http(e.to_string()));
        sender.ready().await.map_err(broken)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(Full::new(body))
            .expect("a parsed URI and constant headers make a valid request");
        let response = sender.send_request(request).await.map_err(broken)?;
        if response.status() != StatusCode::OK {
            return Err(Failure::Answer(DohError::Status(
                response.status().as_u16(),
            )));
        }
        let body = Limited::new(response.into_body(), MAX_ANSWER_LEN)
            .collect()
            .await
            .map_err(|e| {
                if e.is::<LengthLimitError>() {
                    Failure::Answer(DohError::BadAnswer(format!(
                        "longer than {MAX_ANSWER_LEN} bytes"
                    )))
                } else {
                    Failure::Connection(DohError::Http(e.to_string()))
                }
            })?;
        let answer = body.to_bytes().to_vec();
        if answer.len() < DNS_HEADER_LEN {
            return Err(Failure::Answer(DohError::BadAnswer(
                "shorter than a DNS header".to_string(),
            )));
        }
        Ok(answer)
    }
}
