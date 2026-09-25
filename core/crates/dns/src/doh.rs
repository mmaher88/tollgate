//! DNS over HTTPS (RFC 8484): POST `application/dns-message` over HTTP/2 to upstreams
//! reached by IP address, with the TLS name set explicitly.
//!
//! Each upstream has one shared connection. Queries are independent futures that clone the
//! connection's sender, so any number of them run at once on the same connection.

use std::net::SocketAddr;
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
/// Queries resolving at once; above it `resolve` fails at once with [`DohError::Busy`].
pub const MAX_IN_FLIGHT: usize = 128;

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
}

struct Upstream {
    name: String,
    addr: SocketAddr,
    server_name: ServerName<'static>,
    uri: Uri,
    slot: std::sync::Mutex<Slot>,
    /// Held while connecting, so concurrent cold queries open one connection, not many.
    connecting: tokio::sync::Mutex<()>,
}

struct Inner {
    upstreams: Vec<Upstream>,
    tls: TlsConnector,
    in_flight: Semaphore,
}

/// DNS over HTTPS client. Cheap to clone; clones share connections and the in-flight limit.
/// `resolve` must run on a tokio runtime (it spawns each connection's driver task), and its
/// future is `Send`, so callers can spawn one task per query.
#[derive(Clone)]
pub struct DohResolver {
    inner: Arc<Inner>,
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
        }
    }

    /// Sends `query` (a DNS message) to each upstream in turn until one answers, and returns
    /// the answer with the query's id. The error is the last upstream's.
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
        for upstream in &self.inner.upstreams {
            match upstream.query(&self.inner.tls, &body).await {
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
        })
    }

    /// One query: an attempt on the open connection if there is one (retried once on a new
    /// connection if that connection turns out to be closed), otherwise an attempt on a new
    /// connection.
    async fn query(&self, tls: &TlsConnector, body: &Bytes) -> Result<Vec<u8>, DohError> {
        if let Some((generation, sender)) = self.open_sender() {
            match timeout(WARM_DEADLINE, self.exchange(sender, body.clone())).await {
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
                    return Err(DohError::Timeout);
                }
            }
        }
        let attempt = async {
            let sender = self.connected_sender(tls).await?;
            self.exchange(sender, body.clone())
                .await
                .map_err(Failure::into_error)
        };
        timeout(COLD_DEADLINE, attempt)
            .await
            .unwrap_or(Err(DohError::Timeout))
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open_sender(&self) -> Option<(u64, SendRequest<Full<Bytes>>)> {
        let slot = self.slot();
        let sender = slot.sender.as_ref().filter(|s| !s.is_closed())?;
        Some((slot.generation, sender.clone()))
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
    ) -> Result<SendRequest<Full<Bytes>>, DohError> {
        let _connecting = self.connecting.lock().await;
        if let Some((_, sender)) = self.open_sender() {
            return Ok(sender);
        }
        let sender = self.connect(tls).await?;
        let mut slot = self.slot();
        slot.generation += 1;
        slot.sender = Some(sender.clone());
        Ok(sender)
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
