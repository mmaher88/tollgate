//! A local DNS-over-HTTPS server: HTTP/2 over rustls, with a leaf certificate for
//! [`TLS_NAME`] issued by a certificate authority that rcgen makes for each server.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tollgate_dns::DohResolver;
use tollgate_policy::DohUpstream;

pub const TLS_NAME: &str = "doh.test";

/// How the server treats requests from now on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Answers with [`answer_for`].
    Answer,
    /// Answers with this HTTP status and an empty body.
    Status(u16),
    /// Answers 200 with a 5-byte body.
    Short,
    /// Answers once the test calls [`TestServer::open_gate`].
    Gated,
}

/// One request as the server saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub uri: String,
    pub content_type: Option<String>,
    pub accept: Option<String>,
    pub body: Vec<u8>,
}

struct State {
    mode: Mutex<Mode>,
    connections: AtomicUsize,
    requests: AtomicUsize,
    seen: Mutex<Vec<Seen>>,
    gate: Semaphore,
}

pub struct TestServer {
    pub addr: SocketAddr,
    /// The test certificate authority's certificate, to pass as an extra root.
    pub ca: CertificateDer<'static>,
    state: Arc<State>,
}

fn certificates() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Tollgate test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![TLS_NAME.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (ca_cert.der().clone(), leaf.der().clone(), key)
}

impl TestServer {
    /// Starts serving on 127.0.0.1 with an ephemeral port, in `Answer` mode.
    pub async fn start() -> TestServer {
        let (ca, leaf, key) = certificates();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(State {
            mode: Mutex::new(Mode::Answer),
            connections: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            gate: Semaphore::new(0),
        });
        let accepting = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                accepting.connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_connection(acceptor.clone(), tcp, accepting.clone()));
            }
        });
        TestServer { addr, ca, state }
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.state.mode.lock().unwrap() = mode;
    }

    /// TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// Requests received so far, answered or not.
    pub fn requests(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    /// Lets every waiting and future `Gated` request answer.
    pub fn open_gate(&self) {
        self.state.gate.add_permits(10_000);
    }

    /// This server as an upstream with the right TLS name.
    pub fn upstream(&self) -> DohUpstream {
        self.upstream_named(TLS_NAME)
    }

    pub fn upstream_named(&self, tls_name: &str) -> DohUpstream {
        DohUpstream {
            ip: self.addr.ip(),
            port: self.addr.port(),
            tls_name: tls_name.to_string(),
            path: "/dns-query".to_string(),
        }
    }
}

async fn serve_connection(acceptor: TlsAcceptor, tcp: tokio::net::TcpStream, state: Arc<State>) {
    let Ok(tls) = acceptor.accept(tcp).await else {
        return;
    };
    let service = service_fn(move |request| handle(state.clone(), request));
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder.max_concurrent_streams(256);
    let _ = builder.serve_connection(TokioIo::new(tls), service).await;
}

async fn handle(
    state: Arc<State>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await?.to_bytes().to_vec();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    state.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        content_type: header("content-type"),
        accept: header("accept"),
        body: body.clone(),
    });
    state.requests.fetch_add(1, Ordering::SeqCst);
    let mode = *state.mode.lock().unwrap();
    match mode {
        Mode::Answer => {}
        Mode::Status(code) => {
            return Ok(Response::builder()
                .status(code)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
        Mode::Short => return Ok(Response::new(Full::new(Bytes::from_static(b"short")))),
        Mode::Gated => state.gate.acquire().await.unwrap().forget(),
    }
    Ok(Response::builder()
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(answer_for(&body))))
        .unwrap())
}

/// The answer to `query`: its header and question, QR and RA set, OPT and anything else
/// after the question dropped, and one record `192.0.2.1` with a TTL of 300 whose owner
/// name points at the question.
pub fn answer_for(query: &[u8]) -> Vec<u8> {
    let mut end = 12;
    while query[end] != 0 {
        end += 1 + usize::from(query[end]);
    }
    end += 1 + 4;
    let mut answer = query[..end].to_vec();
    answer[2] |= 0x80;
    answer[3] = 0x80;
    answer[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
    answer
}

/// A resolver for `upstreams` that trusts the test authorities of `servers`.
pub fn trusting(upstreams: Vec<DohUpstream>, servers: &[&TestServer]) -> DohResolver {
    let roots: Vec<_> = servers.iter().map(|server| server.ca.clone()).collect();
    DohResolver::with_extra_roots(upstreams, &roots).unwrap()
}

/// An upstream on a local port where nothing listens, so connecting fails at once.
pub async fn closed_upstream() -> DohUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    DohUpstream {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        tls_name: TLS_NAME.to_string(),
        path: "/dns-query".to_string(),
    }
}
