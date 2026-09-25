//! A local DNS-over-HTTPS server on its own thread: HTTP/2 over rustls with a leaf for
//! `doh.test` from a certificate authority rcgen makes for each server. Every answer is
//! `192.0.2.1` with a TTL of 300.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

pub const TLS_NAME: &str = "doh.test";

pub struct DohServer {
    pub addr: SocketAddr,
    /// The test CA, to pass in `EngineOptions::doh_roots`.
    pub ca_der: Vec<u8>,
    requests: Arc<AtomicUsize>,
    gate: Option<Arc<Semaphore>>,
}

impl DohServer {
    /// A server that answers at once.
    pub fn start() -> DohServer {
        DohServer::launch(None)
    }

    /// A server that holds every request until `open_gate`.
    pub fn gated() -> DohServer {
        DohServer::launch(Some(Arc::new(Semaphore::new(0))))
    }

    fn launch(gate: Option<Arc<Semaphore>>) -> DohServer {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Tollgate ffi test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![TLS_NAME.to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let (counter, held) = (requests.clone(), gate.clone());
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        continue;
                    };
                    let (acceptor, counter, held) =
                        (acceptor.clone(), counter.clone(), held.clone());
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let service = service_fn(move |request| {
                            answer(request, counter.clone(), held.clone())
                        });
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            });
        });
        DohServer {
            addr,
            ca_der: ca_cert.der().to_vec(),
            requests,
            gate,
        }
    }

    /// Engine configuration JSON with this server as the only upstream.
    pub fn config_json(&self) -> String {
        format!(
            r#"{{"doh_upstreams":[{{"ip":"{}","port":{},"tls_name":"{TLS_NAME}"}}]}}"#,
            self.addr.ip(),
            self.addr.port()
        )
    }

    /// Requests received so far.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Lets every held and future request answer.
    pub fn open_gate(&self) {
        if let Some(gate) = &self.gate {
            gate.add_permits(10_000);
        }
    }
}

async fn answer(
    request: Request<Incoming>,
    requests: Arc<AtomicUsize>,
    gate: Option<Arc<Semaphore>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let query = request.into_body().collect().await?.to_bytes();
    requests.fetch_add(1, Ordering::SeqCst);
    if let Some(gate) = gate {
        gate.acquire().await.unwrap().forget();
    }
    Ok(Response::builder()
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(answer_for(&query))))
        .unwrap())
}

/// The query's header and question with QR and RA set, and one A record `192.0.2.1` with a
/// TTL of 300 whose owner name points at the question.
fn answer_for(query: &[u8]) -> Vec<u8> {
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
