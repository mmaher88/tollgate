//! Downloads from local HTTP and HTTPS servers; one ignored test uses the network.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use devproxy::args::DEFAULT_LISTS;
use devproxy::fetch::{FetchError, Fetcher, MAX_REDIRECTS, load_source};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const LIST: &str = "! Title: local list\n||ads.example^\n";

async fn route(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = |status: u16, location: Option<&str>, body: &'static str| {
        let mut builder = Response::builder().status(status);
        if let Some(location) = location {
            builder = builder.header("location", location);
        }
        Ok(builder
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap())
    };
    let host = request
        .headers()
        .get("host")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    match request.uri().path() {
        "/list.txt" => response(200, None, LIST),
        "/relative" => response(302, Some("/list.txt"), ""),
        "/absolute" => response(301, Some(&format!("http://{host}/list.txt")), ""),
        "/loop" => response(302, Some("/loop"), ""),
        "/odd" => response(302, Some("list.txt"), ""),
        _ => response(404, None, "not here"),
    }
}

/// A plain HTTP/1.1 server on 127.0.0.1.
async fn http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service_fn(route)),
            );
        }
    });
    addr
}

/// An HTTPS server for `localhost` and a client configuration trusting its CA.
async fn https_server() -> (SocketAddr, Arc<ClientConfig>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(route))
                    .await;
            });
        }
    });
    (addr, Arc::new(client))
}

#[tokio::test]
async fn downloads_a_list_over_http() {
    let addr = http_server().await;
    let text = Fetcher::new()
        .get_text(&format!("http://{addr}/list.txt"))
        .await
        .unwrap();
    assert_eq!(text, LIST);
}

#[tokio::test]
async fn follows_relative_and_absolute_redirects() {
    let addr = http_server().await;
    let fetcher = Fetcher::new();
    for path in ["relative", "absolute"] {
        let text = fetcher
            .get_text(&format!("http://{addr}/{path}"))
            .await
            .unwrap();
        assert_eq!(text, LIST, "{path}");
    }
}

#[tokio::test]
async fn failures_are_errors() {
    let addr = http_server().await;
    let fetcher = Fetcher::new();
    assert_eq!(
        fetcher.get_text(&format!("http://{addr}/missing")).await,
        Err(FetchError::Status(404))
    );
    assert_eq!(
        fetcher.get_text(&format!("http://{addr}/loop")).await,
        Err(FetchError::TooManyRedirects)
    );
    assert_eq!(
        fetcher.get_text(&format!("http://{addr}/odd")).await,
        Err(FetchError::InvalidUrl("list.txt".to_string()))
    );
    assert_eq!(
        fetcher.get_text("ftp://example.com/list.txt").await,
        Err(FetchError::InvalidUrl(
            "ftp://example.com/list.txt".to_string()
        ))
    );
    assert_eq!(MAX_REDIRECTS, 5);
}

#[tokio::test]
async fn downloads_over_https_with_the_given_roots() {
    let (addr, client) = https_server().await;
    let url = format!("https://localhost:{}/list.txt", addr.port());
    let text = Fetcher::with_tls(client).get_text(&url).await.unwrap();
    assert_eq!(text, LIST);
    // The default roots do not trust the test CA.
    let error = Fetcher::new().get_text(&url).await.unwrap_err();
    assert!(matches!(error, FetchError::Tls(..)), "{error:?}");
}

#[tokio::test]
async fn sources_are_files_or_urls() {
    let addr = http_server().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("list.txt");
    std::fs::write(&file, LIST).unwrap();
    let fetcher = Fetcher::new();
    assert_eq!(
        load_source(&fetcher, file.to_str().unwrap()).await.unwrap(),
        LIST
    );
    assert_eq!(
        load_source(&fetcher, &format!("http://{addr}/list.txt"))
            .await
            .unwrap(),
        LIST
    );
    let missing = dir.path().join("missing.txt");
    let error = load_source(&fetcher, missing.to_str().unwrap())
        .await
        .unwrap_err();
    assert!(error.starts_with(missing.to_str().unwrap()), "{error}");
}

/// Needs the network. Run with:
/// `cargo test -p devproxy --test fetch -- --ignored`
#[tokio::test]
#[ignore = "downloads EasyList from easylist.to"]
async fn downloads_easylist() {
    let (_, url) = DEFAULT_LISTS[0];
    let text = Fetcher::new().get_text(url).await.unwrap();
    assert!(text.contains("! Title: EasyList"), "{}", &text[..200]);
    assert!(text.lines().count() > 10_000);
}
