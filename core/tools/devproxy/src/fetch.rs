//! Downloading filter lists over HTTP/1.1 with hyper and the shared rustls configuration.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Incoming;
use hyper::header::{ACCEPT, HOST, LOCATION, USER_AGENT};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Redirects followed before giving up.
pub const MAX_REDIRECTS: usize = 5;
/// Largest list accepted; the biggest default list is about 4.5 MB.
pub const MAX_BODY: usize = 64 * 1024 * 1024;
/// Limit for one request, from connecting to the end of the body.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    #[error("invalid URL {0:?}")]
    InvalidUrl(String),
    #[error("connecting to {0} failed: {1}")]
    Connect(String, String),
    #[error("TLS with {0} failed: {1}")]
    Tls(String, String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
    #[error("the body is larger than {MAX_BODY} bytes")]
    TooLarge,
    #[error("no answer within {REQUEST_TIMEOUT:?}")]
    Timeout,
}

enum Step {
    Body(String),
    Redirect(String),
}

/// An HTTP/1.1 client for `http://` and `https://` URLs. Names are resolved by the system
/// resolver; TLS uses the ring provider and the webpki roots unless configured otherwise.
pub struct Fetcher {
    tls: TlsConnector,
}

impl Default for Fetcher {
    fn default() -> Fetcher {
        Fetcher::new()
    }
}

impl Fetcher {
    pub fn new() -> Fetcher {
        Fetcher::with_tls(tollgate_common::tls::client_config(&[b"http/1.1"]))
    }

    /// A fetcher with its own TLS configuration, for tests against a local server.
    pub fn with_tls(config: Arc<ClientConfig>) -> Fetcher {
        Fetcher {
            tls: TlsConnector::from(config),
        }
    }

    /// GETs `url`, following up to [`MAX_REDIRECTS`] redirects, and returns the body as
    /// text (invalid UTF-8 is replaced). Anything but `200` is an error.
    pub async fn get_text(&self, url: &str) -> Result<String, FetchError> {
        let mut uri: Uri = url
            .parse()
            .map_err(|_| FetchError::InvalidUrl(url.to_string()))?;
        for _ in 0..=MAX_REDIRECTS {
            let step = tokio::time::timeout(REQUEST_TIMEOUT, self.once(&uri))
                .await
                .map_err(|_| FetchError::Timeout)??;
            match step {
                Step::Body(text) => return Ok(text),
                Step::Redirect(location) => uri = follow(&uri, &location)?,
            }
        }
        Err(FetchError::TooManyRedirects)
    }

    async fn once(&self, uri: &Uri) -> Result<Step, FetchError> {
        let invalid = || FetchError::InvalidUrl(uri.to_string());
        let tls = match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => return Err(invalid()),
        };
        let host = uri
            .host()
            .ok_or_else(invalid)?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let authority = uri.authority().ok_or_else(invalid)?.to_string();
        let request = Request::get(uri.path_and_query().map_or("/", |p| p.as_str()))
            .header(HOST, &authority)
            .header(
                USER_AGENT,
                concat!("tollgate-devproxy/", env!("CARGO_PKG_VERSION")),
            )
            .header(ACCEPT, "*/*")
            .body(Empty::<Bytes>::new())
            .map_err(|_| invalid())?;
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| FetchError::Connect(authority.clone(), e.to_string()))?;
        let response = if tls {
            let name = ServerName::try_from(host.clone()).map_err(|_| invalid())?;
            let stream = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| FetchError::Tls(authority.clone(), e.to_string()))?;
            exchange(stream, request).await?
        } else {
            exchange(tcp, request).await?
        };
        let status = response.status();
        if status.is_redirection()
            && let Some(location) = response.headers().get(LOCATION)
        {
            let location = location.to_str().map_err(|_| invalid())?;
            return Ok(Step::Redirect(location.to_string()));
        }
        if status != StatusCode::OK {
            return Err(FetchError::Status(status.as_u16()));
        }
        let body = Limited::new(response.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| {
                if e.is::<http_body_util::LengthLimitError>() {
                    FetchError::TooLarge
                } else {
                    FetchError::Http(e.to_string())
                }
            })?
            .to_bytes();
        Ok(Step::Body(String::from_utf8_lossy(&body).into_owned()))
    }
}

async fn exchange<S>(
    stream: S,
    request: Request<Empty<Bytes>>,
) -> Result<Response<Incoming>, FetchError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("list download connection: {e}");
        }
    });
    sender
        .send_request(request)
        .await
        .map_err(|e| FetchError::Http(e.to_string()))
}

/// The URL a `Location` header points at: absolute, or a path on the same origin.
fn follow(base: &Uri, location: &str) -> Result<Uri, FetchError> {
    let invalid = || FetchError::InvalidUrl(location.to_string());
    let next = if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        let scheme = base.scheme_str().ok_or_else(invalid)?;
        let authority = base.authority().ok_or_else(invalid)?;
        format!("{scheme}://{authority}{location}")
    } else {
        return Err(invalid());
    };
    next.parse().map_err(|_| invalid())
}

/// The text of a list: downloaded when `source` is an `http://` or `https://` URL,
/// otherwise read from the file `source`.
pub async fn load_source(fetcher: &Fetcher, source: &str) -> Result<String, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        fetcher
            .get_text(source)
            .await
            .map_err(|e| format!("{source}: {e}"))
    } else {
        std::fs::read_to_string(source).map_err(|e| format!("{source}: {e}"))
    }
}
