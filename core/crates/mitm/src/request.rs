//! One request on an intercepted connection.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderValue};
use hyper::{HeaderMap, Request, Response, StatusCode, Uri, Version};
use tollgate_common::clock::unix_secs;
use tollgate_policy::Decision;

use crate::body::{Body, DoneBody, blocked, blocked_page, status, text};
use crate::filtering::is_blocked;
use crate::idle::InFlight;
use crate::intercept::Origin;
use crate::proxy::State;
use crate::upstream::{
    UpstreamError, certificate_problem, closed_without_response, http11_required, is_unreachable,
    is_unverified_certificate, learn_from_failure, needs_passthrough,
};
use crate::websocket;

/// Ends a request without a response. hyper closes an HTTP/1.1 connection and resets an
/// HTTP/2 stream, so the client sees a network error: for an upstream failure, the one it
/// would see without the proxy.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NoResponse {
    /// The upstream could not be reached, or closed or reset the connection before any
    /// response; or any other upstream failure of a browser's request that is not a
    /// navigation (see [`failure`]). The HTTP/2 stream is reset with INTERNAL_ERROR.
    #[error("no response: the upstream is unreachable, closed the connection or failed")]
    Closed,
    /// The upstream failure made the host a learned pin (see
    /// `upstream::learn_from_failure`). The client connection closes too (HTTP/2 GOAWAY),
    /// and the HTTP/2 stream is reset with the reason carried here: REFUSED_STREAM, since
    /// the upstream never processed the request, so the client may retry it on a new
    /// connection, whose `CONNECT` is now passed through.
    #[error("no response: the host is passed through from now on")]
    PassedThrough(#[source] h2::Error),
    /// A browser's request on a blocked host's connection (see
    /// [`answer_on_blocked_connection`]), and a blocked request from a browser that is not
    /// a top-level navigation (see [`answer_blocked`]). It does not close the connection by
    /// itself: the HTTP/2 stream is reset with the reason carried here and the connection
    /// stays open for the client's next request, while HTTP/1.1 closes the connection, as
    /// after any error. Built by [`NoResponse::blocked`], whose reason is chosen there.
    #[error("no response: blocked")]
    Blocked(#[source] h2::Error),
    /// A request on a blocked host's connection after the DNS blocklist was reloaded, which
    /// may no longer block the host. The client connection closes too (HTTP/2 GOAWAY), and
    /// the HTTP/2 stream is reset with the reason carried here: REFUSED_STREAM, which tells
    /// the client that the request was not processed and may be retried on a new
    /// connection, whose `CONNECT` is classified again with the new lists.
    #[error("no response: the DNS blocklist changed")]
    ListsChanged(#[source] h2::Error),
}

impl NoResponse {
    /// For a request whose failure made the host a learned pin; the HTTP/2 stream is reset
    /// with `reason`.
    pub(crate) fn passed_through(reason: h2::Reason) -> NoResponse {
        NoResponse::PassedThrough(reason.into())
    }

    /// For a browser's request to a blocked host (see [`answer_on_blocked_connection`]),
    /// and for a blocked request from a browser (see [`answer_blocked`]). The HTTP/2 stream
    /// is reset with INTERNAL_ERROR, which says only that the request failed, as
    /// [`NoResponse::Closed`] says for an unreachable upstream, so a blocked request fails
    /// like any other network error.
    /// The other reasons say more than that: REFUSED_STREAM tells the client that the
    /// request was never processed and may be retried, on a new connection if need be (RFC
    /// 9113, section 8.7), and HTTP_1_1_REQUIRED asks for a retry over HTTP/1.1 on a new
    /// connection, and a blocked request must invite no retry; CANCEL is for a stream the
    /// sender no longer needs and NO_ERROR for one that ended normally, neither of which is
    /// true here.
    pub(crate) fn blocked() -> NoResponse {
        NoResponse::Blocked(h2::Reason::INTERNAL_ERROR.into())
    }

    /// For a request on a blocked host's connection after the DNS blocklist was reloaded;
    /// the HTTP/2 stream is reset with REFUSED_STREAM (see [`NoResponse::ListsChanged`]).
    pub(crate) fn lists_changed() -> NoResponse {
        NoResponse::ListsChanged(h2::Reason::REFUSED_STREAM.into())
    }

    /// True when the client connection should close as well.
    pub(crate) fn closes_connection(&self) -> bool {
        matches!(
            self,
            NoResponse::PassedThrough(_) | NoResponse::ListsChanged(_)
        )
    }
}

/// The service for one request on an intercepted connection. An upstream that cannot be
/// reached, that hangs up without answering, or whose TLS failure makes the host a learned
/// pin, gets [`NoResponse`] rather than a `502`: the proxy answered the `CONNECT` and the
/// TLS handshake itself, so a `502` over its trusted leaf would be an ordinary server
/// response to the browser, shown as an empty page, and would keep it from falling back
/// from `https://` to `http://`. A request from a browser that is not a navigation gets
/// [`NoResponse`] too when it is blocked (see [`answer_blocked`]) and for any other
/// upstream failure (see [`failure`]).
pub(crate) async fn handle(
    state: Arc<State>,
    origin: Arc<Origin>,
    in_flight: InFlight,
    request: Request<Incoming>,
) -> Result<Response<Body>, NoResponse> {
    diag_request(&state, &origin, &request);
    let http1 = request.version() < Version::HTTP_2;
    // The client connection closes after this request when its host is now passed through
    // (a pin learned on another connection, or by this request), so the client's next
    // request opens a new `CONNECT` instead of coming back here.
    let passed_through = matches!(
        state.ctx.policy.classify(&origin.name, unix_secs()),
        Decision::Passthrough(_)
    );
    let (mut response, untrusted) = match forward(&state, &origin, request).await {
        Ok(answer) => answer,
        Err(e) => {
            // HTTP/2 gets GOAWAY; HTTP/1.1 closes after any service error anyway.
            if passed_through || e.closes_connection() {
                in_flight.request_close();
            }
            drop(in_flight);
            return Err(e);
        }
    };
    // An upgraded WebSocket no longer belongs to the HTTP connection; leave it alone.
    if (passed_through || untrusted) && response.status() != StatusCode::SWITCHING_PROTOCOLS {
        // HTTP/2 gets GOAWAY; HTTP/1.1 closes after this response, which says so.
        in_flight.request_close();
        if http1 {
            response
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
    }
    Ok(response.map(|body| DoneBody::new(body, move || drop(in_flight)).boxed_unsync()))
}

/// The answer to a request that the filter engine blocks, or, in absolute form, whose host
/// the DNS blocklist blocks, chosen from the request's `Sec-Fetch-Dest` header. Browsers,
/// WebKit among them, send it with every request to an `https://` URL (Fetch Metadata),
/// and apps' own HTTP clients send none:
///
/// - `document`, a top-level navigation, gets [`blocked_page`], which says that Tollgate
///   blocked it.
/// - Any other value (`script`, `image`, `style`, `font`, `iframe`, `websocket`, `empty`
///   for `fetch()` and XHR, and so on) gets no response ([`NoResponse::blocked`]): the
///   HTTP/2 stream is reset and the connection stays open, and an HTTP/1.1 connection
///   closes. The page sees a network error, as it would with a blocker inside the browser,
///   so pages that treat a failed request as blocked, such as ad-block tests, see it
///   blocked; to them a `403` is a response, so the request loaded. A request that fails
///   on a working connection gives iOS no reason to try another network (see
///   `crate::sink`).
/// - No header, an app, gets [`blocked`]'s empty `403`: an SDK that retries network errors
///   could retry a request that fails without a response again and again, while an HTTP
///   error ends it.
///
/// Stats and the blocked log do not depend on the answer: `crate::filtering` records the
/// block before this is called.
pub(crate) fn answer_blocked(headers: &HeaderMap) -> Result<Response<Body>, NoResponse> {
    match Destination::of(headers) {
        Destination::App => Ok(blocked()),
        Destination::Document => Ok(blocked_page()),
        Destination::Subresource => Err(NoResponse::blocked()),
    }
}

/// The answer to a request on a blocked host's connection (see `crate::sink`), chosen from
/// its `Sec-Fetch-Dest` header as in [`answer_blocked`], except for a navigation:
///
/// - No header, an app, gets [`blocked`]'s empty `403`, for the reason given there: on a
///   device, an app's telemetry SDKs sent the batches that failed here again and again,
///   239 requests in 5 minutes.
/// - Any value, `document` included, gets no response ([`NoResponse::blocked`]), so a
///   navigation to the host shows the browser's own error page, as when the host is
///   blocked by DNS alone (HTTPS filtering off).
pub(crate) fn answer_on_blocked_connection(
    headers: &HeaderMap,
) -> Result<Response<Body>, NoResponse> {
    match Destination::of(headers) {
        Destination::App => Ok(blocked()),
        Destination::Document | Destination::Subresource => Err(NoResponse::blocked()),
    }
}

/// The Fetch Metadata request header that says what a browser will do with the response.
const SEC_FETCH_DEST: &str = "sec-fetch-dest";

/// Who sent a request and what for, as its `Sec-Fetch-Dest` header says (see
/// [`answer_blocked`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Destination {
    /// No header: an app's own HTTP client.
    App,
    /// `document`, in any case: a browser's top-level navigation.
    Document,
    /// Any other value: a browser's request for part of a page, `fetch()` and XHR
    /// included.
    Subresource,
}

impl Destination {
    fn of(headers: &HeaderMap) -> Destination {
        match headers.get(SEC_FETCH_DEST) {
            None => Destination::App,
            Some(dest) if dest.as_bytes().eq_ignore_ascii_case(b"document") => {
                Destination::Document
            }
            Some(_) => Destination::Subresource,
        }
    }
}

/// Filters and forwards one request; a blocked one, WebSocket upgrades included, is
/// answered by [`answer_blocked`]. The flag is true when a WebSocket upstream's TLS
/// failed in a way that makes the host a learned pin (see `upstream::needs_passthrough`);
/// any other request that teaches a pin gets [`NoResponse::PassedThrough`].
async fn forward(
    state: &State,
    origin: &Origin,
    mut request: Request<Incoming>,
) -> Result<(Response<Body>, bool), NoResponse> {
    // An HTTP/2 client may reuse this connection for another host it believes shares the
    // certificate. The leaf and the upstream belong to one origin, so send it elsewhere.
    if request.version() == Version::HTTP_2
        && let Some(authority) = request.uri().authority()
        && !origin.matches(authority)
    {
        return Ok((status(StatusCode::MISDIRECTED_REQUEST), false));
    }
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_string();
    let websocket = websocket::is_upgrade(&request);
    let (scheme, forced_type) = if websocket {
        ("wss", Some("websocket"))
    } else {
        ("https", None)
    };
    let url = format!("{scheme}://{}{path_and_query}", origin.authority());
    if is_blocked(
        &state.ctx,
        &url,
        request.uri().path(),
        request.headers(),
        forced_type,
    ) {
        return answer_blocked(request.headers()).map(|response| (response, false));
    }
    if websocket {
        return Ok(websocket::forward(state, origin.target(), request).await);
    }
    if let Ok(uri) = url.parse::<Uri>() {
        *request.uri_mut() = uri;
    }
    // The pool takes the request, headers and all.
    let destination = Destination::of(request.headers());
    match state
        .pool
        .send(&origin.target(), request.map(|b| b.boxed_unsync()))
        .await
    {
        Ok(response) => Ok((response, false)),
        Err(e) => {
            state.log_upstream_failure(&origin.authority(), &e);
            failure(state, origin, &e, destination)
        }
    }
}

/// The answer to a request from `destination` that the upstream pool could not send. An
/// upstream that cannot be reached at all, or that closes or resets the connection (or the
/// HTTP/2 stream) before any response without a TLS error, gets no response; no free
/// upstream connection `503`. A TLS failure that makes the host a learned pin gets no
/// response either, and closes the client connection, so the browser retries on a new
/// `CONNECT` (now passed through), or shows its own error page and may fall back to
/// `http://`. Anything else gets `502` (see [`bad_gateway`]), except that a browser's
/// request that is not a navigation gets no response ([`NoResponse::Closed`]): without the
/// proxy the browser would have refused the certificate itself or seen the broken
/// connection, and the page a network error, while to the page a `502` is a response, so
/// the request loaded (an ad-block test counts the host as not blocked). A navigation
/// keeps the `502`, whose text says what went wrong, and an app keeps it, as it keeps the
/// `403` of a blocked request (see [`answer_blocked`]). Pin learning does not depend on
/// `destination`.
fn failure(
    state: &State,
    origin: &Origin,
    error: &UpstreamError,
    destination: Destination,
) -> Result<(Response<Body>, bool), NoResponse> {
    if gets_no_response(error) {
        return Err(NoResponse::Closed);
    }
    if let UpstreamError::Exhausted = error {
        return Ok((status(StatusCode::SERVICE_UNAVAILABLE), false));
    }
    let http11 = http11_required(error);
    if learn_from_failure(&state.ctx, &origin.name, error) {
        // An HTTP/2 client that learns HTTP/1.1 is required retries over HTTP/1.1 on a new
        // connection, which is now passed through, so it talks to the server itself.
        let reason = if http11 {
            h2::Reason::HTTP_1_1_REQUIRED
        } else {
            h2::Reason::REFUSED_STREAM
        };
        return Err(NoResponse::passed_through(reason));
    }
    if http11 || destination == Destination::Subresource {
        return Err(NoResponse::Closed);
    }
    Ok((bad_gateway(error), false))
}

/// True for the failures that get [`NoResponse`] whoever sent the request, in [`failure`]
/// and in [`crate::forward::forward`].
pub(crate) fn gets_no_response(error: &UpstreamError) -> bool {
    is_unreachable(error) || closed_without_response(error)
}

/// `502` for a failed upstream request (on an intercepted connection, only an app's or a
/// navigation's: see [`failure`]). The client accepted the proxy's certificate (or,
/// for an absolute-form `https://` request, left TLS to the proxy), so it cannot show its
/// own warning for a server certificate that is expired or for another name; a short text
/// says what is wrong instead of an empty page. So does a failure that would make the host
/// a learned pin when it was not learned (see `Policy::learn_upstream_untrusted`: many
/// hosts failing at once look like a captive portal or a network that intercepts HTTPS).
/// Anything else gets an empty `502`.
pub(crate) fn bad_gateway(error: &UpstreamError) -> Response<Body> {
    if let Some(problem) = certificate_problem(error) {
        return text(
            StatusCode::BAD_GATEWAY,
            format!("Tollgate: the server's certificate {problem}, so this site was not loaded.\n"),
        );
    }
    if needs_passthrough(error) && !http11_required(error) {
        let what = if is_unverified_certificate(error) {
            "the server's certificate could not be verified"
        } else {
            "no secure connection to the server could be made"
        };
        return text(
            StatusCode::BAD_GATEWAY,
            format!(
                "Tollgate: {what}, so this site was not loaded. A Wi-Fi sign-in page \
                 (captive portal) or a network filter that intercepts HTTPS can cause this; \
                 if you just joined this network, sign in and reload.\n"
            ),
        );
    }
    status(StatusCode::BAD_GATEWAY)
}

/// Diagnostic build only: logs at info level how the client of an intercepted connection
/// identifies its requests (User-Agent and the Fetch Metadata headers browsers send), at
/// most once a minute per host and User-Agent, to compare with what its `CONNECT` said.
fn diag_request(state: &State, origin: &Origin, request: &Request<Incoming>) {
    let headers = request.headers();
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-")
    };
    let ua = get("user-agent");
    if !state
        .diag_log
        .allow(&format!("request {} {ua}", origin.name))
    {
        return;
    }
    log::info!(
        "diag request {} ua={ua:?} sec-fetch-dest={} sec-fetch-mode={} sec-fetch-site={} version={:?}",
        origin.name,
        get("sec-fetch-dest"),
        get("sec-fetch-mode"),
        get("sec-fetch-site"),
        request.version()
    );
}

#[cfg(test)]
mod tests {
    use std::io;

    use http_body_util::BodyExt;
    use hyper::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE};
    use rustls::CertificateError;

    use super::*;

    fn certificate(error: CertificateError) -> UpstreamError {
        UpstreamError::Connect(io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(error),
        ))
    }

    async fn text(response: Response<Body>) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn fetch_dest(value: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(SEC_FETCH_DEST, HeaderValue::from_static(value));
        }
        headers
    }

    #[tokio::test]
    async fn a_blocked_navigation_gets_a_page_that_says_so() {
        for dest in ["document", "Document"] {
            let response = answer_blocked(&fetch_dest(Some(dest))).unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let headers = response.headers();
            assert_eq!(headers[CONTENT_TYPE], "text/plain; charset=utf-8");
            assert_eq!(headers[CACHE_CONTROL], "no-store");
            assert!(
                text(response)
                    .await
                    .starts_with("Tollgate blocked this page.")
            );
        }
    }

    #[test]
    fn other_blocked_requests_from_a_browser_get_no_response() {
        let dests = "empty script image style font iframe frame video audio websocket worker";
        // A value the Fetch standard does not define, and an empty one.
        for dest in dests.split(' ').chain(["unknown", ""]) {
            let answer = answer_blocked(&fetch_dest(Some(dest)));
            let Err(no_response) = answer else {
                panic!("{dest:?}: {answer:?}");
            };
            assert!(matches!(no_response, NoResponse::Blocked(_)), "{dest:?}");
            assert!(!no_response.closes_connection(), "{dest:?}");
        }
    }

    #[tokio::test]
    async fn a_blocked_request_from_an_app_gets_an_empty_403() {
        let response = answer_blocked(&fetch_dest(None)).unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(text(response).await, "");
    }

    #[tokio::test]
    async fn on_a_blocked_connection_only_an_apps_request_gets_a_response() {
        let response = answer_on_blocked_connection(&fetch_dest(None)).unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(text(response).await, "");

        // A navigation included: the browser shows its own error page.
        for dest in [
            "document", "Document", "empty", "script", "image", "iframe", "",
        ] {
            let answer = answer_on_blocked_connection(&fetch_dest(Some(dest)));
            let Err(no_response) = answer else {
                panic!("{dest:?}: {answer:?}");
            };
            assert!(matches!(no_response, NoResponse::Blocked(_)), "{dest:?}");
            assert!(!no_response.closes_connection(), "{dest:?}");
        }
    }

    #[tokio::test]
    async fn a_certificate_the_client_would_reject_gets_a_502_that_says_so() {
        for (error, says) in [
            (CertificateError::Expired, "expired"),
            (CertificateError::NotValidForName, "another name"),
            (CertificateError::NotValidYet, "not valid yet"),
            (CertificateError::Revoked, "revoked"),
            (
                CertificateError::InvalidPurpose,
                "not meant for a web server",
            ),
        ] {
            let response = bad_gateway(&certificate(error.clone()));
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            let headers = response.headers();
            assert_eq!(headers[CONTENT_TYPE], "text/plain; charset=utf-8");
            assert_eq!(headers[CACHE_CONTROL], "no-store");
            let body = text(response).await;
            assert!(body.starts_with("Tollgate: "), "{error:?}: {body}");
            assert!(body.contains(says), "{error:?}: {body}");
        }

        // What rustls reports for a server whose certificate is for another name, with the
        // 85 bytes of every 502 an app got from such a server in three device logs.
        let error = CertificateError::NotValidForNameContext {
            expected: rustls::pki_types::ServerName::try_from("api.tollgate.test")
                .unwrap()
                .to_owned(),
            presented: vec![r#"DnsName("*.cdn.tollgate.test")"#.to_string()],
        };
        let body = text(bad_gateway(&certificate(error))).await;
        assert_eq!(
            body,
            "Tollgate: the server's certificate is for another name, so this site was not \
             loaded.\n"
        );
        assert_eq!(body.len(), 85);
    }

    /// Reads fail with `error`, or end the connection when it is `None`; writes succeed.
    struct Upstream(Option<io::Error>);

    impl tokio::io::AsyncRead for Upstream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(self.0.take().map_or(Ok(()), Err))
        }
    }

    impl tokio::io::AsyncWrite for Upstream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// What the upstream pool reports when an HTTP/1.1 request fails because reading the
    /// response fails with `read` (`None`: the server closes the connection).
    async fn http1_failure(read: Option<io::Error>) -> UpstreamError {
        use http_body_util::Empty;
        use hyper_util::rt::TokioIo;
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<bytes::Bytes>>(
            TokioIo::new(Upstream(read)),
        )
        .await
        .unwrap();
        tokio::spawn(conn);
        let request = Request::get("/").body(Empty::new()).unwrap();
        UpstreamError::Http(sender.send_request(request).await.unwrap_err())
    }

    fn alert(description: rustls::AlertDescription) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(description),
        )
    }

    #[tokio::test]
    async fn an_upstream_that_hangs_up_gets_no_response() {
        assert!(gets_no_response(&http1_failure(None).await));
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
        ] {
            let error = http1_failure(Some(io::Error::from(kind))).await;
            assert!(gets_no_response(&error), "{kind:?}");
            assert!(!is_unreachable(&error), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn tls_alerts_and_client_certificates_still_get_a_502() {
        // A TLS alert after the handshake keeps its 502, and learns a pin when it says so.
        for (description, learned) in [
            (rustls::AlertDescription::InternalError, false),
            (rustls::AlertDescription::CertificateRequired, true),
        ] {
            let error = http1_failure(Some(alert(description))).await;
            assert!(!gets_no_response(&error), "{description:?}");
            assert_eq!(needs_passthrough(&error), learned, "{description:?}");
        }
        // A server that required a client certificate and hung up is still learned.
        let error = UpstreamError::ClientCertificate(Box::new(http1_failure(None).await));
        assert!(!gets_no_response(&error));
        assert!(needs_passthrough(&error));
        // So is a response the proxy cannot parse.
        let garbled = io::Error::new(io::ErrorKind::InvalidData, "garbled");
        assert!(!gets_no_response(&http1_failure(Some(garbled)).await));
        assert!(!gets_no_response(&UpstreamError::Exhausted));
    }

    /// Failures that would make the host a learned pin, when the burst guard declined to
    /// learn it (a captive portal or a network that intercepts HTTPS): a `502` that says so.
    #[tokio::test]
    async fn a_failure_that_was_not_learned_gets_a_502_that_says_so() {
        for (error, says) in [
            (
                certificate(CertificateError::UnknownIssuer),
                "certificate could not be verified",
            ),
            (
                UpstreamError::Connect(alert(rustls::AlertDescription::ProtocolVersion)),
                "no secure connection",
            ),
        ] {
            let response = bad_gateway(&error);
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            let body = text(response).await;
            assert!(body.starts_with("Tollgate: "), "{error}: {body}");
            assert!(body.contains(says), "{error}: {body}");
            assert!(body.contains("captive portal"), "{error}: {body}");
        }
    }

    #[tokio::test]
    async fn other_upstream_failures_get_an_empty_502() {
        let garbled = io::Error::new(io::ErrorKind::InvalidData, "garbled");
        for error in [
            UpstreamError::Connect(io::Error::from(io::ErrorKind::ConnectionReset)),
            UpstreamError::Connect(alert(rustls::AlertDescription::InternalError)),
            http1_failure(Some(garbled)).await,
        ] {
            let response = bad_gateway(&error);
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert!(response.headers().get(CONTENT_TYPE).is_none());
            assert_eq!(text(response).await, "");
        }
    }
}
