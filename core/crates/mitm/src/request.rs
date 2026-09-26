//! One request on an intercepted connection.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri, Version};
use tollgate_common::clock::unix_secs;
use tollgate_policy::Decision;

use crate::body::{Body, DoneBody, blocked, status, text};
use crate::filtering::is_blocked;
use crate::idle::InFlight;
use crate::intercept::Origin;
use crate::proxy::State;
use crate::upstream::{
    UpstreamError, certificate_problem, closed_without_response, is_unreachable, learn_from_failure,
};
use crate::websocket;

/// Ends a request without a response, for an upstream that could not be reached or that
/// closed or reset the connection before any response. hyper closes an HTTP/1.1 connection
/// and resets an HTTP/2 stream, so the client sees a connection failure, as it would
/// without the proxy.
#[derive(Debug, thiserror::Error)]
#[error("no response: the upstream is unreachable or closed the connection")]
pub(crate) struct NoResponse;

/// The service for one request on an intercepted connection. An upstream that cannot be
/// reached, or that hangs up without answering, gets [`NoResponse`] rather than a `502`:
/// the proxy answered the `CONNECT` and the TLS handshake itself, so a `502` over its
/// trusted leaf would be an ordinary server response to the browser, shown as an empty
/// page, and would keep it from falling back from `https://` to `http://`.
pub(crate) async fn handle(
    state: Arc<State>,
    origin: Arc<Origin>,
    in_flight: InFlight,
    request: Request<Incoming>,
) -> Result<Response<Body>, NoResponse> {
    let http1 = request.version() < Version::HTTP_2;
    let (mut response, close) = match respond(&state, &origin, request).await {
        Ok(answer) => answer,
        Err(e) => {
            drop(in_flight);
            return Err(e);
        }
    };
    // An upgraded WebSocket no longer belongs to the HTTP connection; leave it alone.
    if close && response.status() != StatusCode::SWITCHING_PROTOCOLS {
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

/// The response, and whether the client connection should close after it: its host is
/// now passed through (a pin learned on another connection, or by this request), so the
/// client's next request should open a new `CONNECT` instead of coming back here.
async fn respond(
    state: &State,
    origin: &Origin,
    request: Request<Incoming>,
) -> Result<(Response<Body>, bool), NoResponse> {
    let passed_through = matches!(
        state.ctx.policy.classify(&origin.name, unix_secs()),
        Decision::Passthrough(_)
    );
    let (response, untrusted) = forward(state, origin, request).await?;
    Ok((response, passed_through || untrusted))
}

/// Filters and forwards one request. The flag is true when the upstream TLS failed in a way
/// that makes the host a learned pin (see `upstream::needs_passthrough`).
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
        return Ok((blocked(), false));
    }
    if websocket {
        return Ok(websocket::forward(state, origin.target(), request).await);
    }
    if let Ok(uri) = url.parse::<Uri>() {
        *request.uri_mut() = uri;
    }
    match state
        .pool
        .send(&origin.target(), request.map(|b| b.boxed_unsync()))
        .await
    {
        Ok(response) => Ok((response, false)),
        Err(e) => {
            state.log_upstream_failure(&origin.authority(), &e);
            failure(state, origin, &e)
        }
    }
}

/// The answer to a request the upstream pool could not send. An upstream that cannot be
/// reached at all, or that closes or resets the connection (or the HTTP/2 stream) before
/// any response without a TLS error, gets no response; no free upstream connection `503`;
/// anything else, TLS failures included, `502` (which may teach the proxy to pass the host
/// through, see [`bad_gateway`]).
fn failure(
    state: &State,
    origin: &Origin,
    error: &UpstreamError,
) -> Result<(Response<Body>, bool), NoResponse> {
    if gets_no_response(error) {
        return Err(NoResponse);
    }
    if let UpstreamError::Exhausted = error {
        return Ok((status(StatusCode::SERVICE_UNAVAILABLE), false));
    }
    let untrusted = learn_from_failure(&state.ctx, &origin.name, error);
    Ok((bad_gateway(error), untrusted))
}

/// True for the failures [`failure`] answers with [`NoResponse`].
fn gets_no_response(error: &UpstreamError) -> bool {
    is_unreachable(error) || closed_without_response(error)
}

/// `502` for a failed upstream request. The client accepted the proxy's certificate (or,
/// for an absolute-form `https://` request, left TLS to the proxy), so it cannot show its
/// own warning for a server certificate that is expired or for another name; a short text
/// says what is wrong instead of an empty page. Anything else gets an empty `502`.
pub(crate) fn bad_gateway(error: &UpstreamError) -> Response<Body> {
    match certificate_problem(error) {
        Some(problem) => text(
            StatusCode::BAD_GATEWAY,
            format!("Tollgate: the server's certificate {problem}, so this site was not loaded.\n"),
        ),
        None => status(StatusCode::BAD_GATEWAY),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use http_body_util::BodyExt;
    use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
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
        use crate::upstream::needs_passthrough;
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

    #[tokio::test]
    async fn other_upstream_failures_get_an_empty_502() {
        for error in [
            certificate(CertificateError::UnknownIssuer),
            UpstreamError::Connect(io::Error::from(io::ErrorKind::ConnectionReset)),
        ] {
            let response = bad_gateway(&error);
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert!(response.headers().get(CONTENT_TYPE).is_none());
            assert_eq!(text(response).await, "");
        }
    }
}
