//! One request on an intercepted connection.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri, Version};
use tollgate_common::clock::unix_secs;
use tollgate_policy::Decision;

use crate::body::{Body, DoneBody, blocked, status};
use crate::filtering::is_blocked;
use crate::idle::InFlight;
use crate::intercept::Origin;
use crate::proxy::State;
use crate::upstream::{UpstreamError, is_unreachable, learn_from_failure};
use crate::websocket;

/// Ends a request without a response. hyper closes an HTTP/1.1 connection and resets an
/// HTTP/2 stream, so the client sees a connection failure, as it would without the proxy.
#[derive(Debug, thiserror::Error)]
#[error("no response: the upstream is unreachable")]
pub(crate) struct NoResponse;

/// The service for one request on an intercepted connection. An upstream that cannot be
/// reached gets [`NoResponse`] rather than a `502`: the proxy answered the `CONNECT` and
/// the TLS handshake itself, so a `502` over its trusted leaf would be an ordinary server
/// response to the browser, shown as an empty page, and would keep it from falling back
/// from `https://` to `http://`.
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

/// The answer to a request the upstream pool could not send. A TLS failure gets `502`
/// (and may teach the proxy to pass the host through), no free upstream connection `503`,
/// and an upstream that cannot be reached at all no response.
fn failure(
    state: &State,
    origin: &Origin,
    error: &UpstreamError,
) -> Result<(Response<Body>, bool), NoResponse> {
    if is_unreachable(error) {
        return Err(NoResponse);
    }
    if let UpstreamError::Exhausted = error {
        return Ok((status(StatusCode::SERVICE_UNAVAILABLE), false));
    }
    let untrusted = learn_from_failure(&state.ctx, &origin.name, error);
    Ok((status(StatusCode::BAD_GATEWAY), untrusted))
}
