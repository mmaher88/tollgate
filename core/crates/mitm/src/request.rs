//! One request on an intercepted connection.

use std::convert::Infallible;
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
use crate::upstream::learn_from_failure;
use crate::websocket;

pub(crate) async fn handle(
    state: Arc<State>,
    origin: Arc<Origin>,
    in_flight: InFlight,
    request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let http1 = request.version() < Version::HTTP_2;
    let (mut response, close) = respond(&state, &origin, request).await;
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
) -> (Response<Body>, bool) {
    let passed_through = matches!(
        state.ctx.policy.classify(&origin.name, unix_secs()),
        Decision::Passthrough(_)
    );
    let (response, untrusted) = forward(state, origin, request).await;
    (response, passed_through || untrusted)
}

/// Filters and forwards one request. The flag is true when the upstream TLS failed in a way
/// that makes the host a learned pin (see `upstream::needs_passthrough`).
async fn forward(
    state: &State,
    origin: &Origin,
    mut request: Request<Incoming>,
) -> (Response<Body>, bool) {
    // An HTTP/2 client may reuse this connection for another host it believes shares the
    // certificate. The leaf and the upstream belong to one origin, so send it elsewhere.
    if request.version() == Version::HTTP_2
        && let Some(authority) = request.uri().authority()
        && !origin.matches(authority)
    {
        return (status(StatusCode::MISDIRECTED_REQUEST), false);
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
        return (blocked(), false);
    }
    if websocket {
        return websocket::forward(state, origin.target(), request).await;
    }
    if let Ok(uri) = url.parse::<Uri>() {
        *request.uri_mut() = uri;
    }
    match state
        .pool
        .send(&origin.target(), request.map(|b| b.boxed_unsync()))
        .await
    {
        Ok(response) => (response, false),
        Err(e) => {
            log::debug!("upstream {}: {e}", origin.authority());
            let untrusted = learn_from_failure(&state.ctx, &origin.name, &e);
            (status(StatusCode::BAD_GATEWAY), untrusted)
        }
    }
}
