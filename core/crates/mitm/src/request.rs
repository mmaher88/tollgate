//! One request on an intercepted connection.

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, Uri, Version};

use crate::body::{Body, DoneBody, blocked, status};
use crate::filtering::is_blocked;
use crate::idle::InFlight;
use crate::intercept::Origin;
use crate::proxy::State;

pub(crate) async fn handle(
    state: Arc<State>,
    origin: Arc<Origin>,
    in_flight: InFlight,
    request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let response = respond(&state, &origin, request).await;
    Ok(response.map(|body| DoneBody::new(body, move || drop(in_flight)).boxed_unsync()))
}

async fn respond(state: &State, origin: &Origin, mut request: Request<Incoming>) -> Response<Body> {
    // An HTTP/2 client may reuse this connection for another host it believes shares the
    // certificate. The leaf and the upstream belong to one origin, so send it elsewhere.
    if request.version() == Version::HTTP_2
        && let Some(authority) = request.uri().authority()
        && !origin.matches(authority)
    {
        return status(StatusCode::MISDIRECTED_REQUEST);
    }
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_string();
    let url = format!("https://{}{path_and_query}", origin.authority());
    if is_blocked(
        &state.ctx,
        &url,
        request.uri().path(),
        request.headers(),
        None,
    ) {
        return blocked();
    }
    if let Ok(uri) = url.parse::<Uri>() {
        *request.uri_mut() = uri;
    }
    match state
        .pool
        .send(&origin.target(), request.map(|b| b.boxed_unsync()))
        .await
    {
        Ok(response) => response,
        Err(e) => {
            log::debug!("upstream {}: {e}", origin.authority());
            status(StatusCode::BAD_GATEWAY)
        }
    }
}
