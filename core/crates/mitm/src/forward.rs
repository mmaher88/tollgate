//! Requests sent to the proxy in absolute form (`GET http://host/path`), not tunneled.

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use crate::body::{Body, blocked, status};
use crate::filtering::{is_blocked, is_domain_blocked};
use crate::http::bare_host;
use crate::proxy::State;
use crate::upstream::{Target, learn_from_failure};

/// Filters and forwards one request. `https://` URLs are forwarded over TLS; anything
/// that is not an absolute `http://` or `https://` URL gets `400`.
pub(crate) async fn forward(state: &State, request: Request<Incoming>) -> Response<Body> {
    let uri = request.uri();
    let tls = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        _ => return status(StatusCode::BAD_REQUEST),
    };
    let Some(host) = uri.host().map(bare_host) else {
        return status(StatusCode::BAD_REQUEST);
    };
    if is_domain_blocked(&state.ctx, host) {
        return blocked();
    }
    let target = Target {
        tls,
        host: host.to_string(),
        port: uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
        server_name: host.to_string(),
    };
    let url = uri.to_string();
    if is_blocked(&state.ctx, &url, uri.path(), request.headers(), None) {
        return blocked();
    }
    match state
        .pool
        .send(&target, request.map(|b| b.boxed_unsync()))
        .await
    {
        Ok(response) => response,
        Err(e) => {
            state.log_upstream_failure(&target.authority(), &e);
            // No connection to close: requests here are not tunneled.
            let _ = learn_from_failure(&state.ctx, &target.server_name, &e);
            status(StatusCode::BAD_GATEWAY)
        }
    }
}
