//! Requests sent to the proxy in absolute form (`GET http://host/path`), not tunneled.

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use crate::body::{Body, blocked, status};
use crate::filtering::{is_blocked, is_domain_blocked};
use crate::http::bare_host;
use crate::proxy::State;
use crate::request::{NoResponse, bad_gateway};
use crate::upstream::{Target, UpstreamError, is_unreachable, learn_from_failure};

/// Filters and forwards one request. `https://` URLs are forwarded over TLS; anything
/// that is not an absolute `http://` or `https://` URL gets `400`. An upstream that cannot
/// be reached gets [`NoResponse`]: the client connection closes, so the browser shows its
/// own error page, as without the proxy, instead of an empty `502`.
pub(crate) async fn forward(
    state: &State,
    request: Request<Incoming>,
) -> Result<Response<Body>, NoResponse> {
    let uri = request.uri();
    let tls = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        _ => return Ok(status(StatusCode::BAD_REQUEST)),
    };
    let Some(host) = uri.host().map(bare_host) else {
        return Ok(status(StatusCode::BAD_REQUEST));
    };
    if is_domain_blocked(&state.ctx, host) {
        return Ok(blocked());
    }
    let target = Target {
        tls,
        host: host.to_string(),
        port: uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
        server_name: host.to_string(),
    };
    let url = uri.to_string();
    if is_blocked(&state.ctx, &url, uri.path(), request.headers(), None) {
        return Ok(blocked());
    }
    match state
        .pool
        .send(&target, request.map(|b| b.boxed_unsync()))
        .await
    {
        Ok(response) => Ok(response),
        Err(e) => {
            state.log_upstream_failure(&target.authority(), &e);
            if is_unreachable(&e) {
                return Err(NoResponse::Closed);
            }
            if let UpstreamError::Exhausted = e {
                return Ok(status(StatusCode::SERVICE_UNAVAILABLE));
            }
            // No connection to close: requests here are not tunneled.
            let _ = learn_from_failure(&state.ctx, &target.server_name, &e);
            Ok(bad_gateway(&e))
        }
    }
}
