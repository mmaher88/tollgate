//! WebSocket upgrades on intercepted connections.
//!
//! Each upgrade gets its own HTTP/1.1 upstream connection (ALPN `http/1.1` only), because
//! an upgraded connection can never go back to the pool. After both sides answer `101`,
//! the two upgraded streams are copied into each other untouched.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{CONNECTION, HOST, HeaderValue, UPGRADE};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::sync::OwnedSemaphorePermit;
use tokio_rustls::TlsConnector;

use crate::body::{Body, DoneBody, empty, status};
use crate::http::strip_hop_by_hop;
use crate::limits::H1_MAX_BUF;
use crate::proxy::State;
use crate::upstream::{Target, UpstreamError, connect_tcp, learn_from_failure};

pub(crate) fn is_upgrade<B>(request: &Request<B>) -> bool {
    request.version() == Version::HTTP_11
        && request
            .headers()
            .get(UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

pub(crate) async fn forward(
    state: &State,
    target: Target,
    mut request: Request<Incoming>,
) -> Response<Body> {
    let (mut sender, permit) = match dial(state, &target).await {
        Ok(dialed) => dialed,
        Err(e) => {
            log::debug!("WebSocket upstream {}: {e}", target.authority());
            learn_from_failure(&state.ctx, &target.server_name, &e);
            return status(StatusCode::BAD_GATEWAY);
        }
    };
    let client_upgrade = hyper::upgrade::on(&mut request);
    let upgrade = request.headers().get(UPGRADE).cloned();
    let (mut parts, body) = request.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts
        .headers
        .insert(CONNECTION, HeaderValue::from_static("upgrade"));
    if let Some(upgrade) = upgrade {
        parts.headers.insert(UPGRADE, upgrade);
    }
    if let Ok(host) = HeaderValue::from_str(&target.authority()) {
        parts.headers.insert(HOST, host);
    }
    if let Some(pq) = parts.uri.path_and_query()
        && let Ok(uri) = pq.as_str().parse::<Uri>()
    {
        parts.uri = uri;
    }
    parts.version = Version::HTTP_11;
    let upstream_request = Request::from_parts(parts, body.boxed_unsync());

    let mut response = match sender.send_request(upstream_request).await {
        Ok(response) => response,
        Err(e) => {
            log::debug!("WebSocket upstream {}: {e}", target.authority());
            return status(StatusCode::BAD_GATEWAY);
        }
    };
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        strip_hop_by_hop(response.headers_mut());
        return response.map(|b| DoneBody::new(b, move || drop(permit)).boxed_unsync());
    }
    let upstream_upgrade = hyper::upgrade::on(&mut response);
    let authority = target.authority();
    state.shutdown.spawn(async move {
        let _permit = permit;
        match tokio::join!(client_upgrade, upstream_upgrade) {
            (Ok(client), Ok(upstream)) => {
                let mut client = TokioIo::new(client);
                let mut upstream = TokioIo::new(upstream);
                if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                    log::debug!("WebSocket {authority}: {e}");
                }
            }
            (client, upstream) => {
                log::debug!(
                    "WebSocket {authority} upgrade failed: client {:?}, upstream {:?}",
                    client.err(),
                    upstream.err()
                );
            }
        }
    });
    let (parts, _) = response.into_parts();
    Response::from_parts(parts, empty())
}

/// A new HTTP/1.1 connection outside the pool, counted against the upstream limit.
async fn dial(
    state: &State,
    target: &Target,
) -> Result<(http1::SendRequest<Body>, OwnedSemaphorePermit), UpstreamError> {
    let permit = state.pool.global_permit().await?;
    let connect = async {
        let resolver = state.options.resolver.as_deref();
        let tcp = connect_tcp(resolver, &target.host, target.port).await?;
        let mut config = (*state.options.upstream_tls).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(target.server_name.clone())
            .map_err(|_| UpstreamError::ServerName(target.server_name.clone()))?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await?;
        let (sender, conn) = http1::Builder::new()
            .max_buf_size(H1_MAX_BUF)
            .handshake(TokioIo::new(tls))
            .await?;
        state.shutdown.spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                log::debug!("WebSocket upstream connection: {e}");
            }
        });
        Ok::<_, UpstreamError>(sender)
    };
    let sender = tokio::time::timeout(state.options.connect_timeout, connect)
        .await
        .map_err(|_| UpstreamError::Timeout)??;
    Ok((sender, permit))
}
