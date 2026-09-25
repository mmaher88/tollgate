//! Checking one request against the filter engine.

use hyper::HeaderMap;
use tollgate_common::stats::Stats;
use tollgate_filter::{Verdict, request_type, source_url};

use crate::ProxyContext;

/// Counts the request and returns true when it must be blocked.
///
/// `url` is the full URL. The request type comes from `forced_type` when given (WebSocket
/// upgrades), otherwise from `Sec-Fetch-Dest`, then `Accept`, then the path extension. The
/// source is the URL itself for a document, otherwise `Referer`, then `Origin`. Without a
/// loaded engine every request is allowed.
pub(crate) fn is_blocked(
    ctx: &ProxyContext,
    url: &str,
    path: &str,
    headers: &HeaderMap,
    forced_type: Option<&'static str>,
) -> bool {
    Stats::inc(&ctx.stats.http_requests);
    let engine = ctx.filter.load();
    let Some(engine) = engine.as_ref() else {
        return false;
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let kind = forced_type
        .unwrap_or_else(|| request_type(header("sec-fetch-dest"), header("accept"), path));
    let source = source_url(url, kind, header("referer"), header("origin"));
    match engine.check(url, source, kind) {
        Verdict::Allow => false,
        Verdict::Block { rule } => {
            Stats::inc(&ctx.stats.http_blocked);
            match rule {
                Some(rule) => log::debug!("blocked {kind} {url} by {rule}"),
                None => log::debug!("blocked {kind} {url}"),
            }
            true
        }
    }
}
