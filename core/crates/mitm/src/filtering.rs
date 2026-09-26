//! Checking one request against the allowlist and the filter engine, and a host against
//! the DNS blocklist.

use std::net::IpAddr;

use hyper::HeaderMap;
use tollgate_common::clock::unix_secs;
use tollgate_common::events::{BlockEvent, EventKind};
use tollgate_common::stats::Stats;
use tollgate_filter::{Verdict, request_type, source_url};

use crate::ProxyContext;

/// Counts the request and returns true when it must be blocked.
///
/// `url` is the full URL. The request type comes from `forced_type` when given (WebSocket
/// upgrades), otherwise from `Sec-Fetch-Dest`, then `Accept`, then the path extension. The
/// source is the URL itself for a document, otherwise `Referer`, then `Origin`. Without a
/// loaded engine every request is allowed, and so is a request whose own host or page host
/// (the host of the source) is allowlisted. Blocks are recorded in `ctx.events`.
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
    let host = url_host(url);
    let page_host = url_host(source);
    if [host, page_host]
        .into_iter()
        .flatten()
        .any(|h| ctx.policy.is_allowlisted(h))
    {
        return false;
    }
    match engine.check(url, source, kind) {
        Verdict::Allow => false,
        Verdict::Block { rule } => {
            Stats::inc(&ctx.stats.http_blocked);
            match rule {
                Some(rule) => log::debug!("blocked {kind} {url} by {rule}"),
                None => log::debug!("blocked {kind} {url}"),
            }
            if let Some(events) = &ctx.events {
                events.record(BlockEvent {
                    unix_secs: unix_secs(),
                    kind: EventKind::Request,
                    host: host.unwrap_or_default().to_ascii_lowercase(),
                    url: Some(url.to_string()),
                    source_host: page_host.map(str::to_ascii_lowercase),
                });
            }
            true
        }
    }
}

/// True when the DNS blocklist blocks `host` and the allowlist does not cover it: the same
/// decision the tunnel's DNS responder makes for a lookup of the name. Clients that use the
/// proxy send it the name instead of looking it up, so without this check names that only
/// the DNS lists block would load. A block counts in `dns_blocked` and is recorded as a DNS
/// block. IP addresses are never blocked.
pub(crate) fn is_domain_blocked(ctx: &ProxyContext, host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.is_empty() || bare.parse::<IpAddr>().is_ok() {
        return false;
    }
    let domains = ctx.domains.load();
    let Some(domains) = domains.as_ref() else {
        return false;
    };
    if !domains.is_blocked(bare) || ctx.policy.is_allowlisted(bare) {
        return false;
    }
    Stats::inc(&ctx.stats.dns_blocked);
    log::debug!("blocked host {bare} by the DNS blocklist");
    if let Some(events) = &ctx.events {
        events.record(BlockEvent {
            unix_secs: unix_secs(),
            kind: EventKind::Dns,
            host: bare.to_ascii_lowercase(),
            url: None,
            source_host: None,
        });
    }
    true
}

/// The host of an absolute URL, without userinfo, port, IPv6 brackets or a trailing dot.
/// `None` for anything that is not `scheme://host...`, such as an empty source or `null`.
fn url_host(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']')?.0,
        None => authority.split(':').next()?,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::url_host;

    #[test]
    fn url_host_takes_the_bare_host() {
        let cases = [
            ("https://www.example.com/a?b#c", Some("www.example.com")),
            ("https://Example.COM:8443/", Some("Example.COM")),
            ("http://user:pw@host.test:80/x", Some("host.test")),
            ("https://host.test.?q", Some("host.test")),
            ("wss://host.test#frag", Some("host.test")),
            ("http://[2001:db8::1]:8080/", Some("2001:db8::1")),
            ("https://host.test", Some("host.test")),
            ("", None),
            ("null", None),
            ("https:///path", None),
            ("http://[::1/", None),
        ];
        for (url, host) in cases {
            assert_eq!(url_host(url), host, "{url}");
        }
    }
}
