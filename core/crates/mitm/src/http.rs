//! Header and authority helpers shared by the forwarding paths.

use hyper::HeaderMap;
use hyper::header::{self, HeaderName, HeaderValue};

/// Headers that describe one hop and must not be forwarded (RFC 9110, section 7.6.1).
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// Removes hop-by-hop headers, including every header named in `Connection`.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// HTTP/2 clients may send several `Cookie` headers; HTTP/1.1 servers expect one.
pub(crate) fn join_cookies(headers: &mut HeaderMap) {
    let cookies: Vec<&[u8]> = headers
        .get_all(header::COOKIE)
        .iter()
        .map(|v| v.as_bytes())
        .collect();
    if cookies.len() < 2 {
        return;
    }
    let joined = cookies.join(&b"; "[..]);
    if let Ok(value) = HeaderValue::from_bytes(&joined) {
        headers.insert(header::COOKIE, value);
    }
}

/// `host` or `host:port`, leaving out the scheme's default port. IPv6 addresses get
/// brackets.
pub(crate) fn authority(host: &str, port: u16, default_port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// The host without IPv6 brackets or a trailing dot, as used for dialing and policy.
pub(crate) fn bare_host(host: &str) -> &str {
    let host = host.strip_suffix('.').unwrap_or(host);
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}
