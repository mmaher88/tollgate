//! Names that only the local network's resolver can answer: bare device names, names under
//! the suffixes routers and home networks use, and the reverse zones of private and
//! link-local addresses. The public DoH upstreams answer NXDOMAIN for all of them, and
//! sending them there would tell Cloudflare and Quad9 the names of the owner's devices.

/// Suffixes of names only a local resolver knows. `fritz.box` is the name AVM routers give
/// themselves and their network; the rest of `.box` is a public top-level domain.
///
/// Keep in sync with `proxyExceptions` in `ios/Tunnel/PacketTunnelProvider.swift`, which
/// must list `*.<suffix>` for every entry (and `fritz.box` bare) so these names bypass the
/// system proxy. The test `proxy_exceptions_cover_local_suffixes` checks it. `*.local` is
/// the one intended difference: mDNS names bypass the proxy but are not listed here.
const LOCAL_SUFFIXES: &[&str] = &[
    "lan",
    "home.arpa",
    "internal",
    "localdomain",
    "fritz.box",
    "intranet",
    "corp",
    "private",
];

/// Reverse zones of 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7 and fe80::/10.
const LOCAL_REVERSE_ZONES: &[&str] = &[
    "10.in-addr.arpa",
    "16.172.in-addr.arpa",
    "17.172.in-addr.arpa",
    "18.172.in-addr.arpa",
    "19.172.in-addr.arpa",
    "20.172.in-addr.arpa",
    "21.172.in-addr.arpa",
    "22.172.in-addr.arpa",
    "23.172.in-addr.arpa",
    "24.172.in-addr.arpa",
    "25.172.in-addr.arpa",
    "26.172.in-addr.arpa",
    "27.172.in-addr.arpa",
    "28.172.in-addr.arpa",
    "29.172.in-addr.arpa",
    "30.172.in-addr.arpa",
    "31.172.in-addr.arpa",
    "168.192.in-addr.arpa",
    "254.169.in-addr.arpa",
    "c.f.ip6.arpa",
    "d.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
];

/// Whether `name` is `suffix` or ends in `.suffix`, ignoring ASCII letter case. Compares
/// bytes, so a name with other characters never panics.
fn under(name: &str, suffix: &str) -> bool {
    let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
    let Some(start) = name.len().checked_sub(suffix.len()) else {
        return false;
    };
    name[start..].eq_ignore_ascii_case(suffix) && (start == 0 || name[start - 1] == b'.')
}

/// Whether `name` (with or without the final dot, in any letter case) is answered only by
/// the local network's resolver: a single label such as `nas`, a name under `lan`,
/// `home.arpa`, `internal`, `localdomain`, `fritz.box`, `intranet`, `corp` or `private`, or
/// a name in the reverse zone of a private or link-local address. The root is not.
pub fn is_local_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return false;
    }
    !name.contains('.')
        || LOCAL_SUFFIXES
            .iter()
            .chain(LOCAL_REVERSE_ZONES)
            .any(|suffix| under(name, suffix))
}

#[cfg(test)]
mod tests {
    use super::{LOCAL_SUFFIXES, is_local_name};

    /// Every local suffix must bypass the system proxy, or HTTPS pages under it are
    /// intercepted by the extension (and a self-signed LAN device becomes a learned pin).
    #[test]
    fn proxy_exceptions_cover_local_suffixes() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../ios/Tunnel/PacketTunnelProvider.swift"
        );
        let swift = std::fs::read_to_string(path).expect("read PacketTunnelProvider.swift");
        let start = swift
            .find("static let proxyExceptions")
            .expect("proxyExceptions in PacketTunnelProvider.swift");
        let end = start
            + swift[start..]
                .find("\n    ]")
                .expect("end of proxyExceptions");
        let list = &swift[start..end];
        for suffix in LOCAL_SUFFIXES {
            let wildcard = format!("\"*.{suffix}\"");
            assert!(list.contains(&wildcard), "proxyExceptions lacks {wildcard}");
        }
        assert!(
            list.contains("\"fritz.box\""),
            "proxyExceptions lacks \"fritz.box\""
        );
    }

    #[test]
    fn local_names() {
        for name in [
            "nas",
            "nas.",
            "nas.lan",
            "NAS.LAN.",
            "lan",
            "homeassistant.home.arpa.",
            "db.internal",
            "router.localdomain",
            "fritz.box",
            "myfritz.fritz.box.",
            "x.intranet",
            "x.corp",
            "x.private",
            "1.1.168.192.in-addr.arpa.",
            "5.0.0.10.in-addr.arpa",
            "1.0.16.172.in-addr.arpa",
            "1.0.31.172.in-addr.arpa",
            "7.3.254.169.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.6.4.7.0.0.d.f.ip6.arpa.",
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            "x.b.e.f.ip6.arpa",
        ] {
            assert!(is_local_name(name), "{name}");
        }
    }

    #[test]
    fn public_names() {
        for name in [
            "",
            ".",
            "example.com",
            "example.com.",
            "planet.box",
            "evil-lan.example",
            "notlan.com",
            "x.xlan",
            "home.arpa.example",
            "1.1.1.1.in-addr.arpa",
            "1.0.15.172.in-addr.arpa",
            "1.0.32.172.in-addr.arpa",
            "8.8.8.8.in-addr.arpa",
            "1.0.0.2.ip6.arpa",
            "c.e.f.ip6.arpa",
            "in-addr.arpa",
            "caf\u{e9}.lan\u{e9}",
            "\u{e9}lan.example",
        ] {
            assert!(!is_local_name(name), "{name}");
        }
    }
}
