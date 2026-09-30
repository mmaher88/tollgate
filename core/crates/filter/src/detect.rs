//! Telling a hosts file from a list in adblock syntax by its content, so that a list added
//! with the wrong type can still be compiled by the parser that reads it.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv6Addr};

use crate::ListFormat;

/// Guesses how a list is written from its rule lines.
///
/// Blank lines and comments are left out: lines that start with `!` or `#` (comments in
/// adblock and hosts syntax; generic `##` element hiding rules, which Tollgate never
/// applies, go with them) and `[` headers such as `[Adblock Plus 2.0]`. Every other line,
/// with surrounding whitespace and a Windows line ending removed, is a hosts line when it
/// has one of the two shapes the hosts parser reads:
///
/// - an IP address (IPv4, or IPv6 with an optional `%zone`) followed by at least one more
///   field that is not a `#` comment, as in `0.0.0.0 ads.example`, `127.0.0.1 localhost`
///   or `::1 localhost`;
/// - a single host name, optionally followed by whitespace and a `#` comment, as in lists
///   with one name per line: at least two labels of letters, digits, `-` and `_`, each
///   starting with a letter or digit, the last not all digits.
///
/// Any other line is adblock syntax: `||ads.example^`, `/banner/*`, `example.com##.ad`.
///
/// The result is the format of the majority of the rule lines: `Hosts` when hosts lines
/// outnumber the others, `Adblock` when the others outnumber them, and `None` when there
/// are no rule lines (an empty list, or only comments) or both kinds are equally many,
/// which gives no verdict. A majority, because each DNS parser reads only its own kind of
/// line (the hosts parser skips `||name^` rules, the adblock parser skips `0.0.0.0 name`
/// lines), so the majority names the parser that reads more of the list, and a few lines
/// of the other shape do not change the verdict. In the default lists, no rule line of the
/// adblock lists has a hosts shape and every rule line of the StevenBlack hosts file does.
pub fn detect_format(text: &str) -> Option<ListFormat> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut hosts = 0_u64;
    let mut other = 0_u64;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['!', '#', '[']) {
            continue;
        }
        if is_hosts_line(line) {
            hosts += 1;
        } else {
            other += 1;
        }
    }
    match hosts.cmp(&other) {
        Ordering::Greater => Some(ListFormat::Hosts),
        Ordering::Less => Some(ListFormat::Adblock),
        Ordering::Equal => None,
    }
}

/// Whether a trimmed rule line has one of the two hosts shapes described at
/// [`detect_format`].
fn is_hosts_line(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    let Some(first) = fields.next() else {
        return false;
    };
    let second = fields.next();
    if is_address(first) {
        // An address alone names no host; the hosts parser skips it too.
        return second.is_some_and(|field| !field.starts_with('#'));
    }
    is_host_name(first) && second.is_none_or(|field| field.starts_with('#'))
}

/// An IPv4 or IPv6 address, or an IPv6 address with a zone such as `fe80::1%lo0`.
fn is_address(field: &str) -> bool {
    match field.split_once('%') {
        Some((address, _zone)) => address.parse::<Ipv6Addr>().is_ok(),
        None => field.parse::<IpAddr>().is_ok(),
    }
}

/// A host name as a hosts file writes it, with an optional trailing dot: at least two
/// labels of at most 63 letters, digits, `-` and `_`, each starting with a letter or digit,
/// the last not all digits, at most 253 bytes. Stricter than the hosts parser, which also
/// takes labels that start with `-` or `_`: EasyPrivacy has file name suffixes such as
/// `-name.js` and `_name.js` on lines of their own, and those must not count as host names.
fn is_host_name(field: &str) -> bool {
    let name = field.strip_suffix('.').unwrap_or(field);
    if name.len() > 253 {
        return false;
    }
    let mut labels = 0;
    let mut last = "";
    for label in name.split('.') {
        let valid = label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return false;
        }
        labels += 1;
        last = label;
    }
    labels >= 2 && !last.bytes().all(|b| b.is_ascii_digit())
}
