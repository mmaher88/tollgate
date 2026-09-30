//! Host patterns for passthrough lists.

use std::fmt;

use crate::PolicyError;

/// `example.com` matches exactly that host; `*.example.com` matches `example.com` and every
/// subdomain. Matching ignores ASCII case and one trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPattern {
    /// Lowercase, without the `*.` prefix or a trailing dot.
    name: String,
    wildcard: bool,
}

impl HostPattern {
    pub fn parse(s: &str) -> Result<HostPattern, PolicyError> {
        let invalid = |reason| PolicyError::InvalidPattern {
            pattern: s.to_string(),
            reason,
        };
        let trimmed = s.trim();
        let (wildcard, rest) = match trimmed.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, trimmed),
        };
        let rest = rest.strip_suffix('.').unwrap_or(rest);
        if rest.is_empty() {
            return Err(invalid("empty host name"));
        }
        if rest.contains('*') {
            return Err(invalid("a wildcard is only allowed as a leading \"*.\""));
        }
        let name = validate_name(rest).map_err(invalid)?;
        Ok(HostPattern { name, wildcard })
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).as_bytes();
        let name = self.name.as_bytes();
        if host.len() == name.len() {
            return host.eq_ignore_ascii_case(name);
        }
        if !self.wildcard || host.len() <= name.len() {
            return false;
        }
        let split = host.len() - name.len();
        host[split - 1] == b'.' && host[split..].eq_ignore_ascii_case(name)
    }

    /// The host name without `*.`, lowercase.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            write!(f, "*.{}", self.name)
        } else {
            f.write_str(&self.name)
        }
    }
}

/// Checks a host name (no trailing dot) and returns it lowercased.
fn validate_name(name: &str) -> Result<String, &'static str> {
    if name.len() > 253 {
        return Err("host name longer than 253 bytes");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > 63 {
            return Err("label longer than 63 bytes");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("only letters, digits, '-', '_' and '.' are allowed");
        }
    }
    Ok(name.to_ascii_lowercase())
}
