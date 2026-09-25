//! The iOS configuration profile that installs the root certificate.

use std::fmt::Write;

use crate::CertAuthority;

impl CertAuthority {
    /// iOS configuration profile containing only the root certificate.
    ///
    /// `identifier` is the profile's reverse-DNS identifier; the certificate payload uses
    /// `<identifier>.certificate`. Both payload UUIDs are derived from the certificate, so
    /// the same CA always produces the same profile and installing it again replaces the
    /// old one instead of adding a second copy.
    pub fn mobileconfig(&self, display_name: &str, identifier: &str) -> Vec<u8> {
        let der = self.cert_der();
        let profile_uuid = uuid_from(b"tollgate profile", &der);
        let payload_uuid = uuid_from(b"tollgate certificate", &der);
        let name = xml_escape(display_name);
        let id = xml_escape(identifier);
        let data = base64(&der);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>tollgate-ca.cer</string>
      <key>PayloadContent</key>
      <data>{data}</data>
      <key>PayloadDescription</key>
      <string>Root certificate used by Tollgate to filter HTTPS requests on this device.</string>
      <key>PayloadDisplayName</key>
      <string>{name}</string>
      <key>PayloadIdentifier</key>
      <string>{id}.certificate</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{payload_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>{name}</string>
  <key>PayloadIdentifier</key>
  <string>{id}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"#
        )
        .into_bytes()
    }
}

/// A version 8 (RFC 9562 custom) UUID from SHA-256 of `label` and `data`, uppercase.
fn uuid_from(label: &[u8], data: &[u8]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(label);
    ctx.update(data);
    let digest = ctx.finish();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest.as_ref()[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        write!(out, "{byte:02X}").expect("writing to a String cannot fail");
    }
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Standard base64 with padding (RFC 4648), on one line.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= n {
                out.push(ALPHABET[((v >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
