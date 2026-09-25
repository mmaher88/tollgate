use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tollgate_mitm::CertAuthority;

/// A CA made once with `CertAuthority::generate("Tollgate Golden CA")`, so the profile can
/// be compared byte for byte. Test data only; it is trusted nowhere.
const GOLDEN_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUSwyO972LuYZl26O/knpo23gnxrUwCgYIKoZIzj0EAwIw
MDEbMBkGA1UEAwwSVG9sbGdhdGUgR29sZGVuIENBMREwDwYDVQQKDAhUb2xsZ2F0
ZTAeFw0yNjA5MjQxNzE5MDFaFw0zNjA5MjExNzE5MDFaMDAxGzAZBgNVBAMMElRv
bGxnYXRlIEdvbGRlbiBDQTERMA8GA1UECgwIVG9sbGdhdGUwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQijeyB/IHEG+9CMs46DH8LMw+q0kHXMzKPb0+/lwu3EwFg
ya7VPvJ/B1a8Zqe/dvDkB1dltmFRK3ZtAGHTDiaVo0UwQzAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFOoYc6cq4dbmBWJ0fG+7unQxtLcLMBIGA1UdEwEB/wQIMAYB
Af8CAQAwCgYIKoZIzj0EAwIDSAAwRQIgVcnqw/PMBuqFBBYMU474XOlZY1zrVH/9
ehorajcnMtwCIQClBpRh5Yl+MVfg/e7pLTlwbdcdJoa2r5gKe6SKk45zbw==
-----END CERTIFICATE-----
";

const GOLDEN_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGkpevBwv5v9ZSWi8
Mn3hdLcoT0W67/cpl6MCI+mwt2GhRANCAAQijeyB/IHEG+9CMs46DH8LMw+q0kHX
MzKPb0+/lwu3EwFgya7VPvJ/B1a8Zqe/dvDkB1dltmFRK3ZtAGHTDiaV
-----END PRIVATE KEY-----
";

fn golden() -> CertAuthority {
    CertAuthority::from_pem(GOLDEN_CERT, GOLDEN_KEY).unwrap()
}

/// The PEM body on one line is the certificate's base64, encoded by rcgen's PEM writer.
fn pem_base64(pem: &str) -> String {
    pem.lines().filter(|l| !l.starts_with("-----")).collect()
}

#[test]
fn profile_matches_the_expected_plist() {
    let profile = golden().mobileconfig("Tollgate", "dev.tollgate.ca");
    let expected = format!(
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
      <data>{}</data>
      <key>PayloadDescription</key>
      <string>Root certificate used by Tollgate to filter HTTPS requests on this device.</string>
      <key>PayloadDisplayName</key>
      <string>Tollgate</string>
      <key>PayloadIdentifier</key>
      <string>dev.tollgate.ca.certificate</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>F8A7A404-4EDE-842B-A3ED-B4B71BEF20E3</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>Tollgate</string>
  <key>PayloadIdentifier</key>
  <string>dev.tollgate.ca</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>E48B165F-C5F8-8840-AEC2-CA19D5972DEF</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"#,
        pem_base64(GOLDEN_CERT)
    );
    assert_eq!(String::from_utf8(profile).unwrap(), expected);
}

fn between<'a>(text: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    text.split(open)
        .skip(1)
        .map(|rest| &rest[..rest.find(close).unwrap()])
        .collect()
}

#[test]
fn payload_data_is_the_certificate_der() {
    // Every length remainder mod 3 is covered by generating a few CAs.
    for i in 0..6 {
        let ca = CertAuthority::generate(&format!("Tollgate CA {}", "x".repeat(i))).unwrap();
        let profile = String::from_utf8(ca.mobileconfig("Tollgate", "dev.tollgate.ca")).unwrap();
        let data = between(&profile, "<data>", "</data>");
        assert_eq!(data.len(), 1);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            data[0]
        );
        let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        assert_eq!(der.as_ref(), ca.cert_der().as_slice());
    }
}

#[test]
fn uuids_are_stable_per_ca_and_well_formed() {
    let a = golden().mobileconfig("Tollgate", "dev.tollgate.ca");
    assert_eq!(a, golden().mobileconfig("Tollgate", "dev.tollgate.ca"));

    let other = CertAuthority::generate("Another CA").unwrap();
    let a = String::from_utf8(a).unwrap();
    let b = String::from_utf8(other.mobileconfig("Tollgate", "dev.tollgate.ca")).unwrap();
    let uuids_a = between(&a, "<key>PayloadUUID</key>\n", "\n");
    let uuids_b = between(&b, "<key>PayloadUUID</key>\n", "\n");
    assert_eq!(uuids_a.len(), 2);
    assert_ne!(uuids_a, uuids_b);
    for line in uuids_a.iter().chain(&uuids_b) {
        let uuid = line
            .trim()
            .trim_start_matches("<string>")
            .trim_end_matches("</string>");
        let groups: Vec<&str> = uuid.split('-').collect();
        let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
        assert_eq!(lengths, [8, 4, 4, 4, 12], "{uuid}");
        assert!(
            uuid.chars()
                .all(|c| c == '-' || c.is_ascii_digit() || c.is_ascii_uppercase())
        );
        assert!(groups[2].starts_with('8'), "version 8: {uuid}");
        assert!(
            groups[3].starts_with(['8', '9', 'A', 'B']),
            "RFC variant: {uuid}"
        );
    }
}

#[test]
fn names_are_xml_escaped() {
    let profile = golden().mobileconfig("Tom & Jerry's <CA>", "dev.\"tollgate\"");
    let profile = String::from_utf8(profile).unwrap();
    assert_eq!(
        between(&profile, "<key>PayloadDisplayName</key>\n", "\n")
            .iter()
            .map(|l| l.trim())
            .collect::<Vec<_>>(),
        vec![
            "<string>Tom &amp; Jerry&apos;s &lt;CA&gt;</string>",
            "<string>Tom &amp; Jerry&apos;s &lt;CA&gt;</string>"
        ]
    );
    assert!(profile.contains("<string>dev.&quot;tollgate&quot;</string>"));
    assert!(profile.contains("<string>dev.&quot;tollgate&quot;.certificate</string>"));
}
