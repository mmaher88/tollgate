use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tollgate_ffi::{
    CA_CERT_FILE, CA_KEY_FILE, TollgateError, ca_mobileconfig, generate_ca, load_ca, sha256_hex,
};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The base64 body of a PEM block on one line, which is the base64 of the DER bytes.
fn pem_body(pem: &str) -> String {
    pem.lines().filter(|l| !l.starts_with("-----")).collect()
}

#[test]
fn generates_once_and_stores_private_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("group");
    let path = dir.to_str().unwrap().to_string();

    let first = generate_ca(path.clone()).unwrap();
    assert!(first.created);
    assert!(first.cert_pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert_eq!(first.sha256_fingerprint.len(), 64);
    assert_eq!(mode(&dir.join(CA_CERT_FILE)), 0o600);
    assert_eq!(mode(&dir.join(CA_KEY_FILE)), 0o600);
    assert_eq!(
        fs::read_to_string(dir.join(CA_CERT_FILE)).unwrap(),
        first.cert_pem
    );
    assert!(
        fs::read_to_string(dir.join(CA_KEY_FILE))
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----\n")
    );

    let second = generate_ca(path).unwrap();
    assert!(!second.created);
    assert_eq!(second.cert_pem, first.cert_pem);
    assert_eq!(second.sha256_fingerprint, first.sha256_fingerprint);

    let ca = load_ca(&dir).unwrap().unwrap();
    assert_eq!(ca.cert_pem(), first.cert_pem);
    assert_eq!(sha256_hex(ca.cert_der()), first.sha256_fingerprint);
    // No temporary files are left behind.
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["ca.key", "ca.pem"]);
}

#[test]
fn a_missing_key_means_a_new_ca() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let first = generate_ca(path.clone()).unwrap();
    fs::remove_file(tmp.path().join(CA_KEY_FILE)).unwrap();
    assert!(load_ca(tmp.path()).unwrap().is_none());
    let second = generate_ca(path).unwrap();
    assert!(second.created);
    assert_ne!(second.cert_pem, first.cert_pem);
}

#[test]
fn an_invalid_stored_ca_is_an_error_and_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join(CA_CERT_FILE), "not a certificate").unwrap();
    fs::write(tmp.path().join(CA_KEY_FILE), "not a key").unwrap();
    let error = generate_ca(tmp.path().to_str().unwrap().to_string()).unwrap_err();
    assert!(
        matches!(&error, TollgateError::Ca { message } if message.starts_with("invalid CA")),
        "{error:?}"
    );
    assert_eq!(
        fs::read_to_string(tmp.path().join(CA_CERT_FILE)).unwrap(),
        "not a certificate"
    );
    assert!(load_ca(tmp.path()).is_err());
}

#[test]
fn no_ca_means_no_profile() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        ca_mobileconfig(tmp.path().to_str().unwrap().to_string()),
        Err(TollgateError::Ca {
            message: "no CA in the data directory; call generate_ca first".to_string()
        })
    );
}

#[test]
fn the_profile_installs_the_stored_root() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let info = generate_ca(path.clone()).unwrap();
    let profile = String::from_utf8(ca_mobileconfig(path.clone()).unwrap()).unwrap();
    assert!(profile.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
    for expected in [
        "<string>com.apple.security.root</string>",
        "<string>Configuration</string>",
        "<string>dev.tollgate.ca</string>",
        "<string>dev.tollgate.ca.certificate</string>",
        "<string>Tollgate Root CA</string>",
    ] {
        assert!(profile.contains(expected), "missing {expected}");
    }
    assert!(profile.contains(&format!("<data>{}</data>", pem_body(&info.cert_pem))));
    // The same CA always gives the same profile.
    assert_eq!(ca_mobileconfig(path).unwrap(), profile.into_bytes());
}
