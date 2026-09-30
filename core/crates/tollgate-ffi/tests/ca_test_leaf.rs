//! `ca_test_leaf` issues a leaf from the stored CA so the app can ask iOS whether the root
//! is trusted for TLS, the same judgement Safari makes for intercepted sites.

use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tollgate_ffi::{TollgateError, ca_test_leaf, generate_ca, load_ca};

const HOST: &str = "trust-check.tollgate.invalid";

fn verifier_trusting(ca_der: Vec<u8>) -> Arc<WebPkiServerVerifier> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der)).unwrap();
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap()
}

#[test]
fn the_leaf_chains_to_the_stored_root_for_the_requested_host() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    generate_ca(path.clone()).unwrap();
    let ca = load_ca(tmp.path()).unwrap().unwrap();

    let leaf = ca_test_leaf(path, HOST.to_string()).unwrap();

    let verifier = verifier_trusting(ca.cert_der());
    let name = ServerName::try_from(HOST).unwrap();
    rustls::client::danger::ServerCertVerifier::verify_server_cert(
        verifier.as_ref(),
        &CertificateDer::from(leaf.clone()),
        &[],
        &name,
        &[],
        UnixTime::now(),
    )
    .expect("the leaf verifies against the stored root for the host");

    let other = ServerName::try_from("example.com").unwrap();
    assert!(
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            verifier.as_ref(),
            &CertificateDer::from(leaf),
            &[],
            &other,
            &[],
            UnixTime::now(),
        )
        .is_err(),
        "the leaf is only valid for the requested host"
    );
}

#[test]
fn no_stored_ca_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        ca_test_leaf(tmp.path().to_str().unwrap().to_string(), HOST.to_string()),
        Err(TollgateError::Ca {
            message: "no CA in the data directory; call generate_ca first".to_string()
        })
    );
}

#[test]
fn an_empty_host_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    generate_ca(path.clone()).unwrap();
    assert!(matches!(
        ca_test_leaf(path, String::new()),
        Err(TollgateError::Ca { .. })
    ));
}
