use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tollgate_mitm::{
    CA_VALIDITY_DAYS, CertAuthority, LEAF_CACHE_SIZE, LEAF_VALIDITY_DAYS, MitmError,
};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256,
};
use x509_parser::prelude::{FromDer, X509Certificate};

const DAY: i64 = 24 * 60 * 60;

fn now() -> i64 {
    tollgate_common::clock::unix_secs() as i64
}

fn verifier(ca_der: &[u8]) -> Arc<WebPkiServerVerifier> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap()
}

fn verify(ca_der: &[u8], leaf: &CertificateDer<'_>, name: &str) -> Result<(), rustls::Error> {
    let name = ServerName::try_from(name.to_string()).unwrap();
    verifier(ca_der)
        .verify_server_cert(leaf, &[], &name, &[], UnixTime::now())
        .map(|_| ())
}

fn subject_key_id(cert: &X509Certificate<'_>) -> Vec<u8> {
    cert.extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
            _ => None,
        })
        .expect("the CA has a subject key identifier")
}

fn authority_key_id(cert: &X509Certificate<'_>) -> Vec<u8> {
    cert.extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => None,
        })
        .expect("the leaf has an authority key identifier")
}

#[test]
fn generate_makes_a_p256_root_valid_for_ten_years() {
    let ca = CertAuthority::generate("Tollgate Test CA").unwrap();
    let der = ca.cert_der();
    let (_, cert) = X509Certificate::from_der(&der).unwrap();

    assert!(cert.is_ca());
    let constraints = cert.basic_constraints().unwrap().unwrap();
    assert!(constraints.critical);
    assert_eq!(constraints.value.path_len_constraint, Some(0));
    let usage = cert.key_usage().unwrap().unwrap().value;
    assert!(usage.key_cert_sign() && usage.crl_sign() && usage.digital_signature());

    assert_eq!(
        cert.subject().to_string(),
        "CN=Tollgate Test CA, O=Tollgate"
    );
    assert_eq!(cert.subject(), cert.issuer());
    assert_eq!(
        cert.signature_algorithm.algorithm,
        OID_SIG_ECDSA_WITH_SHA256
    );
    let spki = &cert.public_key().algorithm;
    assert_eq!(spki.algorithm, OID_KEY_TYPE_EC_PUBLIC_KEY);
    let curve = spki.parameters.as_ref().unwrap().as_oid().unwrap();
    assert_eq!(curve, OID_EC_P256);

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    assert!(
        (not_before - (now() - DAY)).abs() < 120,
        "starts one day ago"
    );
    assert_eq!(not_after - not_before, CA_VALIDITY_DAYS * DAY);
    assert_eq!(CA_VALIDITY_DAYS, 3650);
}

#[test]
fn pem_round_trip_keeps_the_same_ca() {
    let ca = CertAuthority::generate("Round Trip CA").unwrap();
    assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(ca.key_pem().starts_with("-----BEGIN PRIVATE KEY-----"));

    let loaded = CertAuthority::from_pem(&ca.cert_pem(), &ca.key_pem()).unwrap();
    assert_eq!(loaded.cert_pem(), ca.cert_pem());
    assert_eq!(loaded.key_pem(), ca.key_pem());
    assert_eq!(loaded.cert_der(), ca.cert_der());

    // A leaf from the reloaded CA chains to the certificate stored before the reload.
    let leaf = loaded.leaf("example.com").unwrap();
    verify(&ca.cert_der(), &leaf.cert[0], "example.com").unwrap();
}

#[test]
fn from_pem_rejects_bad_input() {
    let ca = CertAuthority::generate("A").unwrap();
    let other = CertAuthority::generate("B").unwrap();

    let bad_cert = CertAuthority::from_pem("not a certificate", &ca.key_pem());
    assert!(matches!(bad_cert, Err(MitmError::InvalidCertificate(_))));

    let bad_key = CertAuthority::from_pem(&ca.cert_pem(), "not a key");
    assert!(matches!(bad_key, Err(MitmError::InvalidKey(_))));

    let mismatch = CertAuthority::from_pem(&ca.cert_pem(), &other.key_pem());
    assert!(matches!(mismatch, Err(MitmError::KeyMismatch)));

    // A certificate that is not a CA cannot issue leaves.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["server.test".to_string()]).unwrap();
    let server = params.self_signed(&key).unwrap();
    let not_ca = CertAuthority::from_pem(&server.pem(), &key.serialize_pem());
    assert!(matches!(not_ca, Err(MitmError::NotCa)));
}

#[test]
fn leaf_is_san_only_server_auth_for_thirty_days() {
    let ca = CertAuthority::generate("Leaf CA").unwrap();
    let ca_der = ca.cert_der();
    let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();

    let leaf = ca.leaf("Example.COM.").unwrap();
    assert_eq!(leaf.cert.len(), 1, "the chain is the leaf alone");
    let (_, cert) = X509Certificate::from_der(&leaf.cert[0]).unwrap();

    assert!(!cert.is_ca());
    assert_eq!(cert.subject().iter().count(), 0, "empty subject");
    assert_eq!(cert.issuer(), ca_cert.subject());
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert!(san.critical, "SAN is critical when the subject is empty");
    assert_eq!(
        san.value.general_names,
        vec![GeneralName::DNSName("example.com")]
    );
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth);
    assert!(!eku.client_auth && !eku.any && eku.other.is_empty());
    let usage = cert.key_usage().unwrap().unwrap().value;
    assert!(usage.digital_signature() && !usage.key_cert_sign());
    assert_eq!(authority_key_id(&cert), subject_key_id(&ca_cert));
    let curve = cert.public_key().algorithm.parameters.as_ref().unwrap();
    assert_eq!(curve.as_oid().unwrap(), OID_EC_P256);

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    assert!(
        (not_before - (now() - DAY)).abs() < 120,
        "starts one day ago"
    );
    assert_eq!(not_after - not_before, LEAF_VALIDITY_DAYS * DAY);
    assert_eq!(LEAF_VALIDITY_DAYS, 30);

    verify(&ca_der, &leaf.cert[0], "example.com").unwrap();
    assert!(verify(&ca_der, &leaf.cert[0], "example.org").is_err());
    assert!(
        verify(
            &CertAuthority::generate("Other").unwrap().cert_der(),
            &leaf.cert[0],
            "example.com"
        )
        .is_err()
    );
}

#[test]
fn ip_literals_get_an_ip_address_san() {
    let ca = CertAuthority::generate("IP CA").unwrap();
    for (host, name, bytes) in [
        ("127.0.0.1", "127.0.0.1", vec![127, 0, 0, 1]),
        ("[::1]", "::1", {
            let mut v = vec![0; 16];
            v[15] = 1;
            v
        }),
    ] {
        let leaf = ca.leaf(host).unwrap();
        let (_, cert) = X509Certificate::from_der(&leaf.cert[0]).unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            san.value.general_names,
            vec![GeneralName::IPAddress(&bytes)]
        );
        verify(&ca.cert_der(), &leaf.cert[0], name).unwrap();
    }
}

#[test]
fn leaves_have_distinct_serials() {
    let ca = CertAuthority::generate("Serial CA").unwrap();
    let a = ca.leaf("a.test").unwrap();
    let b = ca.leaf("b.test").unwrap();
    let (_, a) = X509Certificate::from_der(&a.cert[0]).unwrap();
    let (_, b) = X509Certificate::from_der(&b.cert[0]).unwrap();
    assert_ne!(a.raw_serial(), b.raw_serial());
}

#[test]
fn leaf_cache_is_a_bounded_lru() {
    let ca = CertAuthority::generate("Cache CA").unwrap();
    let first = ca.leaf("a.test").unwrap();
    assert!(
        Arc::ptr_eq(&first, &ca.leaf("A.TEST.").unwrap()),
        "normalized hit"
    );
    assert_eq!(ca.cached_leaves(), 1);

    let h0 = ca.leaf("h0.test").unwrap();
    for i in 1..LEAF_CACHE_SIZE - 1 {
        ca.leaf(&format!("h{i}.test")).unwrap();
    }
    assert_eq!(ca.cached_leaves(), LEAF_CACHE_SIZE);
    // a.test is the oldest entry; using it again makes h0 the least recently used.
    assert!(Arc::ptr_eq(&first, &ca.leaf("a.test").unwrap()));
    ca.leaf("new.test").unwrap();
    assert_eq!(ca.cached_leaves(), LEAF_CACHE_SIZE);
    assert!(
        Arc::ptr_eq(&first, &ca.leaf("a.test").unwrap()),
        "a.test was kept"
    );
    assert!(
        !Arc::ptr_eq(&h0, &ca.leaf("h0.test").unwrap()),
        "h0 was evicted"
    );
    assert_eq!(LEAF_CACHE_SIZE, 128);
}

#[test]
fn empty_host_is_rejected() {
    let ca = CertAuthority::generate("Empty CA").unwrap();
    assert!(matches!(ca.leaf(""), Err(MitmError::InvalidHost(_))));
    assert!(matches!(ca.leaf("."), Err(MitmError::InvalidHost(_))));
}

#[test]
fn cert_authority_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CertAuthority>();
}
