use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{CertificateError, ClientConnection, ServerConfig, ServerConnection};
use tollgate_common::tls::{client_config, webpki_root_store};

#[test]
fn alpn_is_offered_in_the_given_order() {
    let config = client_config(&[b"h2", b"http/1.1"]);
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(client_config(&[]).alpn_protocols.is_empty());
}

#[test]
fn uses_the_ring_provider() {
    let config = client_config(&[b"h2"]);
    let ring = rustls::crypto::ring::default_provider();
    let ours: Vec<_> = config
        .crypto_provider()
        .cipher_suites
        .iter()
        .map(|s| s.suite())
        .collect();
    let expected: Vec<_> = ring.cipher_suites.iter().map(|s| s.suite()).collect();
    assert_eq!(ours, expected);
    assert!(!ours.is_empty());
}

#[test]
fn root_store_holds_the_webpki_roots() {
    let roots = webpki_root_store();
    assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    assert!(roots.len() > 100, "only {} roots", roots.len());
}

fn self_signed_server(name: &str) -> Arc<ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    Arc::new(config)
}

/// Runs a handshake over in-memory buffers and returns the client's error, if any.
fn handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    for _ in 0..16 {
        let mut to_server = Vec::new();
        client.write_tls(&mut to_server).unwrap();
        if !to_server.is_empty() {
            server.read_tls(&mut to_server.as_slice()).unwrap();
            let _ = server.process_new_packets();
        }
        let mut to_client = Vec::new();
        server.write_tls(&mut to_client).unwrap();
        if !to_client.is_empty() {
            client.read_tls(&mut to_client.as_slice()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn rejects_a_certificate_from_an_unknown_issuer() {
    let server_config = self_signed_server("example.com");
    let mut server = ServerConnection::new(server_config).unwrap();
    let name = ServerName::try_from("example.com").unwrap();
    let mut client = ClientConnection::new(client_config(&[b"h2"]), name).unwrap();
    let err = handshake(&mut client, &mut server).unwrap_err();
    assert_eq!(
        err,
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );
}

// Needs the network. Run with:
//   cargo test -p tollgate-common --test tls -- --ignored
#[test]
#[ignore = "needs network access to 1.1.1.1:443"]
fn connects_to_cloudflare_dns_with_h2() {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::Duration;

    let name = ServerName::try_from("cloudflare-dns.com").unwrap();
    let mut conn = ClientConnection::new(client_config(&[b"h2"]), name).unwrap();
    let mut sock =
        TcpStream::connect_timeout(&"1.1.1.1:443".parse().unwrap(), Duration::from_secs(5))
            .unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).unwrap();
    }
    assert_eq!(conn.alpn_protocol(), Some(&b"h2"[..]));
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    sock.flush().unwrap();
}
