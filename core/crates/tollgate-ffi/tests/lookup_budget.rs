//! The proxy's name lookups and the DNS forwarder share one DoH resolver. Each has its own
//! share of its in-flight limit, so lookups for a page full of new hosts never make
//! forwarded queries fail with Busy while they could wait.

mod support;

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use support::doh::DohServer;
use support::{query, reply, sink, wait_until};
use tollgate_ffi::{Engine, EngineOptions};

#[test]
fn proxy_lookups_never_make_forwarded_queries_busy() {
    let server = DohServer::gated();
    let dir = tempfile::tempdir().unwrap();
    let options = EngineOptions {
        doh_roots: vec![server.ca_der.clone()],
        ..EngineOptions::default()
    };
    let forwarded = options.forward_in_flight;
    let engine = Engine::with_options(&server.config_json(), dir.path(), options).unwrap();
    let (sink, answers) = sink();
    let port = engine.start(sink).unwrap();

    // Forty CONNECTs to new hosts: each looks its host up (A and AAAA) and waits at the
    // server.
    let clients: Vec<TcpStream> = (0..40)
        .map(|i| {
            let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let host = format!("page{i}.example:443");
            write!(client, "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
            client
        })
        .collect();
    wait_until("the lookups at the server", || server.requests() >= 32);
    std::thread::sleep(Duration::from_millis(100));

    let queries = (0..forwarded)
        .map(|i| query(i as u16, &format!("app{i}.example."), RecordType::A))
        .collect();
    assert!(engine.handle_packets(queries).unwrap().is_empty());
    // Nothing is answered while the server holds every query: none failed with Busy.
    if let Ok(early) = answers.recv_timeout(Duration::from_millis(300)) {
        panic!(
            "answered while the server holds every query: {:?}",
            reply(&early).metadata.response_code
        );
    }
    server.open_gate();
    for _ in 0..forwarded {
        let message = reply(&answers.recv_timeout(Duration::from_secs(5)).unwrap());
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    }
    assert_eq!(engine.stats().dns_failed, 0);
    drop(clients);
    engine.stop();
}
