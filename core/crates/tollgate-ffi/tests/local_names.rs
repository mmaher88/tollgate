//! Local network names go to the `LocalResolver` Swift provides, never to DoH.

mod support;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, RecordType};
use support::doh::DohServer;
use support::{query, reply, sink};
use tollgate_ffi::{DnsRecord, Engine, EngineOptions, LOCAL_PENDING, LocalResolver};

/// Records every call; answers nothing by itself.
#[derive(Default)]
struct Recorder(Mutex<Vec<(u64, String, u16, u16)>>);

impl LocalResolver for Recorder {
    fn resolve(&self, id: u64, name: String, rtype: u16, rclass: u16) {
        self.0.lock().unwrap().push((id, name, rtype, rclass));
    }
}

impl Recorder {
    fn calls(&self) -> Vec<(u64, String, u16, u16)> {
        self.0.lock().unwrap().clone()
    }
}

fn engine(server: &DohServer, options: EngineOptions) -> (tempfile::TempDir, Arc<Engine>) {
    let dir = tempfile::tempdir().unwrap();
    let options = EngineOptions {
        doh_roots: vec![server.ca_der.clone()],
        ..options
    };
    let engine = Engine::with_options(&server.config_json(), dir.path(), options).unwrap();
    (dir, engine)
}

#[test]
fn local_names_are_resolved_by_the_local_resolver() {
    let server = DohServer::start();
    let (_dir, engine) = engine(&server, EngineOptions::default());
    let (sink, answers) = sink();
    engine.start(sink).unwrap();
    let local = Arc::new(Recorder::default());
    engine.set_local_resolver(Some(local.clone()));
    engine.set_network("en0 192.168.1.1".to_string());

    let immediate = engine
        .handle_packets(vec![query(0x1111, "nas.lan.", RecordType::A)])
        .unwrap();
    assert!(immediate.is_empty());
    let calls = local.calls();
    assert_eq!(calls.len(), 1);
    let (id, name, rtype, rclass) = calls[0].clone();
    assert_eq!((name.as_str(), rtype, rclass), ("nas.lan.", 1, 1));

    let record = DnsRecord {
        rtype: 1,
        rclass: 1,
        ttl: 30,
        data: vec![192, 168, 1, 20],
    };
    let packets = engine.complete_local(id, Some(vec![record.clone()]));
    assert_eq!(packets.len(), 1);
    let message = reply(&packets[0]);
    assert_eq!(message.metadata.id, 0x1111);
    assert_eq!(
        message.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 168, 1, 20)))
    );
    // A second answer for the same id, or an unknown id, writes nothing.
    assert!(engine.complete_local(id, Some(vec![record])).is_empty());
    assert!(engine.complete_local(id + 100, None).is_empty());

    // Cached now; and nothing went to DoH or through the sink.
    let cached = engine
        .handle_packets(vec![query(0x2222, "nas.lan.", RecordType::A)])
        .unwrap();
    assert_eq!(reply(&cached[0]).answers.len(), 1);
    assert_eq!(server.requests(), 0);
    assert!(answers.recv_timeout(Duration::from_millis(100)).is_err());
    engine.stop();
}

#[test]
fn local_failures_and_a_missing_resolver_answer_servfail() {
    let server = DohServer::start();
    let (_dir, engine) = engine(&server, EngineOptions::default());

    // No resolver yet: SERVFAIL at once, never DoH.
    let immediate = engine
        .handle_packets(vec![query(1, "x.home.arpa.", RecordType::AAAA)])
        .unwrap();
    assert_eq!(
        reply(&immediate[0]).metadata.response_code,
        ResponseCode::ServFail
    );

    let local = Arc::new(Recorder::default());
    engine.set_local_resolver(Some(local.clone()));
    assert!(
        engine
            .handle_packets(vec![query(2, "x.home.arpa.", RecordType::AAAA)])
            .unwrap()
            .is_empty()
    );
    let id = local.calls()[0].0;
    let packets = engine.complete_local(id, None);
    assert_eq!(
        reply(&packets[0]).metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(server.requests(), 0);
}

#[test]
fn waiting_local_queries_are_bounded_and_expire() {
    let server = DohServer::start();
    let options = EngineOptions {
        local_deadline: Duration::from_millis(50),
        ..EngineOptions::default()
    };
    let (_dir, engine) = engine(&server, options);
    let local = Arc::new(Recorder::default());
    engine.set_local_resolver(Some(local.clone()));

    let queries = (0..LOCAL_PENDING as u16 + 3)
        .map(|i| query(i, &format!("host{i}.lan."), RecordType::A))
        .collect();
    let immediate = engine.handle_packets(queries).unwrap();
    // The ones beyond the limit get SERVFAIL at once.
    assert_eq!(immediate.len(), 3);
    assert_eq!(local.calls().len(), LOCAL_PENDING);

    // After the deadline the waiting ones are answered SERVFAIL with the next local query.
    std::thread::sleep(Duration::from_millis(100));
    let expired = engine
        .handle_packets(vec![query(999, "late.lan.", RecordType::A)])
        .unwrap();
    assert_eq!(expired.len(), LOCAL_PENDING);
    assert!(
        expired
            .iter()
            .all(|p| reply(p).metadata.response_code == ResponseCode::ServFail)
    );
    assert_eq!(local.calls().len(), LOCAL_PENDING + 1);
    let first = local.calls()[0].0;
    assert!(engine.complete_local(first, None).is_empty());
}

/// A second query for a question already waiting joins it instead of starting another
/// lookup. Besides saving work, this ends a lookup that comes back through the tunnel (a
/// network whose own resolver is the tunnel's), which would otherwise start a new lookup
/// for itself over and over.
#[test]
fn identical_local_queries_share_one_lookup() {
    let server = DohServer::start();
    let (_dir, engine) = engine(&server, EngineOptions::default());
    let local = Arc::new(Recorder::default());
    engine.set_local_resolver(Some(local.clone()));

    let immediate = engine
        .handle_packets(vec![
            query(1, "nas.lan.", RecordType::A),
            query(2, "NAS.lan.", RecordType::A),
            query(3, "nas.lan.", RecordType::AAAA),
        ])
        .unwrap();
    assert!(immediate.is_empty());
    assert!(
        engine
            .handle_packets(vec![query(4, "nas.lan.", RecordType::A)])
            .unwrap()
            .is_empty()
    );
    let calls = local.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");

    let record = DnsRecord {
        rtype: 1,
        rclass: 1,
        ttl: 30,
        data: vec![192, 168, 1, 20],
    };
    let packets = engine.complete_local(calls[0].0, Some(vec![record]));
    let mut ids: Vec<u16> = packets.iter().map(|p| reply(p).metadata.id).collect();
    ids.sort_unstable();
    assert_eq!(ids, [1, 2, 4]);
    assert!(packets.iter().all(|p| reply(p).answers.len() == 1));
    assert_eq!(engine.complete_local(calls[1].0, Some(Vec::new())).len(), 1);
}
