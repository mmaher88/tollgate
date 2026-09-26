//! Forwarded queries through the runtime, a local DoH server and a PacketSink.

mod support;

use std::net::Ipv4Addr;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, RecordType};
use support::doh::DohServer;
use support::{query, reply, sink, wait_until};
use tollgate_ffi::{Engine, EngineOptions, PacketSink, Stats};

const WAIT: Duration = Duration::from_secs(5);

fn engine_for(server: &DohServer, options: EngineOptions) -> (tempfile::TempDir, Arc<Engine>) {
    let dir = tempfile::tempdir().unwrap();
    let options = EngineOptions {
        doh_roots: vec![server.ca_der.clone()],
        ..options
    };
    let engine = Engine::with_options(&server.config_json(), dir.path(), options).unwrap();
    (dir, engine)
}

#[test]
fn answers_arrive_through_the_sink_and_are_cached() {
    let server = DohServer::start();
    let (_dir, engine) = engine_for(&server, EngineOptions::default());
    let (sink, answers) = sink();
    engine.start(sink).unwrap();

    let immediate = engine
        .handle_packets(vec![query(0x1234, "Example.com.", RecordType::A)])
        .unwrap();
    assert!(immediate.is_empty());
    let message = reply(&answers.recv_timeout(WAIT).unwrap());
    assert_eq!(message.metadata.id, 0x1234);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.queries[0].name().to_ascii(), "Example.com.");
    assert_eq!(
        message.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))
    );

    // The same question again is answered from the cache, at once.
    let cached = engine
        .handle_packets(vec![query(0x4321, "example.com.", RecordType::A)])
        .unwrap();
    assert_eq!(cached.len(), 1);
    let message = reply(&cached[0]);
    assert_eq!(message.metadata.id, 0x4321);
    assert!((299..=300).contains(&message.answers[0].ttl));
    assert_eq!(server.requests(), 1);
    assert_eq!(
        engine.stats(),
        Stats {
            dns_queries: 2,
            dns_forwarded: 1,
            dns_cache_hits: 1,
            ..Stats::default()
        }
    );
    engine.stop();
}

#[test]
fn reset_connections_also_drops_the_doh_connection() {
    let server = DohServer::start();
    let (_dir, engine) = engine_for(&server, EngineOptions::default());
    let (sink, answers) = sink();
    engine.start(sink).unwrap();
    engine
        .handle_packets(vec![query(1, "one.example.", RecordType::A)])
        .unwrap();
    answers.recv_timeout(WAIT).unwrap();
    assert_eq!(server.connections(), 1);

    // A wake or a network path change: the next query must not wait on a connection
    // from the old path.
    engine.reset_connections();
    engine
        .handle_packets(vec![query(2, "two.example.", RecordType::A)])
        .unwrap();
    answers.recv_timeout(WAIT).unwrap();
    assert_eq!(server.connections(), 2);
    engine.stop();
    // Stopped: nothing to reset, and no panic.
    engine.reset_connections();
}

#[test]
fn a_full_queue_answers_servfail_at_once() {
    let server = DohServer::gated();
    let options = EngineOptions {
        forward_queue: 2,
        forward_in_flight: 1,
        ..EngineOptions::default()
    };
    let (_dir, engine) = engine_for(&server, options);
    let (sink, answers) = sink();
    engine.start(sink).unwrap();

    let queries = (0..6)
        .map(|i| query(100 + i, &format!("host{i}.example."), RecordType::A))
        .collect();
    let immediate = engine.handle_packets(queries).unwrap();
    // Two wait in the queue and at most one has been taken by the runtime already.
    assert!(
        (3..=4).contains(&immediate.len()),
        "{} immediate replies",
        immediate.len()
    );
    for packet in &immediate {
        assert_eq!(reply(packet).metadata.response_code, ResponseCode::ServFail);
    }
    // Only forward_in_flight queries reach the server while it holds them; the rest wait
    // in the queue. The first may take a while on a slow machine (a new TLS connection),
    // so wait for it before giving the others time to arrive too if they could.
    wait_until("the first query at the server", || server.requests() >= 1);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        server.requests(),
        1,
        "queries at the server while it holds them"
    );
    server.open_gate();
    for _ in 0..6 - immediate.len() {
        let message = reply(&answers.recv_timeout(WAIT).unwrap());
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    }
    let stats = engine.stats();
    assert_eq!(stats.dns_forwarded, 6);
    assert_eq!(stats.dns_failed, immediate.len() as u64);
    engine.stop();
}

/// Panics on its first call, then forwards packets.
struct FlakySink {
    calls: Mutex<u32>,
    out: Mutex<Sender<Vec<u8>>>,
}

impl PacketSink for FlakySink {
    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        let first = {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            *calls == 1
        };
        if first {
            panic!("the Swift side failed");
        }
        for packet in packets {
            self.out.lock().unwrap().send(packet).unwrap();
        }
    }
}

#[test]
fn a_panicking_sink_loses_one_answer_not_the_engine() {
    let server = DohServer::start();
    let (_dir, engine) = engine_for(&server, EngineOptions::default());
    let (tx, answers) = channel();
    let sink = Arc::new(FlakySink {
        calls: Mutex::new(0),
        out: Mutex::new(tx),
    });
    engine.start(sink.clone()).unwrap();

    engine
        .handle_packets(vec![query(1, "first.example.", RecordType::A)])
        .unwrap();
    support::wait_until("the first answer", || *sink.calls.lock().unwrap() == 1);
    engine
        .handle_packets(vec![query(2, "second.example.", RecordType::A)])
        .unwrap();
    let message = reply(&answers.recv_timeout(WAIT).unwrap());
    assert_eq!(message.metadata.id, 2);
    engine.stop();
}
