//! Its own test binary, with one test, because it counts the process's threads.

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use support::{closed_upstream_config, data_dir, path, query, reply, sink, wait_until};
use tollgate_ffi::{Engine, LEARNED_PINS_FILE, PacketSink, RUNTIME_THREAD, TollgateError};

fn threads() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .map(|name| name.trim_end().to_string())
        .collect()
}

fn runtime_threads() -> usize {
    threads()
        .iter()
        .filter(|name| *name == RUNTIME_THREAD)
        .count()
}

/// Sends one request to the proxy in absolute form and returns the whole response.
fn proxy_get(port: u16, url: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// Stops the engine from inside the callback, which runs on the runtime thread.
struct StopSink {
    engine: OnceLock<Arc<Engine>>,
    seen: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl PacketSink for StopSink {
    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        self.seen.lock().unwrap().extend(packets);
        if let Some(engine) = self.engine.get() {
            engine.stop();
        }
    }
}

#[test]
fn start_stop_restart_drop_and_stop_from_the_runtime_thread() {
    let dir = data_dir("||blocked.example^\n", "");
    let config = closed_upstream_config();
    let engine = Engine::new(config.clone(), path(&dir)).unwrap();
    let before = threads().len();
    assert_eq!(runtime_threads(), 0);

    // start() on one thread, stop() on another, like Swift does.
    let starter = engine.clone();
    let port = std::thread::spawn(move || starter.start(sink().0).unwrap())
        .join()
        .unwrap();
    assert_ne!(port, 0);
    assert_eq!(engine.port(), Some(port));
    wait_until("one runtime thread", || runtime_threads() == 1);
    assert_eq!(engine.start(sink().0), Err(TollgateError::AlreadyRunning));
    // What the tunnel calls on wake and on network changes.
    engine.reset_connections();

    // The proxy listens as soon as start() returns and filters plain HTTP.
    let response = proxy_get(port, "http://blocked.example/ad.js", "blocked.example");
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("access-control-allow-origin: *"),
        "{response}"
    );
    let stats = engine.stats();
    assert_eq!((stats.http_requests, stats.http_blocked), (1, 1));

    let stopper = engine.clone();
    std::thread::spawn(move || stopper.stop()).join().unwrap();
    assert_eq!(engine.port(), None);
    wait_until("the runtime thread to end", || {
        runtime_threads() == 0 && threads().len() == before
    });
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(dir.path().join(LEARNED_PINS_FILE).exists());
    engine.stop();

    // Restart, then drop the last reference without stop().
    let port = engine.start(sink().0).unwrap();
    assert_ne!(port, 0);
    wait_until("one runtime thread", || runtime_threads() == 1);
    drop(engine);
    wait_until("the runtime thread to end after drop", || {
        runtime_threads() == 0 && threads().len() == before
    });

    // stop() from inside a PacketSink callback must not join its own thread.
    let engine = Engine::new(config, path(&dir)).unwrap();
    let stopping = Arc::new(StopSink {
        engine: OnceLock::new(),
        seen: std::sync::Mutex::new(Vec::new()),
    });
    engine.start(stopping.clone()).unwrap();
    stopping.engine.set(engine.clone()).ok().unwrap();
    let immediate = engine
        .handle_packets(vec![query(0x7777, "example.com.", RecordType::A)])
        .unwrap();
    assert!(immediate.is_empty());
    wait_until("the SERVFAIL through the sink", || {
        !stopping.seen.lock().unwrap().is_empty()
    });
    let message = reply(&stopping.seen.lock().unwrap()[0]);
    assert_eq!(message.metadata.id, 0x7777);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    wait_until("the runtime thread to end after stopping itself", || {
        runtime_threads() == 0 && threads().len() == before
    });
    assert_eq!(engine.port(), None);
}
