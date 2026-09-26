//! The proxy refuses hosts the DNS blocklist blocks, with the same set as the DNS path,
//! also after the lists are reloaded.

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;

use support::{closed_upstream_config, compile_into, data_dir, path, sink};
use tollgate_ffi::Engine;

/// Sends `CONNECT host:443` and returns the status line.
fn connect_status(port: u16, host: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n") {
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap().trim_end().to_string()
}

#[test]
fn the_proxy_uses_the_dns_blocklist_and_its_reloads() {
    let dir = data_dir("", "||blocked.example^\n");
    let engine = Engine::new(closed_upstream_config(), path(&dir)).unwrap();
    let port = engine.start(sink().0).unwrap();

    assert_eq!(
        connect_status(port, "ads.blocked.example"),
        "HTTP/1.1 403 Forbidden"
    );
    assert_eq!(engine.stats().dns_blocked, 1);

    compile_into(&dir, "", "||other.example^\n");
    engine.reload_lists().unwrap();
    assert_eq!(
        connect_status(port, "other.example"),
        "HTTP/1.1 403 Forbidden"
    );
    assert_eq!(engine.stats().dns_blocked, 2);
    engine.stop();
}
