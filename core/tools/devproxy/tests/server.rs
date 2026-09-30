//! The whole harness in-process: lists from files, both listeners on ephemeral ports.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use devproxy::args::{Args, ListKind, ListSpec};
use devproxy::server::{DevProxy, EVENTS_ON_EXIT, format_events, instructions};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::runtime::Runtime;
use tollgate_common::events::{BlockEvent, EventKind};

fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    message.to_vec().unwrap()
}

/// Sends one query and returns the decoded reply.
fn ask(server: SocketAddr, payload: &[u8]) -> Message {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.send_to(payload, server).unwrap();
    let mut buf = [0u8; 1500];
    let (len, from) = client.recv_from(&mut buf).unwrap();
    assert_eq!(from, server);
    Message::from_vec(&buf[..len]).unwrap()
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn args(dir: &Path, lists: Vec<ListSpec>) -> Args {
    Args {
        data_dir: dir.join("data"),
        config: None,
        lists,
        dns: "127.0.0.1:0".parse().unwrap(),
        proxy: "127.0.0.1:0".parse().unwrap(),
    }
}

fn list(kind: ListKind, path: &Path) -> ListSpec {
    ListSpec {
        kind,
        source: path.to_str().unwrap().to_string(),
    }
}

#[test]
fn compiles_serves_dns_and_filters_http() {
    let tmp = tempfile::tempdir().unwrap();
    let url_list = tmp.path().join("url.txt");
    std::fs::write(&url_list, "||blocked.example^\n").unwrap();
    let hosts = tmp.path().join("hosts");
    std::fs::write(&hosts, "0.0.0.0 ads.example\n").unwrap();
    let args = args(
        tmp.path(),
        vec![
            list(ListKind::Url, &url_list),
            list(ListKind::Hosts, &hosts),
        ],
    );
    let runtime = runtime();
    let proxy = runtime.block_on(DevProxy::prepare(&args)).unwrap();
    let (dns, http) = (proxy.dns_addr(), proxy.proxy_addr());
    let data = tmp.path().join("data");
    assert_eq!(proxy.ca_path(), data.join("ca.pem"));
    for file in ["engine.dat", "domains.bin"] {
        assert!(data.join(file).exists(), "{file}");
    }
    let mode = std::fs::metadata(data.join("ca.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = std::thread::spawn(move || {
        runtime.block_on(proxy.serve(async {
            let _ = stopped.await;
        }))
    });

    let message = ask(dns, &query(0x2222, "ads.example.", RecordType::A));
    assert_eq!(message.metadata.id, 0x2222);
    assert_eq!(message.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

    let mut stream = TcpStream::connect(http).unwrap();
    stream
        .write_all(
            b"GET http://blocked.example/ad.js HTTP/1.1\r\nHost: blocked.example\r\nReferer: https://news.test/\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 403 "), "{response}");

    stop.send(()).unwrap();
    let summary = server.join().unwrap();
    let stats = summary.stats;
    assert_eq!((stats.dns_queries, stats.dns_blocked), (1, 1));
    assert_eq!((stats.http_requests, stats.http_blocked), (1, 1));
    // The proxy and the DNS responder share one blocked log.
    let events: Vec<_> = summary
        .events
        .iter()
        .map(|e| {
            (
                e.kind,
                e.host.as_str(),
                e.url.as_deref(),
                e.source_host.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        events,
        [
            (
                EventKind::Request,
                "blocked.example",
                Some("http://blocked.example/ad.js"),
                Some("news.test")
            ),
            (EventKind::Dns, "ads.example", None, None),
        ]
    );
    assert_eq!(
        std::fs::read_to_string(data.join("learned-pins.json")).unwrap(),
        r#"{"version":1,"pins":[]}"#
    );
}

#[test]
fn a_second_run_reuses_the_data_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let url_list = tmp.path().join("url.txt");
    std::fs::write(&url_list, "||blocked.example^\n").unwrap();
    let runtime = runtime();
    let first = args(tmp.path(), vec![list(ListKind::Url, &url_list)]);
    let (ca, engine) = {
        let proxy = runtime.block_on(DevProxy::prepare(&first)).unwrap();
        let engine = std::fs::read(tmp.path().join("data/engine.dat")).unwrap();
        (std::fs::read_to_string(proxy.ca_path()).unwrap(), engine)
    };
    // No list options: the compiled files and the CA stay as they are.
    let proxy = runtime
        .block_on(DevProxy::prepare(&args(tmp.path(), Vec::new())))
        .unwrap();
    assert_eq!(std::fs::read_to_string(proxy.ca_path()).unwrap(), ca);
    assert_eq!(
        std::fs::read(tmp.path().join("data/engine.dat")).unwrap(),
        engine
    );
}

#[test]
fn a_missing_list_file_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.txt");
    let error = runtime()
        .block_on(DevProxy::prepare(&args(
            tmp.path(),
            vec![list(ListKind::Dns, &missing)],
        )))
        .err()
        .unwrap();
    assert!(error.starts_with(missing.to_str().unwrap()), "{error}");
}

#[test]
fn the_dns_port_is_shared_with_an_mdns_responder() {
    // Like avahi on port 5353: the wildcard address with SO_REUSEADDR.
    let mdns = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    mdns.set_reuse_address(true).unwrap();
    mdns.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
        .unwrap();
    let port = mdns.local_addr().unwrap().as_socket().unwrap().port();

    let tmp = tempfile::tempdir().unwrap();
    let mut args = args(tmp.path(), Vec::new());
    args.dns = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let runtime = runtime();
    let proxy = runtime.block_on(DevProxy::prepare(&args)).unwrap();
    assert_eq!(proxy.dns_addr(), args.dns);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = std::thread::spawn(move || {
        runtime.block_on(proxy.serve(async {
            let _ = stopped.await;
        }))
    });
    // HTTPS queries are answered locally, so no upstream is needed.
    let message = ask(args.dns, &query(0x3333, "example.com.", RecordType::HTTPS));
    assert_eq!(message.metadata.id, 0x3333);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    stop.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn instructions_name_the_addresses_and_firefox_settings() {
    let text = instructions(
        "127.0.0.1:8080".parse().unwrap(),
        "127.0.0.1:5353".parse().unwrap(),
        Path::new("/tmp/tg/ca.pem"),
    );
    for expected in [
        "HTTP and HTTPS proxy  127.0.0.1:8080",
        "DNS over UDP          127.0.0.1:5353",
        "Root certificate      /tmp/tg/ca.pem",
        "HTTP Proxy 127.0.0.1, Port 8080",
        "Also use this proxy for HTTPS",
        "Import...: choose /tmp/tg/ca.pem",
        "Trust this CA to identify websites",
        "network.trr.mode to 5",
        "network.dns.echconfig.enabled to false",
        "dig @127.0.0.1 -p 5353 doubleclick.net A",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
}

#[test]
fn the_exit_summary_keeps_the_last_20_events() {
    let tmp = tempfile::tempdir().unwrap();
    let hosts = tmp.path().join("hosts");
    let names: Vec<String> = (0..25).map(|i| format!("ads{i}.example")).collect();
    let text: String = names.iter().map(|n| format!("0.0.0.0 {n}\n")).collect();
    std::fs::write(&hosts, text).unwrap();
    let args = args(tmp.path(), vec![list(ListKind::Hosts, &hosts)]);
    let runtime = runtime();
    let proxy = runtime.block_on(DevProxy::prepare(&args)).unwrap();
    let dns = proxy.dns_addr();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = std::thread::spawn(move || {
        runtime.block_on(proxy.serve(async {
            let _ = stopped.await;
        }))
    });
    for (i, name) in names.iter().enumerate() {
        ask(dns, &query(i as u16, &format!("{name}."), RecordType::A));
    }
    stop.send(()).unwrap();
    let summary = server.join().unwrap();

    assert_eq!(EVENTS_ON_EXIT, 20);
    assert_eq!(summary.stats.dns_blocked, 25);
    let hosts: Vec<&str> = summary.events.iter().map(|e| e.host.as_str()).collect();
    let expected: Vec<&str> = names.iter().rev().take(20).map(String::as_str).collect();
    assert_eq!(hosts, expected);
}

#[test]
fn the_config_allowlist_applies_to_dns() {
    let tmp = tempfile::tempdir().unwrap();
    let hosts = tmp.path().join("hosts");
    std::fs::write(&hosts, "0.0.0.0 ads.example\n0.0.0.0 tracker.example\n").unwrap();
    // Nothing listens on the upstream port, so a forwarded query gets SERVFAIL.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let config = tmp.path().join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"allowlist":["ads.example"],"doh_upstreams":[{{"ip":"127.0.0.1","port":{port},"tls_name":"doh.test"}}]}}"#
        ),
    )
    .unwrap();
    let mut args = args(tmp.path(), vec![list(ListKind::Hosts, &hosts)]);
    args.config = Some(config);
    let runtime = runtime();
    let proxy = runtime.block_on(DevProxy::prepare(&args)).unwrap();
    let dns = proxy.dns_addr();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = std::thread::spawn(move || {
        runtime.block_on(proxy.serve(async {
            let _ = stopped.await;
        }))
    });
    let allowed = ask(dns, &query(1, "ads.example.", RecordType::A));
    assert_eq!(allowed.metadata.response_code, ResponseCode::ServFail);
    let blocked = ask(dns, &query(2, "tracker.example.", RecordType::A));
    assert_eq!(blocked.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    stop.send(()).unwrap();
    let summary = server.join().unwrap();
    assert_eq!(summary.stats.dns_blocked, 1);
    let hosts: Vec<&str> = summary.events.iter().map(|e| e.host.as_str()).collect();
    assert_eq!(hosts, ["tracker.example"]);
}

#[test]
fn events_are_printed_one_per_line() {
    assert_eq!(format_events(&[]), "No blocks recorded.\n");
    let events = [
        BlockEvent {
            unix_secs: 1_790_000_001,
            kind: EventKind::Request,
            host: "ads.example".into(),
            url: Some("https://ads.example/a.js".into()),
            source_host: Some("news.test".into()),
        },
        BlockEvent {
            unix_secs: 1_790_000_000,
            kind: EventKind::Request,
            host: "ads.example".into(),
            url: Some("https://ads.example/b.js".into()),
            source_host: None,
        },
        BlockEvent {
            unix_secs: 1_789_999_999,
            kind: EventKind::Dns,
            host: "tracker.example".into(),
            url: None,
            source_host: None,
        },
    ];
    assert_eq!(
        format_events(&events),
        "\
Last 3 blocks, newest first:
  1790000001  request  https://ads.example/a.js  (page news.test)
  1790000000  request  https://ads.example/b.js
  1789999999  dns      tracker.example
"
    );
}
