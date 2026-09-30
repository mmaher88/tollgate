//! Helpers shared by the integration tests; each test binary uses a different part.
#![allow(dead_code)]

pub mod doh;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tempfile::TempDir;
use tollgate_dns::packet::{build_udp, parse_udp};
use tollgate_ffi::{ListFormat, ListInput, ListTarget, PacketSink, compile_lists};

/// The address the phone's DNS queries come from.
pub fn client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 53001)
}

/// The tunnel's DNS server.
pub fn dns_server() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 53)
}

/// A recursion-desired query for `name` wrapped in an IPv4 packet from the client to the
/// tunnel's DNS address.
pub fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    build_udp(client(), dns_server(), &message.to_vec().unwrap()).unwrap()
}

/// Decodes a reply packet after checking it goes from the DNS address to the client.
pub fn reply(packet: &[u8]) -> Message {
    let datagram = parse_udp(packet).expect("a UDP packet");
    assert_eq!(datagram.source, dns_server());
    assert_eq!(datagram.destination, client());
    Message::from_vec(datagram.payload).expect("a DNS message")
}

/// A temporary data directory with `url_rules` compiled into `engine.dat` and
/// `dns_rules` into `domains.bin`.
pub fn data_dir(url_rules: &str, dns_rules: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    compile_into(&dir, url_rules, dns_rules);
    dir
}

pub fn compile_into(dir: &TempDir, url_rules: &str, dns_rules: &str) {
    let lists = vec![
        ListInput {
            name: "url".to_string(),
            text: url_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Url,
        },
        ListInput {
            name: "dns".to_string(),
            text: dns_rules.to_string(),
            format: ListFormat::Adblock,
            target: ListTarget::Dns,
        },
    ];
    compile_lists(lists, path(dir)).unwrap();
}

pub fn path(dir: &TempDir) -> String {
    dir.path().to_str().unwrap().to_string()
}

/// A config whose only DoH upstream is a local port where nothing listens, so forwarded
/// queries fail at once.
pub fn closed_upstream_config() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!(r#"{{"doh_upstreams":[{{"ip":"127.0.0.1","port":{port},"tls_name":"doh.test"}}]}}"#)
}

/// A PacketSink that sends every packet into a channel.
pub struct ChannelSink(Mutex<Sender<Vec<u8>>>);

impl PacketSink for ChannelSink {
    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        let sender = self.0.lock().unwrap();
        for packet in packets {
            let _ = sender.send(packet);
        }
    }
}

pub fn sink() -> (Arc<ChannelSink>, Receiver<Vec<u8>>) {
    let (tx, rx) = channel();
    (Arc::new(ChannelSink(Mutex::new(tx))), rx)
}

/// Polls `condition` every millisecond for up to five seconds.
pub fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}
