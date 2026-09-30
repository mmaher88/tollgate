mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use etherparse::PacketBuilder;
use support::{checksums_valid, client_v4, client_v6, dns_v4, dns_v6, read_udp, udp_packet};
use tollgate_dns::packet::{UdpDatagram, build_udp, parse_udp};
use tollgate_dns::{TUNNEL_DNS_V4, TUNNEL_DNS_V6};

#[test]
fn tunnel_addresses() {
    assert_eq!(TUNNEL_DNS_V4.to_string(), "198.18.0.1");
    assert_eq!(TUNNEL_DNS_V6.to_string(), "fd00:7467::1");
}

#[test]
fn parses_ipv4_udp() {
    let packet = udp_packet(client_v4(), dns_v4(), b"odd-length-payload!");
    assert_eq!(
        parse_udp(&packet),
        Some(UdpDatagram {
            source: client_v4(),
            destination: dns_v4(),
            payload: b"odd-length-payload!",
        })
    );
}

#[test]
fn parses_ipv6_udp() {
    let packet = udp_packet(client_v6(), dns_v6(), b"abc");
    assert_eq!(
        parse_udp(&packet),
        Some(UdpDatagram {
            source: client_v6(),
            destination: dns_v6(),
            payload: b"abc",
        })
    );
}

#[test]
fn builds_ipv4_reply_with_valid_checksums() {
    for payload in [&b"reply"[..], b"even", b""] {
        let packet = build_udp(dns_v4(), client_v4(), payload).unwrap();
        assert_eq!(packet.len(), 20 + 8 + payload.len());
        assert!(checksums_valid(&packet), "{packet:02x?}");
        let read = read_udp(&packet);
        assert_eq!(read.source, dns_v4());
        assert_eq!(read.destination, client_v4());
        assert_eq!(read.payload, payload);
        // TTL 64, protocol UDP.
        assert_eq!((packet[8], packet[9]), (64, 17));
    }
}

#[test]
fn builds_ipv6_reply_with_valid_checksums() {
    let packet = build_udp(dns_v6(), client_v6(), b"odd").unwrap();
    assert_eq!(packet.len(), 40 + 8 + 3);
    assert!(checksums_valid(&packet), "{packet:02x?}");
    let read = read_udp(&packet);
    assert_eq!(read.source, dns_v6());
    assert_eq!(read.destination, client_v6());
    assert_eq!(read.payload, b"odd");
    // Next header UDP, hop limit 64.
    assert_eq!((packet[6], packet[7]), (17, 64));
}

#[test]
fn build_refuses_mixed_families() {
    assert_eq!(build_udp(dns_v4(), client_v6(), b"x"), None);
    assert_eq!(build_udp(dns_v6(), client_v4(), b"x"), None);
}

#[test]
fn rejects_fragmented_ipv4() {
    let mut first = udp_packet(client_v4(), dns_v4(), b"payload");
    // More fragments flag.
    first[6] |= 0x20;
    assert_eq!(parse_udp(&first), None);

    let mut later = udp_packet(client_v4(), dns_v4(), b"payload");
    // Fragment offset 8 (in units of 8 bytes: 1).
    later[7] = 1;
    assert_eq!(parse_udp(&later), None);
}

#[test]
fn rejects_fragmented_ipv6() {
    let udp = {
        let whole = udp_packet(client_v6(), dns_v6(), b"payload");
        whole[40..].to_vec()
    };
    let mut packet = Vec::new();
    // Version 6, payload length (fragment header + UDP), next header 44 (fragment), hop 64.
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&((8 + udp.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[44, 64]);
    packet.extend_from_slice(&client_v6_octets());
    packet.extend_from_slice(&dns_v6_octets());
    // Fragment header: next header UDP, offset 0 with the more-fragments bit, id 7.
    packet.extend_from_slice(&[17, 0, 0, 1, 0, 0, 0, 7]);
    packet.extend_from_slice(&udp);
    assert_eq!(parse_udp(&packet), None);
}

fn client_v6_octets() -> [u8; 16] {
    let IpAddr::V6(ip) = client_v6().ip() else {
        unreachable!()
    };
    ip.octets()
}

fn dns_v6_octets() -> [u8; 16] {
    let IpAddr::V6(ip) = dns_v6().ip() else {
        unreachable!()
    };
    ip.octets()
}

#[test]
fn rejects_other_protocols_and_garbage() {
    let tcp = {
        let builder = PacketBuilder::ipv4([198, 18, 0, 2], [198, 18, 0, 1], 64).tcp(1, 53, 0, 1000);
        let mut v = Vec::new();
        builder.write(&mut v, b"x").unwrap();
        v
    };
    assert_eq!(parse_udp(&tcp), None);

    let icmp = {
        let builder =
            PacketBuilder::ipv4([198, 18, 0, 2], [198, 18, 0, 1], 64).icmpv4_echo_request(1, 1);
        let mut v = Vec::new();
        builder.write(&mut v, b"ping").unwrap();
        v
    };
    assert_eq!(parse_udp(&icmp), None);

    assert_eq!(parse_udp(&[]), None);
    assert_eq!(parse_udp(&[0x45, 0, 0]), None);
    assert_eq!(parse_udp(&[0x00; 40]), None);
    // A UDP header that claims more bytes than the packet holds.
    let mut short = udp_packet(client_v4(), dns_v4(), b"12345678");
    short.truncate(30);
    assert_eq!(parse_udp(&short), None);
}

#[test]
fn round_trips_through_parse_and_build() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 1234);
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);
    let packet = build_udp(source, destination, b"hello").unwrap();
    let parsed = parse_udp(&packet).unwrap();
    assert_eq!(parsed.source, source);
    assert_eq!(parsed.destination, destination);
    assert_eq!(parsed.payload, b"hello");
}
