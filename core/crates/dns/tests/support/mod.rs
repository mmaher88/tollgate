//! Helpers shared by the integration tests. Every test binary includes this module and uses
//! a different part of it. Packets are built and checked with etherparse and an independent
//! RFC 1071 checksum, never with the crate's own packet code.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

pub const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x7467, 0, 0, 0, 0, 0, 2);

pub fn client_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(CLIENT_V4), 53001)
}

pub fn client_v6() -> SocketAddr {
    SocketAddr::new(IpAddr::V6(CLIENT_V6), 40000)
}

pub fn dns_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 53)
}

pub fn dns_v6() -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0x7467, 0, 0, 0, 0, 0, 1)),
        53,
    )
}

/// One UDP packet built by etherparse.
pub fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let builder = match (source.ip(), destination.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), 64),
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), 64),
        _ => panic!("mixed address families"),
    }
    .udp(source.port(), destination.port());
    let mut out = Vec::new();
    builder.write(&mut out, payload).unwrap();
    out
}

/// A UDP datagram read back with etherparse.
#[derive(Debug, PartialEq, Eq)]
pub struct Datagram {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: Vec<u8>,
}

pub fn read_udp(packet: &[u8]) -> Datagram {
    let sliced = SlicedPacket::from_ip(packet).expect("an IP packet");
    let (source, destination) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => (
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        ),
        Some(NetSlice::Ipv6(v6)) => (
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        ),
        other => panic!("not IP: {other:?}"),
    };
    let Some(TransportSlice::Udp(udp)) = &sliced.transport else {
        panic!("not UDP");
    };
    Datagram {
        source: SocketAddr::new(source, udp.source_port()),
        destination: SocketAddr::new(destination, udp.destination_port()),
        payload: udp.payload().to_vec(),
    }
}

fn ones_complement_sum(mut acc: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        acc += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// Checks the IPv4 header checksum and the UDP checksum over the pseudo header with an
/// independent RFC 1071 sum. A UDP checksum of zero ("not computed") counts as invalid.
pub fn checksums_valid(packet: &[u8]) -> bool {
    match packet[0] >> 4 {
        4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let header_ok = fold(ones_complement_sum(0, &packet[..header_len])) == 0xffff;
            let udp = &packet[header_len..];
            let mut acc = ones_complement_sum(0, &packet[12..20]);
            acc += 17 + udp.len() as u32;
            acc = ones_complement_sum(acc, udp);
            header_ok && fold(acc) == 0xffff && udp[6..8] != [0, 0]
        }
        6 => {
            let udp = &packet[40..];
            let mut acc = ones_complement_sum(0, &packet[8..40]);
            acc += 17 + udp.len() as u32;
            acc = ones_complement_sum(acc, udp);
            fold(acc) == 0xffff && udp[6..8] != [0, 0]
        }
        _ => false,
    }
}
