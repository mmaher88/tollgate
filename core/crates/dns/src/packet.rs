//! Raw IPv4 and IPv6 packets from the tunnel: lifting a UDP datagram out, and writing the
//! reply packet with its checksums.
//!
//! Public so that tools which receive plain UDP (devproxy) can wrap payloads into the packets
//! [`crate::DnsHandler`] expects, and unwrap its replies.

use std::net::{IpAddr, SocketAddr};

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

/// A UDP datagram inside one raw IP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: &'a [u8],
}

/// Parses a raw IP packet with no link-layer header, as the tunnel delivers it. Returns
/// `None` for anything that is not one whole UDP datagram: other protocols, fragments and
/// malformed input.
pub fn parse_udp(packet: &[u8]) -> Option<UdpDatagram<'_>> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    let (source, destination) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => {
            if v4.is_payload_fragmented() {
                return None;
            }
            let header = v4.header();
            (
                IpAddr::V4(header.source_addr()),
                IpAddr::V4(header.destination_addr()),
            )
        }
        Some(NetSlice::Ipv6(v6)) => {
            if v6.is_payload_fragmented() {
                return None;
            }
            let header = v6.header();
            (
                IpAddr::V6(header.source_addr()),
                IpAddr::V6(header.destination_addr()),
            )
        }
        _ => return None,
    };
    match sliced.transport {
        Some(TransportSlice::Udp(udp)) => Some(UdpDatagram {
            source: SocketAddr::new(source, udp.source_port()),
            destination: SocketAddr::new(destination, udp.destination_port()),
            payload: udp.payload(),
        }),
        _ => None,
    }
}

/// Writes one UDP packet from `source` to `destination` with a hop limit of 64. The IPv4
/// header checksum and the UDP checksum (for both families) are filled in. Returns `None`
/// when the two addresses are of different families or the payload does not fit in one
/// packet.
pub fn build_udp(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let builder = match (source.ip(), destination.ip()) {
        (IpAddr::V4(from), IpAddr::V4(to)) => PacketBuilder::ipv4(from.octets(), to.octets(), 64),
        (IpAddr::V6(from), IpAddr::V6(to)) => PacketBuilder::ipv6(from.octets(), to.octets(), 64),
        _ => return None,
    }
    .udp(source.port(), destination.port());
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).ok()?;
    Some(out)
}
