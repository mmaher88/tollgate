//! The DNS path of the tunnel. Queries arrive as raw IP packets addressed to the tunnel's DNS
//! address. Blocked names, HTTPS and SVCB queries and cache hits are answered at once;
//! everything else is forwarded over DNS over HTTPS and answered through
//! [`DnsHandler::complete`].

mod answer;
mod cache;
mod doh;
mod handler;
pub mod packet;
mod wire;

use std::net::{Ipv4Addr, Ipv6Addr};

pub use answer::{BLOCK_TTL, MAX_UDP_PAYLOAD};
pub use cache::{CACHE_CAPACITY, MAX_CACHE_TTL, MIN_CACHE_TTL};
pub use doh::DohError;
pub use handler::{DnsHandler, ForwardJob, Outcome};

/// The tunnel's IPv4 DNS server address.
pub const TUNNEL_DNS_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// The tunnel's IPv6 DNS server address.
pub const TUNNEL_DNS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x7467, 0, 0, 0, 0, 0, 1);
