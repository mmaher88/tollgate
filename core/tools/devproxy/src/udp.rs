//! DNS over plain UDP for tools that receive DNS payloads, not the tunnel's IP packets.
//!
//! [`PayloadHandler`] wraps each payload into the IPv4 packet the tunnel would deliver to
//! [`DnsHandler`] (from `198.18.0.2:53000` to `198.18.0.1:53`) and unwraps the reply, so
//! blocking, caching and forwarding behave exactly as on the phone.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tollgate_common::clock;
use tollgate_dns::packet::{build_udp, parse_udp};
use tollgate_dns::{DnsHandler, DohError, DohResolver, ForwardJob, Outcome, TUNNEL_DNS_V4};

/// Where wrapped queries appear to come from: the tunnel's own address.
pub const WRAP_CLIENT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 53000);
/// Where wrapped queries go: the tunnel's DNS address.
pub const WRAP_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(TUNNEL_DNS_V4), 53);

/// What to do with one DNS payload.
#[derive(Debug)]
pub enum PayloadOutcome {
    /// Send this payload back to the client now.
    Reply(Vec<u8>),
    /// Resolve upstream, then call [`PayloadHandler::complete`].
    Forward(ForwardJob),
    /// Not a query; nothing to send.
    Drop,
}

/// [`DnsHandler`] for DNS payloads.
pub struct PayloadHandler {
    handler: Arc<DnsHandler>,
}

fn payload_of(packet: &[u8]) -> Option<Vec<u8>> {
    parse_udp(packet).map(|datagram| datagram.payload.to_vec())
}

impl PayloadHandler {
    pub fn new(handler: Arc<DnsHandler>) -> PayloadHandler {
        PayloadHandler { handler }
    }

    /// Like [`DnsHandler::handle_packet`] for a DNS payload. Never blocks or awaits.
    pub fn handle(&self, payload: &[u8], now: u64) -> PayloadOutcome {
        let Some(packet) = build_udp(WRAP_CLIENT, WRAP_SERVER, payload) else {
            return PayloadOutcome::Drop;
        };
        match self.handler.handle_packet(&packet, now) {
            Outcome::Reply(reply) => {
                payload_of(&reply).map_or(PayloadOutcome::Drop, PayloadOutcome::Reply)
            }
            Outcome::Forward(job) => PayloadOutcome::Forward(job),
            Outcome::Drop => PayloadOutcome::Drop,
        }
    }

    /// Like [`DnsHandler::complete`], returning the reply payload.
    pub fn complete(
        &self,
        job: ForwardJob,
        answer: Result<Vec<u8>, DohError>,
        now: u64,
    ) -> Vec<u8> {
        payload_of(&self.handler.complete(job, answer, now)).unwrap_or_default()
    }
}

/// Answers DNS queries arriving on `socket` until the future is dropped. Each forwarded
/// query runs in its own task; `resolve` caps them at 128 in flight (more get SERVFAIL).
pub async fn serve_dns(socket: UdpSocket, handler: PayloadHandler, resolver: DohResolver) {
    let socket = Arc::new(socket);
    let handler = Arc::new(handler);
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                // Linux reports ICMP errors from earlier replies here; they are not fatal.
                log::debug!("DNS socket: {e}");
                tokio::task::yield_now().await;
                continue;
            }
        };
        match handler.handle(&buf[..len], clock::now_secs()) {
            PayloadOutcome::Reply(reply) => {
                let _ = socket.send_to(&reply, peer).await;
            }
            PayloadOutcome::Drop => {}
            PayloadOutcome::Forward(job) => {
                let (socket, handler, resolver) =
                    (socket.clone(), handler.clone(), resolver.clone());
                tokio::spawn(async move {
                    let answer = resolver.resolve(job.query()).await;
                    let reply = handler.complete(job, answer, clock::now_secs());
                    let _ = socket.send_to(&reply, peer).await;
                });
            }
        }
    }
}
