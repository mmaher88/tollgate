mod support;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use etherparse::PacketBuilder;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use support::{
    client_v4, client_v6, dns_v4, dns_v6, expect_forward, expect_reply, query, query_packet,
    udp_packet,
};
use tollgate_common::stats::{Stats, StatsSnapshot};
use tollgate_dns::{DnsHandler, Outcome};

const NOW: u64 = 1_000;

fn handler() -> (DnsHandler, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    (DnsHandler::new(None, stats.clone()), stats)
}

#[test]
fn handler_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<DnsHandler>();
}

#[test]
fn drops_everything_that_is_not_a_query_to_the_tunnel() {
    let (handler, stats) = handler();
    let a_query = query(1, "example.com.", RecordType::A, None);
    let other_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 3)), 53);
    let other_v6 = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0x7467, 0, 0, 0, 0, 0, 3)),
        53,
    );
    let other_port = SocketAddr::new(dns_v4().ip(), 5353);
    let tcp = {
        let builder =
            PacketBuilder::ipv4([198, 18, 0, 2], [198, 18, 0, 1], 64).tcp(5000, 53, 1, 1000);
        let mut v = Vec::new();
        builder.write(&mut v, &a_query).unwrap();
        v
    };
    let mut fragment = udp_packet(client_v4(), dns_v4(), &a_query);
    fragment[6] |= 0x20;
    let mut response = a_query.clone();
    response[2] |= 0x80;

    let dropped = [
        udp_packet(client_v4(), other_v4, &a_query),
        udp_packet(client_v6(), other_v6, &a_query),
        udp_packet(client_v4(), other_port, &a_query),
        tcp,
        fragment,
        vec![0x45, 0, 0, 20],
        udp_packet(client_v4(), dns_v4(), &a_query[..11]),
        udp_packet(client_v4(), dns_v4(), &response),
    ];
    for packet in &dropped {
        assert!(matches!(handler.handle_packet(packet, NOW), Outcome::Drop));
    }
    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            packets_dropped: 8,
            ..StatsSnapshot::default()
        }
    );
}

#[test]
fn undecodable_query_gets_formerr() {
    let (handler, stats) = handler();
    // Header of a recursion-desired query claiming one question, and no question.
    let payload = [0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    let packet = udp_packet(client_v4(), dns_v4(), &payload);
    let reply = expect_reply(handler.handle_packet(&packet, NOW));
    assert_eq!(reply.source, dns_v4());
    assert_eq!(reply.destination, client_v4());
    // Same id; QR, RD, RA; FORMERR; no sections.
    assert_eq!(
        reply.payload,
        [0xab, 0xcd, 0x81, 0x81, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(stats.snapshot().dns_queries, 1);
    assert_eq!(stats.snapshot().packets_dropped, 0);
}

#[test]
fn two_questions_get_formerr() {
    let (handler, _) = handler();
    let mut message = Message::new(7, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii("a.example.").unwrap(),
        RecordType::A,
    ));
    message.add_query(Query::query(
        Name::from_ascii("b.example.").unwrap(),
        RecordType::A,
    ));
    let packet = udp_packet(client_v4(), dns_v4(), &message.to_vec().unwrap());
    let reply = expect_reply(handler.handle_packet(&packet, NOW));
    assert_eq!(reply.payload, [0, 7, 0x80, 0x81, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn compressed_question_gets_formerr() {
    let (handler, _) = handler();
    // One question whose name is "a" followed by a pointer back to that label.
    let payload = [
        0, 9, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0xc0, 12, 0, 1, 0, 1,
    ];
    let packet = udp_packet(client_v4(), dns_v4(), &payload);
    let reply = expect_reply(handler.handle_packet(&packet, NOW));
    assert_eq!(reply.payload, [0, 9, 0x81, 0x81, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn other_opcodes_get_notimp() {
    let (handler, stats) = handler();
    let mut message = Message::new(0x0102, MessageType::Query, OpCode::Notify);
    message.add_query(Query::query(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::SOA,
    ));
    let packet = udp_packet(client_v6(), dns_v6(), &message.to_vec().unwrap());
    let reply = expect_reply(handler.handle_packet(&packet, NOW));
    assert_eq!(reply.source, dns_v6());
    assert_eq!(reply.destination, client_v6());
    // Opcode NOTIFY (4) kept, QR set, RA and NOTIMP.
    assert_eq!(reply.payload, [1, 2, 0xa0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(stats.snapshot().dns_queries, 1);
}

#[test]
fn forwards_queries_it_cannot_answer() {
    let (handler, stats) = handler();
    let payload = query(0x4242, "Example.COM.", RecordType::A, Some((4096, true)));
    let packet = udp_packet(client_v4(), dns_v4(), &payload);
    let job = expect_forward(handler.handle_packet(&packet, NOW));
    assert_eq!(job.query(), payload.as_slice());

    let packet = udp_packet(client_v6(), dns_v6(), &payload);
    let job = expect_forward(handler.handle_packet(&packet, NOW));
    assert_eq!(job.query(), payload.as_slice());

    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            dns_queries: 2,
            dns_forwarded: 2,
            ..StatsSnapshot::default()
        }
    );
}

#[test]
fn forwards_other_record_types() {
    let (handler, _) = handler();
    let job = expect_forward(
        handler.handle_packet(&query_packet(3, "example.org.", RecordType::MX, None), NOW),
    );
    assert_eq!(
        job.query(),
        query(3, "example.org.", RecordType::MX, None).as_slice()
    );
}
