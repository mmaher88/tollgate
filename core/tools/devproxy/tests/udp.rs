use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use devproxy::udp::{PayloadHandler, PayloadOutcome, serve_dns};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::net::UdpSocket;
use tollgate_common::stats::{Stats, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohError, DohResolver};
use tollgate_filter::{DomainSet, ListFormat, ListSource};
use tollgate_policy::DohUpstream;

const NOW: u64 = 1_000;

fn query(id: u16, name: &str, rtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    message.to_vec().unwrap()
}

fn blocklist() -> Arc<DomainSet> {
    let list = ListSource {
        name: "test",
        text: "||ads.example^\n",
        format: ListFormat::Adblock,
    };
    Arc::new(DomainSet::from_bytes(DomainSet::build(&[list])).unwrap())
}

fn handler() -> (PayloadHandler, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    let dns = Arc::new(DnsHandler::new(Some(blocklist()), stats.clone()));
    (PayloadHandler::new(dns), stats)
}

fn reply(outcome: PayloadOutcome) -> Message {
    match outcome {
        PayloadOutcome::Reply(payload) => Message::from_vec(&payload).unwrap(),
        other => panic!("expected a reply, got {other:?}"),
    }
}

#[test]
fn blocked_names_are_answered_from_the_payload() {
    let (handler, stats) = handler();
    let message = reply(handler.handle(&query(0x0a0b, "ads.example.", RecordType::A), NOW));
    assert_eq!(message.metadata.id, 0x0a0b);
    assert_eq!(message.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    let message = reply(handler.handle(&query(2, "example.com.", RecordType::HTTPS), NOW));
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            dns_queries: 2,
            dns_blocked: 1,
            ..StatsSnapshot::default()
        }
    );
}

#[test]
fn other_names_are_forwarded_with_the_payload_unchanged() {
    let (handler, stats) = handler();
    let payload = query(0x7777, "example.com.", RecordType::A);
    let PayloadOutcome::Forward(job) = handler.handle(&payload, NOW) else {
        panic!("expected a forward");
    };
    assert_eq!(job.query(), payload.as_slice());
    let message = Message::from_vec(&handler.complete(job, Err(DohError::Timeout), NOW)).unwrap();
    assert_eq!(message.metadata.id, 0x7777);
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(stats.snapshot().dns_failed, 1);
}

#[test]
fn responses_and_short_payloads_are_dropped() {
    let (handler, stats) = handler();
    let mut response = query(1, "example.com.", RecordType::A);
    response[2] |= 0x80;
    assert!(matches!(
        handler.handle(&response, NOW),
        PayloadOutcome::Drop
    ));
    assert!(matches!(
        handler.handle(&[1, 2, 3, 4, 5], NOW),
        PayloadOutcome::Drop
    ));
    assert_eq!(stats.snapshot().packets_dropped, 2);
}

async fn exchange(client: &UdpSocket, server: SocketAddr, payload: &[u8]) -> Message {
    client.send_to(payload, server).await.unwrap();
    let mut buf = [0u8; 1500];
    let (len, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, server);
    Message::from_vec(&buf[..len]).unwrap()
}

#[tokio::test]
async fn the_udp_responder_answers_and_forwards() {
    let (handler, _) = handler();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = DohUpstream {
        ip: "127.0.0.1".parse().unwrap(),
        port: closed.local_addr().unwrap().port(),
        tls_name: "doh.test".to_string(),
        path: "/dns-query".to_string(),
    };
    drop(closed);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = socket.local_addr().unwrap();
    let responder = tokio::spawn(serve_dns(socket, handler, DohResolver::new(vec![upstream])));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blocked = exchange(&client, server, &query(11, "ads.example.", RecordType::A)).await;
    assert_eq!(blocked.metadata.id, 11);
    assert_eq!(blocked.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    let failed = exchange(&client, server, &query(12, "example.com.", RecordType::A)).await;
    assert_eq!(failed.metadata.id, 12);
    assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
    responder.abort();
}
