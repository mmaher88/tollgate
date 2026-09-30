//! Queries the real default upstreams. Needs network access to 1.1.1.1:443 and
//! 9.9.9.9:443, and IPv6 for the IPv6 upstreams. Run with:
//!   cargo test -p tollgate-dns --test live -- --ignored

mod support;

use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};
use support::{checked_reply, decode, expect_forward, expect_reply, query, query_packet};
use tollgate_common::clock::now_secs;
use tollgate_common::stats::Stats;
use tollgate_dns::{DnsHandler, DohResolver};
use tollgate_policy::{Config, DohUpstream};

#[tokio::test]
#[ignore = "needs network access to 1.1.1.1:443 and 9.9.9.9:443"]
async fn each_default_upstream_answers() {
    each_answers([DohUpstream::cloudflare(), DohUpstream::quad9()]).await;
}

#[tokio::test]
#[ignore = "needs IPv6 network access to 2606:4700:4700::1111:443 and 2620:fe::fe:443"]
async fn each_ipv6_upstream_answers() {
    each_answers([DohUpstream::cloudflare_v6(), DohUpstream::quad9_v6()]).await;
}

async fn each_answers(upstreams: [DohUpstream; 2]) {
    for upstream in upstreams {
        let name = upstream.tls_name.clone();
        let resolver = DohResolver::new(vec![upstream]);
        for (id, rtype) in [(0x4242, RecordType::A), (0x4243, RecordType::AAAA)] {
            let start = Instant::now();
            let answer = resolver
                .resolve(&query(id, "example.com.", rtype, Some((1232, false))))
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let message = decode(&answer);
            println!(
                "{name} {rtype:?}: {} answers in {:?}",
                message.answers.len(),
                start.elapsed()
            );
            assert_eq!(message.metadata.id, id);
            assert_eq!(message.metadata.response_code, ResponseCode::NoError);
            assert!(message.answers.iter().any(|r| matches!(
                (&r.data, rtype),
                (RData::A(_), RecordType::A) | (RData::AAAA(_), RecordType::AAAA)
            )));
        }
    }
}

#[tokio::test]
#[ignore = "needs network access to 1.1.1.1:443 and 9.9.9.9:443"]
async fn full_path_with_the_default_config() {
    let resolver = DohResolver::new(Config::default().doh_upstreams);
    let handler = DnsHandler::new(None, Arc::new(Stats::default()));
    let packet = query_packet(7, "wWw.eXample.COM.", RecordType::A, None);
    let job = expect_forward(handler.handle_packet(&packet, now_secs()));
    let answer = resolver.resolve(job.query()).await;
    let reply = handler.complete(job, answer, now_secs());
    let message = decode(&checked_reply(&reply).payload);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.queries[0].name().to_ascii(), "wWw.eXample.COM.");
    assert!(!message.answers.is_empty());
    assert!(message.edns.is_none());

    let again = query_packet(8, "www.example.com.", RecordType::A, None);
    let message = decode(&expect_reply(handler.handle_packet(&again, now_secs())).payload);
    assert_eq!(message.metadata.id, 8);
}
