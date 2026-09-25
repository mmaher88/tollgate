use std::fs;

use tollgate_ffi::{ListFormat, ListInput, ListTarget, TollgateError, compile_lists};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, Verdict};

const URL_RULES: &str =
    "! Title: test URL list\n||ads.example^\n||tracker.example^$third-party\n/banner/*$image\n";
const DNS_RULES: &str = "! Title: test DNS list\n||dns-block.example^\n@@||ok.dns-block.example^\n";
const HOSTS: &str = "# test hosts\n0.0.0.0 hosts-block.example\n127.0.0.1 localhost\n";

fn input(name: &str, text: &str, format: ListFormat, target: ListTarget) -> ListInput {
    ListInput {
        name: name.to_string(),
        text: text.to_string(),
        format,
        target,
    }
}

#[test]
fn url_lists_feed_the_engine_and_dns_lists_the_blocklist() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("lists");
    let report = compile_lists(
        vec![
            input("easylist", URL_RULES, ListFormat::Adblock, ListTarget::Url),
            input(
                "adguard-dns",
                DNS_RULES,
                ListFormat::Adblock,
                ListTarget::Dns,
            ),
            input("hosts", HOSTS, ListFormat::Hosts, ListTarget::Dns),
        ],
        dir.to_str().unwrap().to_string(),
    )
    .unwrap();
    assert_eq!(report.network_rules, 3);
    assert_eq!(report.domain_entries, 3);
    assert_eq!(
        report.engine_bytes,
        fs::metadata(dir.join(ENGINE_FILE)).unwrap().len()
    );
    assert_eq!(
        report.domains_bytes,
        fs::metadata(dir.join(DOMAINS_FILE)).unwrap().len()
    );

    let domains = DomainSet::load(&dir.join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("dns-block.example"));
    assert!(domains.is_blocked("www.dns-block.example"));
    assert!(!domains.is_blocked("ok.dns-block.example"));
    assert!(domains.is_blocked("hosts-block.example"));
    // URL lists do not reach the DNS blocklist.
    assert!(!domains.is_blocked("ads.example"));

    let engine = FilterEngine::load(&dir.join(ENGINE_FILE)).unwrap();
    assert_eq!(
        engine.check(
            "https://ads.example/x.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Block { rule: None }
    );
    // DNS lists do not reach the engine.
    assert_eq!(
        engine.check(
            "https://dns-block.example/x.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Allow
    );
}

#[test]
fn a_hosts_list_cannot_feed_the_url_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let result = compile_lists(
        vec![input("hosts", HOSTS, ListFormat::Hosts, ListTarget::Url)],
        tmp.path().to_str().unwrap().to_string(),
    );
    assert_eq!(
        result,
        Err(TollgateError::Config {
            message: "list \"hosts\" is in hosts format and can only feed the DNS blocklist"
                .to_string()
        })
    );
    assert!(!tmp.path().join(ENGINE_FILE).exists());
}

#[test]
fn no_lists_give_empty_files() {
    let tmp = tempfile::tempdir().unwrap();
    let report = compile_lists(Vec::new(), tmp.path().to_str().unwrap().to_string()).unwrap();
    assert_eq!(
        (
            report.network_rules,
            report.domain_entries,
            report.domains_bytes
        ),
        (0, 0, 32)
    );
    assert!(tmp.path().join(ENGINE_FILE).exists());
    assert!(tmp.path().join(DOMAINS_FILE).exists());
}

#[test]
fn an_unwritable_directory_is_a_lists_error() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("a-file");
    fs::write(&file, "").unwrap();
    let result = compile_lists(Vec::new(), file.to_str().unwrap().to_string());
    assert!(
        matches!(&result, Err(TollgateError::Lists { .. })),
        "{result:?}"
    );
}
