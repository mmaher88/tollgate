use std::fs;

use tollgate_ffi::{
    ListFormat, ListInput, ListTarget, TollgateError, compile_lists, detect_list_format,
};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, Verdict};
use tollgate_policy::BundledGroup;

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
        exempt_sensitive_hosts: false,
    }
}

/// A DNS list in adblock syntax that must not block sensitive or bank hosts.
fn exempting(name: &str, text: &str) -> ListInput {
    ListInput {
        exempt_sensitive_hosts: true,
        ..input(name, text, ListFormat::Adblock, ListTarget::Dns)
    }
}

fn compile_blocklist(lists: Vec<ListInput>) -> DomainSet {
    let tmp = tempfile::tempdir().unwrap();
    compile_lists(lists, tmp.path().to_str().unwrap().to_string()).unwrap();
    DomainSet::load(&tmp.path().join(DOMAINS_FILE)).unwrap()
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
    // An empty DNS blocklist is the 40-byte header alone.
    assert_eq!(
        (
            report.network_rules,
            report.domain_entries,
            report.domains_bytes
        ),
        (0, 0, 40)
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

#[test]
fn detect_list_format_reports_the_majority_format() {
    assert_eq!(
        detect_list_format(HOSTS.to_string()),
        Some(ListFormat::Hosts)
    );
    assert_eq!(
        detect_list_format(URL_RULES.to_string()),
        Some(ListFormat::Adblock)
    );
    assert_eq!(
        detect_list_format(DNS_RULES.to_string()),
        Some(ListFormat::Adblock)
    );
    assert_eq!(detect_list_format("# only a comment\n".to_string()), None);
    assert_eq!(detect_list_format(String::new()), None);
}

/// The names of the patterns of `groups`, without `*.`, each with whether it had one
/// (the name and its subdomains) or not (that host only).
fn group_names(groups: &[BundledGroup]) -> Vec<(&'static str, bool)> {
    groups
        .iter()
        .flat_map(|group| group.patterns().iter())
        .map(|pattern| match pattern.strip_prefix("*.") {
            Some(name) => (name, true),
            None => (*pattern, false),
        })
        .collect()
}

#[test]
fn exempting_lists_leave_sensitive_and_bank_hosts_unblocked() {
    let exempt = group_names(&[BundledGroup::Sensitive, BundledGroup::Banks]);
    // Every sensitive and bank host blocked as a name and its subdomains and as one host
    // and, under each domain, a telemetry host blocked as one host, by a wildcard pattern
    // and in a hosts file.
    let mut text = String::new();
    let mut hosts = String::new();
    for &(name, domain) in &exempt {
        text += &format!("||{name}^\n|{name}^\n");
        if domain {
            text += &format!("|telemetry.{name}^\n||log*.{name}^\n");
            hosts += &format!("0.0.0.0 metrics.{name}\n");
        }
    }
    // The other bundled groups (Apple, and the apps that refuse our certificate) are not
    // exempt: ad hosts under them stay blockable.
    let others = group_names(&[BundledGroup::Apple, BundledGroup::SilentRefusers]);
    for (name, _) in &others {
        text += &format!("||ads.{name}^\n");
    }
    let bank = exempt[exempt.len() - 1].0;
    let domains = compile_blocklist(vec![
        // A list that exempts nothing still blocks a bank host.
        input(
            "plain",
            &format!("||plain.{bank}^\n"),
            ListFormat::Adblock,
            ListTarget::Dns,
        ),
        exempting(
            "exempting",
            &format!("{text}||plain.{bank}^\n||tracker.example^\n"),
        ),
        ListInput {
            exempt_sensitive_hosts: true,
            ..input(
                "exempting hosts",
                &format!("{hosts}0.0.0.0 hosts-tracker.example\n"),
                ListFormat::Hosts,
                ListTarget::Dns,
            )
        },
    ]);
    for &(name, domain) in &exempt {
        assert!(!domains.is_blocked(name), "{name}");
        if domain {
            for host in [
                format!("telemetry.{name}"),
                format!("logx.{name}"),
                format!("metrics.{name}"),
            ] {
                assert!(!domains.is_blocked(&host), "{host}");
            }
        }
    }
    for (name, _) in &others {
        let host = format!("ads.{name}");
        assert!(domains.is_blocked(&host), "{host}");
    }
    for host in [
        format!("plain.{bank}"),
        "tracker.example".to_string(),
        "hosts-tracker.example".to_string(),
    ] {
        assert!(domains.is_blocked(&host), "{host}");
    }
}

#[test]
fn a_url_list_cannot_exempt_sensitive_hosts() {
    let tmp = tempfile::tempdir().unwrap();
    let list = ListInput {
        exempt_sensitive_hosts: true,
        ..input("easylist", URL_RULES, ListFormat::Adblock, ListTarget::Url)
    };
    let result = compile_lists(vec![list], tmp.path().to_str().unwrap().to_string());
    assert_eq!(
        result,
        Err(TollgateError::Config {
            message: "list \"easylist\" exempts sensitive hosts, which only a DNS list can do"
                .to_string()
        })
    );
    assert!(!tmp.path().join(ENGINE_FILE).exists());
}
