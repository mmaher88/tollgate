use std::fs;

use tollgate_filter::{
    DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError, ListFormat, ListSource,
    Verdict, compile, compile_split,
};

const EASYLIST: &str =
    "! Title: snippet\n||ads.example^\n/banner/*/img^\n##.ad\n||tracker.example^$third-party\n";
const DNS_ADBLOCK: &str = "||dns-only.example^\n@@||ok.ads.example^\n";
const HOSTS: &str = "0.0.0.0 hosts-only.example\n127.0.0.1 localhost\n";

fn lists() -> [ListSource<'static>; 2] {
    [
        ListSource {
            name: "easylist",
            text: EASYLIST,
            format: ListFormat::Adblock,
        },
        ListSource {
            name: "hosts",
            text: HOSTS,
            format: ListFormat::Hosts,
        },
    ]
}

fn file_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn compile_writes_both_files_and_reports_them() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("lists");
    let report = compile(&lists(), &out).unwrap();

    assert_eq!(
        file_names(&out),
        vec![DOMAINS_FILE.to_string(), ENGINE_FILE.to_string()]
    );
    assert_eq!(report.network_rules, 3);
    // ads.example (adblock list) and hosts-only.example (hosts list).
    assert_eq!(report.domain_entries, 2);
    assert_eq!(
        report.engine_bytes,
        fs::metadata(out.join(ENGINE_FILE)).unwrap().len()
    );
    assert_eq!(
        report.domains_bytes,
        fs::metadata(out.join(DOMAINS_FILE)).unwrap().len()
    );
    assert_eq!(report.domains_bytes, 32 + 8 * 2);

    let engine = FilterEngine::load(&out.join(ENGINE_FILE)).unwrap();
    assert_eq!(
        engine.check(
            "https://ads.example/a.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Block { rule: None }
    );
    // Hosts lists stay out of the engine.
    assert_eq!(
        engine.check(
            "https://hosts-only.example/a.js",
            "https://site.example/",
            "script"
        ),
        Verdict::Allow
    );
    let domains = DomainSet::load(&out.join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("x.ads.example"));
    assert!(domains.is_blocked("hosts-only.example"));
    // $third-party rules are not host rules.
    assert!(!domains.is_blocked("tracker.example"));
}

#[test]
fn compile_split_routes_lists() {
    let dir = tempfile::tempdir().unwrap();
    let engine_lists = [ListSource {
        name: "easylist",
        text: EASYLIST,
        format: ListFormat::Adblock,
    }];
    let dns_lists = [
        ListSource {
            name: "adguard-dns",
            text: DNS_ADBLOCK,
            format: ListFormat::Adblock,
        },
        ListSource {
            name: "hosts",
            text: HOSTS,
            format: ListFormat::Hosts,
        },
    ];
    let report = compile_split(&engine_lists, &dns_lists, dir.path()).unwrap();
    assert_eq!(report.network_rules, 3);
    assert_eq!(report.domain_entries, 3);

    let engine = FilterEngine::load(&dir.path().join(ENGINE_FILE)).unwrap();
    assert_eq!(
        engine.check(
            "https://dns-only.example/",
            "https://site.example/",
            "script"
        ),
        Verdict::Allow
    );
    let domains = DomainSet::load(&dir.path().join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("dns-only.example"));
    assert!(domains.is_blocked("hosts-only.example"));
    // DNS lists alone decide the DNS blocklist.
    assert!(!domains.is_blocked("ads.example"));
}

#[test]
fn recompiling_replaces_the_files() {
    let dir = tempfile::tempdir().unwrap();
    compile(&lists(), dir.path()).unwrap();
    let old_domains = DomainSet::load(&dir.path().join(DOMAINS_FILE)).unwrap();

    let replacement = [ListSource {
        name: "new",
        text: "||new.example^\n",
        format: ListFormat::Adblock,
    }];
    let report = compile(&replacement, dir.path()).unwrap();
    assert_eq!(report.network_rules, 1);
    assert_eq!(
        file_names(dir.path()),
        vec![DOMAINS_FILE.to_string(), ENGINE_FILE.to_string()]
    );

    let domains = DomainSet::load(&dir.path().join(DOMAINS_FILE)).unwrap();
    assert!(domains.is_blocked("new.example"));
    assert!(!domains.is_blocked("ads.example"));
    // A set loaded before the rename still sees the old file.
    assert!(old_domains.is_blocked("ads.example"));
    assert!(!old_domains.is_blocked("new.example"));
}

#[test]
fn compile_reports_io_errors() {
    let dir = tempfile::tempdir().unwrap();
    let not_a_dir = dir.path().join("file");
    fs::write(&not_a_dir, b"x").unwrap();
    let err = compile(&lists(), &not_a_dir).unwrap_err();
    assert!(
        matches!(err, FilterError::Io { ref path, .. } if path == &not_a_dir),
        "{err:?}"
    );
}
