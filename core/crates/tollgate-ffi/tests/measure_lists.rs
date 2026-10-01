//! The DNS blocklist compiled from the default lists, measured with the real lists. Not
//! part of the normal test run: it needs the lists on disk. Run from core/ with:
//!
//!   TOLLGATE_LISTS_DIR=/path/to/lists cargo test --release -p tollgate-ffi --test measure_lists -- --ignored --nocapture
//!
//! The directory must hold each default list of ios/Shared/FilterLists.swift as `<id>.txt`,
//! the name the app's list cache gives it: easylist, easyprivacy, adguard-mobile,
//! adguard-dns, stevenblack, hagezi-light and oisd-small. Each compile runs in a fresh child
//! process, first with the five lists from before HaGeZi Multi LIGHT and OISD small, then
//! with all seven, and reports its peak resident memory (VmHWM) with the list texts loaded.
//!
//! Optionally, TOLLGATE_EXPECT_BLOCKED and TOLLGATE_EXPECT_OPEN name files of host names,
//! one per line, that the blocklist of all seven lists must block and must leave open.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use tollgate_ffi::{ListFormat, ListInput, ListTarget, compile_lists};
use tollgate_filter::{DOMAINS_FILE, DnsList, DomainRules, DomainSet, Exemption, ListSource};
use tollgate_policy::BundledGroup;

/// The default lists: id, format, target, and whether the list exempts sensitive hosts.
const DEFAULTS: [(&str, ListFormat, ListTarget, bool); 7] = [
    ("easylist", ListFormat::Adblock, ListTarget::Url, false),
    ("easyprivacy", ListFormat::Adblock, ListTarget::Url, false),
    (
        "adguard-mobile",
        ListFormat::Adblock,
        ListTarget::Url,
        false,
    ),
    ("adguard-dns", ListFormat::Adblock, ListTarget::Dns, false),
    ("stevenblack", ListFormat::Hosts, ListTarget::Dns, false),
    ("hagezi-light", ListFormat::Adblock, ListTarget::Dns, true),
    ("oisd-small", ListFormat::Adblock, ListTarget::Dns, true),
];

/// The defaults before HaGeZi Multi LIGHT and OISD small.
const BEFORE: usize = 5;

fn status_kib(field: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with(field))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn lists_dir() -> String {
    std::env::var("TOLLGATE_LISTS_DIR").expect("set TOLLGATE_LISTS_DIR")
}

#[test]
#[ignore = "needs real filter lists in TOLLGATE_LISTS_DIR"]
fn measure_default_lists() {
    lists_dir();
    for count in [BEFORE, DEFAULTS.len()] {
        println!("== the first {count} default lists");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "compile_default_lists",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("TOLLGATE_MEASURE_COUNT", count.to_string())
            .status()
            .unwrap();
        assert!(status.success());
    }
}

/// Run by measure_default_lists in a child process.
#[test]
#[ignore = "run through measure_default_lists"]
fn compile_default_lists() {
    let Some(count) = std::env::var_os("TOLLGATE_MEASURE_COUNT") else {
        println!("compile_default_lists only runs as part of measure_default_lists");
        return;
    };
    let count: usize = count.to_str().unwrap().parse().unwrap();
    let dir = lists_dir();
    let inputs: Vec<ListInput> = DEFAULTS[..count]
        .iter()
        .map(|&(id, format, target, exempt_sensitive_hosts)| {
            let path = Path::new(&dir).join(format!("{id}.txt"));
            ListInput {
                name: id.to_string(),
                text: std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display())),
                format,
                target,
                exempt_sensitive_hosts,
            }
        })
        .collect();
    println!(
        "RssAnon with the lists read: {:?} KiB",
        status_kib("RssAnon:")
    );

    let out = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let report = compile_lists(inputs.clone(), out.path().to_str().unwrap().to_string()).unwrap();
    println!("compile took {:?}: {report:?}", started.elapsed());
    println!("peak resident (VmHWM): {:?} KiB", status_kib("VmHWM:"));
    let domains = DomainSet::load(&out.path().join(DOMAINS_FILE)).unwrap();
    println!(
        "domains.bin: {} hashes, {} wildcard patterns, {} bytes",
        domains.len(),
        domains.pattern_count(),
        report.domains_bytes
    );

    let exemption = Exemption::new(
        [BundledGroup::Sensitive, BundledGroup::Banks]
            .iter()
            .flat_map(|group| group.patterns().iter().copied()),
    );
    for input in inputs.iter().filter(|input| input.exempt_sensitive_hosts) {
        let list = DnsList {
            source: ListSource {
                name: &input.name,
                text: &input.text,
                format: tollgate_filter::ListFormat::Adblock,
            },
            exempt: Some(&exemption),
        };
        let rules = DomainRules::parse_exempting(&[list]);
        println!(
            "{}: {} block rules left out for sensitive and bank hosts",
            input.name, rules.exempted
        );
    }

    if count == DEFAULTS.len() {
        check_hosts(&domains, "TOLLGATE_EXPECT_BLOCKED", true);
        check_hosts(&domains, "TOLLGATE_EXPECT_OPEN", false);
    }
}

/// Checks that every host in the file the variable `var` names is blocked (or not).
fn check_hosts(domains: &DomainSet, var: &str, blocked: bool) {
    let Some(path) = std::env::var_os(var) else {
        return;
    };
    let text = std::fs::read_to_string(&path).unwrap();
    let hosts: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let wrong: Vec<&str> = hosts
        .iter()
        .copied()
        .filter(|host| domains.is_blocked(host) != blocked)
        .collect();
    println!(
        "{var}: {} of {} hosts as expected",
        hosts.len() - wrong.len(),
        hosts.len()
    );
    assert!(wrong.is_empty(), "{var}: {wrong:?}");
}
