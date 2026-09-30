//! Sizes and timings with real filter lists. Not part of the normal test run: it needs
//! the lists on disk. Run from core/ with:
//!
//!   TOLLGATE_LISTS_DIR=/path/to/lists cargo test --release -p tollgate-filter --test measure -- --ignored --nocapture
//!
//! The directory must hold easylist.txt, easyprivacy.txt, adguard-mobile-11.txt,
//! adguard-dns-filter.txt and stevenblack-hosts.txt. Loading is measured in a fresh child
//! process, so memory freed by the compile step does not hide the load cost. Memory is
//! reported as RssAnon, the closest Linux figure to the dirty memory iOS counts.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use tollgate_filter::{
    DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, ListFormat, ListSource, Verdict,
    compile_split,
};

fn rss_anon_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("RssAnon:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn report_rss(label: &str, baseline: Option<u64>) {
    if let (Some(baseline), Some(now)) = (baseline, rss_anon_kib()) {
        println!(
            "{label}: RssAnon {:+.2} MiB",
            (now as f64 - baseline as f64) / 1024.0
        );
    }
}

#[test]
#[ignore = "needs real filter lists in TOLLGATE_LISTS_DIR"]
fn measure_real_lists() {
    let dir = PathBuf::from(std::env::var("TOLLGATE_LISTS_DIR").expect("set TOLLGATE_LISTS_DIR"));
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    };
    let easylist = read("easylist.txt");
    let easyprivacy = read("easyprivacy.txt");
    let mobile = read("adguard-mobile-11.txt");
    let adguard_dns = read("adguard-dns-filter.txt");
    let hosts = read("stevenblack-hosts.txt");
    let adblock = |name, text| ListSource {
        name,
        text,
        format: ListFormat::Adblock,
    };
    let engine_lists = [
        adblock("easylist", &easylist),
        adblock("easyprivacy", &easyprivacy),
        adblock("adguard-mobile", &mobile),
    ];
    let dns_lists = [
        adblock("adguard-dns", &adguard_dns),
        ListSource {
            name: "stevenblack",
            text: &hosts,
            format: ListFormat::Hosts,
        },
    ];

    let out = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let report = compile_split(&engine_lists, &dns_lists, out.path()).unwrap();
    println!("compile took {:?}: {report:?}", started.elapsed());
    println!(
        "{ENGINE_FILE} {:.2} MiB, {DOMAINS_FILE} {:.2} MiB",
        mib(report.engine_bytes),
        mib(report.domains_bytes)
    );

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["load_compiled_lists", "--exact", "--ignored", "--nocapture"])
        .env("TOLLGATE_COMPILED_DIR", out.path())
        .status()
        .unwrap();
    assert!(status.success());
}

/// Run by measure_real_lists in a child process.
#[test]
#[ignore = "run through measure_real_lists"]
fn load_compiled_lists() {
    let Some(dir) = std::env::var_os("TOLLGATE_COMPILED_DIR") else {
        println!("load_compiled_lists only runs as part of measure_real_lists");
        return;
    };
    let dir = Path::new(&dir);
    let baseline = rss_anon_kib();

    let started = Instant::now();
    let engine = FilterEngine::load(&dir.join(ENGINE_FILE)).unwrap();
    println!("engine load took {:?}", started.elapsed());
    report_rss("after engine load", baseline);

    let started = Instant::now();
    let domains = DomainSet::load(&dir.join(DOMAINS_FILE)).unwrap();
    println!(
        "domain set load took {:?}, {} entries",
        started.elapsed(),
        domains.len()
    );
    report_rss("after domain set load", baseline);

    let requests = [
        (
            "https://securepubads.g.doubleclick.net/tag/js/gpt.js",
            "https://www.cnn.com/",
            "script",
        ),
        (
            "https://www.google-analytics.com/analytics.js",
            "https://www.bbc.com/",
            "script",
        ),
        (
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
            "https://example.com/",
            "script",
        ),
        (
            "https://connect.facebook.net/en_US/fbevents.js",
            "https://shop.example/",
            "script",
        ),
        (
            "https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js",
            "https://example.com/",
            "script",
        ),
        (
            "https://fonts.gstatic.com/s/roboto/v30/x.woff2",
            "https://example.com/",
            "font",
        ),
        (
            "https://www.wikipedia.org/",
            "https://www.wikipedia.org/",
            "document",
        ),
        (
            "https://api.github.com/repos/x/y",
            "https://github.com/",
            "xmlhttprequest",
        ),
    ];
    let n = 20_000;
    let started = Instant::now();
    let mut blocked = 0;
    for i in 0..n {
        let (url, source, kind) = requests[i % requests.len()];
        let url = format!("{url}?r={i}");
        if matches!(engine.check(&url, source, kind), Verdict::Block { .. }) {
            blocked += 1;
        }
    }
    let elapsed = started.elapsed();
    println!(
        "{n} checks in {elapsed:?} ({:.2} us each), {blocked} blocked",
        elapsed.as_secs_f64() * 1e6 / n as f64
    );

    let hosts = [
        "securepubads.g.doubleclick.net",
        "www.google.com",
        "a.b.c.d.example.com",
        "app-measurement.com",
        "graph.facebook.com",
        "x.y.z.adnxs.com",
    ];
    let n = 1_000_000;
    let started = Instant::now();
    let mut blocked = 0;
    for i in 0..n {
        if domains.is_blocked(hosts[i % hosts.len()]) {
            blocked += 1;
        }
    }
    let elapsed = started.elapsed();
    println!(
        "{n} DNS lookups in {elapsed:?} ({:.0} ns each), {blocked} blocked",
        elapsed.as_secs_f64() * 1e9 / n as f64
    );
    for host in hosts {
        println!("  {host}: blocked={}", domains.is_blocked(host));
    }
    report_rss("after the workload", baseline);
}
