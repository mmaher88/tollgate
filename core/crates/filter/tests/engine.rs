use std::io::Write;

use tollgate_filter::{
    FilterEngine, FilterError, ListFormat, ListSource, REGEX_CLEANUP_INTERVAL,
    REGEX_DISCARD_UNUSED, Verdict, network_rule_count,
};

fn adblock(text: &str) -> ListSource<'_> {
    ListSource {
        name: "test",
        text,
        format: ListFormat::Adblock,
    }
}

fn engine(rules: &str) -> FilterEngine {
    FilterEngine::from_lists(&[adblock(rules)], false)
}

fn blocked(e: &FilterEngine, url: &str, source: &str, kind: &str) -> bool {
    matches!(e.check(url, source, kind), Verdict::Block { .. })
}

#[test]
fn host_anchor_blocks_the_domain_and_subdomains() {
    let e = engine("||doubleclick.net^\n");
    assert_eq!(
        e.check(
            "https://ad.doubleclick.net/x.js",
            "https://example.com/",
            "script"
        ),
        Verdict::Block { rule: None }
    );
    assert!(blocked(
        &e,
        "https://doubleclick.net/",
        "https://example.com/",
        "image"
    ));
    assert!(!blocked(
        &e,
        "https://notdoubleclick.net/x.js",
        "https://example.com/",
        "script"
    ));
}

#[test]
fn debug_engine_names_the_rule() {
    let e = FilterEngine::from_lists(&[adblock("||doubleclick.net^\n")], true);
    assert_eq!(
        e.check(
            "https://ad.doubleclick.net/x.js",
            "https://example.com/",
            "script"
        ),
        Verdict::Block {
            rule: Some("||doubleclick.net^".into())
        }
    );
}

#[test]
fn exceptions_and_important() {
    let e = engine(
        "/ads.js\n@@||example.com/ads.js\n||ads.example.net^$important\n@@||ads.example.net^\n",
    );
    assert!(!blocked(
        &e,
        "https://example.com/ads.js",
        "https://example.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://other.com/ads.js",
        "https://other.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://ads.example.net/a.js",
        "https://news.com/",
        "script"
    ));
}

#[test]
fn third_party_uses_the_registrable_domain() {
    let e = engine("||tracker.com^$third-party\n||a.github.io^$third-party\n");
    assert!(blocked(
        &e,
        "https://tracker.com/p.gif",
        "https://news.com/",
        "image"
    ));
    assert!(!blocked(
        &e,
        "https://tracker.com/p.gif",
        "https://tracker.com/",
        "image"
    ));
    assert!(!blocked(
        &e,
        "https://cdn.tracker.com/p.gif",
        "https://www.tracker.com/",
        "image"
    ));
    // An empty source counts as third party.
    assert!(blocked(&e, "https://tracker.com/p.gif", "", "image"));
    // The public suffix list makes a.github.io and b.github.io different sites.
    assert!(blocked(
        &e,
        "https://a.github.io/x",
        "https://b.github.io/",
        "script"
    ));
}

#[test]
fn caret_is_a_separator_but_not_a_dot() {
    let e = engine("/banner/*/img^\n");
    for (url, want) in [
        ("https://example.com/banner/300x250/img/ad.gif", true),
        ("https://example.com/banner/300x250/img?x=1", true),
        ("https://example.com/banner/300x250/img", true),
        ("https://example.com/banner/a/b/img/x", true),
        ("https://example.com/banner/300x250/img.png", false),
        ("https://example.com/banner/300x250/images/x", false),
        ("https://example.com/banners/300x250/img/x", false),
    ] {
        assert_eq!(
            blocked(&e, url, "https://example.com/", "image"),
            want,
            "{url}"
        );
    }
}

#[test]
fn type_options_see_our_type_strings() {
    let e = engine(
        "||img.test^$image\n||xhr.test^$xmlhttprequest\n||frame.test^$subdocument\n||css.test^$stylesheet\n\
         ||media.test^$media\n||obj.test^$object\n||ping.test^$ping\n||font.test^$font\n",
    );
    let src = "https://site.example/";
    for (host, kind) in [
        ("img.test", "image"),
        ("xhr.test", "xmlhttprequest"),
        ("frame.test", "sub_frame"),
        ("css.test", "stylesheet"),
        ("media.test", "media"),
        ("obj.test", "object"),
        ("ping.test", "ping"),
        ("font.test", "font"),
    ] {
        let url = format!("https://{host}/a");
        assert!(blocked(&e, &url, src, kind), "{host} as {kind}");
        assert!(!blocked(&e, &url, src, "script"), "{host} as script");
    }
    // A rule without type options also matches documents.
    let e = engine("||ads.test^\n");
    assert!(blocked(&e, "https://ads.test/", "", "document"));
    assert!(blocked(&e, "https://ads.test/", "", "other"));
}

#[test]
fn hosts_lists_block_names_and_subdomains() {
    let text = "0.0.0.0 ads.example.org\n127.0.0.1 localhost\n# comment\nplain.example.net\n";
    let e = FilterEngine::from_lists(
        &[ListSource {
            name: "hosts",
            text,
            format: ListFormat::Hosts,
        }],
        false,
    );
    assert!(blocked(
        &e,
        "https://ads.example.org/x",
        "https://e.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://sub.ads.example.org/x",
        "https://e.com/",
        "script"
    ));
    assert!(blocked(
        &e,
        "https://plain.example.net/x",
        "https://e.com/",
        "script"
    ));
    assert!(!blocked(
        &e,
        "https://localhost/x",
        "https://e.com/",
        "script"
    ));
}

#[test]
fn cosmetic_rules_are_dropped() {
    // Same line numbers in both lists, so only the cosmetic rules differ.
    let with_cosmetic = engine("##.ad-banner\nexample.com##.sponsored\n||ads.com^\n");
    let without = engine("! one\n! two\n||ads.com^\n");
    assert_eq!(with_cosmetic.serialize(), without.serialize());
    assert!(blocked(
        &with_cosmetic,
        "https://ads.com/x",
        "https://e.com/",
        "script"
    ));
}

#[test]
fn unparseable_urls_are_allowed() {
    let e = engine("||x.com^\n");
    assert_eq!(e.check("not a url", "", "script"), Verdict::Allow);
    assert_eq!(e.check("https://", "", "script"), Verdict::Allow);
}

#[test]
fn counts_network_rules_only() {
    let text = "! comment\n[Adblock Plus 2.0]\n||a.com^\n##.ad\nexample.com##.x\n/ads.js\n@@||b.com^\n||c.com^$popup\n\n";
    assert_eq!(network_rule_count(&[adblock(text)]), 3);
    let hosts = ListSource {
        name: "hosts",
        text: "0.0.0.0 a.example\n127.0.0.1 localhost\n# c\n",
        format: ListFormat::Hosts,
    };
    assert_eq!(network_rule_count(&[adblock(text), hosts]), 4);
}

const RULES: &str = "||doubleclick.net^\n/ads.js\n@@||example.com/ads.js\n||tracker.com^$third-party\n/banner/*/img^\n";

const CASES: [(&str, &str, &str); 7] = [
    (
        "https://ad.doubleclick.net/x.js",
        "https://example.com/",
        "script",
    ),
    (
        "https://example.com/ads.js",
        "https://example.com/",
        "script",
    ),
    ("https://other.com/ads.js", "https://other.com/", "script"),
    ("https://tracker.com/p.gif", "https://news.com/", "image"),
    ("https://tracker.com/p.gif", "https://tracker.com/", "image"),
    (
        "https://example.com/banner/1/img/x",
        "https://example.com/",
        "image",
    ),
    (
        "https://example.com/fine.js",
        "https://example.com/",
        "script",
    ),
];

#[test]
fn serialized_engines_load_through_mmap() {
    for debug in [false, true] {
        let e = FilterEngine::from_lists(&[adblock(RULES)], debug);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&e.serialize()).unwrap();
        let loaded = FilterEngine::load(file.path()).unwrap();
        for (url, source, kind) in CASES {
            assert_eq!(
                loaded.check(url, source, kind),
                e.check(url, source, kind),
                "{url} debug={debug}"
            );
        }
        let blocked_count = CASES
            .iter()
            .filter(|(u, s, k)| blocked(&loaded, u, s, k))
            .count();
        assert_eq!(blocked_count, 4);
    }
}

#[test]
fn load_rejects_bad_files() {
    let missing = std::env::temp_dir().join("tollgate-no-such-engine.dat");
    assert!(matches!(
        FilterEngine::load(&missing),
        Err(FilterError::Io { .. })
    ));

    let mut corrupt = engine("||x.com^\n").serialize();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    for bytes in [b"garbage".to_vec(), corrupt, Vec::new()] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes).unwrap();
        let err = FilterEngine::load(file.path()).err().unwrap();
        assert!(
            matches!(err, FilterError::Engine(_) | FilterError::Io { .. }),
            "{err:?}"
        );
    }
}

#[test]
fn regex_discard_policy_is_short() {
    assert_eq!(REGEX_CLEANUP_INTERVAL.as_secs(), 10);
    assert_eq!(REGEX_DISCARD_UNUSED.as_secs(), 30);
}

#[test]
fn engine_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FilterEngine>();
}
