use tollgate_filter::{
    DomainRules, DomainSet, ListFormat, ListSource, MAX_UNKEYED_PATTERNS, MAX_WILDCARD_PATTERNS,
    detect_format,
};

fn parse(format: ListFormat, text: &str) -> DomainRules {
    DomainRules::parse(&[ListSource {
        name: "test",
        text,
        format,
    }])
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn adblock_host_rule_shapes() {
    let rules = parse(
        ListFormat::Adblock,
        "! Title: test\n\
         [Adblock Plus 2.0]\n\
         # comment\n\
         \n\
         ||doubleclick.net^\n\
         ||pipe.example^|\n\
         ||no-caret.example\n\
         .leading-dot.example^\n\
         ||Trailing.Dot.COM.^\n\
         @@||ad.10010.com^\n\
         @@||exception-pipe.example^|\n\
         ||x.example^$important\n\
         ||y.example^\n",
    );
    assert_eq!(rules.important, names(&["x.example"]));
    assert_eq!(
        rules.allow,
        names(&["ad.10010.com", "exception-pipe.example"])
    );
    assert_eq!(
        rules.block,
        names(&[
            "doubleclick.net",
            "leading-dot.example",
            "no-caret.example",
            "pipe.example",
            "trailing.dot.com",
            "y.example",
        ])
    );
    assert_eq!(rules.skipped, 0);
}

#[test]
fn non_host_rules_are_skipped() {
    let skipped = [
        "|piwik.",
        "@@|piwik.",
        "|prefix.example",
        "|imp.example^$important",
        "||prefix.",
        "/regex-ad[0-9]+/",
        "||path.example/ads^",
        "||opt.example^$third-party",
        "||client.example^$client=1.2.3.4",
        "||dns.example^$dnstype=AAAA",
        "||empty-option.example^$",
        "||1.2.3.4^",
        "||nodot^",
        ".noncaret.example",
        "example.com##.ad",
        "plain.example.com",
        "||exämple.com^",
        "@@||path.example/x",
        "||tail.example^*",
    ];
    let rules = parse(ListFormat::Adblock, &skipped.join("\n"));
    assert_eq!(
        rules,
        DomainRules {
            skipped: skipped.len() as u64,
            ..DomainRules::default()
        }
    );
}

#[test]
fn badfilter_cancels_the_identical_rule_of_the_same_kind() {
    let rules = parse(
        ListFormat::Adblock,
        "||y.example^$badfilter\n\
         ||y.example^\n\
         ||keep.example^\n\
         @@||keep.example^$badfilter\n\
         ||imp.example^$important\n\
         ||imp.example^$important,badfilter\n\
         @@||allowed.example^\n\
         @@||allowed.example^$badfilter\n\
         .dotted.example^\n\
         ||dotted.example^$badfilter\n",
    );
    assert_eq!(rules.block, names(&["keep.example"]));
    assert!(rules.allow.is_empty());
    assert!(rules.important.is_empty());
    assert_eq!(rules.skipped, 0);
}

#[test]
fn important_exception_is_a_plain_exception() {
    let rules = parse(ListFormat::Adblock, "@@||a.example^$important\n");
    assert_eq!(rules.allow, names(&["a.example"]));
    assert!(rules.important.is_empty());
}

#[test]
fn hosts_format_edge_cases() {
    let rules = parse(
        ListFormat::Hosts,
        "\u{feff}# StevenBlack style header\n\
         127.0.0.1 localhost\n\
         127.0.0.1 localhost.localdomain\n\
         255.255.255.255 broadcasthost\n\
         ::1 localhost ip6-localhost ip6-loopback\n\
         fe80::1%lo0 localhost\n\
         ff02::2 ip6-allrouters\n\
         0.0.0.0 0.0.0.0\n\
         0.0.0.0 tracker.example # trailing comment\n\
         0.0.0.0\tTabbed.Example.\r\n\
         127.0.0.1 multi-a.example multi-b.example\n\
         bare.example.org\n\
         :: v6-any.example\n\
         0.0.0.0 bad_name!.example\n\
         0.0.0.0 1.2.3.4\n",
    );
    assert_eq!(
        rules.block,
        names(&[
            "bare.example.org",
            "multi-a.example",
            "multi-b.example",
            "tabbed.example",
            "tracker.example",
            "v6-any.example",
        ])
    );
    // localhost, localhost.localdomain, broadcasthost, the ::1 line, fe80::1%lo0,
    // ip6-allrouters, 0.0.0.0 0.0.0.0, the bad name and the address as a name.
    assert_eq!(rules.skipped, 9);
    assert!(rules.allow.is_empty());
}

#[test]
fn redundant_children_are_dropped_and_names_merge_across_lists() {
    let rules = DomainRules::parse(&[
        ListSource {
            name: "adblock",
            text: "||a.b.example.com^\n||example.com^\n||other.net^\n@@||x.allowed.org^\n@@||allowed.org^\n",
            format: ListFormat::Adblock,
        },
        ListSource {
            name: "hosts",
            text: "0.0.0.0 deep.sub.other.net\n0.0.0.0 fresh.example\n0.0.0.0 example.com\n",
            format: ListFormat::Hosts,
        },
    ]);
    assert_eq!(
        rules.block,
        names(&["example.com", "fresh.example", "other.net"])
    );
    assert_eq!(rules.allow, names(&["allowed.org"]));
}

#[test]
fn empty_input_gives_empty_rules() {
    assert_eq!(DomainRules::parse(&[]), DomainRules::default());
    assert_eq!(parse(ListFormat::Hosts, ""), DomainRules::default());
}

#[test]
fn single_pipe_rules_ending_in_a_caret_are_exact_hosts() {
    let rules = parse(
        ListFormat::Adblock,
        "@@|cdn.example^|\n\
         @@|WWW3.Example.net^\n\
         |a.example^\n\
         |b.example^|\n\
         ||example^\n\
         ||parent.example^\n\
         @@|child.parent.example^|\n\
         |piwik.\n",
    );
    assert_eq!(
        rules.exact_allow,
        names(&["cdn.example", "child.parent.example", "www3.example.net"])
    );
    assert_eq!(rules.exact_block, names(&["a.example", "b.example"]));
    // Exact rules never reach the sets that cover subdomains.
    assert!(rules.allow.is_empty());
    assert_eq!(rules.block, names(&["parent.example"]));
    assert!(rules.important.is_empty());
    // `||example^` has no dot, and `|piwik.` is a prefix.
    assert_eq!(rules.skipped, 2);
}

#[test]
fn badfilter_cancels_exact_rules() {
    let rules = parse(
        ListFormat::Adblock,
        "@@|gone.example^|\n\
         @@|gone.example^|$badfilter\n\
         |gone-block.example^\n\
         |gone-block.example^$badfilter\n\
         @@|kept.example^|\n\
         @@||kept.example^$badfilter\n",
    );
    assert_eq!(rules.exact_allow, names(&["kept.example"]));
    assert!(rules.exact_block.is_empty());
    assert!(rules.allow.is_empty());
}

#[test]
fn wildcard_exceptions_are_kept() {
    let rules = parse(
        ListFormat::Adblock,
        "||tradedoubler.com^\n\
         @@||clk*.tradedoubler.com^|\n\
         @@||Static-V*.trbo.com^\n\
         @@||bcicl.*.evergage.com^|\n\
         @@|only*.example^|\n\
         @@.dot*.example^\n\
         @@||gone*.example^\n\
         @@||gone*.example^$badfilter\n\
         @@||clk*.tradedoubler.com^|\n\
         @@||nodot*^\n\
         @@||*.*^\n\
         @@||bad*char!.example^\n\
         @@||path*.example/x^\n",
    );
    assert_eq!(
        rules.wildcard_allow,
        names(&[
            "bcicl.*.evergage.com",
            "clk*.tradedoubler.com",
            "static-v*.trbo.com",
        ])
    );
    // An unanchored `.dot*.example^` needs the dot in front: subdomains of the matches.
    assert_eq!(
        rules.exact_wildcard_allow,
        names(&["*.dot*.example", "only*.example"])
    );
    assert!(rules.allow.is_empty());
    assert!(rules.exact_allow.is_empty());
    assert_eq!(rules.block, names(&["tradedoubler.com"]));
    assert!(rules.important.is_empty());
    assert!(rules.wildcard_block.is_empty());
    // A pattern without a dot, one with nothing but wildcards, a bad character and a path.
    assert_eq!(rules.skipped, 4);
}

/// Each rule's pattern means what the rule means to adblock for `https://host/`: `||`
/// starts at the host or a label, `|` and `://` at the host, no anchor anywhere; `^` ends
/// at the end of the host, no caret anywhere.
#[test]
fn wildcard_blocks_become_patterns_with_their_anchors() {
    let rules = parse(
        ListFormat::Adblock,
        "||log*.tracker.example^\n\
         ||Tracking.*.PHONE.example^|\n\
         ||*.cdn.example^\n\
         ||adservice.search.example.*\n\
         ||adx-*.cloudstore.\n\
         ||pixel*.audio.example\n\
         ||x*.fqdn.example.^\n\
         ||double**star.example^\n\
         |c.blue.*.example^|\n\
         |pipe*.example^\n\
         ://*.cdn-edge.example^\n\
         -ulog*.short.example^\n\
         *ad.banner.example^\n\
         analytics-*.stats.example\n\
         .sub*.example^\n",
    );
    assert_eq!(
        rules.wildcard_block,
        names(&[
            "*.cdn.example",
            "adservice.search.example.*",
            "adx-*.cloudstore.*",
            "double*star.example",
            "log*.tracker.example",
            "pixel*.audio.example*",
            "tracking.*.phone.example",
            "x*.fqdn.example",
        ])
    );
    assert_eq!(
        rules.exact_wildcard_block,
        names(&[
            "*-ulog*.short.example",
            "*.cdn-edge.example",
            "*.sub*.example",
            "*ad.banner.example",
            "*analytics-*.stats.example*",
            "c.blue.*.example",
            "pipe*.example",
        ])
    );
    assert!(rules.block.is_empty());
    assert!(rules.exact_block.is_empty());
    assert_eq!(rules.skipped, 0);
}

#[test]
fn wildcard_blocks_that_cannot_be_patterns_are_skipped() {
    let skipped = [
        // `$important` would need a section of its own.
        "||imp*.example^$important",
        "|imp*.example^$important",
        // Other options, paths, ports and characters no host has.
        "||opt*.example^$third-party",
        "||path*.example/ads",
        "||port*.example:8080^",
        "||bad*char!.example^",
        "||tail.example^*",
        // A `|` that ends the URL, not the host: never `https://host/`.
        "||end*.example|",
        // No dot, only wildcards and dots, an empty label, an address.
        "||ads*^",
        "||*.*^",
        "||a*..example^",
        "||10.0.*.1^",
    ];
    let rules = parse(ListFormat::Adblock, &skipped.join("\n"));
    assert_eq!(
        rules,
        DomainRules {
            skipped: skipped.len() as u64,
            ..DomainRules::default()
        }
    );
}

#[test]
fn badfilter_cancels_wildcard_rules() {
    let rules = parse(
        ListFormat::Adblock,
        "||gone*.example^\n\
         ||gone*.example^$badfilter\n\
         |gone-exact*.example^|\n\
         |gone-exact*.example^|$badfilter\n\
         ||merged**.example^\n\
         ||merged*.example^$badfilter\n\
         ||kept*.example^\n\
         |kept*.example^$badfilter\n\
         @@||kept*.example^$badfilter\n",
    );
    assert_eq!(rules.wildcard_block, names(&["kept*.example"]));
    assert!(rules.exact_wildcard_block.is_empty());
    assert_eq!(rules.skipped, 0);
}

/// The AdGuard DNS filter writes some host blocks without an anchor (`name^`, the host and
/// its subdomains) and some anchored with `://` (`://name^`, the host only).
#[test]
fn unanchored_and_scheme_anchored_host_rules() {
    let text = "dlsdk.appsflyer.com^\n\
                Pipe.Example.net^|\n\
                ://jhf.ru^\n\
                ://exact-pipe.example^|\n\
                @@ok.appsflyer.com^\n\
                @@://ok-exact.example^\n\
                imp.example^$important\n\
                -pia.appsflyersdk.com^\n\
                @@-ds.metric.gstatic.com^|\n\
                ://*.a-akamaihd.com^\n\
                @@://exc*.example^\n\
                no-caret.example\n\
                ://no-caret.example\n\
                ://path.example/x^\n";
    let rules = parse(ListFormat::Adblock, text);
    assert_eq!(
        rules.block,
        names(&["dlsdk.appsflyer.com", "pipe.example.net"])
    );
    assert_eq!(rules.exact_block, names(&["exact-pipe.example", "jhf.ru"]));
    assert_eq!(rules.allow, names(&["ok.appsflyer.com"]));
    assert_eq!(rules.exact_allow, names(&["ok-exact.example"]));
    assert_eq!(rules.important, names(&["imp.example"]));
    assert_eq!(rules.exact_wildcard_allow, names(&["exc*.example"]));
    assert!(rules.wildcard_allow.is_empty());
    assert_eq!(rules.exact_wildcard_block, names(&["*.a-akamaihd.com"]));
    // A leading `-`, two rules without a caret and a path.
    assert_eq!(rules.skipped, 5);

    let set = DomainSet::from_bytes(rules.encode()).unwrap();
    assert!(set.is_blocked("dlsdk.appsflyer.com"));
    assert!(set.is_blocked("eu.dlsdk.appsflyer.com"));
    assert!(set.is_blocked("jhf.ru"));
    assert!(!set.is_blocked("www.jhf.ru"));
    assert!(!set.is_blocked("pia.appsflyersdk.com"));
}

#[test]
fn badfilter_cancels_unanchored_and_scheme_anchored_rules() {
    let rules = parse(
        ListFormat::Adblock,
        "gone.example^\n\
         gone.example^$badfilter\n\
         ://gone-exact.example^\n\
         ://gone-exact.example^$badfilter\n\
         @@gone-allow.example^\n\
         @@gone-allow.example^$badfilter\n\
         @@://gone-exact-allow.example^|\n\
         @@://gone-exact-allow.example^|$badfilter\n\
         kept.example^\n\
         ://kept.example^$badfilter\n",
    );
    assert_eq!(rules.block, names(&["kept.example"]));
    assert!(rules.exact_block.is_empty());
    assert!(rules.allow.is_empty());
    assert!(rules.exact_allow.is_empty());
    assert_eq!(rules.skipped, 0);
}

/// DNS lists in the wildcard domains format write one `*.name` per line for `name` and its
/// subdomains. Such a line becomes the hashed name, like `||name^`, not a pattern that
/// every lookup would try.
#[test]
fn the_wildcard_domains_format_gives_names() {
    let text = "# Title: wildcard domains\n\
                # Syntax: Domains Wildcard\n\
                *.telemetry.ads.example\n\
                *.Tracker.Example.\n\
                *.caret.example^\n\
                *.pipe.example^|\n\
                *.sub.telemetry.ads.example\n\
                @@*.ok.tracker.example^\n\
                *.imp.example^$important\n\
                *.gone.example\n\
                *.gone.example$badfilter\n\
                *.zip\n\
                *.bad!.example\n\
                *.10.0.0.1\n";
    // Adblock syntax to the detector, so the app compiles a list of these typed Hosts file
    // as Domain rules; the hosts parser reads none of its lines.
    assert_eq!(detect_format(text), Some(ListFormat::Adblock));
    assert!(parse(ListFormat::Hosts, text).block.is_empty());

    let rules = parse(ListFormat::Adblock, text);
    assert_eq!(
        rules,
        DomainRules {
            important: names(&["imp.example"]),
            allow: names(&["ok.tracker.example"]),
            block: names(&[
                "caret.example",
                "pipe.example",
                "telemetry.ads.example",
                "tracker.example",
            ]),
            // A top-level domain, a bad character and an address.
            skipped: 3,
            ..DomainRules::default()
        }
    );

    let set = DomainSet::from_bytes(rules.encode()).unwrap();
    assert_eq!(set.pattern_count(), 0);
    for host in [
        "telemetry.ads.example",
        "a.telemetry.ads.example",
        "tracker.example",
        "x.y.tracker.example",
        "caret.example",
        "imp.example",
    ] {
        assert!(set.is_blocked(host), "{host}");
    }
    for host in [
        "telemetry.ads.example.other.example",
        "ads.example",
        "xtracker.example",
        "tracker.example.net",
        "ok.tracker.example",
        "a.ok.tracker.example",
        "gone.example",
    ] {
        assert!(!set.is_blocked(host), "{host}");
    }
}

/// Patterns over the limits are left out: exceptions are kept first, then blocks in the
/// order the lists give them, and patterns `$badfilter` cancels take no room.
#[test]
fn wildcard_patterns_are_limited() {
    let unkeyed_over = 3;
    let mut blocks = String::new();
    // Unanchored and caretless: `*mid0*.example*`, with neither a head nor a tail.
    for i in 0..MAX_UNKEYED_PATTERNS + unkeyed_over {
        blocks += &format!("mid{i}*.example\n");
    }
    for i in 0..10 {
        blocks += &format!("||gone{i}*.example^\n||gone{i}*.example^$badfilter\n");
    }
    for i in 0..MAX_WILDCARD_PATTERNS {
        blocks += &format!("||k{i}*.example^\n");
    }
    let exceptions = "@@||ok0*.example^\n@@|ok1*.example^|\n";
    let rules = DomainRules::parse(&[
        ListSource {
            name: "blocks",
            text: &blocks,
            format: ListFormat::Adblock,
        },
        ListSource {
            name: "exceptions",
            text: exceptions,
            format: ListFormat::Adblock,
        },
    ]);

    assert_eq!(rules.wildcard_allow, names(&["ok0*.example"]));
    assert_eq!(rules.exact_wildcard_allow, names(&["ok1*.example"]));
    let unkeyed = &rules.exact_wildcard_block;
    assert_eq!(unkeyed.len(), MAX_UNKEYED_PATTERNS);
    let last = MAX_UNKEYED_PATTERNS - 1;
    assert!(unkeyed.contains(&"*mid0*.example*".to_string()));
    assert!(unkeyed.contains(&format!("*mid{last}*.example*")));
    assert!(!unkeyed.contains(&format!("*mid{}*.example*", last + 1)));
    let keyed = &rules.wildcard_block;
    let room = MAX_WILDCARD_PATTERNS - MAX_UNKEYED_PATTERNS - 2;
    assert_eq!(keyed.len(), room);
    assert!(keyed.contains(&"k0*.example".to_string()));
    assert!(keyed.contains(&format!("k{}*.example", room - 1)));
    assert!(!keyed.contains(&format!("k{room}*.example")));
    assert!(!keyed.iter().any(|p| p.starts_with("gone")));
    // Each pattern left out is a skipped line.
    let left_out = unkeyed_over + (MAX_WILDCARD_PATTERNS - room);
    assert_eq!(rules.skipped, left_out as u64);
}
