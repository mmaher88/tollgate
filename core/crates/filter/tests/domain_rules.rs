use tollgate_filter::{DomainRules, DomainSet, ListFormat, ListSource};

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
        "||*.wildcard.example^",
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
fn wildcard_exceptions_are_kept_and_wildcard_blocks_skipped() {
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
         ||ad*.example^\n\
         ||*.wildcard.example^\n\
         ||imp*.example^$important\n\
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
            "dot*.example",
            "static-v*.trbo.com",
        ])
    );
    assert_eq!(rules.exact_wildcard_allow, names(&["only*.example"]));
    assert!(rules.allow.is_empty());
    assert!(rules.exact_allow.is_empty());
    assert_eq!(rules.block, names(&["tradedoubler.com"]));
    assert!(rules.important.is_empty());
    // The wildcard block, the wildcard important block, a pattern without a dot, one
    // with nothing but wildcards, a bad character and a path.
    assert_eq!(rules.skipped, 7);
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
    // A leading `-`, the wildcard block, two rules without a caret and a path.
    assert_eq!(rules.skipped, 6);

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
