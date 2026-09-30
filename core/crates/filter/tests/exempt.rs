use tollgate_filter::{
    DnsList, DomainRules, DomainSet, Exemption, ListFormat, ListSource, compile_split_exempting,
};

/// Exempts `bank.example` and `login.idp.example` with their subdomains, only the host
/// `id.portal.example`, and every host under `mil`.
fn exemption() -> Exemption {
    Exemption::new([
        "*.bank.example",
        "*.login.idp.example",
        "id.portal.example",
        " *.MIL. ",
    ])
}

fn exempting<'a>(text: &'a str, format: ListFormat, exempt: &'a Exemption) -> DnsList<'a> {
    DnsList {
        source: ListSource {
            name: "exempting",
            text,
            format,
        },
        exempt: Some(exempt),
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn blocklist(lists: &[DnsList]) -> DomainSet {
    DomainSet::from_bytes(DomainRules::parse_exempting(lists).encode()).unwrap()
}

#[test]
fn covers_the_host_patterns_it_was_given() {
    let exempt = exemption();
    for host in [
        "bank.example",
        "metrics.bank.example",
        "a.b.bank.example",
        "METRICS.Bank.Example.",
        "login.idp.example",
        "id.portal.example",
        "www.army.mil",
    ] {
        assert!(exempt.covers(host), "{host}");
    }
    for host in [
        "otherbank.example",
        "bank.example.evil.example",
        "portal.example",
        "sub.id.portal.example",
        "idp.example",
        "x.idp.example",
        "example",
    ] {
        assert!(!exempt.covers(host), "{host}");
    }
    assert!(!Exemption::default().covers("bank.example"));
}

#[test]
fn name_blocks_that_cover_an_exempt_host_are_left_out() {
    let exempt = exemption();
    let rules = DomainRules::parse_exempting(&[exempting(
        // Left out: names under an exempt domain, the domain itself, the parents of an
        // exempt domain and of an exempt host, and an important block. Kept: a name that
        // only ends alike, a subdomain of an exempt host, a neighbour of an exempt domain
        // and an unrelated name.
        "||metrics.bank.example^\n\
         ||bank.example^\n\
         ||idp.example^\n\
         ||portal.example^\n\
         ||deep.tracker.bank.example^$important\n\
         ||army.mil^\n\
         ||otherbank.example^\n\
         ||sub.id.portal.example^\n\
         ||x.idp.example^\n\
         ||tracker.example^\n",
        ListFormat::Adblock,
        &exempt,
    )]);
    assert_eq!(
        rules.block,
        names(&[
            "otherbank.example",
            "sub.id.portal.example",
            "tracker.example",
            "x.idp.example",
        ])
    );
    assert!(rules.important.is_empty());
    assert_eq!(rules.exempted, 6);
    assert_eq!(rules.skipped, 0);
}

#[test]
fn one_host_blocks_are_left_out_only_for_an_exempt_host() {
    let exempt = exemption();
    let rules = DomainRules::parse_exempting(&[exempting(
        // `|portal.example^` blocks that host alone, which is not exempt.
        "|metrics.bank.example^\n|id.portal.example^\n|login.idp.example^\n\
         |portal.example^\n|x.example^\n",
        ListFormat::Adblock,
        &exempt,
    )]);
    assert_eq!(rules.exact_block, names(&["portal.example", "x.example"]));
    assert_eq!(rules.exempted, 3);
}

#[test]
fn wildcard_blocks_that_could_match_an_exempt_host_are_left_out() {
    let exempt = exemption();
    let rules = DomainRules::parse_exempting(&[exempting(
        // Left out: a pattern for names under `bank.example`, one whose literal tail is
        // the end of such a name, one for `bank.example` itself, a host-only pattern for
        // an exempt host, a `||` pattern that matches the parent of `id.portal.example`,
        // and a pattern open at the end, which can match a name under any exempt domain.
        //
        // Kept: patterns that match no exempt host, and a host-only pattern for the
        // parent of an exempt host, which blocks that parent alone.
        "||log*.bank.example^\n\
         ||t*ank.example^\n\
         ||b*k.example^\n\
         |id.p*l.example^\n\
         ||p*tal.example^\n\
         ||ads-*.example.\n\
         ||log*.tracker.example^\n\
         |x*.bank.example.other^\n\
         |p*tal.example^\n",
        ListFormat::Adblock,
        &exempt,
    )]);
    assert_eq!(rules.wildcard_block, names(&["log*.tracker.example"]));
    assert_eq!(
        rules.exact_wildcard_block,
        names(&["p*tal.example", "x*.bank.example.other"])
    );
    assert_eq!(rules.exempted, 6);
}

#[test]
fn exceptions_of_an_exempting_list_are_kept() {
    let exempt = exemption();
    let rules = DomainRules::parse_exempting(&[exempting(
        "@@||ok.bank.example^\n@@|id.portal.example^\n@@||ok*.bank.example^\n",
        ListFormat::Adblock,
        &exempt,
    )]);
    assert_eq!(rules.allow, names(&["ok.bank.example"]));
    assert_eq!(rules.exact_allow, names(&["id.portal.example"]));
    assert_eq!(rules.wildcard_allow, names(&["ok*.bank.example"]));
    assert_eq!(rules.exempted, 0);
}

#[test]
fn hosts_lists_leave_out_exempt_names_without_skipping_their_lines() {
    let exempt = exemption();
    let rules = DomainRules::parse_exempting(&[exempting(
        "0.0.0.0 metrics.bank.example\n\
         0.0.0.0 tracker.example stats.bank.example\n\
         id.portal.example\n",
        ListFormat::Hosts,
        &exempt,
    )]);
    assert_eq!(rules.block, names(&["tracker.example"]));
    assert_eq!(rules.exempted, 3);
    assert_eq!(rules.skipped, 0);
}

#[test]
fn another_list_still_blocks_what_an_exempting_list_leaves_out() {
    let exempt = exemption();
    let set = blocklist(&[
        DnsList::from(ListSource {
            name: "plain",
            text: "||metrics.bank.example^\n",
            format: ListFormat::Adblock,
        }),
        exempting(
            "||metrics.bank.example^\n||stats.bank.example^\n||tracker.example^\n",
            ListFormat::Adblock,
            &exempt,
        ),
    ]);
    assert!(set.is_blocked("metrics.bank.example"));
    assert!(!set.is_blocked("stats.bank.example"));
    assert!(set.is_blocked("tracker.example"));
}

#[test]
fn without_an_exemption_every_block_stays() {
    let text = "||metrics.bank.example^\n|id.portal.example^\n||log*.bank.example^\n";
    let list = ListSource {
        name: "plain",
        text,
        format: ListFormat::Adblock,
    };
    let rules = DomainRules::parse_exempting(&[DnsList::from(list)]);
    assert_eq!(rules, DomainRules::parse(&[list]));
    assert_eq!(rules.block, names(&["metrics.bank.example"]));
    assert_eq!(rules.exact_block, names(&["id.portal.example"]));
    assert_eq!(rules.wildcard_block, names(&["log*.bank.example"]));
    assert_eq!(rules.exempted, 0);
}

#[test]
fn the_compile_report_counts_the_blocks_left_out() {
    let exempt = exemption();
    let dir = tempfile::tempdir().unwrap();
    let report = compile_split_exempting(
        &[],
        &[exempting(
            "||metrics.bank.example^\n||tracker.example^\n",
            ListFormat::Adblock,
            &exempt,
        )],
        dir.path(),
    )
    .unwrap();
    assert_eq!(report.domain_exempted, 1);
    assert_eq!(report.domain_entries, 1);
}
