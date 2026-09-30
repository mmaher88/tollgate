use std::io::Write;

use tollgate_filter::{
    DomainRules, DomainSet, DomainSetError, FilterError, ListFormat, ListSource,
};

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn rules() -> DomainRules {
    DomainRules {
        important: names(&["forced.example"]),
        allow: names(&["ad.10010.com", "forced.example", "ok.tracker.example"]),
        block: names(&["10010.com", "doubleclick.net", "tracker.example"]),
        ..DomainRules::default()
    }
}

fn set() -> DomainSet {
    DomainSet::from_bytes(rules().encode()).unwrap()
}

/// FNV-1a 64, written out here so the tests pin the hash the file format depends on.
fn fnv1a64_bytes(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn fnv1a64(s: &str) -> u64 {
    fnv1a64_bytes(s.as_bytes())
}

#[test]
fn fnv_reference_vectors() {
    assert_eq!(fnv1a64(""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64("a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a64("foobar"), 0x8594_4171_f739_67e8);
}

#[test]
fn file_layout_matches_the_spec() {
    let bytes = DomainRules {
        important: names(&["c.example"]),
        allow: names(&["b.example"]),
        block: names(&["a.example", "d.example"]),
        wildcard_allow: names(&["ok*.a.example"]),
        wildcard_block: names(&["log*.e.example"]),
        exact_wildcard_block: names(&["*-x*.f.example"]),
        ..DomainRules::default()
    }
    .encode();
    let allow_section = b"||ok*.a.example\n";
    let block_section = b"||log*.e.example\n|*-x*.f.example\n";
    assert_eq!(
        bytes.len(),
        40 + 8 * 4 + allow_section.len() + block_section.len()
    );
    assert_eq!(&bytes[0..4], b"TGDS");
    assert_eq!(&bytes[4..8], &2u32.to_le_bytes());
    assert_eq!(&bytes[8..12], &2u32.to_le_bytes());
    assert_eq!(&bytes[12..16], &1u32.to_le_bytes());
    assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
    assert_eq!(&bytes[20..24], &(allow_section.len() as u32).to_le_bytes());
    assert_eq!(&bytes[24..32], &fnv1a64_bytes(&bytes[40..]).to_le_bytes());
    assert_eq!(&bytes[32..36], &(block_section.len() as u32).to_le_bytes());
    assert_eq!(&bytes[36..40], &[0, 0, 0, 0]);
    let mut block = [fnv1a64("a.example"), fnv1a64("d.example")];
    block.sort_unstable();
    let body: Vec<u64> = bytes[40..72]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect();
    assert_eq!(
        body,
        vec![
            block[0],
            block[1],
            fnv1a64("b.example"),
            fnv1a64("c.example")
        ]
    );
    let sections = &bytes[72..];
    assert_eq!(&sections[..allow_section.len()], allow_section);
    assert_eq!(&sections[allow_section.len()..], block_section);
}

#[test]
fn matches_the_host_and_every_parent() {
    let d = set();
    assert!(d.is_blocked("doubleclick.net"));
    assert!(d.is_blocked("ad.doubleclick.net"));
    assert!(d.is_blocked("a.b.c.ad.doubleclick.net"));
    assert!(!d.is_blocked("notdoubleclick.net"));
    assert!(!d.is_blocked("doubleclick.net.example"));
    assert!(!d.is_blocked("net"));
    assert!(!d.is_blocked(""));
    assert!(!d.is_blocked("."));
}

#[test]
fn ignores_case_and_one_trailing_dot() {
    let d = set();
    assert!(d.is_blocked("Ad.DoubleClick.NET."));
    assert!(!d.is_blocked("ad.doubleclick.net.."));
}

#[test]
fn important_then_allow_then_block() {
    let d = set();
    // Allowed child of a blocked parent.
    assert!(d.is_blocked("10010.com"));
    assert!(d.is_blocked("www.10010.com"));
    assert!(!d.is_blocked("ad.10010.com"));
    assert!(!d.is_blocked("x.ad.10010.com"));
    assert!(!d.is_blocked("ok.tracker.example"));
    assert!(d.is_blocked("tracker.example"));
    // Important wins over an exception for the same name.
    assert!(d.is_blocked("forced.example"));
    assert!(d.is_blocked("sub.forced.example"));
}

#[test]
fn len_counts_every_section() {
    let d = set();
    assert_eq!(d.len(), 7);
    assert!(!d.is_empty());
    let empty = DomainSet::from_bytes(DomainRules::default().encode()).unwrap();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert!(!empty.is_blocked("anything.example"));
}

#[test]
fn build_parses_and_encodes() {
    let bytes = DomainSet::build(&[ListSource {
        name: "dns",
        text: "||ads.example^\n@@||ok.ads.example^\n",
        format: ListFormat::Adblock,
    }]);
    let d = DomainSet::from_bytes(bytes).unwrap();
    assert!(d.is_blocked("x.ads.example"));
    assert!(!d.is_blocked("ok.ads.example"));
    assert_eq!(d.len(), 2);
}

fn error(bytes: Vec<u8>) -> DomainSetError {
    match DomainSet::from_bytes(bytes) {
        Err(FilterError::DomainSet(e)) => e,
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("accepted a bad file"),
    }
}

/// Rewrites the checksum after a test edits the body: of every byte after the 32-byte
/// header in version 1 files, after the 40-byte header in later ones.
fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
    let header = if bytes[4..8] == 1u32.to_le_bytes() {
        32
    } else {
        40
    };
    let sum = fnv1a64_bytes(&bytes[header..]);
    bytes[24..32].copy_from_slice(&sum.to_le_bytes());
    bytes
}

#[test]
fn rejects_damaged_files() {
    let good = rules().encode();
    assert_eq!(error(Vec::new()), DomainSetError::TooShort);
    assert_eq!(error(good[..31].to_vec()), DomainSetError::TooShort);
    // Long enough for a version 1 header, not for this version's.
    assert_eq!(error(good[..39].to_vec()), DomainSetError::TooShort);

    let mut bad = good.clone();
    bad[0] = b'X';
    assert_eq!(error(bad), DomainSetError::BadMagic);

    for version in [0u32, 3] {
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&version.to_le_bytes());
        assert_eq!(error(bad), DomainSetError::UnsupportedVersion(version));
    }

    // Either wildcard section's length counts toward the file length.
    for at in [20, 32] {
        let mut bad = good.clone();
        bad[at] = 1;
        assert!(matches!(error(bad), DomainSetError::LengthMismatch { .. }));
    }

    // The padding after the block section's length must stay zero.
    let mut bad = good.clone();
    bad[36] = 1;
    assert_eq!(error(bad), DomainSetError::BadHeader);

    assert_eq!(
        error(good[..good.len() - 8].to_vec()),
        DomainSetError::LengthMismatch {
            expected: good.len() as u64,
            actual: good.len() as u64 - 8,
        }
    );
    let mut longer = good.clone();
    longer.push(0);
    assert!(matches!(
        error(longer),
        DomainSetError::LengthMismatch { .. }
    ));
    let mut huge = good.clone();
    huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(error(huge), DomainSetError::LengthMismatch { .. }));

    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(error(bad), DomainSetError::BadChecksum);

    // Swap the first two block hashes and fix the checksum: sorted order is checked too.
    let mut bad = good.clone();
    let (first, second) = (bad[40..48].to_vec(), bad[48..56].to_vec());
    bad[40..48].copy_from_slice(&second);
    bad[48..56].copy_from_slice(&first);
    assert_eq!(error(reseal(bad)), DomainSetError::Unsorted);

    // A duplicate hash is not allowed either.
    let mut bad = good.clone();
    let first = bad[40..48].to_vec();
    bad[48..56].copy_from_slice(&first);
    assert_eq!(error(reseal(bad)), DomainSetError::Unsorted);
}

#[test]
fn load_maps_the_file() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&rules().encode()).unwrap();
    let d = DomainSet::load(file.path()).unwrap();
    assert_eq!(d.len(), 7);
    assert!(d.is_blocked("ad.doubleclick.net"));
    assert!(!d.is_blocked("ad.10010.com"));
}

#[test]
fn load_reports_missing_and_short_files() {
    let missing = std::env::temp_dir().join("tollgate-no-such-domains.bin");
    assert!(matches!(
        DomainSet::load(&missing),
        Err(FilterError::Io { .. })
    ));
    let empty = tempfile::NamedTempFile::new().unwrap();
    assert!(matches!(
        DomainSet::load(empty.path()),
        Err(FilterError::DomainSet(DomainSetError::TooShort))
    ));
    let mut garbage = tempfile::NamedTempFile::new().unwrap();
    garbage.write_all(&[0u8; 40]).unwrap();
    assert!(matches!(
        DomainSet::load(garbage.path()),
        Err(FilterError::DomainSet(DomainSetError::BadMagic))
    ));
}

#[test]
fn domain_set_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DomainSet>();
}

fn build(text: &str) -> DomainSet {
    DomainSet::from_bytes(DomainSet::build(&[ListSource {
        name: "dns",
        text,
        format: ListFormat::Adblock,
    }]))
    .unwrap()
}

#[test]
fn exact_exceptions_allow_only_their_host() {
    let d = build(
        "||example.com^\n\
         @@|cdn.example.com^|\n\
         ||daraz.com^\n\
         @@|daraz.com^|\n\
         @@|x.example.com^|\n\
         @@|x.example.com^|$badfilter\n",
    );
    assert!(!d.is_blocked("cdn.example.com"));
    assert!(!d.is_blocked("CDN.example.com."));
    assert!(d.is_blocked("x.cdn.example.com"));
    assert!(d.is_blocked("example.com"));
    assert!(d.is_blocked("other.example.com"));
    assert!(!d.is_blocked("daraz.com"));
    assert!(d.is_blocked("ads.daraz.com"));
    // Removed by $badfilter.
    assert!(d.is_blocked("x.example.com"));
}

#[test]
fn exact_blocks_cover_only_their_host_and_lose_to_exceptions() {
    let d = build(
        "|a.klaviyo.com^\n\
         @@||fine.org^\n\
         |ads.fine.org^|\n\
         ||imp.org^$important\n\
         @@|a.imp.org^|\n",
    );
    assert!(d.is_blocked("a.klaviyo.com"));
    assert!(!d.is_blocked("x.a.klaviyo.com"));
    assert!(!d.is_blocked("klaviyo.com"));
    assert!(!d.is_blocked("ads.fine.org"));
    assert!(d.is_blocked("a.imp.org"));
}

#[test]
fn wildcard_exceptions_unblock_matching_hosts() {
    let d = build(
        "||tradedoubler.com^\n\
         @@||clk*.tradedoubler.com^|\n\
         ||evergage.com^\n\
         @@||bcicl.*.evergage.com^|\n\
         ||brsrvr.com^\n\
         @@|brm-core-*.brsrvr.com^|\n\
         ||forced.example^$important\n\
         @@||x*.forced.example^\n",
    );
    assert!(!d.is_blocked("clk1.tradedoubler.com"));
    assert!(!d.is_blocked("CLK.tradedoubler.com."));
    assert!(!d.is_blocked("a.clk1.tradedoubler.com"));
    assert!(d.is_blocked("www.tradedoubler.com"));
    assert!(d.is_blocked("tradedoubler.com"));
    assert!(d.is_blocked("xclk1.tradedoubler.com"));
    // `*` matches across labels.
    assert!(!d.is_blocked("bcicl.eu.evergage.com"));
    assert!(!d.is_blocked("bcicl.a.b.evergage.com"));
    assert!(d.is_blocked("bcicl.evergage.com"));
    assert!(d.is_blocked("x.evergage.com"));
    // `|` patterns cover the host only.
    assert!(!d.is_blocked("brm-core-0.brsrvr.com"));
    assert!(d.is_blocked("x.brm-core-0.brsrvr.com"));
    // Important blocks still win.
    assert!(d.is_blocked("x1.forced.example"));
    // Hosts that nothing blocks stay unblocked.
    assert!(!d.is_blocked("clk1.example.org"));
}

#[test]
fn wildcard_exceptions_survive_a_file_round_trip() {
    let bytes = DomainSet::build(&[ListSource {
        name: "dns",
        text: "||tradedoubler.com^\n@@||clk*.tradedoubler.com^|\n@@|a*.tradedoubler.com^|\n",
        format: ListFormat::Adblock,
    }]);
    let section = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 40 + 8 + section);
    assert_eq!(
        &bytes[bytes.len() - section..],
        b"||clk*.tradedoubler.com\n|a*.tradedoubler.com\n"
    );
    assert_eq!(&bytes[24..32], &fnv1a64_bytes(&bytes[40..]).to_le_bytes());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let d = DomainSet::load(file.path()).unwrap();
    assert!(!d.is_blocked("clk9.tradedoubler.com"));
    assert!(!d.is_blocked("ab.tradedoubler.com"));
    assert!(d.is_blocked("x.ab.tradedoubler.com"));
    assert!(d.is_blocked("www.tradedoubler.com"));
    assert_eq!(d.len(), 1);
}

/// A file written by the build before wildcard exceptions: version 1, reserved word 0.
#[test]
fn files_without_a_pattern_section_still_load() {
    let block = fnv1a64("tradedoubler.com");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"TGDS");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&block.to_le_bytes());
    let d = DomainSet::from_bytes(reseal(bytes)).unwrap();
    assert!(d.is_blocked("clk1.tradedoubler.com"));
    assert_eq!(d.len(), 1);
}

#[test]
fn rejects_a_damaged_pattern_section() {
    // One block hash, then the exception section, then the block section.
    let good = DomainSet::build(&[ListSource {
        name: "dns",
        text: "||tradedoubler.com^\n@@||clk*.tradedoubler.com^|\n||log*.example.com^\n",
        format: ListFormat::Adblock,
    }]);
    let exceptions = b"||clk*.tradedoubler.com\n".len();
    for section in [48, 48 + exceptions] {
        for (from, to) in [(b'|', b'x'), (b'c', b'!'), (b'o', b'O'), (b'\n', b' ')] {
            let mut bad = good.clone();
            let at = section + bad[section..].iter().position(|&b| b == from).unwrap();
            bad[at] = to;
            assert_eq!(error(reseal(bad)), DomainSetError::BadPatterns);
        }
    }
    // Moving the boundary between the two sections leaves a line without its newline.
    let mut bad = good.clone();
    bad[20..24].copy_from_slice(&(exceptions as u32 - 1).to_le_bytes());
    bad[32..36].copy_from_slice(&(b"||log*.example.com\n".len() as u32 + 1).to_le_bytes());
    assert_eq!(error(reseal(bad)), DomainSetError::BadPatterns);
    // The section length counts toward the file length.
    let mut bad = good.clone();
    bad[20..24].copy_from_slice(&1000u32.to_le_bytes());
    assert!(matches!(error(bad), DomainSetError::LengthMismatch { .. }));
}

/// Wildcard blocks of the shapes DNS lists use, which the parser used to skip.
#[test]
fn wildcard_blocks_match_like_adblock() {
    let d = build(
        "||log*.tracker.example^\n\
         ||tracking.*.phone.example^\n\
         ||mcs-*.video.example^\n\
         ||ads-*.v.ssp.portal.example^\n\
         ||adserver.*.dns.example^\n",
    );
    // `*` matches any run of characters, none included, and dots too.
    for host in [
        "log.tracker.example",
        "log123.tracker.example",
        "log.x.tracker.example",
        "a.log.tracker.example",
        "LOG1.Tracker.EXAMPLE.",
        "tracking.eu.phone.example",
        "tracking.a.b.phone.example",
        "x.tracking.eu.phone.example",
        "mcs-va.video.example",
        "mcs-.video.example",
        "ads-1.v.ssp.portal.example",
        "adserver.a.dns.example",
    ] {
        assert!(d.is_blocked(host), "{host}");
    }
    // `||` starts the match at a label, and `^` ends it at the end of the host.
    for host in [
        "blog.tracker.example",
        "tracker.example",
        "log.tracker.example.net",
        "log.tracker.examples",
        "tracking.phone.example",
        "xtracking.eu.phone.example",
        "mcs.video.example",
        "ads-1.ssp.portal.example",
        "adserver.dns.example",
    ] {
        assert!(!d.is_blocked(host), "{host}");
    }
    assert_eq!(d.len(), 0);
    assert_eq!(d.pattern_count(), 5);
}

#[test]
fn wildcard_blocks_follow_their_anchors() {
    let d = build(
        "|exact*.example^|\n\
         ://scheme*.example^\n\
         -ulog*.short.example^\n\
         *ad.banner.example^\n\
         .sub*.dot.example^\n\
         ||adservice.search.example.*\n\
         ||adx-*.cloudstore.\n\
         ||pixel*.audio.example\n",
    );
    let blocked = [
        // `|` and `://`: the host itself.
        "exact1.example",
        "scheme.example",
        // No anchor: anywhere in the host.
        "x-ulog1.short.example",
        "a.b-ulog.short.example",
        "ad.banner.example",
        "bad.banner.example",
        "x.ad.banner.example",
        "a.sub1.dot.example",
        // No caret: the match may end anywhere.
        "adservice.search.example.net",
        "x.adservice.search.example.co.test",
        "adx-drcn.cloudstore.example",
        "adx-a.cloudstore.test",
        "pixel.audio.example",
        "pixel1.audio.example.net",
    ];
    for host in blocked {
        assert!(d.is_blocked(host), "{host}");
    }
    let allowed = [
        "x.exact1.example",
        "a.scheme1.example",
        "ulog1.short.example",
        "banner.example",
        "sub1.dot.example",
        "adservice.search.example",
        "adservice.search.examples",
        "adx-a.cloudstore",
        "xpixel.audio.example",
    ];
    for host in allowed {
        assert!(!d.is_blocked(host), "{host}");
    }
}

/// Exceptions of every kind win over wildcard blocks, as over any other block, and
/// important blocks still win over every exception.
#[test]
fn exceptions_win_over_wildcard_blocks() {
    let d = build(
        "||log*.one.example^\n\
         @@|log-ok.one.example^|\n\
         @@||log-fine.one.example^\n\
         ||ads*.two.example^\n\
         @@||two.example^\n\
         ||track*.three.example^\n\
         @@||track-safe*.three.example^\n\
         |exact*.four.example^|\n\
         @@|exact-ok*.four.example^|\n\
         ||imp*.five.example^\n\
         ||five.example^$important\n\
         @@||imp-ok*.five.example^\n\
         @@|imp-exact.five.example^|\n\
         @@||imp-fine.five.example^\n",
    );
    // An exception for the host only.
    assert!(!d.is_blocked("log-ok.one.example"));
    assert!(d.is_blocked("x.log-ok.one.example"));
    // An exception for the host and its subdomains.
    assert!(!d.is_blocked("log-fine.one.example"));
    assert!(!d.is_blocked("a.log-fine.one.example"));
    assert!(d.is_blocked("log1.one.example"));
    // An exception for a parent.
    assert!(!d.is_blocked("ads1.two.example"));
    // Wildcard exceptions.
    assert!(!d.is_blocked("track-safe1.three.example"));
    assert!(!d.is_blocked("a.track-safe1.three.example"));
    assert!(d.is_blocked("track1.three.example"));
    assert!(!d.is_blocked("exact-ok1.four.example"));
    assert!(d.is_blocked("exact1.four.example"));
    // Important blocks win over all of them.
    for host in [
        "imp-ok1.five.example",
        "imp-exact.five.example",
        "imp-fine.five.example",
        "imp1.five.example",
    ] {
        assert!(d.is_blocked(host), "{host}");
    }
}

/// Builds a version 1 file: 32-byte header, hashes, then the wildcard exception section.
fn version_1(block: &[&str], allow: &[&str], exceptions: &str) -> Vec<u8> {
    let sorted = |names: &[&str]| {
        let mut hashes: Vec<u64> = names.iter().map(|n| fnv1a64(n)).collect();
        hashes.sort_unstable();
        hashes
    };
    let (block, allow) = (sorted(block), sorted(allow));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"TGDS");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(block.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(allow.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(exceptions.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    for hash in block.iter().chain(&allow) {
        bytes.extend_from_slice(&hash.to_le_bytes());
    }
    bytes.extend_from_slice(exceptions.as_bytes());
    reseal(bytes)
}

/// After an app update the tunnel loads the file the previous version compiled until the
/// lists are compiled again. Its wildcard section holds exceptions, including patterns
/// with `**`, which builds before this one did not merge.
#[test]
fn version_1_files_still_load_with_their_wildcard_exceptions() {
    let bytes = version_1(
        &["affiliate.example", "blocked.example"],
        &["ok.blocked.example"],
        "||clk*.affiliate.example\n|a**.affiliate.example\n",
    );
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let d = DomainSet::load(file.path()).unwrap();
    assert_eq!(d.len(), 3);
    assert_eq!(d.pattern_count(), 2);
    assert!(d.is_blocked("www.affiliate.example"));
    assert!(!d.is_blocked("clk1.affiliate.example"));
    assert!(!d.is_blocked("x.clk1.affiliate.example"));
    assert!(!d.is_blocked("ab.affiliate.example"));
    assert!(d.is_blocked("x.ab.affiliate.example"));
    assert!(d.is_blocked("a.blocked.example"));
    assert!(!d.is_blocked("a.ok.blocked.example"));
    // A version 1 file with a line no build writes is still rejected.
    let bad = version_1(&["affiliate.example"], &[], "||clk*.Affiliate.example\n");
    assert_eq!(error(bad), DomainSetError::BadPatterns);
}

/// Whether `text` matches `glob`, tried every way: an independent reference for the index.
fn reference_glob(glob: &[u8], text: &[u8]) -> bool {
    match glob.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|i| reference_glob(rest, &text[i..])),
        Some((&c, rest)) => {
            text.first().is_some_and(|b| b.to_ascii_lowercase() == c)
                && reference_glob(rest, &text[1..])
        }
    }
}

/// The index only narrows down which patterns are tried; it must never miss one. Patterns
/// here share heads and tails, are filed under a head, a tail or neither, and hosts are
/// built from the same pieces.
#[test]
fn pattern_lookups_agree_with_trying_every_pattern() {
    let parents = names(&[
        "ad*.example.com",
        "ads*.example.com",
        "a*.b",
        "adserver.*.net",
        "adserver.*",
        "adserv*.net",
        "*.le.com",
        "*le.com",
        "x*le.com",
        "*mid*.net*",
        "*.*.co.uk",
        "co.*.uk",
        "b-*-c.example.com",
    ]);
    let host = names(&["ad*.net", "*x.example.com", "mid*.co.*", "*-c.*", "ex*.b*"]);
    let d = DomainSet::from_bytes(
        DomainRules {
            wildcard_block: parents.clone(),
            exact_wildcard_block: host.clone(),
            ..DomainRules::default()
        }
        .encode(),
    )
    .unwrap();
    let labels = [
        "ad", "ads", "adserver", "a", "b", "x", "mid", "le", "xle", "example", "com", "net", "co",
        "uk", "b-mid-c", "-c",
    ];
    let mut hosts: Vec<String> = Vec::new();
    for a in labels {
        for b in labels {
            hosts.push(format!("{a}.{b}"));
            for c in labels {
                hosts.push(format!("{a}.{b}.{c}"));
                for e in ["com", "net", "uk"] {
                    hosts.push(format!("{a}.{b}.{c}.{e}"));
                }
            }
        }
    }
    hosts.extend(["", ".", "ad", "AD.Example.COM", "Ads1.EXAMPLE.com."].map(String::from));
    let mut blocked = 0;
    for name in &hosts {
        let bare = name.strip_suffix('.').unwrap_or(name).as_bytes();
        let names_of = |host: &[u8]| -> Vec<Vec<u8>> {
            let mut out = vec![host.to_vec()];
            for (i, &b) in host.iter().enumerate() {
                if b == b'.' {
                    out.push(host[i + 1..].to_vec());
                }
            }
            out
        };
        let expected = bare.contains(&b'.')
            && (parents.iter().any(|p| {
                names_of(bare)
                    .iter()
                    .any(|n| reference_glob(p.as_bytes(), n))
            }) || host.iter().any(|p| reference_glob(p.as_bytes(), bare)));
        assert_eq!(d.is_blocked(name), expected, "{name}");
        blocked += usize::from(expected);
    }
    // The pieces make both outcomes common.
    assert!(blocked > 1000 && hosts.len() - blocked > 1000, "{blocked}");
}
