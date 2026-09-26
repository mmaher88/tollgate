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
        ..DomainRules::default()
    }
    .encode();
    assert_eq!(bytes.len(), 32 + 8 * 4);
    assert_eq!(&bytes[0..4], b"TGDS");
    assert_eq!(&bytes[4..8], &1u32.to_le_bytes());
    assert_eq!(&bytes[8..12], &2u32.to_le_bytes());
    assert_eq!(&bytes[12..16], &1u32.to_le_bytes());
    assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
    assert_eq!(&bytes[20..24], &[0, 0, 0, 0]);
    assert_eq!(&bytes[24..32], &fnv1a64_bytes(&bytes[32..]).to_le_bytes());
    let mut block = [fnv1a64("a.example"), fnv1a64("d.example")];
    block.sort_unstable();
    let body: Vec<u64> = bytes[32..]
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

/// Rewrites the checksum after a test edits the body.
fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
    let sum = fnv1a64_bytes(&bytes[32..]);
    bytes[24..32].copy_from_slice(&sum.to_le_bytes());
    bytes
}

#[test]
fn rejects_damaged_files() {
    let good = rules().encode();
    assert_eq!(error(Vec::new()), DomainSetError::TooShort);
    assert_eq!(error(good[..31].to_vec()), DomainSetError::TooShort);

    let mut bad = good.clone();
    bad[0] = b'X';
    assert_eq!(error(bad), DomainSetError::BadMagic);

    let mut bad = good.clone();
    bad[4..8].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(error(bad), DomainSetError::UnsupportedVersion(2));

    let mut bad = good.clone();
    bad[20] = 1;
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
    let (first, second) = (bad[32..40].to_vec(), bad[40..48].to_vec());
    bad[32..40].copy_from_slice(&second);
    bad[40..48].copy_from_slice(&first);
    assert_eq!(error(reseal(bad)), DomainSetError::Unsorted);

    // A duplicate hash is not allowed either.
    let mut bad = good.clone();
    let first = bad[32..40].to_vec();
    bad[40..48].copy_from_slice(&first);
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
