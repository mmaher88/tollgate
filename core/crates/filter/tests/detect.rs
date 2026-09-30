//! `detect_format` on edge cases here, and on real lists with:
//!
//!   TOLLGATE_LISTS_DIR=/path/to/lists cargo test -p tollgate-filter --test detect -- --ignored
//!
//! In that directory, every `.txt` file whose name contains `hosts` must be detected as a
//! hosts file and every other `.txt` file as adblock syntax.

use std::path::PathBuf;

use tollgate_filter::{ListFormat, detect_format};

#[test]
fn text_without_rule_lines_gives_no_verdict() {
    for text in [
        "",
        "\n\n  \n",
        "\u{feff}",
        "# Title: hosts header\n# 0.0.0.0 commented-out.example\n",
        "! Title: adblock header\n! ||commented-out.example^\n",
        "[Adblock Plus 2.0]\n! Version: 1\n",
        "\r\n# Windows comment\r\n\r\n",
    ] {
        assert_eq!(detect_format(text), None, "{text:?}");
    }
}

#[test]
fn hosts_lines_with_any_address() {
    for line in [
        "0.0.0.0 ads.example",
        "127.0.0.1 ads.example",
        "::1 ads.example",
        ":: ads.example",
        "fe80::1%lo0 ads.example",
        "255.255.255.255 broadcasthost",
        "127.0.0.1 localhost",
        "0.0.0.0\tads.example",
        "0.0.0.0 ads.example # a trailing comment",
        "0.0.0.0 a.example b.example",
        "0.0.0.0 0.0.0.0",
    ] {
        assert_eq!(detect_format(line), Some(ListFormat::Hosts), "{line:?}");
    }
}

#[test]
fn one_name_per_line_is_a_hosts_file() {
    let text = "# domains\nads.example\nTracker.Example.\nads.example # comment\nx_y.example\n";
    assert_eq!(detect_format(text), Some(ListFormat::Hosts));
}

#[test]
fn adblock_rules_and_near_misses_are_adblock() {
    for line in [
        "||ads.example^",
        "@@||ok.example^",
        "|https://ads.example/",
        "/banner/*$image",
        "example.com##.ad",
        "example.com#@#.ad",
        "ads.example##.banner",
        "ads.example#comment",
        "ads.example^",
        "-ad.js",
        "_ads.js",
        ".ads.example",
        "localhost",
        "1.2.3.4",
        "0.0.0.0",
        "0.0.0.0 # nothing named",
        "1.2.3.4%lo0 ads.example",
        "ads.example extra.example",
    ] {
        assert_eq!(detect_format(line), Some(ListFormat::Adblock), "{line:?}");
    }
}

#[test]
fn windows_line_endings_and_a_byte_order_mark() {
    let hosts =
        "\u{feff}# hosts\r\n127.0.0.1 localhost\r\n::1 localhost\r\n0.0.0.0 ads.example\r\n";
    assert_eq!(detect_format(hosts), Some(ListFormat::Hosts));
    let adblock = "\u{feff}[Adblock Plus 2.0]\r\n! Title: x\r\n||ads.example^\r\n/ad/*\r\n";
    assert_eq!(detect_format(adblock), Some(ListFormat::Adblock));
}

#[test]
fn an_adblock_list_with_a_few_hosts_lines_stays_adblock() {
    let text = "! Title: mostly adblock\n\
                ||a.example^\n\
                ||b.example^\n\
                @@||c.example^\n\
                /ads/*\n\
                example.com##.ad\n\
                0.0.0.0 d.example\n\
                e.example\n";
    assert_eq!(detect_format(text), Some(ListFormat::Adblock));
}

#[test]
fn a_hosts_file_with_a_few_adblock_lines_stays_hosts() {
    let text = "# Title: mostly hosts\n\
                127.0.0.1 localhost\n\
                ::1 localhost\n\
                0.0.0.0 a.example\n\
                0.0.0.0 b.example\n\
                c.example\n\
                ||d.example^\n";
    assert_eq!(detect_format(text), Some(ListFormat::Hosts));
}

#[test]
fn a_tie_gives_no_verdict() {
    let text = "0.0.0.0 a.example\n||b.example^\nc.example\n/ads/*\n";
    assert_eq!(detect_format(text), None);
}

#[test]
fn host_name_limits() {
    let long_label = format!("{}.example", "a".repeat(64));
    let long_name = format!("{}example", "abcdefghi.".repeat(25));
    for line in [
        long_label.as_str(),
        long_name.as_str(),
        "ads.123",
        "a..example",
    ] {
        assert_eq!(detect_format(line), Some(ListFormat::Adblock), "{line:?}");
    }
    let longest_label = format!("{}.example", "a".repeat(63));
    assert_eq!(detect_format(&longest_label), Some(ListFormat::Hosts));
}

#[test]
#[ignore = "needs real filter lists in TOLLGATE_LISTS_DIR"]
fn real_lists_are_detected() {
    let dir = PathBuf::from(std::env::var("TOLLGATE_LISTS_DIR").expect("set TOLLGATE_LISTS_DIR"));
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "txt") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let expected = if name.contains("hosts") {
            ListFormat::Hosts
        } else {
            ListFormat::Adblock
        };
        assert_eq!(detect_format(&text), Some(expected), "{name}");
        checked += 1;
    }
    assert!(checked > 0, "no .txt files in {}", dir.display());
}
