use adblock::request::{Request, RequestType};
use tollgate_filter::{FilterEngine, ListFormat, ListSource, Verdict, request_type, source_url};

/// Every Sec-Fetch-Dest value in the Fetch standard, plus `fencedframe`.
const FETCH_DEST: [(&str, &str); 24] = [
    ("audio", "media"),
    ("audioworklet", "script"),
    ("document", "document"),
    ("embed", "object"),
    ("empty", "xmlhttprequest"),
    ("fencedframe", "sub_frame"),
    ("font", "font"),
    ("frame", "sub_frame"),
    ("iframe", "sub_frame"),
    ("image", "image"),
    ("json", "xmlhttprequest"),
    ("manifest", "other"),
    ("object", "object"),
    ("paintworklet", "script"),
    ("report", "ping"),
    ("script", "script"),
    ("serviceworker", "script"),
    ("sharedworker", "script"),
    ("style", "stylesheet"),
    ("track", "media"),
    ("video", "media"),
    ("webidentity", "other"),
    ("worker", "script"),
    ("xslt", "other"),
];

#[test]
fn every_sec_fetch_dest_value_is_mapped() {
    for (dest, want) in FETCH_DEST {
        assert_eq!(request_type(Some(dest), None, "/x.js"), want, "{dest}");
    }
}

#[test]
fn sec_fetch_dest_ignores_case_and_whitespace_and_wins() {
    assert_eq!(request_type(Some(" Style "), None, "/"), "stylesheet");
    assert_eq!(request_type(Some("IFRAME"), None, "/"), "sub_frame");
    assert_eq!(
        request_type(Some("image"), Some("text/html"), "/a.js"),
        "image"
    );
}

#[test]
fn unknown_sec_fetch_dest_falls_back() {
    assert_eq!(
        request_type(Some("speculationrules"), Some("text/css"), "/a.js"),
        "stylesheet"
    );
    assert_eq!(
        request_type(Some("speculationrules"), None, "/a.js"),
        "script"
    );
    assert_eq!(request_type(Some(""), None, "/a.png"), "image");
}

#[test]
fn accept_uses_the_first_media_range() {
    let cases = [
        (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "document",
        ),
        ("application/xhtml+xml", "document"),
        ("text/css,*/*;q=0.1", "stylesheet"),
        (
            "image/webp,image/avif,image/jxl,image/heic,video/*;q=0.8,image/png,*/*;q=0.5",
            "image",
        ),
        ("image/*", "image"),
        ("application/javascript", "script"),
        ("text/javascript; charset=utf-8", "script"),
        ("font/woff2;q=1.0", "font"),
        ("application/font-woff", "font"),
        ("video/mp4", "media"),
        ("audio/*", "media"),
        ("application/json, text/plain, */*", "xmlhttprequest"),
        ("application/ld+json", "xmlhttprequest"),
        ("TEXT/CSS", "stylesheet"),
    ];
    for (accept, want) in cases {
        assert_eq!(request_type(None, Some(accept), "/"), want, "{accept}");
    }
}

#[test]
fn uninformative_accept_falls_back_to_the_path() {
    assert_eq!(request_type(None, Some("*/*"), "/lib/app.js"), "script");
    assert_eq!(
        request_type(None, Some("text/plain"), "/a.css"),
        "stylesheet"
    );
    assert_eq!(request_type(None, Some(""), "/a.gif"), "image");
}

#[test]
fn path_extension_is_the_last_resort() {
    let cases = [
        ("/a/b.JS?x=1", "script"),
        ("/m.mjs", "script"),
        ("/x.css#top", "stylesheet"),
        ("/img.png", "image"),
        ("/photo.jpeg?w=100", "image"),
        ("/icon.svg", "image"),
        ("/f.woff2", "font"),
        ("/live/index.m3u8", "media"),
        ("/clip.mp4", "media"),
        ("/api/data.json", "xmlhttprequest"),
        ("/page.html", "other"),
        ("/dir.v2/file", "other"),
        ("/archive.tar.gz", "other"),
        ("/", "other"),
        ("", "other"),
        ("/noext", "other"),
        ("/a.js/", "other"),
    ];
    for (path, want) in cases {
        assert_eq!(request_type(None, None, path), want, "{path}");
    }
}

#[test]
fn adblock_recognizes_every_type_we_produce() {
    let expected = [
        ("document", RequestType::Document),
        ("sub_frame", RequestType::Subdocument),
        ("stylesheet", RequestType::Stylesheet),
        ("script", RequestType::Script),
        ("image", RequestType::Image),
        ("font", RequestType::Font),
        ("media", RequestType::Media),
        ("object", RequestType::Object),
        ("xmlhttprequest", RequestType::Xmlhttprequest),
        ("ping", RequestType::Ping),
        ("other", RequestType::Other),
    ];
    for (_, kind) in FETCH_DEST {
        assert!(
            expected.iter().any(|(s, _)| *s == kind),
            "{kind} not covered"
        );
    }
    for (kind, want) in expected {
        let request =
            Request::new("https://a.example/x", "https://b.example/", kind, "GET").unwrap();
        assert_eq!(request.request_type, want, "{kind}");
    }
}

#[test]
fn source_url_prefers_document_then_referer_then_origin() {
    let url = "https://news.example/story";
    assert_eq!(
        source_url(url, "document", Some("https://search.example/"), None),
        url
    );
    assert_eq!(
        source_url(
            url,
            "script",
            Some("https://page.example/a"),
            Some("https://origin.example")
        ),
        "https://page.example/a"
    );
    assert_eq!(
        source_url(url, "xmlhttprequest", None, Some("https://origin.example")),
        "https://origin.example"
    );
    assert_eq!(
        source_url(
            url,
            "xmlhttprequest",
            Some(""),
            Some("https://origin.example")
        ),
        "https://origin.example"
    );
    assert_eq!(source_url(url, "image", None, Some("null")), "");
    assert_eq!(source_url(url, "image", None, None), "");
}

fn engine(rules: &str) -> FilterEngine {
    FilterEngine::from_lists(
        &[ListSource {
            name: "test",
            text: rules,
            format: ListFormat::Adblock,
        }],
        false,
    )
}

fn blocked(e: &FilterEngine, url: &str, source: &str, kind: &str) -> bool {
    matches!(e.check(url, source, kind), Verdict::Block { .. })
}

#[test]
fn documents_are_their_own_source() {
    let e = engine(
        "||tracker.com^$third-party\n||cdn.example^$domain=news.com\n||ads.example^$~third-party\n",
    );
    let page = "https://tracker.com/";
    // Without a source the page itself would look third party and be blocked.
    assert!(blocked(&e, page, "", "document"));
    assert!(!blocked(
        &e,
        page,
        source_url(page, "document", None, None),
        "document"
    ));
    // $domain= only applies when the source is known.
    let script = "https://cdn.example/lib.js";
    assert!(!blocked(
        &e,
        script,
        source_url(script, "script", None, None),
        "script"
    ));
    assert!(blocked(
        &e,
        script,
        source_url(script, "script", Some("https://news.com/story"), None),
        "script"
    ));
    assert!(blocked(
        &e,
        script,
        source_url(script, "script", None, Some("https://news.com")),
        "script"
    ));
    // $~third-party needs a same-site source.
    let ad = "https://ads.example/x.js";
    assert!(!blocked(&e, ad, "", "script"));
    assert!(blocked(&e, ad, "https://www.ads.example/", "script"));
}
