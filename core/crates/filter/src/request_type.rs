//! Request type and source URL for the adblock engine, from request headers.

/// `Sec-Fetch-Dest` values (Fetch standard, plus `fencedframe`) to adblock type strings.
/// adblock does not know `style`, `iframe`, `frame` or `empty` and would treat them as
/// `other`, so every value is mapped explicitly.
const FETCH_DEST: &[(&str, &str)] = &[
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

/// Maps Sec-Fetch-Dest, then Accept, then path extension to an adblock request type string.
///
/// A `Sec-Fetch-Dest` value missing from the table (a future one) falls through to
/// `Accept`. `Accept` is judged by its first media range only, because browsers put the
/// type they want first and end with `*/*`. `path` may include a query or fragment.
pub fn request_type(
    sec_fetch_dest: Option<&str>,
    accept: Option<&str>,
    path: &str,
) -> &'static str {
    if let Some(dest) = sec_fetch_dest
        && let Some(kind) = from_fetch_dest(dest)
    {
        return kind;
    }
    if let Some(accept) = accept
        && let Some(kind) = from_accept(accept)
    {
        return kind;
    }
    from_extension(path)
}

fn from_fetch_dest(dest: &str) -> Option<&'static str> {
    let dest = dest.trim();
    FETCH_DEST
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(dest))
        .map(|(_, kind)| *kind)
}

fn from_accept(accept: &str) -> Option<&'static str> {
    let first = accept.split(',').next()?.split(';').next()?.trim();
    let first = first.to_ascii_lowercase();
    let kind = match first.as_str() {
        "text/html" | "application/xhtml+xml" => "document",
        "text/css" => "stylesheet",
        "application/javascript"
        | "text/javascript"
        | "application/ecmascript"
        | "text/ecmascript" => "script",
        "application/json" => "xmlhttprequest",
        t if t.starts_with("image/") => "image",
        t if t.starts_with("font/") || t.starts_with("application/font-") => "font",
        t if t.starts_with("video/") || t.starts_with("audio/") => "media",
        t if t.ends_with("+json") => "xmlhttprequest",
        _ => return None,
    };
    Some(kind)
}

fn from_extension(path: &str) -> &'static str {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let file = path.rsplit('/').next().unwrap_or("");
    let Some((_, ext)) = file.rsplit_once('.') else {
        return "other";
    };
    match ext.to_ascii_lowercase().as_str() {
        "js" | "mjs" | "cjs" => "script",
        "css" => "stylesheet",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" | "bmp" | "apng"
        | "heic" | "jxl" => "image",
        "woff" | "woff2" | "ttf" | "otf" | "eot" => "font",
        "mp4" | "m4v" | "webm" | "mov" | "mp3" | "m4a" | "aac" | "ogg" | "oga" | "opus" | "wav"
        | "flac" | "m3u8" | "mpd" | "m4s" => "media",
        "json" => "xmlhttprequest",
        _ => "other",
    }
}

/// The source URL adblock uses to decide first or third party.
///
/// A top-level document is its own source: with an empty source adblock treats every
/// request as third party, so `$third-party` rules would block the page itself and
/// `$domain=` rules would never apply. Other requests use `Referer`, then `Origin` (an
/// opaque `null` origin counts as missing), then the empty string.
pub fn source_url<'a>(
    url: &'a str,
    request_type: &str,
    referer: Option<&'a str>,
    origin: Option<&'a str>,
) -> &'a str {
    if request_type == "document" {
        return url;
    }
    referer
        .filter(|r| !r.is_empty())
        .or(origin.filter(|o| !o.is_empty() && *o != "null"))
        .unwrap_or("")
}
