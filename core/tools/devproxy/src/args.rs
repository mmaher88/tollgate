//! Command line parsing with `std::env::args`, no parser crate.

use std::net::SocketAddr;
use std::path::PathBuf;

/// What a list is and which file it feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListKind {
    /// Adblock syntax for URL filtering (`engine.dat`).
    Url,
    /// Adblock syntax for the DNS blocklist (`domains.bin`).
    Dns,
    /// Adblock syntax for the DNS blocklist, without its blocks of hosts of sensitive
    /// services and banks (`ListInput::exempt_sensitive_hosts`).
    DnsExempting,
    /// Hosts format for the DNS blocklist (`domains.bin`).
    Hosts,
}

/// One list: a file path or an `http://` or `https://` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSpec {
    pub kind: ListKind,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub data_dir: PathBuf,
    pub config: Option<PathBuf>,
    pub lists: Vec<ListSpec>,
    pub dns: SocketAddr,
    pub proxy: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Run(Args),
    Help,
}

/// The lists the app ships with: three URL lists, then four DNS lists.
pub const DEFAULT_LISTS: [(ListKind, &str); 7] = [
    (ListKind::Url, "https://easylist.to/easylist/easylist.txt"),
    (
        ListKind::Url,
        "https://easylist.to/easylist/easyprivacy.txt",
    ),
    (
        ListKind::Url,
        "https://filters.adtidy.org/extension/ublock/filters/11.txt",
    ),
    (
        ListKind::Dns,
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    ),
    (
        ListKind::Hosts,
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        ListKind::DnsExempting,
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    ),
    (ListKind::DnsExempting, "https://small.oisd.nl"),
];

pub const DEFAULT_DATA_DIR: &str = "devproxy-data";
pub const DEFAULT_DNS: &str = "127.0.0.1:5353";
pub const DEFAULT_PROXY: &str = "127.0.0.1:8080";

pub const USAGE: &str = "\
Usage: devproxy [options]

Runs Tollgate's DNS responder and HTTPS filtering proxy on this machine.

Options:
  --data-dir DIR     engine.dat, domains.bin, ca.pem, ca.key and learned-pins.json
                     (default: devproxy-data)
  --config FILE      config.json in the tunnel's format (default: built-in defaults)
  --url-list SRC     adblock list for URL filtering; SRC is a file or an http(s) URL
  --dns-list SRC     adblock-syntax list for the DNS blocklist
  --hosts-list SRC   hosts-format list for the DNS blocklist
  --exempting-dns-list SRC
                     like --dns-list, without its blocks of hosts of sensitive
                     services and banks (the app's bundled passthrough groups)
  --default-lists    EasyList, EasyPrivacy, AdGuard Mobile Ads, AdGuard DNS filter,
                     StevenBlack hosts, HaGeZi Multi LIGHT and OISD small, downloaded
  --dns ADDR         UDP address of the DNS responder (default: 127.0.0.1:5353)
  --proxy ADDR       TCP address of the proxy (default: 127.0.0.1:8080)
  -h, --help         this text

List options may repeat. With any list option the lists are compiled into the data
directory; without one, the files already there are used.
";

fn address(flag: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("{flag}: invalid socket address {value:?}"))
}

/// Parses the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut parsed = Args {
        data_dir: PathBuf::from(DEFAULT_DATA_DIR),
        config: None,
        lists: Vec::new(),
        dns: address("--dns", DEFAULT_DNS)?,
        proxy: address("--proxy", DEFAULT_PROXY)?,
    };
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--data-dir" => parsed.data_dir = PathBuf::from(value()?),
            "--config" => parsed.config = Some(PathBuf::from(value()?)),
            "--url-list" | "--dns-list" | "--hosts-list" | "--exempting-dns-list" => {
                let kind = match flag.as_str() {
                    "--url-list" => ListKind::Url,
                    "--dns-list" => ListKind::Dns,
                    "--hosts-list" => ListKind::Hosts,
                    _ => ListKind::DnsExempting,
                };
                parsed.lists.push(ListSpec {
                    kind,
                    source: value()?,
                });
            }
            "--default-lists" => {
                parsed
                    .lists
                    .extend(DEFAULT_LISTS.iter().map(|(kind, url)| ListSpec {
                        kind: *kind,
                        source: (*url).to_string(),
                    }));
            }
            "--dns" => parsed.dns = address("--dns", &value()?)?,
            "--proxy" => parsed.proxy = address("--proxy", &value()?)?,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Command::Run(parsed))
}
