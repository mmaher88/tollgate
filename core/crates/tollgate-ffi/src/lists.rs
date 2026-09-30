//! Compiling filter lists in the app process into the files the tunnel loads.

use std::path::Path;
use std::sync::LazyLock;

use tollgate_filter::{DnsList, Exemption, ListSource};
use tollgate_policy::BundledGroup;

use crate::error::{TollgateError, catch_panic};

/// The name of the built-in DNS rule set in log messages and errors.
pub const TOLLGATE_EXTRAS_NAME: &str = "Tollgate extras";

/// A few ad and tracker hosts that no default list blocks and that are safe to block, each
/// with the reason it is here. Compiled into every DNS blocklist, after the lists given,
/// as the list [`TOLLGATE_EXTRAS_NAME`]; every exception in a list (My rules included)
/// still wins over it. Rules in adblock syntax.
pub const TOLLGATE_EXTRAS: &[(&str, &str)] = &[
    (
        "||ads.huawei.com^",
        "HUAWEI Ads, Huawei's ad platform. HaGeZi's Pro and larger lists block it, the \
         default lists do not; Huawei's other hosts stay open.",
    ),
    (
        "|rudderstack.com^",
        "RudderStack, a service that collects analytics events from apps and sites. Only \
         the name itself, which serves nothing but a redirect to www.rudderstack.com: its \
         subdomains (api.rudderstack.com, app.rudderstack.com, www.rudderstack.com) run \
         RudderStack's own service and site and stay open.",
    ),
];

/// The rules of [`TOLLGATE_EXTRAS`] as the text of a list.
fn extras_text() -> String {
    TOLLGATE_EXTRAS
        .iter()
        .map(|(rule, _reason)| format!("{rule}\n"))
        .collect()
}

/// The hosts of the bundled passthrough groups for sensitive services and banks, which
/// a list with `exempt_sensitive_hosts` must not block. The other groups are not exempt:
/// such a list still blocks the hosts it lists under them.
static SENSITIVE_HOSTS: LazyLock<Exemption> = LazyLock::new(|| {
    Exemption::new(
        [BundledGroup::Sensitive, BundledGroup::Banks]
            .iter()
            .flat_map(|group| group.patterns().iter().copied()),
    )
});

/// How a list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ListFormat {
    /// Adblock Plus, uBlock Origin and AdGuard syntax.
    Adblock,
    /// `0.0.0.0 host` lines, or one bare host per line.
    Hosts,
}

/// Which file a list feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ListTarget {
    /// URL rules for the proxy (`engine.dat`): EasyList, EasyPrivacy, AdGuard Mobile Ads.
    Url,
    /// Host names for the DNS blocklist (`domains.bin`): the AdGuard DNS filter, HaGeZi
    /// Multi LIGHT and OISD small in adblock syntax, StevenBlack hosts and other hosts
    /// files.
    Dns,
}

/// One downloaded list.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ListInput {
    /// Used in log messages and errors only.
    pub name: String,
    pub text: String,
    pub format: ListFormat,
    pub target: ListTarget,
    /// Leave out this list's blocks of hosts of sensitive services and banks: every block
    /// rule (a name with its subdomains, one host, or a wildcard pattern) that covers a
    /// host of the bundled passthrough groups for them (`BundledGroup::Sensitive` and
    /// `BundledGroup::Banks`), so that a list added for wider coverage cannot break a bank
    /// or identity app by blocking its telemetry. The other lists still block what they
    /// list. `Dns` lists only. False when left out, in Swift too, so callers written
    /// before it keep their meaning.
    #[uniffi(default = false)]
    pub exempt_sensitive_hosts: bool,
}

/// What `compile_lists` wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CompileReport {
    /// Network rules in `engine.dat`.
    pub network_rules: u64,
    /// Hashes in `domains.bin`.
    pub domain_entries: u64,
    pub engine_bytes: u64,
    pub domains_bytes: u64,
}

impl From<tollgate_filter::CompileReport> for CompileReport {
    fn from(report: tollgate_filter::CompileReport) -> CompileReport {
        CompileReport {
            network_rules: report.network_rules,
            domain_entries: report.domain_entries,
            engine_bytes: report.engine_bytes,
            domains_bytes: report.domains_bytes,
        }
    }
}

impl From<ListFormat> for tollgate_filter::ListFormat {
    fn from(format: ListFormat) -> tollgate_filter::ListFormat {
        match format {
            ListFormat::Adblock => tollgate_filter::ListFormat::Adblock,
            ListFormat::Hosts => tollgate_filter::ListFormat::Hosts,
        }
    }
}

impl From<tollgate_filter::ListFormat> for ListFormat {
    fn from(format: tollgate_filter::ListFormat) -> ListFormat {
        match format {
            tollgate_filter::ListFormat::Adblock => ListFormat::Adblock,
            tollgate_filter::ListFormat::Hosts => ListFormat::Hosts,
        }
    }
}

fn source(input: &ListInput) -> ListSource<'_> {
    ListSource {
        name: &input.name,
        text: &input.text,
        format: input.format.into(),
    }
}

fn compile_in(sources: &[ListInput], dir: &Path) -> Result<CompileReport, TollgateError> {
    let config = |list: &ListInput, problem: &str| TollgateError::Config {
        message: format!("list {:?} {problem}", list.name),
    };
    for list in sources.iter().filter(|l| l.target == ListTarget::Url) {
        if list.format == ListFormat::Hosts {
            return Err(config(
                list,
                "is in hosts format and can only feed the DNS blocklist",
            ));
        }
        if list.exempt_sensitive_hosts {
            return Err(config(
                list,
                "exempts sensitive hosts, which only a DNS list can do",
            ));
        }
    }
    let url_lists: Vec<ListSource> = sources
        .iter()
        .filter(|l| l.target == ListTarget::Url)
        .map(source)
        .collect();
    let extras = extras_text();
    let dns_lists: Vec<DnsList> = sources
        .iter()
        .filter(|l| l.target == ListTarget::Dns)
        .map(|l| DnsList {
            source: source(l),
            exempt: l.exempt_sensitive_hosts.then_some(&*SENSITIVE_HOSTS),
        })
        .chain(std::iter::once(DnsList::from(ListSource {
            name: TOLLGATE_EXTRAS_NAME,
            text: &extras,
            format: tollgate_filter::ListFormat::Adblock,
        })))
        .collect();
    tollgate_filter::compile_split_exempting(&url_lists, &dns_lists, dir)
        .map(CompileReport::from)
        .map_err(|e| TollgateError::Lists {
            message: e.to_string(),
        })
}

/// Builds `engine.dat` from the `Url` lists and `domains.bin` from the `Dns` lists and
/// [`TOLLGATE_EXTRAS`], and writes both into `data_dir` (created if missing), each file
/// atomically. Runs in the app, which has far more memory than the tunnel; the tunnel then
/// calls `Engine.reload_lists`.
#[uniffi::export]
pub fn compile_lists(
    sources: Vec<ListInput>,
    data_dir: String,
) -> Result<CompileReport, TollgateError> {
    catch_panic(|| compile_in(&sources, Path::new(&data_dir)))
}

/// How `text` is written, judged from its rule lines: `Hosts` when most of them are hosts
/// lines (`0.0.0.0 name`, `::1 name` or a name on its own), `Adblock` when most are not.
/// `None` when there is no verdict: no rule lines (an empty list, or only comments), as
/// many lines of each kind, or a panic in the detector. See
/// `tollgate_filter::detect_format` for the exact rule. The app uses it to correct the
/// type of a list the user added: compiled with the wrong type, a list blocks little or
/// nothing, or (a hosts file as request rules) fills the tunnel's engine with rules that
/// belong in the DNS blocklist.
#[uniffi::export]
pub fn detect_list_format(text: String) -> Option<ListFormat> {
    catch_panic(|| Ok(tollgate_filter::detect_format(&text).map(ListFormat::from))).unwrap_or(None)
}
