//! Compiling filter lists in the app process into the files the tunnel loads.

use std::path::Path;

use tollgate_filter::ListSource;

use crate::error::{TollgateError, catch_panic};

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
    /// Host names for the DNS blocklist (`domains.bin`): AdGuard DNS filter, hosts files.
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

fn source(input: &ListInput) -> ListSource<'_> {
    ListSource {
        name: &input.name,
        text: &input.text,
        format: match input.format {
            ListFormat::Adblock => tollgate_filter::ListFormat::Adblock,
            ListFormat::Hosts => tollgate_filter::ListFormat::Hosts,
        },
    }
}

fn compile_in(sources: &[ListInput], dir: &Path) -> Result<CompileReport, TollgateError> {
    if let Some(list) = sources
        .iter()
        .find(|l| l.format == ListFormat::Hosts && l.target == ListTarget::Url)
    {
        return Err(TollgateError::Config {
            message: format!(
                "list {:?} is in hosts format and can only feed the DNS blocklist",
                list.name
            ),
        });
    }
    let pick = |target: ListTarget| -> Vec<ListSource<'_>> {
        sources
            .iter()
            .filter(|l| l.target == target)
            .map(source)
            .collect()
    };
    tollgate_filter::compile_split(&pick(ListTarget::Url), &pick(ListTarget::Dns), dir)
        .map(CompileReport::from)
        .map_err(|e| TollgateError::Lists {
            message: e.to_string(),
        })
}

/// Builds `engine.dat` from the `Url` lists and `domains.bin` from the `Dns` lists and
/// writes both into `data_dir` (created if missing), each file atomically. Runs in the
/// app, which has far more memory than the tunnel; the tunnel then calls
/// `Engine.reload_lists`.
#[uniffi::export]
pub fn compile_lists(
    sources: Vec<ListInput>,
    data_dir: String,
) -> Result<CompileReport, TollgateError> {
    catch_panic(|| compile_in(&sources, Path::new(&data_dir)))
}
