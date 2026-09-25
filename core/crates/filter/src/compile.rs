//! Compiling filter lists into the two files the tunnel loads.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::domain_set::HEADER_LEN;
use crate::{DomainRules, FilterEngine, FilterError, ListFormat, ListSource, network_rule_count};

pub const ENGINE_FILE: &str = "engine.dat";
pub const DOMAINS_FILE: &str = "domains.bin";

#[derive(Clone, Debug)]
pub struct CompileReport {
    /// Network rules in the engine.
    pub network_rules: u64,
    /// Hashes in the DNS blocklist.
    pub domain_entries: u64,
    pub engine_bytes: u64,
    pub domains_bytes: u64,
}

/// Writes ENGINE_FILE and DOMAINS_FILE atomically into dir.
///
/// Adblock lists feed both files; hosts lists feed only the DNS blocklist. A DNS list
/// written in adblock syntax (the AdGuard DNS filter) belongs in the DNS blocklist only,
/// and would more than double the engine; pass it through [`compile_split`] instead.
pub fn compile(lists: &[ListSource], dir: &Path) -> Result<CompileReport, FilterError> {
    let engine_lists: Vec<ListSource> = lists
        .iter()
        .filter(|l| l.format == ListFormat::Adblock)
        .map(|l| ListSource {
            name: l.name,
            text: l.text,
            format: l.format,
        })
        .collect();
    compile_split(&engine_lists, lists, dir)
}

/// Builds ENGINE_FILE from `engine_lists` and DOMAINS_FILE from `dns_lists` and writes
/// both into `dir`, which is created if missing.
///
/// The engine is built without debug information. Each file is written to a temporary
/// file in `dir`, flushed to disk and renamed over the old one, so a reader sees the old
/// file or the new one, never a partial file.
pub fn compile_split(
    engine_lists: &[ListSource],
    dns_lists: &[ListSource],
    dir: &Path,
) -> Result<CompileReport, FilterError> {
    fs::create_dir_all(dir).map_err(|source| FilterError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let network_rules = network_rule_count(engine_lists);
    let engine = FilterEngine::from_lists(engine_lists, false).serialize();
    let domains = DomainRules::parse(dns_lists).encode();
    write_atomically(&dir.join(ENGINE_FILE), &engine)?;
    write_atomically(&dir.join(DOMAINS_FILE), &domains)?;
    let report = CompileReport {
        network_rules,
        domain_entries: ((domains.len() - HEADER_LEN) / 8) as u64,
        engine_bytes: engine.len() as u64,
        domains_bytes: domains.len() as u64,
    };
    log::info!("compiled filter lists: {report:?}");
    Ok(report)
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), FilterError> {
    let file_name = path
        .file_name()
        .expect("compile passes a file name")
        .to_string_lossy();
    let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    result.map_err(|source| {
        let _ = fs::remove_file(&tmp);
        FilterError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}
