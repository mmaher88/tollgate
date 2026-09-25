//! The adblock engine that checks the URLs the proxy sees.

use std::fs::File;
use std::path::Path;
use std::time::Duration;

use adblock::Engine;
use adblock::lists::{FilterFormat, FilterSet, ParseOptions, ParsedLine, RuleTypes, parse_filter};
use adblock::regex_manager::RegexManagerDiscardPolicy;
use adblock::request::Request;

use crate::{FilterError, ListFormat, ListSource};

/// How often the engine looks for compiled regexes to discard.
pub const REGEX_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
/// A compiled regex unused for this long is discarded (adblock's default is 180 s).
pub const REGEX_DISCARD_UNUSED: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// `rule` is the matching rule's text, only known when the engine was built with
    /// `debug = true`; engines loaded from `engine.dat` always give `None`.
    Block {
        rule: Option<String>,
    },
}

/// Network rules only, no cosmetic rules. `Send + Sync`.
pub struct FilterEngine {
    engine: Engine,
}

fn parse_options(format: ListFormat) -> ParseOptions {
    ParseOptions {
        format: match format {
            ListFormat::Adblock => FilterFormat::Standard,
            ListFormat::Hosts => FilterFormat::Hosts,
        },
        rule_types: RuleTypes::NetworkOnly,
        ..ParseOptions::default()
    }
}

impl FilterEngine {
    /// Builds an engine from rule text. `debug` keeps each rule's text so
    /// [`Verdict::Block`] can name it; it roughly doubles memory, so only the app uses it.
    pub fn from_lists(lists: &[ListSource], debug: bool) -> FilterEngine {
        let mut set = FilterSet::new(debug);
        for list in lists {
            set.add_filter_list(list.text.to_owned(), parse_options(list.format));
        }
        FilterEngine::wrap(Engine::new_with_filter_set(set))
    }

    /// The `engine.dat` bytes. Only readable by the same adblock version.
    pub fn serialize(&self) -> Vec<u8> {
        self.engine.serialize()
    }

    /// Loads `engine.dat` through a memory map, so the file's pages are clean, file-backed
    /// memory while adblock copies them into its own buffer, instead of a second heap copy.
    pub fn load(path: &Path) -> Result<FilterEngine, FilterError> {
        let io = |source| FilterError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = File::open(path).map_err(io)?;
        // SAFETY: compile() replaces engine.dat by renaming a new file over it and never
        // writes into an existing file, so the mapped bytes cannot change under us.
        let map = unsafe { memmap2::Mmap::map(&file) }.map_err(io)?;
        let mut engine = Engine::default();
        engine
            .deserialize(&map)
            .map_err(|e| FilterError::Engine(format!("{e:?}")))?;
        drop(map);
        Ok(FilterEngine::wrap(engine))
    }

    /// `request_type` is an adblock type string, see [`crate::request_type`]. A URL the
    /// engine cannot parse is allowed: filtering fails open.
    pub fn check(&self, url: &str, source_url: &str, request_type: &str) -> Verdict {
        let request = match Request::new(url, source_url, request_type, "GET") {
            Ok(request) => request,
            Err(e) => {
                log::debug!("not filtering unparseable request {url:?}: {e:?}");
                return Verdict::Allow;
            }
        };
        let result = self.engine.check_network_request(&request);
        if result.should_block() {
            Verdict::Block {
                rule: result.filter.and_then(|f| f.raw_line),
            }
        } else {
            Verdict::Allow
        }
    }

    fn wrap(engine: Engine) -> FilterEngine {
        engine.set_regex_discard_policy(RegexManagerDiscardPolicy {
            cleanup_interval: REGEX_CLEANUP_INTERVAL,
            discard_unused_time: REGEX_DISCARD_UNUSED,
        });
        FilterEngine { engine }
    }
}

/// Number of network rules adblock accepts from these lists (cosmetic rules, comments and
/// unsupported rules are not counted).
pub fn network_rule_count(lists: &[ListSource]) -> u64 {
    lists
        .iter()
        .map(|list| {
            let options = parse_options(list.format);
            list.text
                .lines()
                .filter(|line| {
                    matches!(
                        parse_filter(line, false, options),
                        Ok(ParsedLine::Network(_))
                    )
                })
                .count() as u64
        })
        .sum()
}
