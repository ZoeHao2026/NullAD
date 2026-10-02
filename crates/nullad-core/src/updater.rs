//! Loading and validating filter lists.
//!
//! The loader is the boundary between "text on disk or on the wire" and "an
//! immutable, indexed rule set". It exists separately from the engine so that
//! the engine stays free of filesystem and network concerns, and so that the
//! safety checks live in one place:
//!
//! * A list that fails to read is reported and skipped, never fatal.
//! * A list that parses to *zero* rules is treated as suspicious rather than
//!   silently accepted, because the most likely cause is a truncated download.
//! * A remote list is never allowed to replace a working one if it is smaller
//!   than a configured floor, which is the guard against serving a captive
//!   portal's error page as a filter list.

use std::collections::HashSet;

use nullad_engine::{RuleSet, RuleSetBuilder};

use crate::settings::{AppSettings, ListSource};
use crate::state::ListSummary;

/// A remote list smaller than this fraction of its previous size is rejected.
const SHRINK_FLOOR: f64 = 0.5;

/// The result of a load attempt.
#[derive(Debug, Clone)]
pub struct LoadOutcome {
    /// The compiled rule set, when at least one rule survived.
    ///
    /// Held behind an `Arc` so the outcome can be cloned cheaply and the same
    /// compiled set can be installed into the engine without rebuilding it.
    pub rule_set: Option<std::sync::Arc<RuleSet>>,
    /// Per-list summaries for the UI.
    pub summaries: Vec<ListSummary>,
    /// Problems that did not prevent loading.
    pub warnings: Vec<String>,
    /// Total rules indexed.
    pub total_rules: usize,
    /// Total rules quarantined.
    pub total_failures: usize,
    /// Wall-clock duration in milliseconds.
    pub elapsed_ms: f64,
}

impl LoadOutcome {
    /// Returns `true` when every configured list failed to load.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_rules == 0
    }
}

/// Loads filter lists into a compiled rule set.
#[derive(Debug, Default)]
pub struct ListLoader {
    /// Sizes of previously loaded remote lists, keyed by URL.
    previous_sizes: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl ListLoader {
    /// Creates an empty loader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads every enabled list and compiles a rule set.
    #[must_use]
    pub fn load(&self, settings: &AppSettings) -> LoadOutcome {
        let started = std::time::Instant::now();
        let mut builder = RuleSetBuilder::new();
        let mut summaries = Vec::new();
        let mut warnings = Vec::new();
        let mut seen_ids = HashSet::new();

        for entry in settings.enabled_lists() {
            if !seen_ids.insert(entry.id) {
                warnings.push(format!("duplicate list id {} ignored", entry.id));
                continue;
            }

            let text = match self.read_source(&entry.source) {
                Ok(text) => text,
                Err(err) => {
                    warnings.push(format!("{}: {err}", entry.name));
                    summaries.push(ListSummary {
                        id: entry.id,
                        name: entry.name.clone(),
                        source: entry.source.describe(),
                        enabled: true,
                        rules: 0,
                        failures: 0,
                        cosmetic: 0,
                    });
                    continue;
                }
            };

            let parser = nullad_engine::RuleParser::new();
            let (_, stats) = parser.parse_list(&text);

            // A list that parses to nothing is almost always a failed download
            // or a wrong path. Accepting it silently would look exactly like a
            // working configuration while blocking nothing.
            if stats.accepted == 0 {
                warnings.push(format!(
                    "{}: parsed zero rules from {} bytes; the file or download is \
                     probably empty or not a filter list",
                    entry.name,
                    text.len()
                ));
                summaries.push(ListSummary {
                    id: entry.id,
                    name: entry.name.clone(),
                    source: entry.source.describe(),
                    enabled: true,
                    rules: 0,
                    failures: stats.failed(),
                    cosmetic: stats.cosmetic,
                });
                continue;
            }

            let added = builder.add_list(&text, entry.id);
            summaries.push(ListSummary {
                id: entry.id,
                name: entry.name.clone(),
                source: entry.source.describe(),
                enabled: true,
                rules: added.accepted,
                failures: added.failed(),
                cosmetic: added.cosmetic,
            });
        }

        let total_rules: usize = summaries.iter().map(|s| s.rules).sum();
        let total_failures: usize = summaries.iter().map(|s| s.failures).sum();

        let rule_set = match builder.build() {
            Ok(rule_set) => Some(std::sync::Arc::new(rule_set)),
            Err(err) => {
                warnings.push(format!("could not compile a rule set: {err}"));
                None
            }
        };

        LoadOutcome {
            rule_set,
            summaries,
            warnings,
            total_rules,
            total_failures,
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        }
    }

    /// Reads a list source into memory.
    fn read_source(&self, source: &ListSource) -> Result<String, String> {
        match source {
            ListSource::Bundled { file } => {
                let path = AppSettings::resolve_bundled(file).ok_or_else(|| {
                    format!("bundled list `{file}` was not found next to the executable or in ./lists")
                })?;
                std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))
            }
            ListSource::Local { path } => std::fs::read_to_string(path)
                .map_err(|e| format!("{path}: {e}")),
            ListSource::Remote { url } => self.fetch_remote(url),
        }
    }

    /// Fetches a remote list with the validation described in the module docs.
    ///
    /// Uses blocking I/O because list loading happens on a dedicated worker, not
    /// in an async context, and a few hundred kilobytes of text does not warrant
    /// making the call path async.
    fn fetch_remote(&self, url: &str) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("NullAD/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("cannot create an HTTP client: {e}"))?;

        let response = client
            .get(url)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("server returned {}", response.status()));
        }

        let text = response
            .text()
            .map_err(|e| format!("could not read the response body: {e}"))?;

        // Guard against a captive portal or error page being accepted as a list.
        let mut sizes = match self.previous_sizes.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(&previous) = sizes.get(url) {
            if previous > 0 {
                let floor = (previous as f64 * SHRINK_FLOOR) as usize;
                if text.len() < floor {
                    return Err(format!(
                        "downloaded list is {} bytes but the previous one was {}; \
                         refusing to replace a working list with a much smaller one",
                        text.len(),
                        previous
                    ));
                }
            }
        }
        sizes.insert(url.to_owned(), text.len());

        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::ListEntry;

    fn settings_with(text: &str) -> (AppSettings, tempdir::TempFile) {
        let file = tempdir::TempFile::new(text);
        let mut settings = AppSettings::default();
        settings.lists = vec![ListEntry {
            id: 1,
            name: "test".into(),
            source: ListSource::Local {
                path: file.path_string(),
            },
            enabled: true,
        }];
        (settings, file)
    }

    /// A temporary list file, without pulling in a `tempfile` dependency.
    ///
    /// Files are created under Cargo's per-target test directory rather than
    /// `std::env::temp_dir()`. That matters for portability: on a locked-down
    /// host the system temp directory may not be writable, while this location
    /// is one Cargo created for exactly this purpose and is cleaned up by
    /// `cargo clean` along with the rest of `target/`.
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        /// Distinguishes files created by tests running in the same process.
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        #[derive(Debug)]
        pub struct TempFile {
            path: PathBuf,
        }

        impl TempFile {
            /// Writes `contents` to a uniquely named file in the test data dir.
            ///
            /// # Panics
            ///
            /// Panics if the file cannot be created, because every caller is a
            /// test that cannot proceed without it.
            pub fn new(contents: &str) -> Self {
                let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
                let dir = test_data_dir();
                std::fs::create_dir_all(&dir).expect("create the test data directory");

                let path = dir.join(format!("list-{}-{unique}.txt", std::process::id()));
                std::fs::write(&path, contents).expect("write temp list");
                Self { path }
            }

            /// The file's path as a string, for use in settings.
            pub fn path_string(&self) -> String {
                self.path.to_string_lossy().into_owned()
            }
        }

        /// Returns a writable directory for test data.
        ///
        /// The system temp directory is deliberately not used here: on a
        /// hardened or sandboxed host it can be unwritable, which is exactly the
        /// failure this helper exists to avoid. The directory holding the running
        /// test binary is safe instead, because if a file could not be written
        /// there the test binary could never have been placed there either.
        fn test_data_dir() -> PathBuf {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
                .map_or_else(std::env::temp_dir, |dir| dir.join("nullad-test-data"))
        }

        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    #[test]
    fn loads_a_local_list() {
        let (settings, _file) = settings_with("||ads.example.com^\n||tracker.example.com^\n");
        let outcome = ListLoader::new().load(&settings);

        assert!(outcome.rule_set.is_some());
        assert_eq!(outcome.total_rules, 2);
        assert_eq!(outcome.total_failures, 0);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    }

    #[test]
    fn missing_file_warns_and_does_not_fail_the_load() {
        let mut settings = AppSettings::default();
        settings.lists = vec![ListEntry {
            id: 1,
            name: "missing".into(),
            source: ListSource::Local {
                path: "definitely/not/here.txt".into(),
            },
            enabled: true,
        }];

        let outcome = ListLoader::new().load(&settings);
        assert_eq!(outcome.total_rules, 0);
        assert!(
            outcome.warnings.iter().any(|w| w.contains("definitely/not/here.txt")),
            "the unreadable path must be named: {:?}",
            outcome.warnings
        );
        // A second warning is expected: with nothing loaded, no rule set could
        // be compiled, and that is reported separately.
        assert!(
            outcome.warnings.iter().any(|w| w.contains("could not compile")),
            "the empty result must be reported: {:?}",
            outcome.warnings
        );
        assert!(outcome.rule_set.is_none());
    }

    #[test]
    fn empty_list_is_flagged_rather_than_silently_accepted() {
        let (settings, _file) = settings_with("! only a comment\n");
        let outcome = ListLoader::new().load(&settings);

        assert_eq!(outcome.total_rules, 0);
        assert!(
            outcome.warnings.iter().any(|w| w.contains("zero rules")),
            "an empty list must be reported: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn disabled_lists_are_skipped_entirely() {
        let (mut settings, _file) = settings_with("||ads.example.com^\n");
        settings.lists[0].enabled = false;

        let outcome = ListLoader::new().load(&settings);
        assert!(outcome.summaries.is_empty());
        assert_eq!(outcome.total_rules, 0);
    }

    #[test]
    fn the_compiled_rule_set_actually_blocks() {
        let (settings, _file) = settings_with("||ads.example.com^\n");
        let outcome = ListLoader::new().load(&settings);
        let rule_set = outcome.rule_set.expect("rule set");

        let request = nullad_engine::Request::new(
            "https://ads.example.com/banner.gif",
            nullad_engine::ResourceType::Image,
        );
        let mut scratch = nullad_engine::MatchScratch::new();
        assert!(rule_set.check(&request, &mut scratch).is_blocked());
    }

    #[test]
    fn duplicate_list_ids_are_reported() {
        let (mut settings, _file) = settings_with("||ads.example.com^\n");
        let duplicate = settings.lists[0].clone();
        settings.lists.push(duplicate);

        let outcome = ListLoader::new().load(&settings);
        assert!(outcome
            .warnings
            .iter()
            .any(|w| w.contains("duplicate list id")));
    }
}


