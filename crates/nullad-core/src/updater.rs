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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use crate::settings::{AppSettings, ListSource};
use crate::state::ListSummary;
use nullad_engine::{ParseStats, Rule, RuleSet, RuleSetBuilder};

const SHRINK_FLOOR: f64 = 0.5;

#[derive(Debug, Clone)]
pub struct LoadOutcome {
    pub rule_set: Option<Arc<RuleSet>>,
    pub summaries: Vec<ListSummary>,
    pub warnings: Vec<String>,
    pub total_rules: usize,
    pub total_failures: usize,
    pub elapsed_ms: f64,
}

impl LoadOutcome {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_rules == 0
    }
}

#[derive(Debug, Clone)]
struct CachedList {
    bytes: usize,
    rules: Vec<Rule>,
    stats: ParseStats,
}

/// Retains the last valid parse per list identity and source.
#[derive(Debug, Default)]
pub struct ListLoader {
    cache: Mutex<HashMap<(u32, ListSource), CachedList>>,
    client: OnceLock<Result<reqwest::blocking::Client, String>>,
    resource_dir: Option<PathBuf>,
    load_lock: Mutex<()>,
}

impl ListLoader {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_resource_dir(resource_dir: Option<PathBuf>) -> Self {
        Self {
            resource_dir,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn load(&self, settings: &AppSettings) -> LoadOutcome {
        let _load = self
            .load_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let started = std::time::Instant::now();
        let mut builder = RuleSetBuilder::new();
        let mut summaries = Vec::new();
        let mut warnings = Vec::new();
        let mut seen_ids = HashSet::new();
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for entry in settings.enabled_lists() {
            if !seen_ids.insert(entry.id) {
                warnings.push(format!("duplicate list id {} ignored", entry.id));
                continue;
            }
            let key = (entry.id, entry.source.clone());
            let candidate = self.read_source(&entry.source).and_then(|text| {
                if matches!(entry.source, ListSource::Remote { .. }) {
                    if let Some(previous) = cache.get(&key) {
                        if text.len() < (previous.bytes as f64 * SHRINK_FLOOR) as usize {
                            return Err(format!("download shrank from {} to {} bytes; retaining the previous valid list", previous.bytes, text.len()));
                        }
                    }
                }
                if matches!(entry.source, ListSource::Remote { .. }) {
                    let prefix = text.trim_start().chars().take(32).collect::<String>().to_ascii_lowercase();
                    if prefix.starts_with("<!doctype html") || prefix.starts_with("<html") {
                        return Err("download returned an HTML page instead of filter rules".into());
                    }
                }
                // Parse once with the actual configured identity.
                let (rules, stats) = nullad_engine::RuleParser::new().list_id(entry.id).parse_list(&text);
                if rules.is_empty() { return Err(format!("parsed zero rules from {} bytes", text.len())); }
                Ok(CachedList { bytes: text.len(), rules, stats })
            });
            let selected = match candidate {
                Ok(valid) => {
                    cache.insert(key.clone(), valid.clone());
                    Some(valid)
                }
                Err(error) => {
                    warnings.push(format!("{}: {error}", entry.name));
                    let previous = cache.get(&key).cloned();
                    if previous.is_some() {
                        warnings.push(format!(
                            "{}: using the last valid rules for this source",
                            entry.name
                        ));
                    }
                    previous
                }
            };
            if let Some(valid) = selected {
                summaries.push(ListSummary {
                    id: entry.id,
                    name: entry.name.clone(),
                    source: entry.source.describe(),
                    enabled: true,
                    rules: valid.stats.accepted,
                    failures: valid.stats.failed(),
                    cosmetic: valid.stats.cosmetic,
                });
                builder.add_rules(valid.rules);
            } else {
                summaries.push(ListSummary {
                    id: entry.id,
                    name: entry.name.clone(),
                    source: entry.source.describe(),
                    enabled: true,
                    rules: 0,
                    failures: 0,
                    cosmetic: 0,
                });
            }
        }
        let total_rules = summaries.iter().map(|summary| summary.rules).sum();
        let total_failures = summaries.iter().map(|summary| summary.failures).sum();
        let rule_set = if builder.is_empty() {
            // Never resurrect removed or disabled rules from an old aggregate.
            // Cached valid rules were already selected separately per source.
            if settings.enabled_lists().next().is_some() {
                warnings.push(
                    "could not compile any valid enabled list; no rules were installed".into(),
                );
            }
            Some(nullad_engine::FilterEngine::new().rule_set())
        } else {
            match builder.build() {
                Ok(rules) => Some(Arc::new(rules)),
                Err(error) => {
                    warnings.push(format!("could not compile a rule set: {error}"));
                    None
                }
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

    fn read_source(&self, source: &ListSource) -> Result<String, String> {
        match source {
            ListSource::Bundled { file } => {
                let resource = self
                    .resource_dir
                    .as_ref()
                    .map(|dir| dir.join("lists").join(file))
                    .filter(|path| path.is_file());
                let path = resource
                    .or_else(|| AppSettings::resolve_bundled(file))
                    .ok_or_else(|| {
                        format!(
                            "bundled list {file} was not found in installed resources or ./lists"
                        )
                    })?;
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
            }
            ListSource::Local { path } => {
                std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
            }
            ListSource::Remote { url } => self.fetch_remote(url),
        }
    }

    fn fetch_remote(&self, url: &str) -> Result<String, String> {
        let client = self
            .client
            .get_or_init(|| {
                reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .user_agent(concat!("NullAD/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .map_err(|e| format!("cannot create HTTP client: {e}"))
            })
            .as_ref()
            .map_err(Clone::clone)?;
        let response = client
            .get(url)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("server returned {}", response.status()));
        }
        response
            .text()
            .map_err(|e| format!("could not read response body: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::ListEntry;

    fn settings_with(text: &str) -> (AppSettings, tempdir::TempFile) {
        let file = tempdir::TempFile::new(text);
        let settings = AppSettings {
            lists: vec![ListEntry {
                id: 1,
                name: "test".into(),
                source: ListSource::Local {
                    path: file.path_string(),
                },
                enabled: true,
            }],
            ..AppSettings::default()
        };
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
        let settings = AppSettings {
            lists: vec![ListEntry {
                id: 1,
                name: "missing".into(),
                source: ListSource::Local {
                    path: "definitely/not/here.txt".into(),
                },
                enabled: true,
            }],
            ..AppSettings::default()
        };

        let outcome = ListLoader::new().load(&settings);
        assert_eq!(outcome.total_rules, 0);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.contains("definitely/not/here.txt")),
            "the unreadable path must be named: {:?}",
            outcome.warnings
        );
        // A second warning is expected: with nothing loaded, no rule set could
        // be compiled, and that is reported separately.
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.contains("could not compile")),
            "the empty result must be reported: {:?}",
            outcome.warnings
        );
        assert!(outcome.rule_set.as_ref().unwrap().rules().next().is_none());
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
    #[test]
    fn failed_reload_retains_only_the_same_identity_and_source() {
        let (mut settings, file) = settings_with("||ads.example.com^\n");
        settings.lists[0].id = 42;
        let loader = ListLoader::new();
        let valid = loader.load(&settings);
        assert_eq!(
            valid
                .rule_set
                .as_ref()
                .unwrap()
                .rules()
                .next()
                .unwrap()
                .list_id,
            42
        );
        std::fs::write(file.path_string(), "! truncated update\n").unwrap();
        let fallback = loader.load(&settings);
        assert_eq!(fallback.total_rules, 1);
        assert!(fallback
            .warnings
            .iter()
            .any(|warning| warning.contains("last valid")));
        settings.lists[0].source = ListSource::Local {
            path: "another/missing/source.txt".into(),
        };
        assert_eq!(loader.load(&settings).total_rules, 0);
    }

    #[test]
    fn installed_resource_directory_is_used_for_bundled_lists() {
        let root = crate::test_support::directory();
        std::fs::create_dir_all(root.join("lists")).unwrap();
        std::fs::write(
            root.join("lists").join("installed.txt"),
            "||installed.example^\n",
        )
        .unwrap();
        let settings = AppSettings {
            lists: vec![ListEntry {
                id: 5,
                name: "installed".into(),
                source: ListSource::Bundled {
                    file: "installed.txt".into(),
                },
                enabled: true,
            }],
            ..AppSettings::default()
        };
        let outcome = ListLoader::with_resource_dir(Some(root)).load(&settings);
        assert_eq!(outcome.total_rules, 1);
    }

    #[test]
    fn invalid_remote_body_does_not_lower_the_shrink_baseline() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/list", listener.local_addr().unwrap());
        let valid = (0..12)
            .map(|index| format!("||advertising-tracker-{index}.example.com^\n"))
            .collect::<String>();
        let invalid = format!("!{}\n", "ignored ".repeat(valid.len()));
        let html = format!(
            "<!doctype html><html>{}</html>",
            "portal ".repeat(valid.len())
        );
        let server = std::thread::spawn(move || {
            for body in [valid, html, invalid, "||tiny.example.com^\n".into()] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                assert!(socket.read(&mut request).unwrap() > 0);
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let settings = AppSettings {
            lists: vec![ListEntry {
                id: 9,
                name: "remote".into(),
                source: ListSource::Remote { url },
                enabled: true,
            }],
            ..AppSettings::default()
        };
        let loader = ListLoader::new();
        assert_eq!(loader.load(&settings).total_rules, 12);
        assert_eq!(loader.load(&settings).total_rules, 12);
        assert_eq!(loader.load(&settings).total_rules, 12);
        let shrink = loader.load(&settings);
        assert_eq!(shrink.total_rules, 12);
        assert!(shrink
            .warnings
            .iter()
            .any(|warning| warning.contains("shrank")));
        server.join().unwrap();
    }
}
