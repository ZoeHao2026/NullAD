//! Filter list discovery, loading, and reporting.

use std::path::{Path, PathBuf};
use std::time::Instant;

use nullad_engine::{ParseStats, Rule, RuleParser, RuleSetBuilder, RuleSetStats};
/// Where lists are looked for when none are named explicitly.
pub const DEFAULT_LIST_DIR: &str = "lists";

/// A list parsed once, sharing the same rules and statistics with build/report.
#[derive(Debug)]
pub struct LoadedList {
    /// Where the list came from, for display.
    pub source: String,
    /// Parsed rules already tagged with the real list ID.
    rules: Vec<Rule>,
    /// The statistics produced by that same parse.
    stats: ParseStats,
    /// Source size before parsing.
    bytes: usize,
}

impl LoadedList {
    fn parse(source: String, text: &str, list_id: u32) -> Self {
        let (rules, stats) = RuleParser::new().list_id(list_id).parse_list(text);
        Self {
            source,
            rules,
            stats,
            bytes: text.len(),
        }
    }
}

/// A collection of filter lists.
#[derive(Debug, Default)]
pub struct ListSet {
    lists: Vec<LoadedList>,
    /// Paths that could not be read, with the reason.
    pub errors: Vec<String>,
    load_elapsed_ms: f64,
}

impl ListSet {
    /// Loads explicit paths, or supported list files from cwd/lists, falling
    /// back to lists beside the executable when the current directory has none.
    #[must_use]
    pub fn load(paths: &[PathBuf]) -> Self {
        let started = Instant::now();
        let mut set = Self::default();

        let resolved: Vec<PathBuf> = if paths.is_empty() {
            discover_default_lists()
        } else {
            paths.to_vec()
        };

        for path in resolved {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let list_id = u32::try_from(set.lists.len()).unwrap_or(u32::MAX);
                    set.lists.push(LoadedList::parse(
                        path.display().to_string(),
                        &text,
                        list_id,
                    ));
                }
                Err(err) => set.errors.push(format!("{}: {err}", path.display())),
            }
        }

        set.load_elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        set
    }

    /// Loads lists from raw in-memory text, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn from_texts(texts: Vec<(String, String)>) -> Self {
        let started = Instant::now();
        let lists = texts
            .into_iter()
            .enumerate()
            .map(|(index, (source, text))| {
                LoadedList::parse(source, &text, u32::try_from(index).unwrap_or(u32::MAX))
            })
            .collect();
        Self {
            lists,
            errors: Vec::new(),
            load_elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        }
    }

    /// Adds the already-parsed rules to a builder, retaining source attribution.
    #[must_use]
    pub fn build_builder(&self) -> RuleSetBuilder {
        let mut builder = RuleSetBuilder::new();
        for list in &self.lists {
            builder.add_rules(list.rules.iter().cloned());
        }
        builder
    }

    /// Produces the human-facing load report.
    ///
    /// `rule_set` must be the statistics of the rule set that was actually
    /// built. Index-derived figures such as trie node and automaton fragment
    /// counts only exist after the index structures are constructed, so taking
    /// them from a pre-build stage would report zeros.
    #[must_use]
    pub fn report(&self, rule_set: RuleSetStats) -> LoadReport {
        let started = Instant::now();
        let mut summaries = Vec::with_capacity(self.lists.len());
        let mut sample_rules = Vec::new();
        let mut total_bytes = 0usize;

        for list in &self.lists {
            total_bytes += list.bytes;
            let stats = &list.stats;

            if sample_rules.len() < 40 {
                for rule in list.rules.iter().take(10) {
                    sample_rules.push(format!("{:<6} {}", rule.action, rule.raw));
                }
            }

            summaries.push(ListSummary {
                source: list.source.clone(),
                lines: stats.lines,
                accepted: stats.accepted,
                failed: stats.failed(),
                cosmetic: stats.cosmetic,
            });
        }

        LoadReport {
            lists: summaries,
            rule_set,
            sample_rules,
            total_bytes,
            elapsed_ms: self.load_elapsed_ms + started.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

/// Discovers list files under the default directory.
fn discover_default_lists() -> Vec<PathBuf> {
    let executable_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    discover_lists_with_fallback(Path::new(DEFAULT_LIST_DIR), executable_dir.as_deref())
}

fn discover_lists_with_fallback(current: &Path, executable_dir: Option<&Path>) -> Vec<PathBuf> {
    let current = discover_lists_in(current);
    if !current.is_empty() {
        return current;
    }
    executable_dir
        .map(|dir| discover_lists_in(&dir.join(DEFAULT_LIST_DIR)))
        .unwrap_or_default()
}

fn discover_lists_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path.extension().is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("txt") || ext.eq_ignore_ascii_case("list")
                })
        })
        .collect();
    paths.sort();
    paths
}

/// Per-list statistics for display.
#[derive(Debug, Clone)]
pub struct ListSummary {
    /// Where the list came from.
    pub source: String,
    /// Lines read.
    pub lines: usize,
    /// Rules accepted.
    pub accepted: usize,
    /// Rules quarantined.
    pub failed: usize,
    /// Cosmetic rules recognised but not applied.
    pub cosmetic: usize,
}

/// Everything the CLI learned while loading lists.
#[derive(Debug)]
pub struct LoadReport {
    /// Per-list statistics.
    pub lists: Vec<ListSummary>,
    /// Aggregated rule-set structure.
    pub rule_set: RuleSetStats,
    /// A few sample rules for inspection.
    pub sample_rules: Vec<String>,
    /// Total bytes of list text read.
    pub total_bytes: usize,
    /// Wall-clock report time in milliseconds.
    pub elapsed_ms: f64,
}

impl LoadReport {
    /// Prints the report in a stable, greppable format.
    pub fn print(&self) {
        let total_rules: usize = self.lists.iter().map(|l| l.accepted).sum();
        let total_failed: usize = self.lists.iter().map(|l| l.failed).sum();

        println!(
            "loaded {} list(s), {} rules, {} quarantined, {} bytes",
            self.lists.len(),
            total_rules,
            total_failed,
            self.total_bytes
        );
        if self.lists.len() > 1 {
            println!();
            println!(
                "{:<44} {:>9} {:>9} {:>8} {:>9}",
                "LIST", "LINES", "RULES", "FAILED", "COSMETIC"
            );
            for list in &self.lists {
                println!(
                    "{:<44} {:>9} {:>9} {:>8} {:>9}",
                    shorten(&list.source, 44),
                    list.lines,
                    list.accepted,
                    list.failed,
                    list.cosmetic
                );
            }
        }

        let rs = &self.rule_set;
        println!();
        println!("rule set structure:");
        println!("  total rules         {}", rs.rules);
        println!("  domain anchors      {}", rs.domain_rules);
        println!("  domain + path       {}", rs.domain_path_rules);
        println!("  substring/wildcard  {}", rs.fragment_rules);
        println!("  regex               {}", rs.regex_rules);
        println!("  option-only         {}", rs.options_only_rules);
        println!("  trie nodes          {}", rs.trie_nodes);
        println!("  automaton fragments {}", rs.distinct_fragments);
    }
}

/// Shortens a path for column display, keeping the informative tail.
fn shorten(text: &str, width: usize) -> String {
    if text.len() <= width {
        return text.to_owned();
    }
    let keep = width.saturating_sub(3);
    let start = text.len().saturating_sub(keep);
    // Avoid slicing mid-character.
    let mut start = start;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &text[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortens_long_paths() {
        let long = "D:/a/very/long/path/to/some/filter/list/file.txt";
        let short = shorten(long, 20);
        assert!(short.len() <= 20);
        assert!(short.starts_with("..."));
        assert!(short.ends_with("file.txt"));
    }

    #[test]
    fn keeps_short_paths_intact() {
        assert_eq!(shorten("lists/a.txt", 44), "lists/a.txt");
    }

    #[test]
    fn builds_a_rule_set_from_texts() {
        let set = ListSet::from_texts(vec![("t".into(), "||ads.com^\n! comment\n".into())]);
        let builder = set.build_builder();
        let rule_set = builder.build().expect("rule set");
        let report = set.report(rule_set.stats().clone());
        assert_eq!(report.lists.len(), 1);
        assert_eq!(report.lists[0].accepted, 1);
        assert_eq!(report.rule_set.rules, 1);
        // Index-derived counts must be populated, not left at zero.
        assert!(report.rule_set.trie_nodes > 0);
    }

    #[test]
    fn missing_files_are_reported_not_fatal() {
        let set = ListSet::load(&[PathBuf::from("definitely/not/here.txt")]);
        assert!(set.lists.is_empty());
        assert_eq!(set.errors.len(), 1);
    }

    #[test]
    fn cached_parse_retains_list_ids_source_lines_and_quarantined_stats() {
        let first = "! first\n||one.example^\n/[/\n";
        let second = "! second\n||two.example^\n";
        let set = ListSet::from_texts(vec![
            ("one".into(), first.into()),
            ("two".into(), second.into()),
        ]);
        let rules = set.build_builder().build().unwrap();
        let attribution: Vec<_> = rules
            .rules()
            .map(|rule| (rule.list_id, rule.source_line))
            .collect();
        assert_eq!(attribution, vec![(0, 2), (1, 2)]);
        let report = set.report(rules.stats().clone());
        assert_eq!(report.lists[0].accepted, 1);
        assert_eq!(report.lists[0].failed, 1);
        assert_eq!(report.lists[1].accepted, 1);
        assert_eq!(report.total_bytes, first.len() + second.len());
        assert!(report.sample_rules[0].contains("||one.example^"));
        assert!(report.sample_rules[1].contains("||two.example^"));
    }

    #[test]
    fn default_discovery_prefers_cwd_then_packaged_lists_and_ignores_documents() {
        let root =
            std::env::temp_dir().join(format!("nullad-cli-discovery-{}", std::process::id()));
        let current = root.join("current/lists");
        let packaged = root.join("package");
        std::fs::create_dir_all(&current).unwrap();
        std::fs::create_dir_all(packaged.join("lists")).unwrap();
        std::fs::write(current.join("README.md"), "not a filter list").unwrap();
        let bundled = packaged.join("lists/nullad-base.txt");
        std::fs::write(&bundled, "||bundled.example^").unwrap();
        assert_eq!(
            discover_lists_with_fallback(&current, Some(&packaged)),
            vec![bundled]
        );
        let local = current.join("local.list");
        std::fs::write(&local, "||local.example^").unwrap();
        assert_eq!(
            discover_lists_with_fallback(&current, Some(&packaged)),
            vec![local]
        );
        assert!(discover_lists_with_fallback(&root.join("missing"), None).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
