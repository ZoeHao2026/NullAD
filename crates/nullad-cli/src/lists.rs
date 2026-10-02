//! Filter list discovery, loading, and reporting.

use std::path::{Path, PathBuf};
use std::time::Instant;

use nullad_engine::{RuleSetBuilder, RuleSetStats};
/// Where lists are looked for when none are named explicitly.
pub const DEFAULT_LIST_DIR: &str = "lists";

/// One loaded list together with its raw text.
///
/// Per-list parse statistics are not cached here: `report` re-parses each list
/// so that statistics can be attributed to the right list, and duplicating them
/// would create two sources of truth.
#[derive(Debug)]
pub struct LoadedList {
    /// Where the list came from, for display.
    pub source: String,
    /// Raw list text.
    pub text: String,
}

/// A collection of filter lists.
#[derive(Debug, Default)]
pub struct ListSet {
    lists: Vec<LoadedList>,
    /// Paths that could not be read, with the reason.
    pub errors: Vec<String>,
}

impl ListSet {
    /// Loads the named lists, or every file in [`DEFAULT_LIST_DIR`] when none
    /// are named.
    #[must_use]
    pub fn load(paths: &[PathBuf]) -> Self {
        let mut set = Self::default();

        let resolved: Vec<PathBuf> = if paths.is_empty() {
            discover_default_lists()
        } else {
            paths.to_vec()
        };

        for path in resolved {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    set.lists.push(LoadedList {
                        source: path.display().to_string(),
                        text,
                    });
                }
                Err(err) => set.errors.push(format!("{}: {err}", path.display())),
            }
        }

        set
    }

    /// Loads lists from raw in-memory text, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn from_texts(texts: Vec<(String, String)>) -> Self {
        Self {
            lists: texts
                .into_iter()
                .map(|(source, text)| LoadedList { source, text })
                .collect(),
            errors: Vec::new(),
        }
    }

    /// Parses every list into a rule set builder.
    #[must_use]
    pub fn build_builder(&self) -> RuleSetBuilder {
        let mut builder = RuleSetBuilder::new();
        for (index, list) in self.lists.iter().enumerate() {
            let list_id = u32::try_from(index).unwrap_or(u32::MAX);
            builder.add_list(&list.text, list_id);
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
            total_bytes += list.text.len();
            let parser = nullad_engine::RuleParser::new();
            let (rules, stats) = parser.parse_list(&list.text);

            if sample_rules.len() < 40 {
                for rule in rules.iter().take(10) {
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
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        }
    }
}

/// Discovers list files under the default directory.
fn discover_default_lists() -> Vec<PathBuf> {
    let dir = Path::new(DEFAULT_LIST_DIR);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("txt") || ext.eq_ignore_ascii_case("list"))
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
}
