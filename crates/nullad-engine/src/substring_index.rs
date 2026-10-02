//! Multi-pattern substring and wildcard matching built on Aho–Corasick.
//!
//! Rules that are not pure domain anchors become one or more literal
//! "fragments". A single automaton is built over every distinct fragment, so
//! one linear pass over the URL text discovers candidate positions for all
//! patterns at once. Cost therefore scales with the length of the URL, not with
//! the number of rules.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use smallvec::SmallVec;

/// A pattern expressed as ordered literal fragments separated by `*`.
#[derive(Debug, Clone)]
pub struct FragmentPattern {
    /// Identifier of the rule this pattern belongs to.
    pub rule_id: u32,
    /// Literal fragments that must appear in order.
    pub fragments: SmallVec<[String; 4]>,
    /// `true` when the pattern began with `*` (so it may match mid-URL).
    pub leading_wildcard: bool,
    /// `true` when the pattern ended with `*`.
    pub trailing_wildcard: bool,
    /// `true` when the pattern was anchored to the start of the URL with `|`.
    pub start_anchored: bool,
    /// `true` when the pattern was anchored to the end of the URL with `|`.
    pub end_anchored: bool,
}

impl FragmentPattern {
    /// Returns `true` for a pattern that must equal the entire URL.
    #[must_use]
    pub fn is_full_match(&self) -> bool {
        self.start_anchored
            && self.end_anchored
            && !self.leading_wildcard
            && !self.trailing_wildcard
            && self.fragments.len() == 1
    }
}

/// An Aho–Corasick index over pattern fragments.
pub struct SubstringIndex {
    /// The automaton, or `None` when no fragments were indexed.
    ac: Option<AhoCorasick>,
    /// Patterns in insertion order, addressed by pattern index.
    patterns: Vec<FragmentPattern>,
    /// For each automaton fragment id, the pattern indices that use it.
    fragment_to_patterns: Vec<SmallVec<[u32; 1]>>,
    /// Fragment text to automaton id, deduplicated across patterns.
    fragment_ids: HashMap<Box<str>, u32>,
}

impl std::fmt::Debug for SubstringIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubstringIndex")
            .field("patterns", &self.patterns.len())
            .field("distinct_fragments", &self.fragment_ids.len())
            .finish()
    }
}

impl Default for SubstringIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SubstringIndex {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ac: None,
            patterns: Vec::new(),
            fragment_to_patterns: Vec::new(),
            fragment_ids: HashMap::new(),
        }
    }

    /// Adds a pattern and returns its pattern index.
    pub fn add(&mut self, pattern: FragmentPattern) -> u32 {
        let index = u32::try_from(self.patterns.len()).unwrap_or(u32::MAX);
        self.patterns.push(pattern);
        index
    }

    /// Number of patterns indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` when no patterns are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Number of distinct automaton fragments.
    #[must_use]
    pub fn distinct_fragments(&self) -> usize {
        self.fragment_ids.len()
    }

    /// Builds the automaton.
    ///
    /// Must be called after all [`Self::add`] calls and before any matching.
    /// Deduplicates fragments so that the automaton stays small even when
    /// hundreds of thousands of rules share common tokens.
    pub fn build(&mut self) {
        self.fragment_ids.clear();
        self.fragment_to_patterns.clear();

        if self.patterns.is_empty() {
            self.ac = None;
            return;
        }

        // Deterministic fragment ordering keeps the automaton reproducible.
        let mut ordered: Vec<(Box<str>, u32)> = Vec::new();
        for (pattern_index, pattern) in self.patterns.iter().enumerate() {
            let pattern_index = u32::try_from(pattern_index).unwrap_or(u32::MAX);
            for fragment in &pattern.fragments {
                if fragment.is_empty() {
                    // An empty fragment (from `**` or a leading/trailing `*`)
                    // carries no automaton information; the anchor flags already
                    // describe its position.
                    continue;
                }
                let id = match self.fragment_ids.get(fragment.as_str()) {
                    Some(&id) => id,
                    None => {
                        let id = u32::try_from(ordered.len()).unwrap_or(u32::MAX);
                        ordered.push((fragment.as_str().into(), id));
                        self.fragment_ids.insert(fragment.as_str().into(), id);
                        id
                    }
                };

                let slot = id as usize;
                if self.fragment_to_patterns.len() <= slot {
                    self.fragment_to_patterns
                        .resize(slot + 1, SmallVec::new());
                }
                let bucket = &mut self.fragment_to_patterns[slot];
                if !bucket.contains(&pattern_index) {
                    bucket.push(pattern_index);
                }
            }
        }

        if ordered.is_empty() {
            self.ac = None;
            return;
        }

        let texts: Vec<&str> = ordered.iter().map(|(text, _)| &**text).collect();
        match AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(&texts)
        {
            Ok(ac) => self.ac = Some(ac),
            Err(_) => {
                // Building cannot realistically fail for literal patterns, but
                // degrading to "no substring rules" is far better than aborting
                // the whole engine.
                self.ac = None;
            }
        }
    }

    /// Returns the pattern at `index`, if present.
    #[must_use]
    pub fn pattern(&self, index: u32) -> Option<&FragmentPattern> {
        self.patterns.get(index as usize)
    }

    /// Scans `haystack` and returns the rule ids of every pattern that matched.
    ///
    /// `haystack` must be lowercase ASCII. Duplicate rule ids are suppressed by
    /// way of the `seen` stamp buffer and the caller-supplied `generation`,
    /// which lets the caller reuse one buffer across many scans without
    /// clearing it.
    ///
    /// Taking the generation as a parameter rather than owning it means this
    /// method needs only `&self`, so a `RuleSet` can be shared immutably across
    /// threads with no lock in the matching path.
    pub fn scan(&self, haystack: &str, seen: &mut Vec<u32>, generation: u32, out: &mut Vec<u32>) {
        let Some(ac) = self.ac.as_ref() else {
            return;
        };
        if self.patterns.is_empty() || haystack.is_empty() {
            return;
        }

        if seen.len() < self.patterns.len() {
            seen.resize(self.patterns.len(), 0);
        }

        for found in ac.find_overlapping_iter(haystack) {
            let Some(patterns) = self.fragment_to_patterns.get(found.pattern().as_usize()) else {
                continue;
            };
            for &pattern_index in patterns {
                if is_seen(seen, pattern_index, generation) {
                    continue;
                }
                let Some(pattern) = self.patterns.get(pattern_index as usize) else {
                    continue;
                };
                if pattern_matches(haystack, found.start(), pattern) {
                    mark_seen(seen, pattern_index, generation);
                    out.push(pattern.rule_id);
                }
            }
        }
    }

    /// Number of patterns, used by callers to size a `seen` buffer.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

/// Returns `true` when `pattern` has already been recorded this generation.
fn is_seen(seen: &[u32], index: u32, generation: u32) -> bool {
    seen.get(index as usize).copied() == Some(generation)
}

/// Records `pattern` as seen for this generation.
fn mark_seen(seen: &mut [u32], index: u32, generation: u32) {
    if let Some(slot) = seen.get_mut(index as usize) {
        *slot = generation;
    }
}

/// Verifies that a pattern truly matches at `start` within `haystack`.
///
/// Fragments must appear in order and without overlap, and any anchor flags
/// must be satisfied. Because a failed verification at one start position
/// cannot be rescued by a later start position, a single forward walk is
/// enough — this is what keeps wildcard matching linear.
fn pattern_matches(haystack: &str, start: usize, pattern: &FragmentPattern) -> bool {
    if pattern.fragments.is_empty() {
        return false;
    }

    if pattern.start_anchored && start != 0 {
        return false;
    }

    let mut cursor = start;
    let mut first = true;
    for fragment in &pattern.fragments {
        if fragment.is_empty() {
            first = false;
            continue;
        }

        if first {
            // The automaton found this fragment exactly at `start`.
            if !haystack[start..].starts_with(fragment.as_str()) {
                return false;
            }
            cursor = start + fragment.len();
            first = false;
            continue;
        }

        // Fragments between wildcards: search forward from the cursor.
        // Adjacency is allowed; overlap is not.
        let Some(offset) = haystack[cursor..].find(fragment.as_str()) else {
            return false;
        };
        cursor += offset + fragment.len();
    }

    if pattern.end_anchored && cursor != haystack.len() {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    fn single(rule_id: u32, fragment: &str) -> FragmentPattern {
        FragmentPattern {
            rule_id,
            fragments: smallvec![fragment.to_owned()],
            leading_wildcard: true,
            trailing_wildcard: true,
            start_anchored: false,
            end_anchored: false,
        }
    }

    fn index(patterns: Vec<FragmentPattern>) -> SubstringIndex {
        let mut idx = SubstringIndex::new();
        for p in patterns {
            idx.add(p);
        }
        idx.build();
        idx
    }

    fn scan_sorted(idx: &SubstringIndex, haystack: &str) -> Vec<u32> {
        let mut seen = Vec::new();
        let mut out = Vec::new();
        idx.scan(haystack, &mut seen, 1, &mut out);
        out.sort_unstable();
        out.dedup();
        out
    }

    #[test]
    fn matches_plain_substring() {
        let idx = index(vec![single(1, "banner.gif")]);
        assert_eq!(scan_sorted(&idx, "http://x.com/banner.gif"), vec![1]);
        assert!(scan_sorted(&idx, "http://x.com/other.png").is_empty());
    }

    #[test]
    fn matches_multiple_patterns_simultaneously() {
        let idx = index(vec![
            single(1, "banner"),
            single(2, "ads"),
            single(3, "tracker"),
        ]);
        assert_eq!(scan_sorted(&idx, "http://x.com/ads/banner"), vec![1, 2]);
        assert_eq!(scan_sorted(&idx, "http://x.com/tracker/1"), vec![3]);
    }

    #[test]
    fn wildcard_requires_fragments_in_order() {
        let mut idx = SubstringIndex::new();
        idx.add(FragmentPattern {
            rule_id: 5,
            fragments: smallvec!["ad".to_owned(), "banner".to_owned()],
            leading_wildcard: true,
            trailing_wildcard: true,
            start_anchored: false,
            end_anchored: false,
        });
        idx.build();

        assert_eq!(scan_sorted(&idx, "/ad/x/banner"), vec![5]);
        assert_eq!(scan_sorted(&idx, "/ad/banner"), vec![5]);
        // Out of order must not match.
        assert!(scan_sorted(&idx, "/banner/x/ad").is_empty());
    }

    #[test]
    fn start_anchor_is_enforced() {
        let mut idx = SubstringIndex::new();
        idx.add(FragmentPattern {
            rule_id: 6,
            fragments: smallvec!["http://ads.".to_owned()],
            leading_wildcard: false,
            trailing_wildcard: true,
            start_anchored: true,
            end_anchored: false,
        });
        idx.build();

        assert_eq!(scan_sorted(&idx, "http://ads.com/x"), vec![6]);
        assert!(scan_sorted(&idx, "http://x.com/ads.").is_empty());
    }

    #[test]
    fn end_anchor_is_enforced() {
        let mut idx = SubstringIndex::new();
        idx.add(FragmentPattern {
            rule_id: 7,
            fragments: smallvec!["banner.gif".to_owned()],
            leading_wildcard: true,
            trailing_wildcard: false,
            start_anchored: false,
            end_anchored: true,
        });
        idx.build();

        assert_eq!(scan_sorted(&idx, "/x/banner.gif"), vec![7]);
        assert!(scan_sorted(&idx, "/x/banner.gif?q=1").is_empty());
    }

    #[test]
    fn duplicate_matches_are_suppressed() {
        let idx = index(vec![single(1, "ad")]);
        // "adadad" would otherwise report the same rule three times.
        let mut seen = Vec::new();
        let mut out = Vec::new();
        idx.scan("adadad", &mut seen, 1, &mut out);
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn repeated_scans_use_independent_generations() {
        let idx = index(vec![single(1, "ad")]);
        let mut seen = Vec::new();
        let mut out = Vec::new();

        idx.scan("ad", &mut seen, 1, &mut out);
        assert_eq!(out.len(), 1);

        out.clear();
        idx.scan("ad", &mut seen, 2, &mut out);
        assert_eq!(out.len(), 1, "second scan must still report the match");
    }

    #[test]
    fn empty_index_is_safe() {
        let idx = index(vec![]);
        assert!(idx.is_empty());
        assert!(scan_sorted(&idx, "anything").is_empty());
    }

    #[test]
    fn empty_fragments_are_ignored_not_panicking() {
        let idx = index(vec![FragmentPattern {
            rule_id: 1,
            fragments: smallvec!["".to_owned(), "ad".to_owned()],
            leading_wildcard: false,
            trailing_wildcard: false,
            start_anchored: false,
            end_anchored: false,
        }]);
        assert_eq!(scan_sorted(&idx, "/ad/"), vec![1]);
    }

    #[test]
    fn overlapping_fragment_sharing_is_deduplicated() {
        let idx = index(vec![single(1, "ad"), single(2, "ad")]);
        assert_eq!(idx.distinct_fragments(), 1);
        assert_eq!(scan_sorted(&idx, "/ad"), vec![1, 2]);
    }
}
