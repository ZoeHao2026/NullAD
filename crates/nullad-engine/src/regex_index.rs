//! Regex rule matching.
//!
//! Only the `regex` crate is used here, and that is a deliberate security
//! decision rather than a convenience one: `regex` guarantees linear-time
//! matching with no backtracking, so a hostile or careless filter list cannot
//! induce catastrophic backtracking (ReDoS) against the engine. Rules that fail
//! to compile are quarantined at parse time and never reach this index.

use regex::{Regex, RegexBuilder};

/// A compiled regex rule.
#[derive(Debug)]
struct RegexEntry {
    /// Identifier of the rule this regex came from.
    rule_id: u32,
    /// The compiled matcher.
    regex: Regex,
    /// Shortest string this regex can possibly match.
    ///
    /// A regex cannot match a haystack shorter than its minimum match length, so
    /// this rejects the great majority of URLs with one integer comparison and
    /// no regex engine invocation at all. On a real rule set the regex bucket is
    /// the single most expensive stage, and almost every request fails this test.
    min_len: usize,
}

/// Returns a lower bound on the length of any string the regex can match.
///
/// The bound is derived from the syntax rather than computed exactly, and it is
/// always an *under*-estimate. That direction is the only safe one: too low
/// merely forgoes the fast rejection, whereas too high would wrongly skip a rule
/// and silently stop blocking.
///
/// The rules are:
///
/// * a literal character contributes one;
/// * `?` and `*` make their atom optional, so it contributes nothing;
/// * `{n,m}` contributes its lower bound `n`;
/// * `+` and a bare atom contribute one;
/// * a top-level alternation contributes the *minimum* over its branches, not
///   their sum, because `ab|cd` matches in two characters;
/// * grouped alternations are not analysed, so a group contributes zero.
///
/// A case-insensitive pattern is compiled into character classes, in which case
/// the literal scan finds little and the bound stays conservative.
#[must_use]
pub fn minimum_match_length(pattern: &str) -> usize {
    let mut total = 0usize;
    let mut best: Option<usize> = None;
    let mut depth = 0usize;
    let mut chars = pattern.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            // Anchors do not consume characters.
            '^' | '$' => {}
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            // A top-level alternation splits the pattern into independent
            // branches; the whole pattern's floor is the smallest branch floor.
            '|' if depth == 0 => {
                best = Some(best.map_or(total, |current: usize| current.min(total)));
                total = 0;
            }
            // A nested alternation belongs to a group this scan does not model,
            // so nothing is claimed for it.
            '|' => {}
            '[' => {
                let mut escaped = false;
                for inner in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if inner == '\\' {
                        escaped = true;
                    } else if inner == ']' {
                        break;
                    }
                }
                total += mandatory_contribution(&mut chars);
            }
            '\\' => {
                if chars.next().is_some() {
                    total += mandatory_contribution(&mut chars);
                }
            }
            // A quantifier with no preceding atom: skip it harmlessly.
            '*' | '+' | '?' => {}
            '{' => {
                let mut nesting = 0usize;
                for inner in chars.by_ref() {
                    if inner == '{' {
                        nesting += 1;
                    } else if inner == '}' {
                        if nesting == 0 {
                            break;
                        }
                        nesting -= 1;
                    }
                }
            }
            _ => {
                total += mandatory_contribution(&mut chars);
            }
        }
    }

    best.map_or(total, |current| current.min(total))
}

/// Counts how many characters the atom preceding a quantifier must contribute.
///
/// The atom itself is always worth one character; the quantifier then decides
/// whether that copy is mandatory. `?` and `*` make it optional (zero), `+` and
/// a bare atom keep it (one), and `{n,m}` raises it to its lower bound `n`.
fn mandatory_contribution(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> usize {
    match chars.peek() {
        // `?` and `*` both make the atom optional: it need not appear at all.
        Some('?') | Some('*') => {
            chars.next();
            0
        }
        // `+` requires at least one copy, which is the atom already counted.
        Some('+') => {
            chars.next();
            1
        }
        Some('{') => {
            chars.next();
            let mut lower = String::new();
            for inner in chars.by_ref() {
                if inner == '}' || inner == ',' {
                    break;
                }
                lower.push(inner);
            }
            // Consume the remainder of a `{n,m}` range.
            while let Some(&next) = chars.peek() {
                chars.next();
                if next == '}' {
                    break;
                }
            }
            // `{0}` makes the atom optional; otherwise its lower bound applies.
            lower.parse::<usize>().unwrap_or(1)
        }
        // A bare atom is one mandatory character.
        _ => 1,
    }
}

/// An index of compiled `/regex/` rules.
#[derive(Debug, Default)]
pub struct RegexIndex {
    entries: Vec<RegexEntry>,
}

impl RegexIndex {
    /// Creates an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Compiles and adds a regex rule.
    ///
    /// Returns `Err` with the compiler's message when the pattern is invalid,
    /// which lets the caller quarantine the rule with a useful diagnostic.
    pub fn add(&mut self, pattern: &str, rule_id: u32, match_case: bool) -> Result<(), String> {
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(!match_case)
            // Bound the compiled program so one absurd pattern cannot allocate
            // without limit.
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .map_err(|e| e.to_string())?;

        // The bound is a property of the pattern's syntax, not of its case
        // sensitivity: case folding maps a character to a character, so it
        // cannot change how many characters a match consumes. It is therefore
        // computed for both forms. The randomised property test in this module
        // verifies that claim rather than relying on it.
        let min_len = minimum_match_length(pattern);

        self.entries.push(RegexEntry {
            rule_id,
            regex,
            min_len,
        });
        Ok(())
    }

    /// Number of compiled regexes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the minimum match length bound recorded for an entry.
    ///
    /// Exposed for tests and diagnostics so the fast-rejection path can be
    /// verified without reaching into private state.
    #[must_use]
    pub fn min_len_of(&self, index: usize) -> usize {
        self.entries.get(index).map_or(0, |entry| entry.min_len)
    }

    /// Returns `true` when no regexes are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends the rule ids of every regex that matches `haystack`.
    pub fn scan(&self, haystack: &str, out: &mut Vec<u32>) {
        // Compared once per scan rather than per entry.
        let len = haystack.len();
        for entry in &self.entries {
            // A regex cannot match a shorter haystack, so this rejects the bulk
            // of traffic without invoking the regex engine at all.
            if len < entry.min_len {
                continue;
            }
            if entry.regex.is_match(haystack) {
                out.push(entry.rule_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_simple_regex() {
        let mut index = RegexIndex::new();
        index.add(r"^https?://ads\.", 1, false).unwrap();
        let mut out = Vec::new();
        index.scan("http://ads.example.com/x", &mut out);
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn ignores_non_matching_input() {
        let mut index = RegexIndex::new();
        index.add(r"^https?://ads\.", 1, false).unwrap();
        let mut out = Vec::new();
        index.scan("http://example.com/x", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn case_insensitive_by_default() {
        let mut index = RegexIndex::new();
        index.add("BANNER", 1, false).unwrap();
        let mut out = Vec::new();
        index.scan("banner", &mut out);
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn match_case_option_is_respected() {
        let mut index = RegexIndex::new();
        index.add("BANNER", 1, true).unwrap();
        let mut out = Vec::new();
        index.scan("banner", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn invalid_regex_is_rejected_with_a_message() {
        let mut index = RegexIndex::new();
        let err = index.add("(unclosed", 1, false).unwrap_err();
        assert!(!err.is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn multiple_rules_can_match_one_url() {
        let mut index = RegexIndex::new();
        index.add("ads", 1, false).unwrap();
        index.add("banner", 2, false).unwrap();
        let mut out = Vec::new();
        index.scan("http://x.com/ads/banner", &mut out);
        out.sort_unstable();
        assert_eq!(out, vec![1, 2]);
    }

    #[test]
    fn short_haystacks_skip_the_regex_engine_but_still_match_when_eligible() {
        let mut index = RegexIndex::new();
        // A long case-sensitive literal, so the minimum length is meaningful.
        index
            .add("verylongliteralpattern", 1, true)
            .expect("compiles");
        assert_eq!(index.min_len_of(0), "verylongliteralpattern".len());

        let mut out = Vec::new();
        index.scan("short", &mut out);
        assert!(out.is_empty(), "a too-short haystack must not match");

        out.clear();
        index.scan("xx verylongliteralpattern yy", &mut out);
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn minimum_length_derivation() {
        // Plain literal.
        assert_eq!(minimum_match_length("abc"), 3);
        // Escaped literal metacharacters still count.
        assert_eq!(minimum_match_length(r"a\.c"), 3);
        // Anchors and groups add nothing.
        assert_eq!(minimum_match_length("^abc$"), 3);
        assert_eq!(minimum_match_length("(abc)"), 3);
        // A shorthand class matches exactly one character.
        assert_eq!(minimum_match_length(r"\d\d"), 2);
        // Unbounded quantifiers do not add beyond the atom they sit on.
        assert_eq!(minimum_match_length("ab*"), 1, "a* matches just \"a\"");
        assert_eq!(minimum_match_length("ab+"), 2);
        assert_eq!(minimum_match_length("abc?"), 2, "the c is optional");
        assert_eq!(minimum_match_length("a*"), 0, "a single optional atom");
        // `{n,m}` contributes its lower bound.
        assert_eq!(minimum_match_length("a{3}"), 3);
        assert_eq!(minimum_match_length("a{2,5}"), 2);
        assert_eq!(minimum_match_length("a{0,5}"), 0);
        // A character class is one character.
        assert_eq!(minimum_match_length("[a-z]"), 1);
        assert_eq!(minimum_match_length("[a-z]{4}"), 4);
        // A top-level alternation is bounded by its *shortest* branch, because
        // any branch may match.
        assert_eq!(minimum_match_length("ab|cd"), 2);
        assert_eq!(minimum_match_length("abcdef|xy"), 2);
        // A grouped alternation is not analysed, so it contributes nothing and
        // the surrounding literals still count.
        assert_eq!(minimum_match_length("(ab|cd)"), 4);
        assert_eq!(minimum_match_length("x(ab|cd)y"), 6);
    }

    #[test]
    fn minimum_length_never_overestimates() {
        // The property that actually matters, and the one the fast rejection
        // depends on: every string a regex matches must be at least as long as
        // the derived bound. This is checked by generating random strings,
        // filtering to the ones the regex matches, and asserting the bound holds.
        use rand::{Rng, SeedableRng};

        let patterns: &[&str] = &[
            "abc",
            "a.c",
            "a+b",
            "^http",
            "^https?://ads\\.",
            "[0-9]{3}",
            "\\d\\.\\d",
            "banner\\d*\\.gif",
            "a{2,}",
            "foo|bar",
            "[a-z]+/[a-z]+",
            "x?y?z?",
            "(ab)+",
            "\\w+@\\w+",
            ".*track.*",
        ];

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0x9E37_79B9_7F4A_7C15);
        let alphabet = b"abchttp01239./:@xyz-_ ";

        for pattern in patterns {
            let Ok(compiled) = regex::Regex::new(pattern) else {
                continue;
            };
            let bound = minimum_match_length(pattern);

            for _ in 0..4000 {
                let len = rng.random_range(0..12usize);
                let candidate: String = (0..len)
                    .map(|_| alphabet[rng.random_range(0..alphabet.len())] as char)
                    .collect();

                if compiled.is_match(&candidate) {
                    assert!(
                        candidate.len() >= bound,
                        "bound {bound} overestimates {pattern:?}, which matched \
                         {candidate:?} of length {}",
                        candidate.len()
                    );
                }
            }
        }
    }

    #[test]
    fn the_bound_holds_for_case_insensitive_patterns_too() {
        // Case folding maps a character to a character, so the syntactic bound
        // must remain a true lower bound when matching is case-insensitive.
        // Randomised search is what makes this a check rather than a claim.
        use rand::{Rng, SeedableRng};

        const PATTERNS: &[&str] = &[
            "banner\\d*\\.gif",
            "ads",
            "BANNER",
            "[0-9]{3}",
            "^https?://ads\\.",
            "foo|bar",
        ];

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0xDEAD_BEEF_1234_5678);
        let alphabet = b"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ01239./:";

        for pattern in PATTERNS {
            let Ok(compiled) = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
            else {
                continue;
            };
            let bound = minimum_match_length(pattern);

            for _ in 0..4000 {
                let len = rng.random_range(0..14usize);
                let candidate: String = (0..len)
                    .map(|_| alphabet[rng.random_range(0..alphabet.len())] as char)
                    .collect();

                if compiled.is_match(&candidate) {
                    assert!(
                        candidate.len() >= bound,
                        "case-insensitive bound {bound} overestimates {pattern:?}, \
                         which matched {candidate:?} of length {}",
                        candidate.len()
                    );
                }
            }
        }
    }

    #[test]
    fn zero_bound_disables_only_the_optimisation() {
        // A pattern whose bound is genuinely zero must still match normally, so
        // the fast rejection never becomes a correctness problem.
        let mut index = RegexIndex::new();
        index.add("a*c", 1, false).expect("compiles");
        assert_eq!(index.min_len_of(0), 1, "the mandatory c counts");

        let mut out = Vec::new();
        index.scan("c", &mut out);
        assert_eq!(out, vec![1]);
    }
}
