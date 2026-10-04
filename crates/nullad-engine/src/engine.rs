//! The compiled rule set, its builder, and the matching engine.

use std::sync::Arc;

use arc_swap::ArcSwap;
use smallvec::SmallVec;

use crate::domain_trie::DomainTrie;
use crate::error::EngineError;
use crate::parser::{ParseStats, RuleParser};
use crate::regex_index::RegexIndex;
use crate::request::Request;
use crate::rule::{Action, Rule, RulePattern};
use crate::stats::{EngineStats, StatsSnapshot};
use crate::substring_index::{FragmentPattern, SubstringIndex};

/// Why a request was allowed or blocked, and by which rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// Whether the request should be blocked.
    pub blocked: bool,
    /// The rule that decided the outcome, when a rule matched.
    pub matched_rule: Option<Arc<Rule>>,
    /// Indexes of every rule that matched, in ascending order.
    pub matched_rule_ids: SmallVec<[u32; 4]>,
}

impl CheckResult {
    /// A result with no matching rule: the request is allowed.
    #[must_use]
    pub fn no_match() -> Self {
        Self {
            blocked: false,
            matched_rule: None,
            matched_rule_ids: SmallVec::new(),
        }
    }

    /// Returns `true` when the request is blocked.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Returns `true` when an exception rule produced this outcome.
    #[must_use]
    pub fn is_exception(&self) -> bool {
        !self.blocked
            && self
                .matched_rule
                .as_ref()
                .is_some_and(|rule| rule.action.is_allow())
    }
}

/// Per-thread scratch buffers reused across matches.
///
/// Reusing these is what keeps matching allocation-free in steady state. Each
/// connection or worker owns one and passes it in; the engine itself holds no
/// mutable state, which is why `RuleSet` can be shared across threads freely.
#[derive(Debug, Default)]
pub struct MatchScratch {
    candidates: Vec<u32>,
    seen_rule: Vec<u32>,
    seen_substring: Vec<u32>,
    seen_sensitive_substring: Vec<u32>,
    generation: u32,
    lowered_url: String,
}

impl MatchScratch {
    /// Creates empty scratch buffers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bumps the per-check generation, clearing stamps if it ever wraps.
    fn next_generation(&mut self, rule_count: usize) {
        if self.seen_rule.len() < rule_count {
            self.seen_rule.resize(rule_count, 0);
        }
        let next = self.generation.wrapping_add(1);
        if next == 0 {
            self.seen_rule.fill(0);
            self.seen_substring.fill(0);
            self.seen_sensitive_substring.fill(0);
            self.generation = 1;
        } else {
            self.generation = next;
        }
    }

    /// Returns `true` when the rule was already evaluated this check.
    fn already_seen(&self, rule_id: u32) -> bool {
        self.seen_rule.get(rule_id as usize).copied() == Some(self.generation)
    }

    /// Marks a rule as evaluated for this check.
    fn mark_seen(&mut self, rule_id: u32) {
        if let Some(slot) = self.seen_rule.get_mut(rule_id as usize) {
            *slot = self.generation;
        }
    }
}

/// Summary of what a rule set contains, for diagnostics and the GUI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSetStats {
    /// Total rules indexed.
    pub rules: usize,
    /// Rules using the domain-anchor index.
    pub domain_rules: usize,
    /// Rules anchoring on a domain *and* a path.
    pub domain_path_rules: usize,
    /// Rules using the substring or wildcard index.
    pub fragment_rules: usize,
    /// Rules using the regex index.
    pub regex_rules: usize,
    /// Option-only rules that match every URL.
    pub options_only_rules: usize,
    /// Nodes allocated in the domain trie.
    pub trie_nodes: usize,
    /// Distinct automaton fragments in the substring index.
    pub distinct_fragments: usize,
}

/// An immutable, fully indexed set of rules.
///
/// Cheap to share: wrap it in an `Arc` and hand it to as many threads as you
/// like. Replacing a rule set is a single atomic pointer store, which is how
/// `NullAD` achieves hot reloads with zero dropped or blocked requests.
#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<Arc<Rule>>,
    domains: DomainTrie,
    substrings: SubstringIndex,
    sensitive_substrings: SubstringIndex,
    regexes: RegexIndex,
    /// Rule ids with no literal pattern, evaluated on every request. Expected
    /// to be empty or near-empty in practice.
    always_candidates: Vec<u32>,
    stats: RuleSetStats,
}

impl RuleSet {
    /// Returns the number of rules in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` when the set contains no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns structural statistics about the set.
    #[must_use]
    pub fn stats(&self) -> &RuleSetStats {
        &self.stats
    }

    /// Returns the rule at `index`.
    #[must_use]
    pub fn rule(&self, index: u32) -> Option<&Arc<Rule>> {
        self.rules.get(index as usize)
    }

    /// Returns an iterator over all rules.
    pub fn rules(&self) -> impl Iterator<Item = &Arc<Rule>> {
        self.rules.iter()
    }

    /// Returns the domain-anchor index.
    ///
    /// Exposed so diagnostics and benchmarks can measure each matching stage in
    /// isolation rather than inferring cost from whole-request timings.
    #[must_use]
    pub fn domains(&self) -> &DomainTrie {
        &self.domains
    }

    /// Returns the substring and wildcard index.
    #[must_use]
    pub fn substrings(&self) -> &SubstringIndex {
        &self.substrings
    }

    /// Returns the regex index.
    #[must_use]
    pub fn regexes(&self) -> &RegexIndex {
        &self.regexes
    }

    /// Evaluates a request against this rule set.
    ///
    /// Semantics follow Adblock Plus: exception (`@@`) rules win over block
    /// rules, except that a block rule carrying `$important` overrides a
    /// non-important exception.
    #[must_use]
    pub fn check(&self, request: &Request, scratch: &mut MatchScratch) -> CheckResult {
        if self.rules.is_empty() {
            return CheckResult::no_match();
        }

        scratch.next_generation(self.rules.len());

        // Normalise the URL once, avoiding the copy entirely when it is already
        // lowercase — which is the overwhelming majority of real traffic. This
        // is the single largest cost in the matching path, so skipping it is
        // worth the two branches.
        let url: &str =
            if request.url.is_ascii() && !request.url.bytes().any(|b| b.is_ascii_uppercase()) {
                &request.url
            } else {
                scratch.lowered_url.clear();
                scratch.lowered_url.push_str(&request.url);
                scratch.lowered_url.make_ascii_lowercase();
                &scratch.lowered_url
            };

        scratch.candidates.clear();

        // 1. Domain-anchor index: one trie walk.
        self.domains.lookup(&request.host, &mut scratch.candidates);

        // 2. Substring/wildcard index: one automaton pass over the URL.
        self.substrings.scan(
            url,
            &mut scratch.seen_substring,
            scratch.generation,
            &mut scratch.candidates,
        );

        // 3. Regex index: only the rules that needed a regex.
        self.sensitive_substrings.scan(
            &request.url,
            &mut scratch.seen_sensitive_substring,
            scratch.generation,
            &mut scratch.candidates,
        );
        self.regexes.scan(&request.url, &mut scratch.candidates);

        // 4. Option-only rules, which have no literal to index.
        scratch
            .candidates
            .extend_from_slice(&self.always_candidates);

        if scratch.candidates.is_empty() {
            return CheckResult::no_match();
        }

        // Resolution order is the whole point of this loop: an `$important`
        // block beats an exception, an exception beats a plain block, and a
        // plain block beats no match at all.
        //
        // The reported `matched_rule` is always the rule that actually decided
        // the outcome, never a merely-coincidental co-match. That matters: a
        // blocked request must always name the block rule that caused it.
        let mut matched: SmallVec<[u32; 4]> = SmallVec::new();
        let mut first_allow: Option<u32> = None;
        let mut first_important_block: Option<u32> = None;
        let mut first_plain_block: Option<u32> = None;

        for index in 0..scratch.candidates.len() {
            let rule_id = scratch.candidates[index];
            if scratch.already_seen(rule_id) {
                continue;
            }
            scratch.mark_seen(rule_id);

            let Some(rule) = self.rules.get(rule_id as usize) else {
                continue;
            };
            if !rule_eligible(rule, request) {
                continue;
            }

            matched.push(rule_id);

            match rule.action {
                Action::Allow => {
                    first_allow.get_or_insert(rule_id);
                }
                Action::Block => {
                    if rule.options.important {
                        first_important_block.get_or_insert(rule_id);
                    } else {
                        first_plain_block.get_or_insert(rule_id);
                    }
                }
            }
        }

        if matched.is_empty() {
            return CheckResult::no_match();
        }
        matched.sort_unstable();

        let (blocked, decided_by) = if let Some(important) = first_important_block {
            (true, Some(important))
        } else if let Some(allow) = first_allow {
            (false, Some(allow))
        } else if let Some(plain) = first_plain_block {
            (true, Some(plain))
        } else {
            // Candidates existed but none survived filtering. Cannot happen
            // given `matched` is non-empty, but resolve safely to "allow".
            (false, None)
        };

        CheckResult {
            blocked,
            matched_rule: decided_by
                .and_then(|id| self.rules.get(id as usize))
                .cloned(),
            matched_rule_ids: matched,
        }
    }
}

/// Returns `true` when a rule's type, page, party, and structural constraints
/// are all satisfied by the request.
///
/// The structural check exists because the indexes are deliberately loose
/// pre-filters: a `||host/path` rule is registered in the host trie so it is
/// found cheaply, but its host and path halves are only truly verified here.
fn rule_eligible(rule: &Rule, request: &Request) -> bool {
    if !rule.applies_to_type(request.resource_type)
        || !rule.applies_to_page(request.page_host.as_deref())
        || !rule.applies_to_party(request.third_party)
    {
        return false;
    }

    match &rule.pattern {
        RulePattern::DomainPath {
            domain,
            fragments,
            trailing_wildcard,
            trailing_separator,
            ..
        } => domain_path_matches(
            request,
            domain,
            fragments,
            *trailing_wildcard,
            *trailing_separator,
            rule.options.match_case,
        ),
        _ => true,
    }
}

/// Verifies a `||host/path` rule against a request.
///
/// The path fragments are matched against the URL text that begins immediately
/// after the host, so `||example.com/path` matches `example.com/path` and
/// `example.com/path/x` but not `example.com/pathology`.
fn domain_path_matches(
    request: &Request,
    domain: &str,
    fragments: &[String],
    trailing_wildcard: bool,
    trailing_separator: bool,
    match_case: bool,
) -> bool {
    use crate::rule::domain_suffix_match;

    if request.host.is_empty() || !domain_suffix_match(&request.host, domain) {
        return false;
    }

    // Locate the host inside the URL so the path can be taken from there.
    // Host matching is case-insensitive because hosts are normalised.
    let lowered = request.url.to_ascii_lowercase();
    let Some(host_pos) = lowered.find(request.host.as_str()) else {
        return false;
    };
    let url = if match_case {
        request.url.as_str()
    } else {
        &lowered
    };
    let after_host = &url[host_pos + request.host.len()..];

    // Skip an explicit port so `example.com:8080/path` still matches.
    let path = match after_host.strip_prefix(':') {
        Some(rest) => match rest.find('/') {
            Some(slash) => &rest[slash..],
            None => "",
        },
        None => after_host,
    };

    let mut cursor = 0usize;
    for fragment in fragments {
        if fragment.is_empty() {
            continue;
        }
        match path[cursor..].find(fragment.as_str()) {
            Some(offset) => cursor += offset + fragment.len(),
            None => return false,
        }
    }

    if trailing_separator {
        // A `^` separator: the pattern must be followed by the end of the URL
        // or by a character that cannot appear in a domain or a word.
        return path[cursor..].chars().next().is_none_or(is_separator);
    }

    if !trailing_wildcard && cursor != path.len() {
        return false;
    }

    true
}

/// Returns `true` for the characters Adblock Plus treats as `^` separators.
fn is_separator(ch: char) -> bool {
    !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '%'))
}

/// Incrementally builds a [`RuleSet`].
///
/// Rules are added in parse order; the index structures are constructed on
/// [`Self::build`] so that a large list pays for index construction exactly
/// once.
#[derive(Debug)]
pub struct RuleSetBuilder {
    accumulated: Vec<Arc<Rule>>,
    next_list_id: u32,
}

impl Default for RuleSetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleSetBuilder {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accumulated: Vec::new(),
            next_list_id: 0,
        }
    }

    /// Creates a builder with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(rules: usize) -> Self {
        Self {
            accumulated: Vec::with_capacity(rules),
            next_list_id: 0,
        }
    }

    /// Number of rules accumulated so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accumulated.len()
    }

    /// Returns `true` when no rules have been accumulated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accumulated.is_empty()
    }

    /// Parses and appends an entire filter list.
    ///
    /// Malformed rules are quarantined and reported in the returned stats; they
    /// never abort the load.
    pub fn add_list(&mut self, source: &str, list_id: u32) -> ParseStats {
        let parser = RuleParser::new().list_id(list_id);
        let (rules, stats) = parser.parse_list(source);
        self.accumulated.extend(rules.into_iter().map(Arc::new));
        stats
    }

    /// Parses and appends a list using the next automatic list id.
    pub fn add_list_auto(&mut self, source: &str) -> ParseStats {
        let id = self.next_list_id;
        self.next_list_id = self.next_list_id.saturating_add(1);
        self.add_list(source, id)
    }

    /// Appends a single already-parsed rule.
    pub fn add_rule(&mut self, rule: Rule) {
        self.accumulated.push(Arc::new(rule));
    }

    /// Appends many already-parsed rules.
    pub fn add_rules(&mut self, rules: impl IntoIterator<Item = Rule>) {
        self.accumulated.extend(rules.into_iter().map(Arc::new));
    }

    /// Computes rule-set structure statistics without consuming the builder.
    ///
    /// This mirrors what [`Self::build`] reports, so a tool can show the
    /// structure of a rule set before deciding whether to build it.
    #[must_use]
    pub fn stats(&self) -> RuleSetStats {
        let mut stats = RuleSetStats {
            rules: self.accumulated.len(),
            ..RuleSetStats::default()
        };
        for rule in &self.accumulated {
            match &rule.pattern {
                RulePattern::DomainAnchor { .. } => stats.domain_rules += 1,
                RulePattern::DomainPath { .. } => stats.domain_path_rules += 1,
                RulePattern::Substring(_) => {
                    stats.fragment_rules += 1;
                }
                RulePattern::Wildcard { .. } => stats.fragment_rules += 1,
                RulePattern::Regex(_) => stats.regex_rules += 1,
                RulePattern::OptionsOnly => stats.options_only_rules += 1,
            }
        }
        stats
    }

    /// Consumes the builder and produces an immutable, indexed rule set.
    ///
    /// Returns [`EngineError::NoUsableRules`] when nothing was accumulated, so
    /// that a caller cannot accidentally install an empty rule set and silently
    /// stop blocking.
    pub fn build(self) -> Result<RuleSet, EngineError> {
        if self.accumulated.is_empty() {
            // Per-rule failures are reported by `add_list`, which returns the
            // parse statistics for each list. At this point the only fact worth
            // stating is that nothing usable was produced.
            return Err(EngineError::NoUsableRules {
                accepted: 0,
                total: 0,
                failures: 0,
            });
        }

        let rules = self.accumulated;
        let mut stats = RuleSetStats {
            rules: rules.len(),
            ..RuleSetStats::default()
        };

        let mut domains = DomainTrie::new();
        let mut substrings = SubstringIndex::new();
        let mut sensitive_substrings = SubstringIndex::case_sensitive();
        let mut regexes = RegexIndex::new();
        let mut always_candidates: Vec<u32> = Vec::new();

        for (index, rule) in rules.iter().enumerate() {
            let rule_id = u32::try_from(index).unwrap_or(u32::MAX);
            let substring_index = if rule.options.match_case {
                &mut sensitive_substrings
            } else {
                &mut substrings
            };
            match &rule.pattern {
                RulePattern::DomainAnchor { domain, .. } => {
                    domains.insert(domain, rule_id);
                    stats.domain_rules += 1;
                }
                RulePattern::DomainPath {
                    domain,
                    fragments,
                    trailing_wildcard,
                    ..
                } => {
                    // Two indexes are needed: the trie finds candidate hosts,
                    // and the fragment automaton finds the path text. The
                    // runtime re-verifies both together, so registering the
                    // host here is only a cheap pre-filter.
                    domains.insert(domain, rule_id);
                    substring_index.add(FragmentPattern {
                        rule_id,
                        fragments: fragments.clone(),
                        leading_wildcard: true,
                        trailing_wildcard: *trailing_wildcard,
                        start_anchored: false,
                        end_anchored: false,
                    });
                    stats.domain_path_rules += 1;
                }
                RulePattern::Substring(text) => {
                    substring_index.add(FragmentPattern {
                        rule_id,
                        fragments: smallvec::smallvec![text.clone()],
                        leading_wildcard: true,
                        trailing_wildcard: true,
                        start_anchored: false,
                        end_anchored: false,
                    });
                    stats.fragment_rules += 1;
                }
                RulePattern::Wildcard {
                    fragments,
                    leading_wildcard,
                    trailing_wildcard,
                    start_anchored,
                    end_anchored,
                } => {
                    substring_index.add(FragmentPattern {
                        rule_id,
                        fragments: fragments.clone(),
                        leading_wildcard: *leading_wildcard,
                        trailing_wildcard: *trailing_wildcard,
                        start_anchored: *start_anchored,
                        end_anchored: *end_anchored,
                    });
                    stats.fragment_rules += 1;
                }
                RulePattern::Regex(pattern) => {
                    // A regex that compiled during parsing can still fail here
                    // under a tighter size limit. Quarantining it keeps the rest
                    // of the set usable.
                    if regexes
                        .add(pattern, rule_id, rule.options.match_case)
                        .is_ok()
                    {
                        stats.regex_rules += 1;
                    }
                }
                RulePattern::OptionsOnly => {
                    // A rule with no pattern, such as `$domain=example.com`.
                    // It has no literal to search for, so it cannot live in any
                    // of the text indexes; it is evaluated unconditionally on
                    // every request instead. Such rules are vanishingly rare in
                    // real lists, so the linear cost never materialises.
                    always_candidates.push(rule_id);
                    stats.options_only_rules += 1;
                }
            }
        }

        substrings.build();
        sensitive_substrings.build();
        stats.trie_nodes = domains.node_count();
        stats.distinct_fragments =
            substrings.distinct_fragments() + sensitive_substrings.distinct_fragments();

        Ok(RuleSet {
            rules,
            domains,
            substrings,
            sensitive_substrings,
            regexes,
            always_candidates,
            stats,
        })
    }
}

/// A background reclaimer for superseded rule sets.
///
/// Replacing a rule set is an atomic pointer store, but *dropping* the old set
/// is not free: tearing down a large trie and automaton costs tens of
/// milliseconds. Doing that on the thread that performed the swap would make a
/// hot reload pause its caller for that whole duration, which defeats the point
/// of a lock-free swap.
///
/// Superseded sets are therefore handed to one shared background thread, which
/// makes swap latency bounded by the pointer store alone. If that thread ever
/// fell behind, memory could grow without bound, so at most
/// [`reclaim::MAX_BACKLOG`] sets may queue; beyond that the send fails and the
/// set is dropped inline rather than accumulated.
mod reclaim {
    use std::sync::mpsc::{self, SyncSender, TrySendError};
    use std::sync::{Arc, OnceLock};

    use super::RuleSet;

    /// How many superseded rule sets may queue before inline dropping resumes.
    pub const MAX_BACKLOG: usize = 4;

    /// A cloneable handle onto the shared reclaimer.
    #[derive(Debug)]
    pub struct Reclaimer {
        sender: SyncSender<Arc<RuleSet>>,
    }

    /// The process-wide reclaimer instance.
    static INSTANCE: OnceLock<Reclaimer> = OnceLock::new();

    impl Reclaimer {
        /// Returns the shared reclaimer, starting its thread on first use.
        pub fn shared() -> Self {
            let sender = INSTANCE
                .get_or_init(|| {
                    let (sender, receiver) = mpsc::sync_channel::<Arc<RuleSet>>(MAX_BACKLOG);
                    let spawned = std::thread::Builder::new()
                        .name("nullad-reclaim".into())
                        .spawn(move || {
                            // Receiving and dropping is the entire job.
                            while receiver.recv().is_ok() {}
                        });
                    if let Err(err) = spawned {
                        // Without the thread the channel would never drain, so
                        // callers are told to drop inline instead: `try_send`
                        // on a disconnected channel fails, which produces
                        // exactly that fallback.
                        tracing_free_note(err);
                    }
                    Reclaimer { sender }
                })
                .clone();
            sender
        }

        /// Hands a superseded rule set to the reclaimer.
        ///
        /// Returns `false` when the backlog is full, in which case the caller
        /// drops the set inline. That keeps memory bounded at the cost of an
        /// occasional slow swap, which is the right trade.
        #[must_use]
        pub fn reclaim(&self, rule_set: Arc<RuleSet>) -> bool {
            match self.sender.try_send(rule_set) {
                Ok(()) => true,
                Err(TrySendError::Full(rule_set)) => {
                    drop(rule_set);
                    false
                }
                Err(TrySendError::Disconnected(rule_set)) => {
                    drop(rule_set);
                    false
                }
            }
        }
    }

    impl Clone for Reclaimer {
        fn clone(&self) -> Self {
            Self {
                sender: self.sender.clone(),
            }
        }
    }

    /// Reports a failure to start the reclaimer thread.
    ///
    /// The engine has no logging dependency by design, so this writes to stderr
    /// once. A missing reclaimer degrades performance, never correctness.
    fn tracing_free_note(err: std::io::Error) {
        eprintln!(
            "nullad-engine: could not start the rule reclaim thread ({err}); \
             superseded rule sets will be freed inline, which makes hot reload \
             slower but remains correct"
        );
    }
}

/// The matching engine, with hot-swappable rule sets.
///
/// Cloning is not supported: share one engine behind an `Arc`. All matching
/// state lives in the caller's [`MatchScratch`], so any number of threads can
/// query the engine concurrently.
#[derive(Debug)]
pub struct FilterEngine {
    active: ArcSwap<RuleSet>,
    stats: EngineStats,
    reclaimer: reclaim::Reclaimer,
}

impl Default for FilterEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterEngine {
    /// Creates an engine with an empty rule set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: ArcSwap::from_pointee(RuleSet {
                rules: Vec::new(),
                domains: DomainTrie::new(),
                substrings: SubstringIndex::new(),
                sensitive_substrings: SubstringIndex::case_sensitive(),
                regexes: RegexIndex::new(),
                always_candidates: Vec::new(),
                stats: RuleSetStats::default(),
            }),
            stats: EngineStats::new(),
            reclaimer: reclaim::Reclaimer::shared(),
        }
    }

    /// Creates an engine from an already-built rule set.
    #[must_use]
    pub fn from_rule_set(rule_set: RuleSet) -> Self {
        let count = rule_set.len();
        let engine = Self {
            active: ArcSwap::from_pointee(rule_set),
            stats: EngineStats::new(),
            reclaimer: reclaim::Reclaimer::shared(),
        };
        engine.stats.record_rules_loaded(count);
        engine
    }

    /// Atomically replaces the active rule set.
    ///
    /// Readers keep using the previous set until they finish, so a swap never
    /// blocks, drops, or mis-answers an in-flight request. The superseded set is
    /// freed on a background thread, so this call's cost is the atomic store
    /// plus a bounded channel send — not the teardown of the old rule set.
    pub fn swap(&self, rule_set: RuleSet) {
        self.swap_shared(Arc::new(rule_set));
    }

    /// Atomically replaces the active rule set from a shared handle.
    ///
    /// Use this when the caller already holds the compiled set behind an `Arc`,
    /// which avoids a second allocation and lets several components refer to the
    /// same immutable rule set.
    pub fn swap_shared(&self, rule_set: Arc<RuleSet>) {
        let count = rule_set.len();
        // Holding the previous set explicitly is what lets it be handed to the
        // reclaimer; letting `store` drop it internally would do the teardown
        // right here on the caller's thread.
        let previous = self.active.swap(rule_set);
        self.stats.record_rules_loaded(count);
        self.stats.record_swap();

        if !previous.is_empty() {
            let _ = self.reclaimer.reclaim(previous);
        }
    }

    /// Returns a snapshot handle to the active rule set.
    ///
    /// Holding the returned `Arc` keeps that set alive even if a swap happens
    /// immediately afterwards.
    #[must_use]
    pub fn rule_set(&self) -> Arc<RuleSet> {
        self.active.load_full()
    }

    /// Parses a list and installs it as the active rule set.
    ///
    /// This is the simple single-list entry point. For multi-list setups build
    /// a [`RuleSetBuilder`], add every list, then call [`Self::swap`].
    pub fn load_list(&mut self, source: &str) -> Result<ParseStats, EngineError> {
        let mut builder = RuleSetBuilder::new();
        let stats = builder.add_list_auto(source);
        let rule_set = builder.build()?;
        self.swap(rule_set);
        Ok(stats)
    }

    /// Evaluates a request, reusing the supplied scratch buffers.
    ///
    /// Prefer this in hot paths: it performs no allocation once `scratch` has
    /// grown to the working size.
    pub fn check_with(&self, request: &Request, scratch: &mut MatchScratch) -> CheckResult {
        let rule_set = self.active.load();
        let result = rule_set.check(request, scratch);
        self.stats.record(result.blocked, result.is_exception());
        result
    }

    /// Evaluates a request with an internally allocated scratch buffer.
    ///
    /// Convenient for one-off checks and tests. Hot paths should use
    /// [`Self::check_with`].
    pub fn check(&self, request: &Request) -> CheckResult {
        let mut scratch = MatchScratch::new();
        self.check_with(request, &mut scratch)
    }

    /// Evaluates many requests with one scratch buffer, returning the count
    /// that were blocked. Useful for benchmarks and bulk verification.
    pub fn check_many<'a, I>(&self, requests: I) -> usize
    where
        I: IntoIterator<Item = &'a Request>,
    {
        let mut scratch = MatchScratch::new();
        let mut blocked = 0;
        for request in requests {
            if self.check_with(request, &mut scratch).blocked {
                blocked += 1;
            }
        }
        blocked
    }

    /// Returns the shared statistics counters.
    #[must_use]
    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }

    /// Returns a serializable snapshot of the statistics.
    #[must_use]
    pub fn stats_snapshot(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Number of rules in the active set.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.active.load().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::ResourceType;

    fn engine_from(list: &str) -> FilterEngine {
        let mut builder = RuleSetBuilder::new();
        builder.add_list_auto(list);
        FilterEngine::from_rule_set(builder.build().expect("rule set"))
    }

    #[test]
    fn blocks_domain_anchor() {
        let engine = engine_from("||ads.example.com^");
        assert!(engine
            .check(&Request::new(
                "https://ads.example.com/banner.gif",
                ResourceType::Image
            ))
            .is_blocked());
    }

    #[test]
    fn allows_unrelated_host() {
        let engine = engine_from("||ads.example.com^");
        assert!(!engine
            .check(&Request::new("https://example.com/x", ResourceType::Image))
            .is_blocked());
    }

    #[test]
    fn exception_overrides_block() {
        let engine = engine_from("||ads.example.com^\n@@||ads.example.com/ok.js");
        let blocked = engine.check(&Request::new(
            "https://ads.example.com/banner.gif",
            ResourceType::Script,
        ));
        assert!(blocked.is_blocked());

        let allowed = engine.check(&Request::new(
            "https://ads.example.com/ok.js",
            ResourceType::Script,
        ));
        assert!(!allowed.is_blocked());
        assert!(allowed.is_exception());
    }

    #[test]
    fn important_block_beats_exception() {
        let engine = engine_from("||ads.example.com^$important\n@@||ads.example.com^");
        assert!(engine
            .check(&Request::new(
                "https://ads.example.com/x",
                ResourceType::Other
            ))
            .is_blocked());
    }

    #[test]
    fn resource_type_restriction_is_enforced() {
        let engine = engine_from("||ads.example.com^$image");
        assert!(engine
            .check(&Request::new(
                "https://ads.example.com/x.png",
                ResourceType::Image
            ))
            .is_blocked());
        assert!(!engine
            .check(&Request::new(
                "https://ads.example.com/x.js",
                ResourceType::Script
            ))
            .is_blocked());
    }

    #[test]
    fn domain_option_restricts_to_initiator() {
        let engine = engine_from("||ads.example.com^$domain=good.com");
        let on_good = Request::new("https://ads.example.com/x", ResourceType::Script)
            .with_page("https://good.com/page");
        assert!(engine.check(&on_good).is_blocked());

        let on_other = Request::new("https://ads.example.com/x", ResourceType::Script)
            .with_page("https://other.com/page");
        assert!(!engine.check(&on_other).is_blocked());
    }

    #[test]
    fn third_party_option_is_enforced() {
        let engine = engine_from("||tracker.com^$third-party");
        let third = Request::new("https://tracker.com/x", ResourceType::Script)
            .with_page("https://example.com/");
        assert!(engine.check(&third).is_blocked());

        let first = Request::new("https://tracker.com/x", ResourceType::Script)
            .with_page("https://tracker.com/");
        assert!(!engine.check(&first).is_blocked());
    }

    #[test]
    fn substring_rules_match_paths() {
        let engine = engine_from("/banner.gif");
        assert!(engine
            .check(&Request::new(
                "https://cdn.example.com/img/banner.gif",
                ResourceType::Image
            ))
            .is_blocked());
    }

    #[test]
    fn regex_rules_match() {
        let engine = engine_from(r"/^https?:\/\/ads\.[a-z]+\.com\//");
        assert!(engine
            .check(&Request::new("http://ads.foo.com/x", ResourceType::Other))
            .is_blocked());
        assert!(!engine
            .check(&Request::new("http://example.com/x", ResourceType::Other))
            .is_blocked());
    }

    #[test]
    fn hosts_file_rules_work() {
        let engine = engine_from("0.0.0.0 tracker.example.com");
        assert!(engine
            .check(&Request::new(
                "https://tracker.example.com/collect",
                ResourceType::Xhr
            ))
            .is_blocked());
    }

    #[test]
    fn stats_track_blocks_and_allows() {
        let engine = engine_from("||ads.com^");
        let _ = engine.check(&Request::new("https://ads.com/x", ResourceType::Other));
        let _ = engine.check(&Request::new("https://ok.com/x", ResourceType::Other));

        let snap = engine.stats_snapshot();
        assert_eq!(snap.queries, 2);
        assert_eq!(snap.blocked, 1);
        assert_eq!(snap.allowed, 1);
        assert_eq!(snap.no_match, 1);
    }

    #[test]
    fn hot_swap_replaces_rules_without_dropping_requests() {
        let engine = engine_from("||ads.com^");
        assert!(engine
            .check(&Request::new("https://ads.com/x", ResourceType::Other))
            .is_blocked());

        // Swap to a set that does not block the same host.
        let mut builder = RuleSetBuilder::new();
        builder.add_list_auto("||other.com^");
        engine.swap(builder.build().unwrap());

        assert!(!engine
            .check(&Request::new("https://ads.com/x", ResourceType::Other))
            .is_blocked());
        assert!(engine
            .check(&Request::new("https://other.com/x", ResourceType::Other))
            .is_blocked());
        // `rule_sets_swapped` counts hot reloads only. Constructing the engine
        // from an existing rule set is the initial load, not a swap, so exactly
        // one swap has occurred here.
        assert_eq!(engine.stats_snapshot().rule_sets_swapped, 1);
    }

    #[test]
    fn empty_rule_set_blocks_nothing() {
        let engine = FilterEngine::new();
        assert_eq!(engine.rule_count(), 0);
        assert!(!engine
            .check(&Request::new("https://ads.com/x", ResourceType::Other))
            .is_blocked());
    }

    #[test]
    fn building_from_nothing_is_an_error() {
        let builder = RuleSetBuilder::new();
        assert!(matches!(
            builder.build(),
            Err(EngineError::NoUsableRules { .. })
        ));
    }

    #[test]
    fn scratch_reuse_gives_identical_results() {
        let engine = engine_from("||ads.com^\n/banner.gif\n@@||ads.com/ok");
        let mut scratch = MatchScratch::new();

        let requests = [
            Request::new("https://ads.com/banner.gif", ResourceType::Image),
            Request::new("https://ads.com/ok", ResourceType::Image),
            Request::new("https://ok.com/x", ResourceType::Image),
        ];

        let first: Vec<bool> = requests
            .iter()
            .map(|r| engine.check_with(r, &mut scratch).blocked)
            .collect();

        // Repeat with the same scratch; results must be stable (this is the
        // regression test for the generation-stamp deduplication).
        for _ in 0..5 {
            let again: Vec<bool> = requests
                .iter()
                .map(|r| engine.check_with(r, &mut scratch).blocked)
                .collect();
            assert_eq!(first, again);
        }

        assert_eq!(first, vec![true, false, false]);
    }

    #[test]
    fn rule_set_stats_are_reported() {
        let engine = engine_from("||ads.com^\n/banner.gif\n/^regex/\n0.0.0.0 h.com");
        let stats = engine.rule_set().stats().clone();
        assert_eq!(stats.rules, 4);
        assert_eq!(stats.domain_rules, 2);
        assert_eq!(stats.fragment_rules, 1);
        assert_eq!(stats.regex_rules, 1);
        assert!(stats.trie_nodes > 1);
    }
}
