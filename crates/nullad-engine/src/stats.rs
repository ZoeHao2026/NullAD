//! Lock-free runtime statistics.
//!
//! All counters are relaxed atomics, so updating them from the matching hot
//! path costs a single uncontended atomic add and never blocks a request. The
//! values are read for the GUI and CLI, where eventual consistency is fine.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters describing engine activity since start-up.
#[derive(Debug, Default)]
pub struct EngineStats {
    queries: AtomicU64,
    blocked: AtomicU64,
    allowed: AtomicU64,
    exceptions_hit: AtomicU64,
    no_match: AtomicU64,
    rules_loaded: AtomicU64,
    rule_sets_swapped: AtomicU64,
}

impl EngineStats {
    /// Creates a zeroed counter set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one decision.
    pub fn record(&self, blocked: bool, exception: bool) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        } else {
            self.allowed.fetch_add(1, Ordering::Relaxed);
        }
        if exception {
            self.exceptions_hit.fetch_add(1, Ordering::Relaxed);
        } else if !blocked {
            self.no_match.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records that a rule set with `count` rules became active.
    pub fn record_rules_loaded(&self, count: usize) {
        self.rules_loaded
            .store(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Records a hot-swap of the active rule set.
    pub fn record_swap(&self) {
        self.rule_sets_swapped.fetch_add(1, Ordering::Relaxed);
    }

    /// Total requests evaluated.
    #[must_use]
    pub fn queries(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }

    /// Requests blocked.
    #[must_use]
    pub fn blocked(&self) -> u64 {
        self.blocked.load(Ordering::Relaxed)
    }

    /// Requests allowed.
    #[must_use]
    pub fn allowed(&self) -> u64 {
        self.allowed.load(Ordering::Relaxed)
    }

    /// Requests allowed specifically because an exception rule matched.
    #[must_use]
    pub fn exceptions_hit(&self) -> u64 {
        self.exceptions_hit.load(Ordering::Relaxed)
    }

    /// Requests allowed because no rule matched at all.
    #[must_use]
    pub fn no_match(&self) -> u64 {
        self.no_match.load(Ordering::Relaxed)
    }

    /// Number of rules in the currently active set.
    #[must_use]
    pub fn rules_loaded(&self) -> u64 {
        self.rules_loaded.load(Ordering::Relaxed)
    }

    /// Number of completed rule-set swaps.
    #[must_use]
    pub fn rule_sets_swapped(&self) -> u64 {
        self.rule_sets_swapped.load(Ordering::Relaxed)
    }

    /// Blocked fraction in `0.0..=1.0`, or `0.0` when nothing was evaluated.
    #[must_use]
    pub fn block_ratio(&self) -> f64 {
        let queries = self.queries();
        if queries == 0 {
            return 0.0;
        }
        self.blocked() as f64 / queries as f64
    }

    /// Returns an owned snapshot suitable for serialization to the GUI.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            queries: self.queries(),
            blocked: self.blocked(),
            allowed: self.allowed(),
            exceptions_hit: self.exceptions_hit(),
            no_match: self.no_match(),
            rules_loaded: self.rules_loaded(),
            rule_sets_swapped: self.rule_sets_swapped(),
            block_ratio: self.block_ratio(),
        }
    }

    /// Resets every counter to zero. Intended for tests and for a UI "reset"
    /// button, never for the hot path.
    pub fn reset(&self) {
        self.queries.store(0, Ordering::Relaxed);
        self.blocked.store(0, Ordering::Relaxed);
        self.allowed.store(0, Ordering::Relaxed);
        self.exceptions_hit.store(0, Ordering::Relaxed);
        self.no_match.store(0, Ordering::Relaxed);
        self.rule_sets_swapped.store(0, Ordering::Relaxed);
    }
}

/// An owned, serializable copy of [`EngineStats`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StatsSnapshot {
    /// Total requests evaluated.
    pub queries: u64,
    /// Requests blocked.
    pub blocked: u64,
    /// Requests allowed.
    pub allowed: u64,
    /// Requests allowed by an exception rule.
    pub exceptions_hit: u64,
    /// Requests allowed with no matching rule.
    pub no_match: u64,
    /// Rules in the active set.
    pub rules_loaded: u64,
    /// Completed rule-set swaps.
    pub rule_sets_swapped: u64,
    /// Blocked fraction in `0.0..=1.0`.
    pub block_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_blocks_and_allows() {
        let stats = EngineStats::new();
        stats.record(true, false);
        stats.record(false, false);
        stats.record(false, true);

        assert_eq!(stats.queries(), 3);
        assert_eq!(stats.blocked(), 1);
        assert_eq!(stats.allowed(), 2);
        assert_eq!(stats.exceptions_hit(), 1);
        // Only the un-matched allow is counted as "no_match".
        assert_eq!(stats.no_match(), 1);
    }

    #[test]
    fn block_ratio_is_safe_with_no_data() {
        let stats = EngineStats::new();
        assert_eq!(stats.block_ratio(), 0.0);
    }

    #[test]
    fn snapshot_matches_counters() {
        let stats = EngineStats::new();
        stats.record(true, false);
        stats.record(false, false);
        stats.record_rules_loaded(1234);
        stats.record_swap();

        let snap = stats.snapshot();
        assert_eq!(snap.queries, 2);
        assert_eq!(snap.blocked, 1);
        assert_eq!(snap.rules_loaded, 1234);
        assert_eq!(snap.rule_sets_swapped, 1);
        assert!((snap.block_ratio - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn reset_clears_counters_but_keeps_rules_loaded() {
        let stats = EngineStats::new();
        stats.record(true, false);
        stats.record_rules_loaded(10);
        stats.reset();
        assert_eq!(stats.queries(), 0);
        assert_eq!(stats.rules_loaded(), 10);
    }
}
