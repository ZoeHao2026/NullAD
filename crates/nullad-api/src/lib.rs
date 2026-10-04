//! # NullAD API
//!
//! The shared contract between the engine/interception layers and any user
//! interface. This crate exists so that the GUI can be replaced — a Tauri
//! window today, a native mobile view or a CLI tomorrow — without touching
//! engine code.
//!
//! It contains only data-transfer objects and traits. There is deliberately no
//! I/O here.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub use nullad_engine::{
    Action, CheckResult, EngineStats, Request, ResourceType, RuleSetStats, StatsSnapshot,
};

/// Current operational state of the protection engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    /// Not running; no traffic is being filtered.
    Stopped,
    /// Starting up; interceptors are binding.
    Starting,
    /// Stop requested; listeners and connections are draining.
    Stopping,
    /// Running and filtering traffic.
    Running,
    /// Running but degraded, for example because an interceptor failed to bind.
    Degraded,
    /// Stopped after an error.
    Failed,
}

impl ProtectionState {
    /// Returns `true` when traffic is actively being filtered.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Degraded)
    }
}

/// A point-in-time report the GUI renders on its dashboard.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusReport {
    /// Current protection state.
    pub state: ProtectionState,
    /// Engine counters.
    pub stats: StatsSnapshotDto,
    /// Structural description of the active rule set.
    pub rule_set: RuleSetStatsDto,
    /// Number of filter lists loaded.
    pub lists_loaded: usize,
    /// Port the HTTP proxy listens on, when running.
    pub proxy_port: Option<u16>,
    /// Port the DNS server listens on, when running.
    pub dns_port: Option<u16>,
    /// Whether system-wide traffic is currently routed through NullAD.
    pub system_proxy_enabled: bool,
}

/// Serializable mirror of the engine's counter snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StatsSnapshotDto {
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

impl From<StatsSnapshot> for StatsSnapshotDto {
    fn from(s: StatsSnapshot) -> Self {
        Self {
            queries: s.queries,
            blocked: s.blocked,
            allowed: s.allowed,
            exceptions_hit: s.exceptions_hit,
            no_match: s.no_match,
            rules_loaded: s.rules_loaded,
            rule_sets_swapped: s.rule_sets_swapped,
            block_ratio: s.block_ratio,
        }
    }
}

/// Serializable mirror of the engine's rule-set structure.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RuleSetStatsDto {
    /// Total rules indexed.
    pub rules: usize,
    /// Rules served by the domain-anchor trie.
    pub domain_rules: usize,
    /// Rules served by the substring/wildcard automaton.
    pub fragment_rules: usize,
    /// Rules served by the regex index.
    pub regex_rules: usize,
    /// Rules with no literal pattern.
    pub options_only_rules: usize,
    /// Domain trie node count.
    pub trie_nodes: usize,
    /// Distinct automaton fragments.
    pub distinct_fragments: usize,
}

impl From<RuleSetStats> for RuleSetStatsDto {
    fn from(s: RuleSetStats) -> Self {
        Self {
            rules: s.rules,
            domain_rules: s.domain_rules,
            fragment_rules: s.fragment_rules,
            regex_rules: s.regex_rules,
            options_only_rules: s.options_only_rules,
            trie_nodes: s.trie_nodes,
            distinct_fragments: s.distinct_fragments,
        }
    }
}

/// Describes a filter list NullAD knows about.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FilterListInfo {
    /// Stable identifier.
    pub id: u32,
    /// Human-readable name.
    pub name: String,
    /// Where the list came from.
    pub source: String,
    /// Whether the list is currently applied.
    pub enabled: bool,
    /// Number of rules contributed.
    pub rules: usize,
    /// Rules quarantined during parsing.
    pub parse_failures: usize,
}

/// One entry in the live request log the dashboard streams.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The request URL.
    pub url: String,
    /// The request host.
    pub host: String,
    /// Whether it was blocked.
    pub blocked: bool,
    /// The rule that decided the outcome, rendered as text.
    pub rule: Option<String>,
}
