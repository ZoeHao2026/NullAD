//! Application state and the lifecycle of running protection.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nullad_api::{LogEntry, ProtectionState, RuleSetStatsDto, StatsSnapshotDto, StatusReport};
use nullad_engine::FilterEngine;
use nullad_host::journal::{ChangeJournal, JournalKind};
use nullad_host::{dns_config::DnsConfigurator, system_proxy::SystemProxy};
use nullad_intercept::{Decision, DecisionSink, EngineHandle, InterceptStats};

use crate::settings::AppSettings;
use crate::updater::{ListLoader, LoadOutcome};

/// How many recent decisions the live log keeps.
pub const DECISION_LOG_CAPACITY: usize = 500;

/// A bounded, thread-safe log of recent decisions.
///
/// A ring buffer rather than an unbounded queue: the log is a debugging and
/// display aid, and letting it grow without limit would make a long-running
/// session leak memory. Old entries are dropped, which is the correct trade for
/// a live feed.
#[derive(Debug)]
pub struct DecisionLog {
    entries: Mutex<VecDeque<LogEntry>>,
    capacity: usize,
}

impl DecisionLog {
    /// Creates a log holding at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity: capacity.max(1),
        }
    }

    /// Appends an entry, dropping the oldest when full.
    pub fn push(&self, entry: LogEntry) {
        // A poisoned lock is recovered rather than propagated: a panic in one
        // connection task must not disable the log for the whole application.
        let mut entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Returns up to `limit` of the most recent entries, newest first.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<LogEntry> {
        let entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        entries.iter().rev().take(limit).cloned().collect()
    }

    /// Total entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.entries.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Returns `true` when nothing has been logged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes every entry.
    pub fn clear(&self) {
        let mut entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        entries.clear();
    }
}

impl DecisionSink for DecisionLog {
    fn record(&self, decision: Decision) {
        self.push(LogEntry {
            timestamp_ms: decision.timestamp_ms,
            url: decision.url,
            host: decision.host,
            blocked: decision.blocked,
            rule: decision.rule,
        });
    }
}

/// The application's shared state.
///
/// This is the single owner of the engine and the settings. It is deliberately
/// not `Clone`: share it behind an `Arc` instead, so there is exactly one place
/// where the active rule set can be swapped.
#[derive(Debug)]
pub struct AppState {
    /// The matching engine.
    pub engine: Arc<FilterEngine>,
    /// Current configuration.
    pub settings: Mutex<AppSettings>,
    /// Recent decisions for the live feed.
    pub decisions: Arc<DecisionLog>,
    /// Interceptor counters.
    pub intercept_stats: Arc<InterceptStats>,
    /// What the last list load produced.
    pub last_load: Mutex<Option<LoadOutcome>>,
    /// Summary of the lists currently applied.
    pub lists: Mutex<Vec<ListSummary>>,
    /// Whether protection is currently active.
    running: AtomicBool,
}

/// A filter list as the UI sees it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ListSummary {
    /// Stable identifier.
    pub id: u32,
    /// Display name.
    pub name: String,
    /// Where it loads from.
    pub source: String,
    /// Whether it is applied.
    pub enabled: bool,
    /// Rules it contributed.
    pub rules: usize,
    /// Rules quarantined during parsing.
    pub failures: usize,
    /// Cosmetic rules recognised but not applied.
    pub cosmetic: usize,
}

impl AppState {
    /// Creates state with an empty engine, then loads the configured lists.
    #[must_use]
    pub fn bootstrap(settings: AppSettings) -> Self {
        let engine = Arc::new(FilterEngine::new());
        let decisions = Arc::new(DecisionLog::new(DECISION_LOG_CAPACITY));

        let state = Self {
            engine,
            settings: Mutex::new(settings),
            decisions,
            intercept_stats: Arc::new(InterceptStats::new()),
            last_load: Mutex::new(None),
            lists: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
        };

        state.reload_lists();
        state
    }

    /// Returns a clone of the current settings.
    #[must_use]
    pub fn settings(&self) -> AppSettings {
        match self.settings.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Replaces the settings and persists them.
    pub fn update_settings(&self, settings: AppSettings) -> Result<(), nullad_host::HostError> {
        {
            let mut guard = match self.settings.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard = settings;
        }
        self.settings().save()
    }

    /// Builds a fresh rule set from the enabled lists and installs it.
    ///
    /// The swap is a single atomic pointer store, so traffic is filtered
    /// continuously across a reload: requests already in flight finish against
    /// the old rule set and new ones see the new one.
    pub fn reload_lists(&self) -> LoadOutcome {
        let settings = self.settings();
        let loader = ListLoader::new();
        let outcome = loader.load(&settings);

        if let Some(rule_set) = outcome.rule_set.clone() {
            // `Arc::try_unwrap` would move it, but we cannot rely on being the
            // only holder, so the swap takes the shared handle and the engine
            // wraps it once more. The clone is an `Arc` bump, not a copy of the
            // compiled rules.
            self.engine.swap_shared(rule_set);
        }

        {
            let mut lists = match self.lists.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *lists = outcome.summaries.clone();
        }
        {
            let mut last = match self.last_load.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *last = Some(outcome.clone());
        }

        outcome
    }

    /// Builds an [`EngineHandle`] wired to this state's counters and log.
    #[must_use]
    pub fn engine_handle(&self) -> EngineHandle {
        EngineHandle {
            engine: Arc::clone(&self.engine),
            stats: Arc::clone(&self.intercept_stats),
            sink: Some(Arc::clone(&self.decisions) as Arc<dyn DecisionSink>),
        }
    }

    /// Marks protection as running.
    pub fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::Relaxed);
    }

    /// Returns `true` when protection is active.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Renders the current status for a UI.
    #[must_use]
    pub fn status(&self) -> ProtectionStatus {
        let settings = self.settings();
        let engine_stats = self.engine.stats_snapshot();
        let rule_stats = self.engine.rule_set().stats().clone();
        let lists = match self.lists.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };

        let state = if self.is_running() {
            ProtectionState::Running
        } else {
            ProtectionState::Stopped
        };

        ProtectionStatus {
            protection: state,
            engine: StatsSnapshotDto::from(engine_stats),
            rule_set: RuleSetStatsDto::from(nullad_engine::RuleSetStats {
                rules: rule_stats.rules,
                domain_rules: rule_stats.domain_rules,
                domain_path_rules: rule_stats.domain_path_rules,
                fragment_rules: rule_stats.fragment_rules,
                regex_rules: rule_stats.regex_rules,
                options_only_rules: rule_stats.options_only_rules,
                trie_nodes: rule_stats.trie_nodes,
                distinct_fragments: rule_stats.distinct_fragments,
            }),
            intercept: InterceptStatus {
                proxy_requests: self.intercept_stats.proxy_requests(),
                proxy_blocked: self.intercept_stats.proxy_blocked(),
                sni_connections: self.intercept_stats.sni_connections(),
                sni_blocked: self.intercept_stats.sni_blocked(),
                dns_queries: self.intercept_stats.dns_queries(),
                dns_blocked: self.intercept_stats.dns_blocked(),
                dns_forwarded: self.intercept_stats.dns_forwarded(),
                dns_failed: self.intercept_stats.dns_failed(),
            },
            lists,
            proxy_port: Some(settings.proxy_port),
            dns_port: settings.dns_enabled.then_some(settings.dns_port),
            intercept_system_proxy: settings.intercept_system_proxy,
        }
    }

    /// Converts the internal status into the shared API report type.
    #[must_use]
    pub fn status_report(&self) -> StatusReport {
        let status = self.status();
        StatusReport {
            state: status.protection,
            stats: status.engine,
            rule_set: status.rule_set,
            lists_loaded: status.lists.iter().filter(|l| l.enabled).count(),
            proxy_port: status.proxy_port,
            dns_port: status.dns_port,
            system_proxy_enabled: status.intercept_system_proxy,
        }
    }
}

/// A complete status snapshot for the UI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtectionStatus {
    /// Current protection state.
    pub protection: ProtectionState,
    /// Engine counters.
    pub engine: StatsSnapshotDto,
    /// Active rule-set structure.
    pub rule_set: RuleSetStatsDto,
    /// Interceptor counters.
    pub intercept: InterceptStatus,
    /// Applied filter lists.
    pub lists: Vec<ListSummary>,
    /// Configured proxy port.
    pub proxy_port: Option<u16>,
    /// Configured DNS port, when DNS is enabled.
    pub dns_port: Option<u16>,
    /// Whether the system proxy is routed through NullAD.
    pub intercept_system_proxy: bool,
}

/// Per-interceptor counters for the dashboard.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct InterceptStatus {
    /// Plaintext HTTP requests seen.
    pub proxy_requests: u64,
    /// Plaintext HTTP requests blocked.
    pub proxy_blocked: u64,
    /// TLS connections inspected.
    pub sni_connections: u64,
    /// TLS connections blocked.
    pub sni_blocked: u64,
    /// DNS queries seen.
    pub dns_queries: u64,
    /// DNS queries sinkholed.
    pub dns_blocked: u64,
    /// DNS queries forwarded upstream.
    pub dns_forwarded: u64,
    /// DNS queries that could not be answered.
    pub dns_failed: u64,
}

/// A handle to the application's shared state.
///
/// Cloning is cheap and the handle is `Send + Sync`, so it can be handed to any
/// number of UI callbacks.
#[derive(Debug, Clone)]
pub struct AppHandle {
    state: Arc<AppState>,
    runtime: RunningProtection,
}

impl AppHandle {
    /// Wraps state into a shareable handle.
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            runtime: RunningProtection::default(),
        }
    }

    /// Returns the underlying state.
    #[must_use]
    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    /// Returns the live protection runtime controls.
    #[must_use]
    pub fn runtime(&self) -> &RunningProtection {
        &self.runtime
    }

    /// Reloads the enabled lists and installs the new rule set.
    pub fn reload(&self) -> LoadOutcome {
        self.state.reload_lists()
    }

    /// Returns the most recent decisions, newest first.
    #[must_use]
    pub fn recent_decisions(&self, limit: usize) -> Vec<LogEntry> {
        self.state.decisions.recent(limit)
    }

    /// Returns the current status snapshot.
    #[must_use]
    pub fn status(&self) -> ProtectionStatus {
        self.state.status()
    }
}

/// Controls for the running interception tasks.
///
/// Holds the cancellation flag and the platform adapters, so that starting and
/// stopping protection is a single, auditable operation rather than a scattering
/// of task spawns.
///
/// Cloning shares the same flags rather than copying their values, so every
/// clone observes the same start/stop state.
#[derive(Debug, Default, Clone)]
pub struct RunningProtection {
    stop: Arc<AtomicBool>,
    system_proxy_active: Arc<AtomicBool>,
    dns_active: Arc<AtomicBool>,
}

impl RunningProtection {
    /// The shared stop flag handed to interceptor loops.
    #[must_use]
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Returns `true` while a stop has been requested.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Requests that running interceptors stop.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Clears a previous stop request, so protection can be restarted.
    pub fn arm(&self) {
        self.stop.store(false, Ordering::Relaxed);
    }

    /// Records whether the system proxy is currently routed through NullAD.
    pub fn set_system_proxy_active(&self, active: bool) {
        self.system_proxy_active.store(active, Ordering::Relaxed);
    }

    /// Returns `true` when the system proxy is routed through NullAD.
    #[must_use]
    pub fn system_proxy_active(&self) -> bool {
        self.system_proxy_active.load(Ordering::Relaxed)
    }

    /// Records whether the DNS sinkhole is running.
    pub fn set_dns_active(&self, active: bool) {
        self.dns_active.store(active, Ordering::Relaxed);
    }

    /// Returns `true` when the DNS sinkhole is running.
    #[must_use]
    pub fn dns_active(&self) -> bool {
        self.dns_active.load(Ordering::Relaxed)
    }

    /// Restores every system change NullAD made, using the journal.
    ///
    /// This is deliberately best-effort and never returns an error: it runs on
    /// shutdown, where the most important property is that it always attempts
    /// both restores and reports what it could not do, rather than aborting
    /// after the first failure and leaving the system modified.
    pub fn restore_system_changes(&self) {
        match SystemProxy::new("127.0.0.1:0") {
            Ok(mut proxy) => match proxy.revert() {
                Ok(Some(restored)) => {
                    tracing::info!(?restored, "restored the system proxy");
                }
                Ok(None) => {}
                Err(err) => tracing::warn!(error = %err, "could not restore the system proxy"),
            },
            Err(err) => tracing::warn!(error = %err, "could not open the system proxy adapter"),
        }

        let local: IpAddr = "127.0.0.1".parse().expect("valid literal address");
        match DnsConfigurator::new(local) {
            Ok(mut dns) => match dns.revert() {
                Ok(Some(restored)) => tracing::info!(?restored, "restored the system resolver"),
                Ok(None) => {}
                Err(err) => tracing::warn!(error = %err, "could not restore the system resolver"),
            },
            Err(err) => tracing::warn!(error = %err, "could not open the resolver adapter"),
        }

        // Only clear the journal once both restores have been attempted. An
        // entry that could not be applied stays recorded, so the next run still
        // offers to fix it.
        match ChangeJournal::load() {
            Ok(mut journal) => {
                if let Err(err) = journal.clear_kind(JournalKind::SystemProxy) {
                    tracing::warn!(error = %err, "could not clear the system proxy journal entry");
                }
                if let Err(err) = journal.clear_kind(JournalKind::DnsResolver) {
                    tracing::warn!(error = %err, "could not clear the resolver journal entry");
                }
            }
            Err(err) => tracing::warn!(error = %err, "could not open the change journal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullad_intercept::DecisionSource;

    fn decision(host: &str, blocked: bool) -> Decision {
        Decision {
            timestamp_ms: 1_700_000_000_000,
            url: format!("https://{host}/x"),
            host: host.to_owned(),
            blocked,
            rule: blocked.then(|| "||ads.example.com^".to_owned()),
            source: DecisionSource::Proxy,
        }
    }

    #[test]
    fn decision_log_is_bounded_and_newest_first() {
        let log = DecisionLog::new(3);
        for i in 0..5 {
            log.push(LogEntry {
                timestamp_ms: i,
                url: format!("https://h{i}.com/"),
                host: format!("h{i}.com"),
                blocked: true,
                rule: None,
            });
        }

        assert_eq!(log.len(), 3, "capacity must be enforced");
        let recent = log.recent(10);
        assert_eq!(recent.len(), 3);
        // Newest first, and the two oldest must have been dropped.
        assert_eq!(recent[0].timestamp_ms, 4);
        assert_eq!(recent[2].timestamp_ms, 2);
    }

    #[test]
    fn decision_log_clear_empties_it() {
        let log = DecisionLog::new(2);
        log.push(LogEntry {
            timestamp_ms: 1,
            url: "u".into(),
            host: "h".into(),
            blocked: false,
            rule: None,
        });
        assert!(!log.is_empty());
        log.clear();
        assert!(log.is_empty());
        assert!(log.recent(5).is_empty());
    }

    #[test]
    fn sink_records_decisions_as_log_entries() {
        let log = DecisionLog::new(10);
        log.record(decision("ads.example.com", true));

        let recent = log.recent(1);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].host, "ads.example.com");
        assert!(recent[0].blocked);
        assert_eq!(recent[0].rule.as_deref(), Some("||ads.example.com^"));
    }

    #[test]
    fn stop_flag_round_trips() {
        let runtime = RunningProtection::default();
        assert!(!runtime.should_stop());
        runtime.request_stop();
        assert!(runtime.should_stop());
        runtime.arm();
        assert!(!runtime.should_stop());
    }

    #[test]
    fn running_flags_default_to_inactive() {
        let runtime = RunningProtection::default();
        assert!(!runtime.system_proxy_active());
        assert!(!runtime.dns_active());
        runtime.set_system_proxy_active(true);
        runtime.set_dns_active(true);
        assert!(runtime.system_proxy_active());
        assert!(runtime.dns_active());
    }

    #[test]
    fn engine_handle_shares_counters_and_the_log() {
        let state = AppState {
            engine: Arc::new(FilterEngine::new()),
            settings: Mutex::new(AppSettings::default()),
            decisions: Arc::new(DecisionLog::new(10)),
            intercept_stats: Arc::new(InterceptStats::new()),
            last_load: Mutex::new(None),
            lists: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
        };

        let handle = state.engine_handle();
        handle.decide(
            "http://ads.example.com/x",
            nullad_engine::ResourceType::Other,
            None,
            DecisionSource::Proxy,
        );

        assert_eq!(state.intercept_stats.proxy_requests(), 1);
        assert_eq!(state.decisions.len(), 1);
    }

    #[test]
    fn status_reports_a_stopped_engine_by_default() {
        let state = AppState {
            engine: Arc::new(FilterEngine::new()),
            settings: Mutex::new(AppSettings::default()),
            decisions: Arc::new(DecisionLog::new(10)),
            intercept_stats: Arc::new(InterceptStats::new()),
            last_load: Mutex::new(None),
            lists: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
        };

        let status = state.status();
        assert_eq!(status.protection, ProtectionState::Stopped);
        assert_eq!(status.engine.queries, 0);

        state.set_running(true);
        assert_eq!(state.status().protection, ProtectionState::Running);
    }
}
