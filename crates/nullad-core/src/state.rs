//! Application state and the lifecycle of running protection.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nullad_api::{LogEntry, ProtectionState, RuleSetStatsDto, StatsSnapshotDto, StatusReport};
use nullad_engine::FilterEngine;
use nullad_host::journal::{ChangeJournal, JournalKind, RestoreItem, RestoreReport};
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
    loader: ListLoader,
    reload_lock: Mutex<()>,
    settings_revision: AtomicU64,
    settings_path: Option<PathBuf>,
    pending_journal_path: Option<PathBuf>,
    runtime_status: Mutex<RuntimeStatus>,
}

#[derive(Debug)]
struct RuntimeStatus {
    protection: ProtectionState,
    proxy_port: Option<u16>,
    dns_port: Option<u16>,
    system_proxy: bool,
    last_error: Option<String>,
    recovery_error: Option<String>,
    started_settings: Option<AppSettings>,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            protection: ProtectionState::Stopped,
            proxy_port: None,
            dns_port: None,
            system_proxy: false,
            last_error: None,
            recovery_error: None,
            started_settings: None,
        }
    }
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
        Self::bootstrap_with_resource_dir(settings, None)
    }

    /// Loads bundled lists from the installed Tauri resource directory.
    pub fn bootstrap_with_resource_dir(
        settings: AppSettings,
        resource_dir: Option<PathBuf>,
    ) -> Self {
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
            loader: ListLoader::with_resource_dir(resource_dir),
            reload_lock: Mutex::new(()),
            settings_revision: AtomicU64::new(0),
            settings_path: None,
            pending_journal_path: None,
            runtime_status: Mutex::new(RuntimeStatus::default()),
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

    /// Replaces settings after persistence succeeds. Prefer patches for UI edits.
    pub fn update_settings(&self, settings: AppSettings) -> Result<(), nullad_host::HostError> {
        self.modify_settings(|current| *current = settings)
    }

    /// Applies a modification to the latest snapshot under the settings lock.
    /// A failed write leaves both the published settings and revision unchanged.
    pub fn modify_settings(
        &self,
        modify: impl FnOnce(&mut AppSettings),
    ) -> Result<(), nullad_host::HostError> {
        let mut current = self
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut proposed = current.clone();
        modify(&mut proposed);
        proposed.validate()?;
        if let Some(path) = &self.settings_path {
            proposed.save_at(path)?;
        } else {
            proposed.save()?;
        }
        *current = proposed;
        self.settings_revision.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Builds a fresh rule set from the enabled lists and installs it.
    ///
    /// The swap is a single atomic pointer store, so traffic is filtered
    /// continuously across a reload: requests already in flight finish against
    /// the old rule set and new ones see the new one.
    pub fn reload_lists(&self) -> LoadOutcome {
        let _reload = self
            .reload_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (settings, revision) = {
            let settings = self
                .settings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                settings.clone(),
                self.settings_revision.load(Ordering::Acquire),
            )
        };
        let mut outcome = self.loader.load(&settings);
        // Hold the settings lock through publication so an edit cannot race this check.
        let _settings = self
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if revision != self.settings_revision.load(Ordering::Acquire) {
            outcome.warnings.push(
                "settings changed during loading; the obsolete reload was not installed".into(),
            );
            return outcome;
        }
        if let Some(rule_set) = outcome.rule_set.clone() {
            self.engine.swap_shared(rule_set);
        }
        *self
            .lists
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = outcome.summaries.clone();
        *self
            .last_load
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome.clone());
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
        let state = if running {
            ProtectionState::Running
        } else {
            ProtectionState::Stopped
        };
        self.set_runtime_status(state, None, None, false, None);
    }

    /// Returns `true` when protection is active.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Publishes actual listener and routing state, separate from persisted settings.
    pub fn set_runtime_status(
        &self,
        protection: ProtectionState,
        proxy_port: Option<u16>,
        dns_port: Option<u16>,
        system_proxy: bool,
        last_error: Option<String>,
    ) {
        let settings = (protection == ProtectionState::Starting).then(|| self.settings());
        let mut runtime = self
            .runtime_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(settings) = settings {
            runtime.started_settings = Some(settings);
        }
        if matches!(
            protection,
            ProtectionState::Stopped | ProtectionState::Failed
        ) {
            runtime.started_settings = None;
        }
        runtime.protection = protection;
        runtime.proxy_port = proxy_port;
        runtime.dns_port = dns_port;
        runtime.system_proxy = system_proxy;
        runtime.last_error = last_error;
        runtime.recovery_error = None;
        self.running.store(
            protection.is_active() || protection == ProtectionState::Starting,
            Ordering::Relaxed,
        );
    }

    /// Publishes a recovery outcome without replaying an earlier lifecycle snapshot.
    /// Listener state and its error can change concurrently while recovery runs.
    pub fn update_recovery_status(&self, system_proxy: bool, recovery_error: Option<String>) {
        let mut runtime = self
            .runtime_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime.system_proxy = system_proxy;
        runtime.recovery_error = recovery_error;
    }

    /// Records the exact snapshot used by the desktop startup transaction.
    pub fn capture_startup_settings(&self, settings: AppSettings) {
        self.runtime_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .started_settings = Some(settings);
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

        let runtime = self
            .runtime_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let needs_restart = runtime
            .started_settings
            .as_ref()
            .is_some_and(|started| !started.same_listener_settings(&settings));

        let journal = self
            .pending_journal_path
            .as_ref()
            .map_or_else(ChangeJournal::load, |path| {
                ChangeJournal::load_at(path.clone())
            });
        let (pending_changes, journal_error) = match journal {
            Ok(journal) => (journal.entries().len(), None),
            Err(error) => (
                0,
                Some(format!(
                    "system recovery journal could not be read: {error}"
                )),
            ),
        };
        let errors = [
            runtime.last_error.clone(),
            runtime
                .recovery_error
                .as_ref()
                .map(|error| format!("recovery: {error}")),
            journal_error,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let last_error = (!errors.is_empty()).then(|| errors.join("; "));

        let observed_proxy = nullad_host::platform::read_proxy().ok();
        ProtectionStatus {
            protection: runtime.protection,
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
            proxy_port: runtime.proxy_port,
            proxy_address: runtime.proxy_port.map(|port| format!("127.0.0.1:{port}")),
            dns_address: runtime.dns_port.map(|port| format!("127.0.0.1:{port}")),
            dns_port: runtime.dns_port,
            intercept_system_proxy: runtime.system_proxy,
            system_proxy_enabled: observed_proxy.as_ref().map(|proxy| proxy.enabled),
            system_proxy_server: observed_proxy.and_then(|proxy| proxy.server),
            last_error,
            pending_changes,
            needs_restart,
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
    /// Actual bound proxy port.
    pub proxy_port: Option<u16>,
    /// Actual bound loopback listener addresses, absent while stopped.
    pub proxy_address: Option<String>,
    pub dns_address: Option<String>,
    /// Actual bound DNS port.
    pub dns_port: Option<u16>,
    /// Whether the system proxy is routed through NullAD.
    pub intercept_system_proxy: bool,
    /// Observed OS proxy state; None means it could not be read.
    pub system_proxy_enabled: Option<bool>,
    pub system_proxy_server: Option<String>,
    pub last_error: Option<String>,
    pub pending_changes: usize,
    pub needs_restart: bool,
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

    /// Attempts all pending restores and retains failed entries for the next run.
    pub fn restore_system_changes(&self) -> RestoreReport {
        let mut report = RestoreReport::default();
        match SystemProxy::new("127.0.0.1:0") {
            Ok(mut proxy) => match proxy.revert() {
                Ok(Some(_)) => {
                    self.set_system_proxy_active(false);
                    report.items.push(RestoreItem {
                        kind: JournalKind::SystemProxy,
                        restored: true,
                        error: None,
                    });
                }
                Ok(None) => {}
                Err(error) => report.items.push(RestoreItem {
                    kind: JournalKind::SystemProxy,
                    restored: false,
                    error: Some(error.to_string()),
                }),
            },
            Err(error) => report.items.push(RestoreItem {
                kind: JournalKind::SystemProxy,
                restored: false,
                error: Some(error.to_string()),
            }),
        }
        let local: IpAddr = "127.0.0.1".parse().expect("valid literal address");
        match DnsConfigurator::new(local) {
            Ok(mut dns) => match dns.revert() {
                Ok(Some(_)) => report.items.push(RestoreItem {
                    kind: JournalKind::DnsResolver,
                    restored: true,
                    error: None,
                }),
                Ok(None) => {}
                Err(error) => report.items.push(RestoreItem {
                    kind: JournalKind::DnsResolver,
                    restored: false,
                    error: Some(error.to_string()),
                }),
            },
            Err(error) => report.items.push(RestoreItem {
                kind: JournalKind::DnsResolver,
                restored: false,
                error: Some(error.to_string()),
            }),
        }
        report.pending_changes = ChangeJournal::load()
            .map(|journal| journal.entries().len())
            .unwrap_or_else(|_| {
                report
                    .items
                    .iter()
                    .filter(|item| item.error.is_some())
                    .count()
            });
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullad_intercept::DecisionSource;

    fn test_state(settings: AppSettings) -> AppState {
        let directory = crate::test_support::directory();
        AppState {
            engine: Arc::new(FilterEngine::new()),
            settings: Mutex::new(settings),
            decisions: Arc::new(DecisionLog::new(10)),
            intercept_stats: Arc::new(InterceptStats::new()),
            last_load: Mutex::new(None),
            lists: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
            loader: ListLoader::new(),
            reload_lock: Mutex::new(()),
            settings_revision: AtomicU64::new(0),
            settings_path: Some(directory.join("settings.json")),
            pending_journal_path: Some(directory.join("journal.json")),
            runtime_status: Mutex::new(RuntimeStatus::default()),
        }
    }

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
        let state = test_state(AppSettings::default());

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
        let state = test_state(AppSettings::default());

        let status = state.status();
        assert_eq!(status.protection, ProtectionState::Stopped);
        assert_eq!(status.engine.queries, 0);

        state.set_running(true);
        assert_eq!(state.status().protection, ProtectionState::Running);
    }
    #[test]
    fn failed_persistence_does_not_publish_settings() {
        let mut state = test_state(AppSettings::default());
        state.settings_path = Some(
            crate::test_support::directory()
                .join("missing-parent")
                .join("settings.json"),
        );
        let before = state.settings();
        assert!(state
            .modify_settings(|settings| settings.ui_language = "en".into())
            .is_err());
        assert_eq!(state.settings(), before);
        assert_eq!(state.settings_revision.load(Ordering::Acquire), 0);
    }

    #[test]
    fn concurrent_patches_preserve_unrelated_fields_and_persist_latest_settings() {
        let state = Arc::new(test_state(AppSettings::default()));
        std::thread::scope(|scope| {
            let first = Arc::clone(&state);
            scope.spawn(move || {
                first
                    .modify_settings(|settings| settings.ui_language = "en".into())
                    .unwrap()
            });
            let second = Arc::clone(&state);
            scope.spawn(move || {
                second
                    .modify_settings(|settings| settings.proxy_port = 9090)
                    .unwrap()
            });
        });
        let settings = state.settings();
        assert_eq!(settings.ui_language, "en");
        assert_eq!(settings.proxy_port, 9090);
        let persisted: AppSettings =
            serde_json::from_slice(&std::fs::read(state.settings_path.as_ref().unwrap()).unwrap())
                .unwrap();
        assert_eq!(persisted, settings);
    }

    #[test]
    fn runtime_status_reports_bound_ports_and_restart_requirement() {
        let state = test_state(AppSettings::default());
        assert_eq!(state.status().proxy_port, None);
        state.set_runtime_status(ProtectionState::Starting, None, None, false, None);
        state.set_runtime_status(
            ProtectionState::Degraded,
            Some(8080),
            None,
            true,
            Some("DNS unavailable".into()),
        );
        state
            .modify_settings(|settings| {
                settings.proxy_port = 9090;
                settings.ui_language = "en".into();
            })
            .unwrap();
        let status = state.status();
        assert_eq!(status.proxy_port, Some(8080));
        assert_eq!(status.dns_port, None);
        assert_eq!(status.protection, ProtectionState::Degraded);
        assert!(status.intercept_system_proxy && status.needs_restart);
        assert_eq!(status.last_error.as_deref(), Some("DNS unavailable"));
        state.set_runtime_status(ProtectionState::Stopped, None, None, false, None);
        assert!(!state.status().needs_restart);
    }

    #[test]
    fn recovery_after_listener_failure_preserves_the_current_failed_state() {
        let state = test_state(AppSettings::default());
        state.set_runtime_status(ProtectionState::Running, Some(8080), Some(5353), true, None);
        // The listener finishes while a manually requested recovery is in flight.
        state.set_runtime_status(
            ProtectionState::Failed,
            None,
            None,
            true,
            Some("DNS listener failed".into()),
        );
        state.update_recovery_status(false, Some("snapshot still pending".into()));
        let status = state.status();
        assert_eq!(status.protection, ProtectionState::Failed);
        assert_eq!(status.proxy_port, None);
        assert_eq!(status.dns_port, None);
        assert!(!status.intercept_system_proxy);
        assert!(!state.is_running());
        assert_eq!(
            status.last_error.as_deref(),
            Some("DNS listener failed; recovery: snapshot still pending")
        );

        // A successful retry clears the recovery error but retains why the
        // listeners stopped. It must not bring stale ports back into the UI.
        state.update_recovery_status(false, None);
        let status = state.status();
        assert_eq!(status.protection, ProtectionState::Failed);
        assert_eq!((status.proxy_port, status.dns_port), (None, None));
        assert_eq!(status.last_error.as_deref(), Some("DNS listener failed"));
    }

    #[test]
    fn listener_failure_after_recovery_remains_the_latest_lifecycle_state() {
        let state = test_state(AppSettings::default());
        state.set_runtime_status(ProtectionState::Running, Some(8080), Some(5353), true, None);
        state.update_recovery_status(false, None);
        let status = state.status();
        assert_eq!(status.protection, ProtectionState::Running);
        assert_eq!(
            (status.proxy_port, status.dns_port),
            (Some(8080), Some(5353))
        );
        assert!(state.is_running());
        assert!(!status.intercept_system_proxy);

        state.set_runtime_status(
            ProtectionState::Failed,
            None,
            None,
            false,
            Some("HTTP listener failed".into()),
        );
        let status = state.status();
        assert_eq!(status.protection, ProtectionState::Failed);
        assert_eq!((status.proxy_port, status.dns_port), (None, None));
        assert_eq!(status.last_error.as_deref(), Some("HTTP listener failed"));
        assert!(!state.is_running());
    }

    #[test]
    fn recovery_preserves_started_listener_settings_and_degraded_error() {
        let state = test_state(AppSettings::default());
        state.set_runtime_status(ProtectionState::Starting, None, None, false, None);
        state.set_runtime_status(
            ProtectionState::Degraded,
            Some(8080),
            None,
            true,
            Some("DNS unavailable".into()),
        );
        state
            .modify_settings(|settings| settings.proxy_port = 9090)
            .unwrap();
        state.update_recovery_status(false, Some("restore unavailable".into()));
        let status = state.status();
        assert_eq!(status.protection, ProtectionState::Degraded);
        assert_eq!(status.proxy_port, Some(8080));
        assert!(status.needs_restart && state.is_running());
        assert_eq!(
            status.last_error.as_deref(),
            Some("DNS unavailable; recovery: restore unavailable")
        );
        state.update_recovery_status(false, None);
        let status = state.status();
        assert!(status.needs_restart);
        assert_eq!(status.last_error.as_deref(), Some("DNS unavailable"));
    }

    #[test]
    fn obsolete_reload_cannot_restore_a_disabled_list() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/list", listener.local_addr().unwrap());
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            assert!(socket.read(&mut request).unwrap() > 0);
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            let body = "||ads.example.com^\n";
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let settings = AppSettings {
            lists: vec![crate::ListEntry {
                id: 7,
                name: "remote".into(),
                source: crate::ListSource::Remote { url },
                enabled: true,
            }],
            ..AppSettings::default()
        };
        let state = Arc::new(test_state(settings));
        let loader_state = Arc::clone(&state);
        let reload = std::thread::spawn(move || loader_state.reload_lists());
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        state
            .modify_settings(|settings| settings.lists[0].enabled = false)
            .unwrap();
        release_tx.send(()).unwrap();
        let obsolete = reload.join().unwrap();
        server.join().unwrap();
        assert!(obsolete
            .warnings
            .iter()
            .any(|warning| warning.contains("obsolete")));
        assert_eq!(state.engine.rule_count(), 0);
        let disabled = state.reload_lists();
        assert!(disabled.rule_set.is_some());
        assert_eq!(state.engine.rule_count(), 0);
    }
    #[test]
    fn corrupt_recovery_journal_is_visible_and_preserved() {
        let state = test_state(AppSettings::default());
        let path = state.pending_journal_path.as_ref().unwrap();
        std::fs::write(path, "{broken").unwrap();
        let status = state.status();
        assert!(status
            .last_error
            .unwrap()
            .contains("recovery journal could not be read"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{broken");
    }

    #[test]
    fn disabling_all_lists_installs_an_empty_rule_set() {
        let mut settings = AppSettings::default();
        let path = crate::test_support::directory().join("list.txt");
        std::fs::write(&path, "||ads.example.com^\n").unwrap();
        settings.lists = vec![crate::ListEntry {
            id: 1,
            name: "local".into(),
            source: crate::ListSource::Local {
                path: path.display().to_string(),
            },
            enabled: true,
        }];
        let state = test_state(settings);
        state.reload_lists();
        assert_eq!(state.engine.rule_count(), 1);
        state
            .modify_settings(|settings| settings.lists[0].enabled = false)
            .unwrap();
        state.reload_lists();
        assert_eq!(state.engine.rule_count(), 0);
    }
}
