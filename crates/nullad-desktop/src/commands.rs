//! The Tauri command surface.
//!
//! Every function here is a thin translation between the UI's JSON and
//! `nullad-core`'s typed API. No filtering logic lives in this file, which is
//! what keeps the GUI swappable: replacing the web UI means replacing these
//! bindings and nothing else.

use std::time::Instant;

use nullad_core::{AppSettings, ListSource, ProtectionStatus};
use nullad_engine::{MatchScratch, Request, ResourceType, RuleSetBuilder};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::DesktopState;

/// A command failure, rendered as a message the UI can show directly.
#[derive(Debug, Serialize)]
pub struct CommandError {
    /// What went wrong, in user-facing language.
    message: String,
}

impl CommandError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<anyhow::Error> for CommandError {
    fn from(err: anyhow::Error) -> Self {
        Self::new(format!("{err:#}"))
    }
}

impl From<nullad_host::HostError> for CommandError {
    fn from(err: nullad_host::HostError) -> Self {
        Self::new(err.to_string())
    }
}

/// Result alias for commands.
type CommandResult<T> = Result<T, CommandError>;

/// Returns the current protection status.
#[tauri::command]
pub fn get_status(state: State<'_, DesktopState>) -> ProtectionStatus {
    state.app.status()
}

/// Returns the most recent decisions, newest first.
#[tauri::command]
pub fn recent_decisions(
    state: State<'_, DesktopState>,
    limit: Option<usize>,
) -> Vec<nullad_core::LogEntry> {
    state.app.recent_decisions(limit.unwrap_or(100))
}

/// Empties the live decision log.
#[tauri::command]
pub fn clear_log(state: State<'_, DesktopState>) {
    state.app.state().decisions.clear();
}

/// Returns the applied filter lists.
#[tauri::command]
pub fn list_lists(state: State<'_, DesktopState>) -> Vec<ListInfoDto> {
    state
        .app
        .status()
        .lists
        .into_iter()
        .map(ListInfoDto::from)
        .collect()
}

/// Returns a sample of the parsed rules, for the rule viewer panel.
#[tauri::command]
pub fn list_rules(state: State<'_, DesktopState>, limit: Option<usize>) -> Vec<RuleInfoDto> {
    let limit = limit.unwrap_or(200);
    let rule_set = state.app.state().engine.rule_set();
    rule_set
        .rules()
        .take(limit)
        .map(|rule| RuleInfoDto {
            action: rule.action.to_string(),
            pattern: format!("{:?}", rule.pattern),
            raw: rule.raw.clone(),
            source_line: rule.source_line,
            list_id: rule.list_id,
        })
        .collect()
}

/// Evaluates a single URL, for the "check a URL" tool.
#[tauri::command]
pub fn check_url(
    state: State<'_, DesktopState>,
    url: String,
    page: Option<String>,
    resource_type: Option<String>,
) -> CheckOutcomeDto {
    let kind = resource_type
        .as_deref()
        .and_then(parse_resource_type)
        .unwrap_or(ResourceType::Other);

    let mut request = Request::new(url, kind);
    if let Some(page) = page.as_deref() {
        request = request.with_page(page);
    }

    let result = state.app.state().engine_handle().evaluate(
        &request.url,
        kind,
        page.as_deref(),
        nullad_intercept::DecisionSource::Proxy,
    );

    CheckOutcomeDto {
        url: request.url.clone(),
        host: request.host.clone(),
        blocked: result.blocked,
        rule: result.matched_rule.as_ref().map(|r| r.raw.clone()),
        matched: result.matched_rule_ids.len(),
        reason: result.reason,
        score: result.score,
    }
}

/// Returns the persisted settings.
#[tauri::command]
pub fn get_settings(state: State<'_, DesktopState>) -> AppSettings {
    state.app.state().settings()
}

/// Persists new settings and reloads lists if the list configuration changed.
#[tauri::command]
pub async fn update_settings(
    state: State<'_, DesktopState>,
    patch: nullad_core::SettingsPatch,
    app_handle: tauri::AppHandle,
) -> CommandResult<AppSettings> {
    let app = state.app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        app.state()
            .modify_settings(|settings| patch.apply_to(settings))?;
        Ok::<_, CommandError>(app.state().settings())
    })
    .await
    .map_err(|e| CommandError::new(e.to_string()))??;
    let settings = state.app.state().settings();
    if let Err(error) = crate::tray::set_language(&app_handle, &settings.ui_language) {
        tracing::warn!(%error, "tray translation failed");
    }
    Ok(settings)
}

/// Reloads every enabled list and returns any warnings.
#[tauri::command]
pub async fn reload_lists(state: State<'_, DesktopState>) -> CommandResult<ReloadResultDto> {
    let app = state.app.clone();
    tauri::async_runtime::spawn_blocking(move || ReloadResultDto::from(app.reload()))
        .await
        .map_err(|error| CommandError::new(error.to_string()))
}

/// Enables or disables one filter list using the latest settings snapshot.
#[tauri::command]
pub async fn set_list_enabled(
    state: State<'_, DesktopState>,
    id: u32,
    enabled: bool,
) -> CommandResult<ReloadResultDto> {
    let app = state.app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if !app
            .state()
            .settings()
            .lists
            .iter()
            .any(|entry| entry.id == id)
        {
            return Err(CommandError::new(format!("no filter list with id {id}")));
        }
        app.state().modify_settings(|settings| {
            if let Some(entry) = settings.lists.iter_mut().find(|entry| entry.id == id) {
                entry.enabled = enabled;
            }
        })?;
        Ok(ReloadResultDto::from(app.reload()))
    })
    .await
    .map_err(|error| CommandError::new(error.to_string()))?
}

/// Saves custom rules off the webview thread, preserving previous file on config failure.
#[tauri::command]
pub async fn set_custom_rules(
    state: State<'_, DesktopState>,
    rules: String,
) -> CommandResult<ReloadResultDto> {
    let app = state.app.clone();
    let edits = state.custom_edits.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = edits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = nullad_host::paths::config_dir()?.join("custom-rules.txt");
        persist_custom_rules(&path, &rules, || {
            app.state()
                .modify_settings(|settings| {
                    update_custom_entry(settings, &path, !rules.trim().is_empty());
                })
                .map_err(CommandError::from)
        })?;
        Ok(ReloadResultDto::from(app.reload()))
    })
    .await
    .map_err(|error| CommandError::new(error.to_string()))?
}

fn update_custom_entry(settings: &mut AppSettings, path: &std::path::Path, enabled: bool) {
    const CUSTOM_ID: u32 = 9_000;
    let source = ListSource::Local {
        path: path.display().to_string(),
    };
    if let Some(entry) = settings
        .lists
        .iter_mut()
        .find(|entry| entry.id == CUSTOM_ID)
    {
        entry.source = source;
        entry.enabled = enabled;
    } else {
        settings.lists.push(nullad_core::ListEntry {
            id: CUSTOM_ID,
            name: "Custom rules".into(),
            source,
            enabled,
        });
    }
}

fn persist_custom_rules(
    path: &std::path::Path,
    rules: &str,
    persist: impl FnOnce() -> CommandResult<()>,
) -> CommandResult<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_BACKUP: AtomicU64 = AtomicU64::new(0);

    // A read error must never be interpreted as an absent previous file.
    let previous = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(CommandError::new(format!(
                "cannot read {}: {error}",
                path.display()
            )));
        }
    };
    let backup = if let Some(bytes) = previous {
        let (backup, mut file) = loop {
            let backup = path.with_extension(format!(
                "txt.previous-{}-{}",
                std::process::id(),
                NEXT_BACKUP.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&backup)
            {
                Ok(file) => break (backup, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(CommandError::new(format!(
                        "cannot preserve {}: {error}",
                        path.display()
                    )));
                }
            }
        };
        let preserved = file.write_all(&bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = preserved {
            let _ = std::fs::remove_file(&backup);
            return Err(CommandError::new(format!(
                "cannot preserve {}: {error}",
                path.display()
            )));
        }
        Some(backup)
    } else {
        None
    };

    if let Err(error) = nullad_host::journal::atomic_write(path, rules.as_bytes()) {
        if let Some(backup) = &backup {
            let _ = std::fs::remove_file(backup);
        }
        return Err(CommandError::new(format!(
            "cannot write {}: {error}",
            path.display()
        )));
    }
    if let Err(error) = persist() {
        let restored = match &backup {
            Some(backup) => std::fs::rename(backup, path),
            None => std::fs::remove_file(path),
        };
        return Err(CommandError::new(match restored {
            Ok(()) => error.to_string(),
            Err(restore) => match backup {
                Some(backup) => format!(
                    "{error}; cannot restore custom rules: {restore}; previous rules retained at {}",
                    backup.display()
                ),
                None => format!("{error}; cannot remove uncommitted custom rules: {restore}"),
            },
        }));
    }
    if let Some(backup) = backup {
        if let Err(error) = std::fs::remove_file(&backup) {
            tracing::warn!(path = %backup.display(), %error, "could not remove old custom rules backup");
        }
    }
    Ok(())
}

/// Returns the current contents of the custom rules file.
#[tauri::command]
pub fn get_custom_rules() -> String {
    let Ok(dir) = nullad_host::paths::config_dir() else {
        return String::new();
    };
    std::fs::read_to_string(dir.join("custom-rules.txt")).unwrap_or_default()
}

/// Starts the configured interceptors.
#[tauri::command]
pub async fn start_protection(state: State<'_, DesktopState>) -> CommandResult<Vec<String>> {
    crate::runtime::start(&state)
        .await
        .map_err(CommandError::new)
}

/// Stops every task and restores recorded system changes.
#[tauri::command]
pub async fn stop_protection(state: State<'_, DesktopState>) -> CommandResult<Vec<String>> {
    crate::runtime::stop(&state)
        .await
        .map_err(CommandError::new)
}

/// Returns the number of system changes still awaiting restoration.
#[tauri::command]
pub fn pending_changes() -> Vec<PendingChangeDto> {
    nullad_host::journal::ChangeJournal::pending()
        .into_iter()
        .map(|entry| PendingChangeDto {
            kind: format!("{:?}", entry.kind),
            description: entry.description,
            applied_at_ms: entry.applied_at_ms,
        })
        .collect()
}

/// Restores every system change NullAD has made.
#[tauri::command]
pub async fn restore_system_changes(
    state: State<'_, DesktopState>,
) -> CommandResult<nullad_core::RestoreReport> {
    let _guard = state.tasks.lock().await;
    let app = state.app.clone();
    let report =
        tauri::async_runtime::spawn_blocking(move || app.runtime().restore_system_changes())
            .await
            .map_err(|e| CommandError::new(e.to_string()))?;
    let errors = report
        .items
        .iter()
        .filter_map(|item| item.error.as_deref())
        .collect::<Vec<_>>()
        .join("; ");
    state.app.state().update_recovery_status(
        state.app.runtime().system_proxy_active(),
        (!errors.is_empty()).then_some(errors),
    );
    Ok(report)
}

/// Runs a short in-process benchmark and returns the measured numbers.
///
/// This exists so the UI can show real performance rather than an assertion in
/// documentation, and so a user can confirm the engine is behaving on their own
/// machine.
#[tauri::command]
pub async fn benchmark(
    state: State<'_, DesktopState>,
    iterations: Option<usize>,
) -> CommandResult<BenchmarkDto> {
    let app = state.app.clone();
    tauri::async_runtime::spawn_blocking(move || benchmark_engine(&app, iterations))
        .await
        .map_err(|error| CommandError::new(error.to_string()))
}

fn benchmark_engine(app: &nullad_core::AppHandle, iterations: Option<usize>) -> BenchmarkDto {
    let iterations = iterations.unwrap_or(20_000).clamp(1_000, 2_000_000);
    let rule_set = app.state().engine.rule_set();
    let engine = &app.state().engine;

    // Build a request mix from the rules actually loaded, so the measurement
    // reflects what this installation really does.
    let requests: Vec<Request> = rule_set
        .rules()
        .take(512)
        .map(|rule| {
            let url = format!("https://{}/", guess_host(&rule.raw));
            Request::new(url, ResourceType::Other)
        })
        .collect();

    if requests.is_empty() {
        return BenchmarkDto {
            iterations: 0,
            rules: rule_set.len(),
            throughput_per_sec: 0.0,
            mean_us: 0.0,
            p50_us: 0.0,
            p99_us: 0.0,
        };
    }

    let mut scratch = MatchScratch::new();
    let mut samples: Vec<f64> = Vec::with_capacity(iterations);

    let started = Instant::now();
    for i in 0..iterations {
        let request = &requests[i % requests.len()];
        let t0 = Instant::now();
        let _ = engine.check_with(request, &mut scratch);
        samples.push(t0.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let total = started.elapsed().as_secs_f64();

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pick = |q: f64| -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let idx = (((samples.len() - 1) as f64) * q).round() as usize;
        samples[idx.min(samples.len() - 1)]
    };

    BenchmarkDto {
        iterations,
        rules: rule_set.len(),
        throughput_per_sec: if total > 0.0 {
            iterations as f64 / total
        } else {
            0.0
        },
        mean_us: samples.iter().sum::<f64>() / samples.len() as f64,
        p50_us: pick(0.50),
        p99_us: pick(0.99),
    }
}

/// Returns platform and capability information for the settings panel.
#[tauri::command]
pub fn platform_info(state: State<'_, DesktopState>) -> PlatformInfoDto {
    let status = state.app.status();
    PlatformInfoDto {
        platform: nullad_host::platform_description(),
        elevated: nullad_host::has_elevated_privileges(),
        data_dir: nullad_host::paths::data_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        config_dir: nullad_host::paths::config_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        rule_count: state.app.state().engine.rule_count(),
        running: state.app.state().is_running(),
        proxy_port: status.proxy_port,
        dns_port: status.dns_port,
    }
}

/// Guesses a host to exercise a rule with, for the benchmark request mix.
fn guess_host(raw: &str) -> String {
    let candidate = raw
        .trim_start_matches("@@")
        .trim_start_matches("||")
        .trim_start_matches('|')
        .trim_start_matches('/');

    let host: String = candidate
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();

    if host.is_empty() {
        "example.com".to_owned()
    } else {
        host
    }
}

/// Maps a UI resource-type name onto the engine mask.
fn parse_resource_type(name: &str) -> Option<ResourceType> {
    match name.to_ascii_lowercase().as_str() {
        "all" => Some(ResourceType::All),
        "script" => Some(ResourceType::Script),
        "image" => Some(ResourceType::Image),
        "stylesheet" => Some(ResourceType::Stylesheet),
        "object" => Some(ResourceType::Object),
        "xhr" | "xmlhttprequest" => Some(ResourceType::Xhr),
        "subdocument" => Some(ResourceType::Subdocument),
        "document" => Some(ResourceType::Document),
        "font" => Some(ResourceType::Font),
        "media" => Some(ResourceType::Media),
        "websocket" => Some(ResourceType::Websocket),
        "ping" => Some(ResourceType::Ping),
        "other" => Some(ResourceType::Other),
        _ => None,
    }
}

/// A filter list as the UI sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListInfoDto {
    /// Stable identifier.
    pub id: u32,
    /// Display name.
    pub name: String,
    /// Where the list loads from.
    pub source: String,
    /// Whether it is applied.
    pub enabled: bool,
    /// Rules contributed.
    pub rules: usize,
    /// Rules quarantined.
    pub failures: usize,
    /// Cosmetic rules seen but not applied.
    pub cosmetic: usize,
}

impl From<nullad_core::state::ListSummary> for ListInfoDto {
    fn from(summary: nullad_core::state::ListSummary) -> Self {
        Self {
            id: summary.id,
            name: summary.name,
            source: summary.source,
            enabled: summary.enabled,
            rules: summary.rules,
            failures: summary.failures,
            cosmetic: summary.cosmetic,
        }
    }
}

/// One parsed rule, for the rule viewer.
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfoDto {
    /// `block` or `allow`.
    pub action: String,
    /// Debug rendering of the parsed pattern.
    pub pattern: String,
    /// The original rule text.
    pub raw: String,
    /// Line in the source list.
    pub source_line: usize,
    /// Contributing list id.
    pub list_id: u32,
}

/// The outcome of evaluating one URL.
#[derive(Debug, Clone, Serialize)]
pub struct CheckOutcomeDto {
    /// The URL evaluated.
    pub url: String,
    /// Its extracted host.
    pub host: String,
    /// Whether it would be blocked.
    pub blocked: bool,
    /// The deciding rule.
    pub rule: Option<String>,
    /// How many rules matched in total.
    pub matched: usize,
    /// Decision reason, including offline advertising features and explicit allow hosts.
    pub reason: Option<String>,
    /// Feature strength, not a probability.
    pub score: Option<u8>,
}

/// The outcome of a list reload.
#[derive(Debug, Clone, Serialize)]
pub struct ReloadResultDto {
    /// Total rules indexed.
    pub rules: usize,
    /// Total rules quarantined.
    pub failures: usize,
    /// Non-fatal problems.
    pub warnings: Vec<String>,
    /// Wall-clock duration.
    pub elapsed_ms: f64,
}

/// A system change awaiting restoration.
#[derive(Debug, Clone, Serialize)]
pub struct PendingChangeDto {
    /// Which subsystem was changed.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// When it was applied.
    pub applied_at_ms: u64,
}

/// Measured engine performance.
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkDto {
    /// Iterations measured.
    pub iterations: usize,
    /// Rules in the active set.
    pub rules: usize,
    /// Requests per second.
    pub throughput_per_sec: f64,
    /// Mean latency in microseconds.
    pub mean_us: f64,
    /// Median latency in microseconds.
    pub p50_us: f64,
    /// 99th percentile latency in microseconds.
    pub p99_us: f64,
}

/// Platform and capability information.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfoDto {
    /// Operating system and architecture.
    pub platform: String,
    /// Whether the process has administrative rights.
    pub elevated: bool,
    /// Per-user data directory.
    pub data_dir: String,
    /// Per-user configuration directory.
    pub config_dir: String,
    /// Rules currently loaded.
    pub rule_count: usize,
    /// Whether protection is running.
    pub running: bool,
    /// Actual bound proxy port.
    pub proxy_port: Option<u16>,
    /// Actual bound DNS port.
    pub dns_port: Option<u16>,
}

/// Builds a throwaway rule set, used by tests and diagnostics.
#[must_use]
pub fn build_rule_set(list: &str) -> Option<nullad_engine::RuleSet> {
    let mut builder = RuleSetBuilder::new();
    builder.add_list_auto(list);
    builder.build().ok()
}

impl From<nullad_core::LoadOutcome> for ReloadResultDto {
    fn from(outcome: nullad_core::LoadOutcome) -> Self {
        Self {
            rules: outcome.total_rules,
            failures: outcome.total_failures,
            warnings: outcome.warnings,
            elapsed_ms: outcome.elapsed_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RuleDirectory(std::path::PathBuf);

    impl RuleDirectory {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "nullad-custom-rules-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> std::path::PathBuf {
            self.0.join("custom-rules.txt")
        }
    }

    impl Drop for RuleDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn existing_custom_id_rebinds_source_without_replacing_other_lists() {
        let mut settings = AppSettings::default();
        let other_lists = settings.lists.clone();
        settings.lists.push(nullad_core::ListEntry {
            id: 9_000,
            name: "My custom rules".into(),
            source: ListSource::Remote {
                url: "https://example.com/old-list".into(),
            },
            enabled: true,
        });
        let path = std::path::Path::new("correct/custom-rules.txt");
        update_custom_entry(&mut settings, path, false);
        let custom = settings.lists.last().unwrap();
        assert_eq!(custom.name, "My custom rules");
        assert_eq!(
            custom.source,
            ListSource::Local {
                path: path.display().to_string()
            }
        );
        assert!(!custom.enabled);
        assert_eq!(&settings.lists[..other_lists.len()], &other_lists);
        assert_eq!(
            settings
                .lists
                .iter()
                .filter(|list| list.id == 9_000)
                .count(),
            1
        );
    }

    #[test]
    fn custom_rule_persistence_failure_restores_previous_bytes() {
        let directory = RuleDirectory::new();
        let path = directory.path();
        std::fs::write(&path, b"||old.example^\n").unwrap();
        let error = persist_custom_rules(&path, "||new.example^", || {
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "||new.example^");
            Err(CommandError::new("settings write denied"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("settings write denied"));
        assert_eq!(std::fs::read(&path).unwrap(), b"||old.example^\n");
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn first_custom_rule_persistence_failure_leaves_no_new_file() {
        let directory = RuleDirectory::new();
        let path = directory.path();
        assert!(persist_custom_rules(&path, "||new.example^", || {
            Err(CommandError::new("settings write denied"))
        })
        .is_err());
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn failed_custom_rule_restore_retains_a_recoverable_backup() {
        let directory = RuleDirectory::new();
        let path = directory.path();
        std::fs::write(&path, b"previous bytes").unwrap();
        let error = persist_custom_rules(&path, "new bytes", || {
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            Err(CommandError::new("settings write denied"))
        })
        .unwrap_err();
        let backup = std::fs::read_dir(&directory.0)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.path().is_file())
            .unwrap()
            .path();
        assert_eq!(std::fs::read(&backup).unwrap(), b"previous bytes");
        assert!(error.to_string().contains(&backup.display().to_string()));
    }

    #[test]
    fn unreadable_previous_custom_file_aborts_before_persistence() {
        let directory = RuleDirectory::new();
        let path = directory.path();
        std::fs::create_dir(&path).unwrap();
        assert!(persist_custom_rules(&path, "new bytes", || {
            panic!("must not publish settings after a read error")
        })
        .is_err());
        assert!(path.is_dir());
    }

    #[test]
    fn successful_custom_save_removes_the_temporary_backup() {
        let directory = RuleDirectory::new();
        let path = directory.path();
        std::fs::write(&path, b"previous bytes").unwrap();
        persist_custom_rules(&path, "new bytes", || Ok(())).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new bytes");
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn resource_type_names_parse() {
        assert_eq!(parse_resource_type("script"), Some(ResourceType::Script));
        assert_eq!(parse_resource_type("XHR"), Some(ResourceType::Xhr));
        assert_eq!(parse_resource_type("bogus"), None);
    }

    #[test]
    fn host_guessing_handles_every_rule_shape() {
        assert_eq!(guess_host("||ads.example.com^"), "ads.example.com");
        assert_eq!(guess_host("@@||safe.example.com^"), "safe.example.com");
        assert_eq!(guess_host("|http://x.example.com/path"), "http");
        assert_eq!(guess_host("/banner.gif"), "banner.gif");
        // A rule with no host-like text must still produce something usable.
        assert_eq!(guess_host("^"), "example.com");
    }

    #[test]
    fn throwaway_rule_sets_build() {
        assert!(build_rule_set("||ads.example.com^").is_some());
        assert!(build_rule_set("").is_none());
    }
}
