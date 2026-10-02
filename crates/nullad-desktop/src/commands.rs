//! The Tauri command surface.
//!
//! Every function here is a thin translation between the UI's JSON and
//! `nullad-core`'s typed API. No filtering logic lives in this file, which is
//! what keeps the GUI swappable: replacing the web UI means replacing these
//! bindings and nothing else.

use std::sync::Arc;
use std::time::Instant;

use nullad_core::{AppSettings, ListSource, ProtectionStatus};
use nullad_engine::{MatchScratch, Request, ResourceType, RuleSetBuilder};
use nullad_intercept::dns::resolve_upstream;
use nullad_intercept::{DnsConfig, DnsServer, ProxyConfig, ProxyServer};
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
pub fn recent_decisions(state: State<'_, DesktopState>, limit: Option<usize>) -> Vec<nullad_core::LogEntry> {
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

    let mut scratch = MatchScratch::new();
    let result = state.app.state().engine.check_with(&request, &mut scratch);

    CheckOutcomeDto {
        url: request.url.clone(),
        host: request.host.clone(),
        blocked: result.blocked,
        rule: result.matched_rule.as_ref().map(|r| r.raw.clone()),
        matched: result.matched_rule_ids.len(),
    }
}

/// Returns the persisted settings.
#[tauri::command]
pub fn get_settings(state: State<'_, DesktopState>) -> AppSettings {
    state.app.state().settings()
}

/// Persists new settings and reloads lists if the list configuration changed.
#[tauri::command]
pub fn update_settings(
    state: State<'_, DesktopState>,
    settings: AppSettings,
) -> CommandResult<Vec<String>> {
    let previous = state.app.state().settings();
    let lists_changed = previous.lists != settings.lists;

    state.app.state().update_settings(settings)?;

    let mut warnings = Vec::new();
    if lists_changed {
        warnings = state.app.reload().warnings;
    }
    Ok(warnings)
}

/// Reloads every enabled list and returns any warnings.
#[tauri::command]
pub fn reload_lists(state: State<'_, DesktopState>) -> ReloadResultDto {
    let outcome = state.app.reload();
    ReloadResultDto {
        rules: outcome.total_rules,
        failures: outcome.total_failures,
        warnings: outcome.warnings,
        elapsed_ms: outcome.elapsed_ms,
    }
}

/// Enables or disables one filter list and reloads.
#[tauri::command]
pub fn set_list_enabled(
    state: State<'_, DesktopState>,
    id: u32,
    enabled: bool,
) -> CommandResult<ReloadResultDto> {
    let mut settings = state.app.state().settings();
    let Some(entry) = settings.lists.iter_mut().find(|entry| entry.id == id) else {
        return Err(CommandError::new(format!("no filter list with id {id}")));
    };
    entry.enabled = enabled;
    state.app.state().update_settings(settings)?;

    let outcome = state.app.reload();
    Ok(ReloadResultDto {
        rules: outcome.total_rules,
        failures: outcome.total_failures,
        warnings: outcome.warnings,
        elapsed_ms: outcome.elapsed_ms,
    })
}

/// Adds a user-supplied rule as a local list, replacing any previous one.
///
/// Custom rules are held as a real list rather than a special case, so they go
/// through exactly the same parsing and indexing path as everything else.
#[tauri::command]
pub fn set_custom_rules(state: State<'_, DesktopState>, rules: String) -> CommandResult<ReloadResultDto> {
    let dir = nullad_host::paths::config_dir()?;
    let path = dir.join("custom-rules.txt");

    std::fs::write(&path, &rules)
        .map_err(|e| CommandError::new(format!("cannot write {}: {e}", path.display())))?;

    let mut settings = state.app.state().settings();
    const CUSTOM_ID: u32 = 9_000;

    match settings.lists.iter_mut().find(|entry| entry.id == CUSTOM_ID) {
        Some(entry) => {
            entry.enabled = !rules.trim().is_empty();
        }
        None => settings.lists.push(nullad_core::ListEntry {
            id: CUSTOM_ID,
            name: "Custom rules".into(),
            source: ListSource::Local {
                path: path.display().to_string(),
            },
            enabled: !rules.trim().is_empty(),
        }),
    }

    state.app.state().update_settings(settings)?;
    let outcome = state.app.reload();
    Ok(ReloadResultDto {
        rules: outcome.total_rules,
        failures: outcome.total_failures,
        warnings: outcome.warnings,
        elapsed_ms: outcome.elapsed_ms,
    })
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
    if state.app.state().is_running() {
        return Err(CommandError::new("protection is already running"));
    }

    let settings = state.app.state().settings();
    let handle = state.app.state().engine_handle();
    let mut notes = Vec::new();

    state.app.runtime().arm();

    if settings.proxy_enabled {
        let config = ProxyConfig {
            listen: format!("127.0.0.1:{}", settings.proxy_port)
                .parse()
                .map_err(|e| CommandError::new(format!("invalid proxy port: {e}")))?,
            ..ProxyConfig::default()
        };

        let server = ProxyServer::bind(config, handle.clone())
            .await
            .map_err(|e| {
                CommandError::new(format!(
                    "could not bind the HTTP proxy on port {}: {e}",
                    settings.proxy_port
                ))
            })?;
        let server = Arc::new(server);
        let addr = server
            .local_addr()
            .map_err(|e| CommandError::new(format!("proxy address unavailable: {e}")))?;

        state
            .tasks
            .push(tauri::async_runtime::spawn(async move { server.run().await }));
        notes.push(format!("HTTP proxy listening on {addr}"));
    }

    if settings.dns_enabled {
        let upstream = resolve_upstream(&settings.dns_upstream)
            .ok_or_else(|| CommandError::new(format!("invalid DNS upstream `{}`", settings.dns_upstream)))?;

        let config = DnsConfig {
            listen: format!("127.0.0.1:{}", settings.dns_port)
                .parse()
                .map_err(|e| CommandError::new(format!("invalid DNS port: {e}")))?,
            upstream,
            nxdomain: settings.dns_nxdomain,
            ..DnsConfig::default()
        };

        match DnsServer::bind(config, handle.clone()).await {
            Ok(server) => {
                let server = Arc::new(server);
                let addr = server.local_addr().map_err(|e| {
                    CommandError::new(format!("DNS address unavailable: {e}"))
                })?;
                state
                    .tasks
                    .push(tauri::async_runtime::spawn(async move { server.run().await }));
                state.app.runtime().set_dns_active(true);
                notes.push(format!("DNS sinkhole listening on {addr}"));
            }
            Err(err) => {
                // DNS failing to bind must not stop the proxy, which needs no
                // privileges and still provides value.
                notes.push(format!(
                    "DNS sinkhole unavailable on port {}: {err}. Ports below 1024 need \
                     administrator rights; try a port above 1024.",
                    settings.dns_port
                ));
            }
        }
    }

    if settings.intercept_system_proxy {
        match nullad_host::SystemProxy::new(format!("127.0.0.1:{}", settings.proxy_port)) {
            Ok(mut proxy) => match proxy.apply() {
                Ok(previous) => {
                    state.app.runtime().set_system_proxy_active(true);
                    notes.push(format!(
                        "system proxy routed through NullAD (was: {})",
                        previous
                            .server
                            .as_deref()
                            .unwrap_or("no proxy configured")
                    ));
                }
                Err(err) => notes.push(format!(
                    "could not route the system proxy through NullAD: {err}"
                )),
            },
            Err(err) => notes.push(format!("system proxy adapter unavailable: {err}")),
        }
    }

    state.app.state().set_running(true);
    Ok(notes)
}

/// Stops the interceptors and restores any system changes NullAD made.
#[tauri::command]
pub fn stop_protection(state: State<'_, DesktopState>) -> CommandResult<Vec<String>> {
    let mut notes = Vec::new();

    let stopped = state.tasks.abort_all();
    if stopped > 0 {
        notes.push(format!("stopped {stopped} interceptor task(s)"));
    }

    state.app.runtime().request_stop();

    // Restoring system settings is not optional: leaving the OS pointing at a
    // proxy that is no longer running would break the user's networking.
    if state.app.runtime().system_proxy_active() {
        match nullad_host::SystemProxy::new("127.0.0.1:0") {
            Ok(mut proxy) => match proxy.revert() {
                Ok(Some(restored)) => {
                    state.app.runtime().set_system_proxy_active(false);
                    notes.push(format!(
                        "restored the system proxy (now: {})",
                        restored.server.as_deref().unwrap_or("disabled")
                    ));
                }
                Ok(None) => {
                    state.app.runtime().set_system_proxy_active(false);
                }
                Err(err) => notes.push(format!("could not restore the system proxy: {err}")),
            },
            Err(err) => notes.push(format!("system proxy adapter unavailable: {err}")),
        }
    }

    state.app.runtime().set_dns_active(false);
    state.app.state().set_running(false);
    Ok(notes)
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
pub fn restore_system_changes(state: State<'_, DesktopState>) -> Vec<String> {
    state.app.runtime().restore_system_changes();
    state.app.runtime().set_system_proxy_active(false);
    state.app.runtime().set_dns_active(false);
    vec!["restored every recorded system change".to_owned()]
}

/// Runs a short in-process benchmark and returns the measured numbers.
///
/// This exists so the UI can show real performance rather than an assertion in
/// documentation, and so a user can confirm the engine is behaving on their own
/// machine.
#[tauri::command]
pub fn benchmark(state: State<'_, DesktopState>, iterations: Option<usize>) -> BenchmarkDto {
    let iterations = iterations.unwrap_or(20_000).clamp(1_000, 2_000_000);
    let rule_set = state.app.state().engine.rule_set();
    let engine = &state.app.state().engine;

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
    let settings = state.app.state().settings();
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
        proxy_port: settings.proxy_port,
        dns_port: settings.dns_port,
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
    /// Configured proxy port.
    pub proxy_port: u16,
    /// Configured DNS port.
    pub dns_port: u16,
}

/// Builds a throwaway rule set, used by tests and diagnostics.
#[must_use]
pub fn build_rule_set(list: &str) -> Option<nullad_engine::RuleSet> {
    let mut builder = RuleSetBuilder::new();
    builder.add_list_auto(list);
    builder.build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
