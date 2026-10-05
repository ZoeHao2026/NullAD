//! Persisted application settings.

use std::path::{Path, PathBuf};

use nullad_api::HeuristicMode;
use nullad_intercept::{DetectionPolicy, UpstreamProxy};
use serde::{Deserialize, Serialize};

use nullad_host::journal::ChangeJournal;
use nullad_host::paths;

/// Where a filter list comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListSource {
    /// A file shipped with NullAD.
    Bundled {
        /// Path relative to the application directory.
        file: String,
    },
    /// A file the user added.
    Local {
        /// Absolute or workspace-relative path.
        path: String,
    },
    /// A remote list, fetched over HTTP.
    ///
    /// Fetching is implemented but cannot be exercised on a host without a
    /// working TLS stack, so the update path is verified against local and
    /// loopback sources instead.
    Remote {
        /// URL of the list.
        url: String,
    },
}

impl ListSource {
    /// A short human-readable description.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Bundled { file } => format!("bundled:{file}"),
            Self::Local { path } => path.clone(),
            Self::Remote { url } => url.clone(),
        }
    }
}

/// User-visible configuration, persisted as JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    /// Enabled filter lists.
    pub lists: Vec<ListEntry>,

    /// Offline advertising detection, independent of filter lists.
    pub heuristic_mode: HeuristicMode,
    /// Explicit domains and their subdomains always allowed by the policy.
    pub allowed_hosts: Vec<String>,
    /// Optional HTTP/SOCKS5 route used by the local HTTP proxy.
    pub upstream_proxy: Option<String>,

    /// Port the HTTP proxy listens on.
    pub proxy_port: u16,
    /// Start the proxy automatically.
    pub proxy_enabled: bool,

    /// Port the DNS sinkhole listens on. Port 53 needs elevation.
    pub dns_port: u16,
    /// Start the DNS sinkhole automatically.
    pub dns_enabled: bool,
    /// Upstream resolver for non-blocked queries.
    pub dns_upstream: String,
    /// Answer blocked queries with NXDOMAIN rather than a sinkhole address.
    pub dns_nxdomain: bool,

    /// Route the operating system's proxy through NullAD while running.
    pub intercept_system_proxy: bool,

    /// Reload lists automatically when a watched file changes.
    pub watch_lists: bool,

    /// Surface a desktop notification when a rule set is reloaded.
    pub notify_on_reload: bool,

    /// Log verbosity: `error`, `warn`, `info`, `debug`, or `trace`.
    pub log_level: String,
    /// Desktop interface language: Simplified Chinese or English.
    pub ui_language: String,
}

/// A filter list entry in the settings file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListEntry {
    /// Stable identifier, unique within the settings file.
    pub id: u32,
    /// Display name.
    pub name: String,
    /// Where the list is loaded from.
    pub source: ListSource,
    /// Whether the list is currently applied.
    pub enabled: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            lists: vec![
                ListEntry {
                    id: 1,
                    name: "NullAD Base".into(),
                    source: ListSource::Bundled {
                        file: "nullad-base.txt".into(),
                    },
                    enabled: true,
                },
                ListEntry {
                    id: 2,
                    name: "Hosts-style trackers".into(),
                    source: ListSource::Bundled {
                        file: "nullad-hosts.txt".into(),
                    },
                    enabled: true,
                },
            ],
            heuristic_mode: HeuristicMode::Balanced,
            allowed_hosts: Vec::new(),
            upstream_proxy: None,
            proxy_port: 8080,
            proxy_enabled: true,
            dns_port: 5353,
            dns_enabled: false,
            dns_upstream: "8.8.8.8:53".into(),
            dns_nxdomain: false,
            intercept_system_proxy: false,
            watch_lists: true,
            notify_on_reload: false,
            log_level: "info".into(),
            ui_language: "zh-CN".into(),
        }
    }
}

impl AppSettings {
    /// Loads settings from disk, falling back to defaults.
    ///
    /// A missing file is normal on first run. A corrupt file is also tolerated:
    /// refusing to start because a JSON file was truncated would turn a minor
    /// problem into an unusable application. The bad file is preserved for
    /// inspection rather than silently overwritten.
    #[must_use]
    pub fn load() -> Self {
        let Ok(path) = paths::settings_path() else {
            return Self::default();
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match serde_json::from_str::<Self>(&text) {
            Ok(settings) => settings,
            Err(err) => {
                tracing::warn!(error = %err, path = %path.display(), "settings file is unreadable; using defaults");
                let backup = path.with_extension("json.corrupt");
                if let Err(rename_err) = std::fs::rename(&path, &backup) {
                    tracing::warn!(error = %rename_err, "could not preserve the unreadable settings file");
                }
                Self::default()
            }
        }
    }

    /// Saves settings to disk atomically.
    pub fn save(&self) -> Result<(), nullad_host::HostError> {
        self.save_at(&paths::settings_path()?)
    }

    /// Saves to a specific location for isolated tests and controlled deployments.
    pub fn save_at(&self, path: &Path) -> Result<(), nullad_host::HostError> {
        let text = serde_json::to_vec_pretty(self)
            .map_err(|e| nullad_host::HostError::Config(format!("serialize: {e}")))?;
        nullad_host::journal::atomic_write(path, &text)
            .map_err(|e| nullad_host::HostError::Config(format!("{}: {e}", path.display())))
    }

    /// Canonicalizes user input before persistence and policy publication.
    pub fn normalize(&mut self) -> Result<(), nullad_host::HostError> {
        self.allowed_hosts = normalize_allowed_hosts(&self.allowed_hosts)?;
        self.upstream_proxy = self
            .upstream_proxy
            .take()
            .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_owned()));
        Ok(())
    }

    /// The policy shared by all interceptors, also available before startup.
    #[must_use]
    pub fn detection_policy(&self) -> DetectionPolicy {
        DetectionPolicy {
            mode: self.heuristic_mode,
            allowed_hosts: self.allowed_hosts.clone(),
        }
    }

    /// Validates a proposed configuration before it can be published.
    pub fn validate(&self) -> Result<(), nullad_host::HostError> {
        normalize_allowed_hosts(&self.allowed_hosts)?;
        if let Some(value) = self
            .upstream_proxy
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            value
                .parse::<UpstreamProxy>()
                .map_err(nullad_host::HostError::Config)?;
        }
        if !matches!(self.ui_language.as_str(), "zh-CN" | "en") {
            return Err(nullad_host::HostError::Config(
                "ui_language must be zh-CN or en".into(),
            ));
        }
        if self.proxy_port == 0 || self.dns_port == 0 {
            return Err(nullad_host::HostError::Config(
                "listener ports must be between 1 and 65535".into(),
            ));
        }
        if self.intercept_system_proxy && !self.proxy_enabled {
            return Err(nullad_host::HostError::Config(
                "system proxy routing requires an enabled proxy".into(),
            ));
        }
        if self.dns_enabled && self.dns_upstream.trim().is_empty() {
            return Err(nullad_host::HostError::Config(
                "DNS upstream cannot be empty".into(),
            ));
        }
        Ok(())
    }

    /// Listener-affecting fields that require a restart after editing.
    pub fn same_listener_settings(&self, other: &Self) -> bool {
        self.proxy_port == other.proxy_port
            && self.proxy_enabled == other.proxy_enabled
            && self.upstream_proxy == other.upstream_proxy
            && self.dns_port == other.dns_port
            && self.dns_enabled == other.dns_enabled
            && self.dns_upstream == other.dns_upstream
            && self.dns_nxdomain == other.dns_nxdomain
            && self.intercept_system_proxy == other.intercept_system_proxy
    }

    /// Returns the enabled lists.
    pub fn enabled_lists(&self) -> impl Iterator<Item = &ListEntry> {
        self.lists.iter().filter(|entry| entry.enabled)
    }

    /// Resolves a bundled list file against the application's list directory.
    ///
    /// Bundled lists are looked for next to the executable first, then in the
    /// working directory, so both an installed layout and a development checkout
    /// work without configuration.
    #[must_use]
    pub fn resolve_bundled(file: &str) -> Option<PathBuf> {
        let mut candidates = Vec::new();

        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("lists").join(file));
                candidates.push(dir.join(file));
            }
        }
        candidates.push(PathBuf::from("lists").join(file));
        if let Ok(dir) = paths::data_dir() {
            candidates.push(dir.join("lists").join(file));
        }

        candidates.into_iter().find(|path| path.is_file())
    }

    /// Returns the number of changes still un-reverted from an earlier run.
    #[must_use]
    pub fn pending_changes() -> usize {
        ChangeJournal::pending().len()
    }
}

/// A settings command updates only the fields actually supplied by its caller.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SettingsPatch {
    pub heuristic_mode: Option<HeuristicMode>,
    pub allowed_hosts: Option<Vec<String>>,
    /// An empty string clears the upstream; an omitted field preserves it.
    pub upstream_proxy: Option<String>,
    pub proxy_port: Option<u16>,
    pub proxy_enabled: Option<bool>,
    pub dns_port: Option<u16>,
    pub dns_enabled: Option<bool>,
    pub dns_upstream: Option<String>,
    pub dns_nxdomain: Option<bool>,
    pub intercept_system_proxy: Option<bool>,
    pub watch_lists: Option<bool>,
    pub notify_on_reload: Option<bool>,
    pub log_level: Option<String>,
    pub ui_language: Option<String>,
}

impl SettingsPatch {
    pub fn apply_to(self, settings: &mut AppSettings) {
        macro_rules! field {
            ($name:ident) => {
                if let Some(value) = self.$name {
                    settings.$name = value;
                }
            };
        }
        field!(heuristic_mode);
        field!(allowed_hosts);
        if let Some(value) = self.upstream_proxy {
            settings.upstream_proxy = (!value.trim().is_empty()).then(|| value.trim().to_owned());
        }
        field!(proxy_port);
        field!(proxy_enabled);
        field!(dns_port);
        field!(dns_enabled);
        field!(dns_upstream);
        field!(dns_nxdomain);
        field!(intercept_system_proxy);
        field!(watch_lists);
        field!(notify_on_reload);
        field!(log_level);
        field!(ui_language);
    }
}

/// Validates bare hosts, normalizes IDNA/case/trailing dots, and removes duplicates.
/// Hostnames include subdomains; IP literals remain exact matches.
pub fn normalize_allowed_hosts(hosts: &[String]) -> Result<Vec<String>, nullad_host::HostError> {
    let mut normalized = Vec::new();
    for value in hosts {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let literal = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(value);
        let ip = literal.parse::<std::net::IpAddr>().ok();
        let host = if let Some(ip) = ip {
            match ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            }
        } else {
            if value.contains(['/', '?', '#', '@', '*', ':'])
                || value.chars().any(char::is_whitespace)
            {
                return Err(nullad_host::HostError::Config(
                    "allowed_hosts requires bare domains or IP addresses".into(),
                ));
            }
            let host = nullad_engine::request::extract_host(value)
                .ok_or_else(|| nullad_host::HostError::Config("invalid allowed host".into()))?;
            if host.len() > 253
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            {
                return Err(nullad_host::HostError::Config(
                    "invalid allowed domain".into(),
                ));
            }
            host
        };
        if !normalized.contains(&host) {
            normalized.push(host);
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_the_bundled_lists_and_the_proxy() {
        let settings = AppSettings::default();
        assert_eq!(settings.enabled_lists().count(), 2);
        assert!(settings.proxy_enabled);
        // DNS needs elevation, so it must be off by default.
        assert!(!settings.dns_enabled);
        // System proxy modification is invasive, so it is opt-in.
        assert!(!settings.intercept_system_proxy);
    }

    #[test]
    fn settings_round_trip_through_json() {
        let settings = AppSettings::default();
        let text = serde_json::to_string(&settings).unwrap();
        let restored: AppSettings = serde_json::from_str(&text).unwrap();
        assert_eq!(settings, restored);
    }

    #[test]
    fn partial_json_fills_in_defaults() {
        // This is the important forward-compatibility property: adding a field
        // must not invalidate an existing settings file.
        let partial = r#"{"proxy_port": 9090}"#;
        let settings: AppSettings = serde_json::from_str(partial).unwrap();
        assert_eq!(settings.proxy_port, 9090);
        assert_eq!(settings.lists.len(), 2, "defaults must fill the gap");
        assert_eq!(settings.log_level, "info");
    }

    #[test]
    fn list_sources_describe_themselves() {
        assert_eq!(
            ListSource::Bundled {
                file: "a.txt".into()
            }
            .describe(),
            "bundled:a.txt"
        );
        assert_eq!(
            ListSource::Remote {
                url: "http://x/a.txt".into()
            }
            .describe(),
            "http://x/a.txt"
        );
    }

    #[test]
    fn policy_defaults_and_patches_are_backward_compatible() {
        let mut settings: AppSettings = serde_json::from_str(r#"{"proxy_port":9090}"#).unwrap();
        assert_eq!(settings.heuristic_mode, HeuristicMode::Balanced);
        assert!(settings.allowed_hosts.is_empty());
        assert_eq!(settings.upstream_proxy, None);
        settings.upstream_proxy = Some("http://127.0.0.1:7890".into());
        let patch: SettingsPatch = serde_json::from_str(r#"{"heuristic_mode":"off","allowed_hosts":["EXAMPLE.com.","例え.jp"],"upstream_proxy":""}"#).unwrap();
        patch.apply_to(&mut settings);
        settings.normalize().unwrap();
        settings.validate().unwrap();
        assert_eq!(settings.heuristic_mode, HeuristicMode::Off);
        assert_eq!(settings.allowed_hosts, ["example.com", "xn--r8jz45g.jp"]);
        assert_eq!(settings.upstream_proxy, None);
    }

    #[test]
    fn policy_edits_do_not_require_listener_restart_but_upstream_does() {
        let original = AppSettings::default();
        let mut edited = original.clone();
        edited.heuristic_mode = HeuristicMode::Off;
        edited.allowed_hosts.push("example.com".into());
        assert!(original.same_listener_settings(&edited));
        edited.upstream_proxy = Some("socks5://127.0.0.1:7890".into());
        assert!(!original.same_listener_settings(&edited));
    }

    #[test]
    fn host_normalization_rejects_urls_ports_and_wildcards() {
        for invalid in [
            "https://example.com",
            "example.com/path",
            "*.example.com",
            "example.com:80",
            "bad domain",
            "-bad.example",
        ] {
            assert!(
                normalize_allowed_hosts(&[invalid.into()]).is_err(),
                "{invalid}"
            );
        }
        assert_eq!(
            normalize_allowed_hosts(&[
                "EXAMPLE.com.".into(),
                "example.com".into(),
                "::1".into(),
                "[::1]".into()
            ])
            .unwrap(),
            ["example.com", "[::1]"]
        );
        let mut settings = AppSettings {
            upstream_proxy: Some("http://user:pass@example.com:80".into()),
            ..AppSettings::default()
        };
        assert!(settings.validate().is_err());
        settings.upstream_proxy = Some("  ".into());
        settings.normalize().unwrap();
        assert_eq!(settings.upstream_proxy, None);
    }

    #[test]
    fn corrupt_json_is_an_error_not_a_default() {
        // Deserialization itself must reject nonsense; `load` is what falls back.
        assert!(serde_json::from_str::<AppSettings>("not json").is_err());
    }
}
