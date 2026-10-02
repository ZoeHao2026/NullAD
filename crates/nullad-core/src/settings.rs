//! Persisted application settings.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use nullad_host::journal::ChangeJournal;
use nullad_host::paths;

/// Where a filter list comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        let path = paths::settings_path()?;
        let temp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| nullad_host::HostError::Config(format!("serialize: {e}")))?;

        std::fs::write(&temp, text)
            .map_err(|e| nullad_host::HostError::Config(format!("{}: {e}", temp.display())))?;
        std::fs::rename(&temp, &path)
            .map_err(|e| nullad_host::HostError::Config(format!("{}: {e}", path.display())))?;
        Ok(())
    }

    /// Returns the enabled lists.
    #[must_use]
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
    fn corrupt_json_is_an_error_not_a_default() {
        // Deserialization itself must reject nonsense; `load` is what falls back.
        assert!(serde_json::from_str::<AppSettings>("not json").is_err());
    }
}
