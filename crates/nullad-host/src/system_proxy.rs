//! System HTTP proxy configuration.
//!
//! Routing the operating system's proxy through NullAD is what makes the
//! application useful without changing any browser settings. It is also the
//! most invasive thing NullAD does, so it is built around three rules:
//!
//! 1. Read and return the complete previous state before touching anything.
//! 2. Journal the change before applying it.
//! 3. Restore exactly the captured state, including the "was disabled" case.
//!
//! ## Platform support
//!
//! * **Windows** — per-user `HKCU\...\Internet Settings`. No elevation needed,
//!   which is why it is the primary verified target. Changes are broadcast with
//!   `InternetSetOption` so running applications notice immediately.
//! * **macOS** — `networksetup` against the active network service. This shells
//!   out rather than reading a plist because `networksetup` is the only
//!   supported way to change the setting and have the system apply it live.
//! * **Linux** — `gsettings` for GNOME, plus a documented environment-variable
//!   fallback, since there is no single system-wide proxy setting across
//!   distributions.

use serde::{Deserialize, Serialize};

use crate::journal::{ChangeJournal, JournalEntry, JournalKind};
use crate::{platform, HostError, Result};

/// A registry value as stored, without normalizing type, encoding or empty data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValueSnapshot {
    pub value_type: u32,
    pub bytes: Vec<u8>,
}

/// All registry values modified by the Windows proxy adapter.
/// A present map key with None records absence; a missing map key is incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProxySnapshot {
    pub values: std::collections::BTreeMap<String, Option<RegistryValueSnapshot>>,
}

/// The system proxy state NullAD found, or set.
///
/// Capturing *all* of these fields matters: restoring only the server address
/// while leaving the bypass list modified is a subtly broken restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySettings {
    /// Whether a proxy is enabled for plaintext HTTP.
    pub enabled: bool,
    /// The `host:port` in effect, when one is.
    pub server: Option<String>,
    /// The semicolon- or comma-separated bypass list.
    pub bypass: Option<String>,
    /// The proxy auto-configuration URL, if one is set.
    pub auto_config_url: Option<String>,
    /// Exact Windows values, required when restoring a Windows snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_registry: Option<WindowsProxySnapshot>,
}

impl ProxySettings {
    /// A settings value describing "no proxy configured".
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            server: None,
            bypass: None,
            auto_config_url: None,
            windows_registry: None,
        }
    }

    /// The default bypass list, so NullAD never proxies its own traffic or any
    /// loopback and private-range destination.
    pub const DEFAULT_BYPASS: &'static str =
        "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;\
172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

    /// Returns settings that route traffic through NullAD.
    #[must_use]
    pub fn routing_through(listen: &str) -> Self {
        Self {
            enabled: true,
            server: Some(listen.to_owned()),
            bypass: Some(Self::DEFAULT_BYPASS.to_owned()),
            auto_config_url: None,
            windows_registry: None,
        }
    }

    /// Returns `true` when these settings already point at `listen`.
    #[must_use]
    pub fn points_at(&self, listen: &str) -> bool {
        self.enabled && self.server.as_deref() == Some(listen)
    }
}

/// Injectable system adapter. Tests provide a mock and never touch live settings.
pub trait ProxyBackend: std::fmt::Debug + Send + Sync {
    fn read(&self) -> Result<ProxySettings>;
    fn write(&self, settings: &ProxySettings) -> Result<()>;
    /// Recovery can require richer metadata than a newly generated desired state.
    fn restore(&self, settings: &ProxySettings) -> Result<()> {
        self.write(settings)
    }
}

#[derive(Debug)]
struct PlatformBackend;
impl ProxyBackend for PlatformBackend {
    fn read(&self) -> Result<ProxySettings> {
        platform::read_proxy()
    }
    fn write(&self, settings: &ProxySettings) -> Result<()> {
        platform::write_proxy(settings)
    }
    fn restore(&self, settings: &ProxySettings) -> Result<()> {
        platform::restore_proxy_settings(settings)
    }
}

/// Read, apply, and revert the system HTTP proxy.
#[derive(Debug)]
pub struct SystemProxy {
    listen: String,
    journal: ChangeJournal,
    backend: std::sync::Arc<dyn ProxyBackend>,
}

impl SystemProxy {
    /// Creates an adapter that will point the system at `listen`.
    ///
    /// The journal is loaded eagerly so that a pending change from a previous
    /// run is visible before anything new is applied.
    pub fn new(listen: impl Into<String>) -> Result<Self> {
        Ok(Self {
            listen: listen.into(),
            journal: ChangeJournal::load()?,
            backend: std::sync::Arc::new(PlatformBackend),
        })
    }

    /// The address NullAD routes the system through.
    #[must_use]
    pub fn listen(&self) -> &str {
        &self.listen
    }

    /// Constructs an adapter with an isolated journal and an injectable backend.
    pub fn with_backend(
        listen: String,
        backend: std::sync::Arc<dyn ProxyBackend>,
        journal_path: std::path::PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            listen,
            backend,
            journal: ChangeJournal::load_at(journal_path)?,
        })
    }

    /// Reads the current system proxy settings.
    pub fn current(&self) -> Result<ProxySettings> {
        self.backend.read()
    }

    /// Returns `true` when the system is already routed through NullAD.
    pub fn is_applied(&self) -> Result<bool> {
        Ok(self.current()?.points_at(&self.listen))
    }

    /// Routes the system proxy through NullAD.
    ///
    /// Returns the state that was replaced, so a caller can restore it without
    /// consulting the journal.
    pub fn apply(&mut self) -> Result<ProxySettings> {
        self.apply_internal(None)
    }

    /// Preserve an existing proxy route by requiring explicit upstream chaining.
    /// PAC cannot be represented by a single static upstream, so browser-only
    /// protection is required while a PAC route remains configured.
    pub fn apply_chained(&mut self, upstream_configured: bool) -> Result<ProxySettings> {
        self.apply_internal(Some(upstream_configured))
    }

    fn apply_internal(&mut self, upstream_configured: Option<bool>) -> Result<ProxySettings> {
        let backend = std::sync::Arc::clone(&self.backend);
        let listen = self.listen.clone();
        self.journal.transaction(|journal| {
            let previous = backend.read()?;
            if upstream_configured.is_some() && previous.auto_config_url.as_deref().is_some_and(|url| !url.trim().is_empty()) {
                return Err(HostError::Config("A PAC route is configured. Use the NullAD browser extension without system proxy takeover to preserve that route.".into()));
            }
            if let Some(entry) = journal.original(JournalKind::SystemProxy) {
                if previous.points_at(&listen) {
                    return entry.before_as().ok_or_else(|| {
                        HostError::Journal("pending snapshot cannot be decoded".into())
                    });
                }
                return Err(HostError::Journal(
                    "restore the pending system change before applying a new one".into(),
                ));
            }
            if previous.points_at(&listen) {
                return Ok(previous);
            }
            if let Some(upstream_configured) = upstream_configured {
                if previous.enabled && !upstream_configured {
                    return Err(HostError::Config("An existing system proxy is enabled. Configure its HTTP/SOCKS5 endpoint as NullAD's upstream, or use the independent browser extension.".into()));
                }
            }
            let mut desired = ProxySettings::routing_through(&listen);
            if upstream_configured == Some(true) && previous.enabled {
                // Keep the original direct/proxied destination split. Adding
                // private-address bypasses here could bypass an existing route.
                desired.bypass = previous.bypass.clone();
            }
            journal.record_unlocked(JournalEntry::new(
                JournalKind::SystemProxy,
                serde_json::to_value(&previous).map_err(|e| HostError::Journal(e.to_string()))?,
                serde_json::to_value(&desired).map_err(|e| HostError::Journal(e.to_string()))?,
                "system settings routed through NullAD",
            ))?;
            if let Err(error) = backend.write(&desired) {
                // A multi-step write may already have changed part of the system.
                // Keep the original snapshot even if this rollback appears successful.
                let rollback = backend.restore(&previous);
                return Err(HostError::Platform(format!(
                    "apply failed: {error}; rollback: {}",
                    rollback.err().map_or_else(
                        || "completed; recovery snapshot retained".into(),
                        |e| e.to_string()
                    )
                )));
            }
            Ok(previous)
        })
    }

    /// Restores the state captured by the most recent [`Self::apply`].
    ///
    /// Returns the settings that were restored, or `None` when there was nothing
    /// pending.
    pub fn revert(&mut self) -> Result<Option<ProxySettings>> {
        let backend = std::sync::Arc::clone(&self.backend);
        self.journal.transaction(|journal| {
            let Some(entry) = journal.original(JournalKind::SystemProxy).cloned() else {
                return Ok(None);
            };
            if entry.platform != std::env::consts::OS {
                return Err(HostError::Journal(
                    "the recovery snapshot belongs to a different operating system".into(),
                ));
            }
            let previous: ProxySettings = entry.before_as().ok_or_else(|| {
                HostError::Journal("journal entry holds no usable previous state".into())
            })?;
            backend.restore(&previous)?;
            let restored = backend.read()?;
            if restored != previous {
                return Err(HostError::Platform(
                    "system settings did not match the recovery snapshot after restore".into(),
                ));
            }
            journal.clear_kind_unlocked(JournalKind::SystemProxy)?;
            Ok(Some(previous))
        })
    }

    /// Returns the pending change, if the system may still be routed through
    /// NullAD from an earlier run.
    #[must_use]
    pub fn pending(&self) -> Option<&JournalEntry> {
        self.journal.latest(JournalKind::SystemProxy)
    }

    /// Returns the loaded change journal.
    #[must_use]
    pub fn journal(&self) -> &ChangeJournal {
        &self.journal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MemoryBackend(std::sync::Mutex<ProxySettings>);
    impl ProxyBackend for MemoryBackend {
        fn read(&self) -> Result<ProxySettings> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn write(&self, value: &ProxySettings) -> Result<()> {
            *self.0.lock().unwrap() = value.clone();
            Ok(())
        }
    }

    #[test]
    fn existing_proxy_without_upstream_is_preserved_without_recovery_record() {
        let original = ProxySettings {
            bypass: Some("*.direct.invalid;<local>".into()),
            ..ProxySettings::routing_through("127.0.0.1:7890")
        };
        let backend = std::sync::Arc::new(MemoryBackend(std::sync::Mutex::new(original.clone())));
        let directory = crate::test_support::directory();
        let mut proxy = SystemProxy::with_backend(
            "127.0.0.1:8080".into(),
            backend.clone(),
            directory.join("journal.json"),
        )
        .unwrap();
        assert!(proxy.apply_chained(false).is_err());
        assert_eq!(backend.read().unwrap(), original);
        assert!(proxy.pending().is_none());
        // Explicit chaining allows takeover and exact restoration of the route.
        proxy.apply_chained(true).unwrap();
        assert!(backend.read().unwrap().points_at("127.0.0.1:8080"));
        assert_eq!(backend.read().unwrap().bypass, original.bypass);
        proxy.revert().unwrap();
        assert_eq!(backend.read().unwrap(), original);
    }

    #[test]
    fn chaining_does_not_add_private_bypasses_when_original_had_none() {
        let original = ProxySettings {
            bypass: None,
            ..ProxySettings::routing_through("127.0.0.1:7890")
        };
        let backend = std::sync::Arc::new(MemoryBackend(std::sync::Mutex::new(original.clone())));
        let directory = crate::test_support::directory();
        let mut proxy = SystemProxy::with_backend(
            "127.0.0.1:8080".into(),
            backend.clone(),
            directory.join("journal.json"),
        )
        .unwrap();
        proxy.apply_chained(true).unwrap();
        assert_eq!(backend.read().unwrap().bypass, None);
        proxy.revert().unwrap();
        assert_eq!(backend.read().unwrap(), original);
    }

    #[test]
    fn pac_is_preserved_even_when_static_upstream_is_configured() {
        let original = ProxySettings {
            auto_config_url: Some("https://configuration.invalid/route.pac".into()),
            ..ProxySettings::disabled()
        };
        let backend = std::sync::Arc::new(MemoryBackend(std::sync::Mutex::new(original.clone())));
        let directory = crate::test_support::directory();
        let mut proxy = SystemProxy::with_backend(
            "127.0.0.1:8080".into(),
            backend.clone(),
            directory.join("journal.json"),
        )
        .unwrap();
        for configured in [false, true] {
            assert!(proxy.apply_chained(configured).is_err());
        }
        assert_eq!(backend.read().unwrap(), original);
        assert!(proxy.pending().is_none());
    }

    #[test]
    fn disabled_settings_describe_no_proxy() {
        let settings = ProxySettings::disabled();
        assert!(!settings.enabled);
        assert!(settings.server.is_none());
        assert!(!settings.points_at("127.0.0.1:8080"));
    }

    #[test]
    fn routing_settings_point_at_the_listener() {
        let settings = ProxySettings::routing_through("127.0.0.1:8080");
        assert!(settings.enabled);
        assert_eq!(settings.server.as_deref(), Some("127.0.0.1:8080"));
        assert!(settings.points_at("127.0.0.1:8080"));
        assert!(!settings.points_at("127.0.0.1:9999"));
    }

    #[test]
    fn points_at_requires_enabled() {
        let settings = ProxySettings {
            enabled: false,
            server: Some("127.0.0.1:8080".into()),
            bypass: None,
            auto_config_url: None,
            windows_registry: None,
        };
        assert!(
            !settings.points_at("127.0.0.1:8080"),
            "a disabled proxy must not be treated as applied"
        );
    }

    #[test]
    fn default_bypass_covers_loopback_and_private_ranges() {
        let bypass = ProxySettings::DEFAULT_BYPASS;
        for expected in [
            "localhost",
            "127.*",
            "10.*",
            "192.168.*",
            "172.16.*",
            "172.31.*",
        ] {
            assert!(
                bypass.contains(expected),
                "bypass should contain {expected}"
            );
        }
    }

    #[test]
    fn settings_round_trip_through_json() {
        let settings = ProxySettings::routing_through("127.0.0.1:8080");
        let text = serde_json::to_string(&settings).unwrap();
        let restored: ProxySettings = serde_json::from_str(&text).unwrap();
        assert_eq!(settings, restored);
    }
}
