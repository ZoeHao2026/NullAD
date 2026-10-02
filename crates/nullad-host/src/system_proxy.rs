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
        }
    }

    /// Returns `true` when these settings already point at `listen`.
    #[must_use]
    pub fn points_at(&self, listen: &str) -> bool {
        self.enabled && self.server.as_deref() == Some(listen)
    }
}

/// Read, apply, and revert the system HTTP proxy.
#[derive(Debug)]
pub struct SystemProxy {
    listen: String,
    journal: ChangeJournal,
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
        })
    }

    /// The address NullAD routes the system through.
    #[must_use]
    pub fn listen(&self) -> &str {
        &self.listen
    }

    /// Reads the current system proxy settings.
    pub fn current(&self) -> Result<ProxySettings> {
        platform::read_proxy()
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
        let previous = self.current()?;

        if previous.points_at(&self.listen) {
            // Already applied. Re-applying would overwrite the journal's record
            // of the original state with our own settings, permanently losing
            // the ability to restore it.
            tracing::info!("system proxy already routed through NullAD");
            return Ok(previous);
        }

        let desired = ProxySettings::routing_through(&self.listen);

        self.journal.record(JournalEntry::new(
            JournalKind::SystemProxy,
            serde_json::to_value(&previous)
                .map_err(|e| HostError::Journal(format!("serialize: {e}")))?,
            serde_json::to_value(&desired)
                .map_err(|e| HostError::Journal(format!("serialize: {e}")))?,
            format!("system HTTP proxy routed through {}", self.listen),
        ))?;

        match platform::write_proxy(&desired) {
            Ok(()) => Ok(previous),
            Err(err) => {
                // The change did not happen, so its journal entry must not
                // linger and later trigger a pointless revert.
                if let Err(clear_err) = self.journal.clear_kind(JournalKind::SystemProxy) {
                    tracing::warn!(error = %clear_err, "could not clear the journal after a failed apply");
                }
                Err(err)
            }
        }
    }

    /// Restores the state captured by the most recent [`Self::apply`].
    ///
    /// Returns the settings that were restored, or `None` when there was nothing
    /// pending.
    pub fn revert(&mut self) -> Result<Option<ProxySettings>> {
        let Some(entry) = self.journal.latest(JournalKind::SystemProxy).cloned() else {
            return Ok(None);
        };

        let previous: ProxySettings = entry.before_as().ok_or_else(|| {
            HostError::Journal("journal entry holds no usable previous state".into())
        })?;

        platform::write_proxy(&previous)?;
        self.journal.clear_kind(JournalKind::SystemProxy)?;
        Ok(Some(previous))
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
        };
        assert!(
            !settings.points_at("127.0.0.1:8080"),
            "a disabled proxy must not be treated as applied"
        );
    }

    #[test]
    fn default_bypass_covers_loopback_and_private_ranges() {
        let bypass = ProxySettings::DEFAULT_BYPASS;
        for expected in ["localhost", "127.*", "10.*", "192.168.*", "172.16.*", "172.31.*"] {
            assert!(bypass.contains(expected), "bypass should contain {expected}");
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
