//! System DNS resolver configuration.
//!
//! Pointing the system resolver at NullAD's sinkhole is what makes DNS-level
//! blocking work. It requires elevation on every supported platform, so the
//! adapter reports that honestly rather than failing with an opaque error.
//!
//! Like the proxy adapter, this captures the complete previous state before
//! changing anything, so the resolver can always be put back exactly as it was.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::journal::{ChangeJournal, JournalEntry, JournalKind};
use crate::{platform, HostError, Result};

/// Whether resolver addresses were explicitly configured or supplied by DHCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    Static,
    Dhcp,
}

/// The resolver configuration of one network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverEntry {
    /// Interface or service name, as the platform identifies it.
    pub interface: String,
    /// Resolver addresses in priority order.
    pub servers: Vec<IpAddr>,
    /// Captured resolver mode; absent in old snapshots and non-Windows backends.
    #[serde(default)]
    pub mode: Option<DnsMode>,
    /// Captured Windows interface index; identity remains the interface GUID.
    #[serde(default)]
    pub interface_index: Option<u32>,
}

/// The system resolver configuration for every interface that has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSettings {
    /// Per-interface resolver lists.
    pub entries: Vec<ResolverEntry>,
}

impl DnsSettings {
    /// Returns settings that point every interface at a single local resolver.
    ///
    /// Existing interfaces are preserved by name so the restore path knows
    /// exactly which ones were touched.
    #[must_use]
    pub fn routing_through(&self, local: IpAddr, port: u16) -> Self {
        // Only the standard port can be expressed through an interface's
        // resolver list, so a non-standard port is rejected by the caller
        // rather than silently recorded as if it were honoured.
        let _ = port;
        Self {
            entries: self
                .entries
                .iter()
                .map(|entry| ResolverEntry {
                    interface: entry.interface.clone(),
                    servers: vec![local],
                    mode: Some(DnsMode::Static),
                    interface_index: entry.interface_index,
                })
                .collect(),
        }
    }

    /// Returns `true` when every interface points at `local`.
    #[must_use]
    pub fn points_at(&self, local: IpAddr) -> bool {
        !self.entries.is_empty()
            && self
                .entries
                .iter()
                .all(|entry| entry.servers.contains(&local))
    }

    /// DHCP addresses may change; verify the source mode and stable identity.
    pub fn matches_restored(&self, expected: &Self) -> bool {
        self.entries.len() == expected.entries.len()
            && expected.entries.iter().all(|before| {
                self.entries
                    .iter()
                    .find(|after| after.interface == before.interface)
                    .is_some_and(|after| {
                        after.mode == before.mode
                            && (before.mode == Some(DnsMode::Dhcp)
                                || after.servers == before.servers)
                    })
            })
    }

    /// Returns the distinct resolver addresses in use.
    #[must_use]
    pub fn distinct_servers(&self) -> Vec<IpAddr> {
        let mut servers: Vec<IpAddr> = self
            .entries
            .iter()
            .flat_map(|entry| entry.servers.iter().copied())
            .collect();
        servers.sort();
        servers.dedup();
        servers
    }
}

/// Injectable system adapter. Tests provide a mock and never touch live settings.
pub trait DnsBackend: std::fmt::Debug + Send + Sync {
    fn read(&self) -> Result<DnsSettings>;
    fn write(&self, settings: &DnsSettings) -> Result<()>;
}

#[derive(Debug)]
struct PlatformBackend;
impl DnsBackend for PlatformBackend {
    fn read(&self) -> Result<DnsSettings> {
        platform::read_dns_settings()
    }
    fn write(&self, settings: &DnsSettings) -> Result<()> {
        platform::write_dns_settings(settings)
    }
}

/// Reads, applies, and reverts system resolver settings.
#[derive(Debug)]
pub struct DnsConfigurator {
    local: IpAddr,
    journal: ChangeJournal,
    backend: std::sync::Arc<dyn DnsBackend>,
}

impl DnsConfigurator {
    /// Creates a configurator that will point the system at `local`.
    pub fn new(local: IpAddr) -> Result<Self> {
        Ok(Self {
            local,
            journal: ChangeJournal::load()?,
            backend: std::sync::Arc::new(PlatformBackend),
        })
    }

    /// Constructs an adapter with an isolated journal and an injectable backend.
    pub fn with_backend(
        local: IpAddr,
        backend: std::sync::Arc<dyn DnsBackend>,
        journal_path: std::path::PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            local,
            backend,
            journal: ChangeJournal::load_at(journal_path)?,
        })
    }

    /// Reads the current resolver configuration.
    pub fn current(&self) -> Result<DnsSettings> {
        self.backend.read()
    }

    /// Returns `true` when the system already resolves through NullAD.
    pub fn is_applied(&self) -> Result<bool> {
        Ok(self.current()?.points_at(self.local))
    }

    /// Routes the system resolver through NullAD.
    ///
    /// Returns the configuration that was replaced.
    pub fn apply(&mut self) -> Result<DnsSettings> {
        let backend = std::sync::Arc::clone(&self.backend);
        let local = self.local;
        self.journal.transaction(|journal| {
            let previous = backend.read()?;
            if previous.entries.is_empty() {
                return Err(HostError::Platform(
                    "no network resolver can be safely captured".into(),
                ));
            }
            if let Some(entry) = journal.original(JournalKind::DnsResolver) {
                if previous.points_at(local) {
                    return entry.before_as().ok_or_else(|| {
                        HostError::Journal("pending snapshot cannot be decoded".into())
                    });
                }
                return Err(HostError::Journal(
                    "restore the pending system change before applying a new one".into(),
                ));
            }
            if previous.points_at(local) {
                return Ok(previous);
            }
            let desired = previous.routing_through(local, 53);
            journal.record_unlocked(JournalEntry::new(
                JournalKind::DnsResolver,
                serde_json::to_value(&previous).map_err(|e| HostError::Journal(e.to_string()))?,
                serde_json::to_value(&desired).map_err(|e| HostError::Journal(e.to_string()))?,
                "system settings routed through NullAD",
            ))?;
            if let Err(error) = backend.write(&desired) {
                // A multi-step write may already have changed part of the system.
                // Keep the original snapshot even if this rollback appears successful.
                let rollback = backend.write(&previous);
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

    /// Restores the resolver configuration captured by the last [`Self::apply`].
    pub fn revert(&mut self) -> Result<Option<DnsSettings>> {
        let backend = std::sync::Arc::clone(&self.backend);
        self.journal.transaction(|journal| {
            let Some(entry) = journal.original(JournalKind::DnsResolver).cloned() else {
                return Ok(None);
            };
            if entry.platform != std::env::consts::OS {
                return Err(HostError::Journal(
                    "the recovery snapshot belongs to a different operating system".into(),
                ));
            }
            let previous: DnsSettings = entry.before_as().ok_or_else(|| {
                HostError::Journal("journal entry holds no usable previous state".into())
            })?;
            backend.write(&previous)?;
            let restored = backend.read()?;
            if !restored.matches_restored(&previous) {
                return Err(HostError::Platform(
                    "system settings did not match the recovery snapshot after restore".into(),
                ));
            }
            journal.clear_kind_unlocked(JournalKind::DnsResolver)?;
            Ok(Some(previous))
        })
    }

    /// Returns the pending resolver change, if any.
    #[must_use]
    pub fn pending(&self) -> Option<&JournalEntry> {
        self.journal.latest(JournalKind::DnsResolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid ip")
    }

    fn settings() -> DnsSettings {
        DnsSettings {
            entries: vec![
                ResolverEntry {
                    interface: "Ethernet".into(),
                    servers: vec![ip("192.168.1.1"), ip("8.8.8.8")],
                    mode: None,
                    interface_index: None,
                },
                ResolverEntry {
                    interface: "Wi-Fi".into(),
                    servers: vec![ip("192.168.1.1")],
                    mode: None,
                    interface_index: None,
                },
            ],
        }
    }

    #[test]
    fn routing_replaces_every_interface_resolver() {
        let routed = settings().routing_through(ip("127.0.0.1"), 53);
        assert_eq!(routed.entries.len(), 2);
        for entry in &routed.entries {
            assert_eq!(entry.servers, vec![ip("127.0.0.1")]);
        }
        // Interface names must survive, so restore knows what to touch.
        assert_eq!(routed.entries[0].interface, "Ethernet");
        assert_eq!(routed.entries[1].interface, "Wi-Fi");
    }

    #[test]
    fn points_at_requires_all_interfaces() {
        let routed = settings().routing_through(ip("127.0.0.1"), 53);
        assert!(routed.points_at(ip("127.0.0.1")));
        assert!(!routed.points_at(ip("127.0.0.2")));

        // A partially-routed configuration is not "applied".
        let mut partial = routed.clone();
        partial.entries[1].servers = vec![ip("8.8.8.8")];
        assert!(!partial.points_at(ip("127.0.0.1")));
    }

    #[test]
    fn empty_settings_never_report_as_applied() {
        let empty = DnsSettings { entries: vec![] };
        assert!(
            !empty.points_at(ip("127.0.0.1")),
            "an empty configuration must not be mistaken for an applied one"
        );
    }

    #[test]
    fn distinct_servers_are_deduplicated_and_sorted() {
        let servers = settings().distinct_servers();
        // `IpAddr`'s ordering is numeric, so 8.8.8.8 precedes 192.168.1.1.
        assert_eq!(servers, vec![ip("8.8.8.8"), ip("192.168.1.1")]);
        assert_eq!(servers.len(), 2, "the duplicated 192.168.1.1 must collapse");
    }

    #[test]
    fn settings_round_trip_through_json() {
        let original = settings();
        let text = serde_json::to_string(&original).unwrap();
        let restored: DnsSettings = serde_json::from_str(&text).unwrap();
        assert_eq!(original, restored);
    }
}
