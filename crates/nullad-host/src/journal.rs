//! A durable journal of system changes, so every one can be undone.
//!
//! NullAD modifies system-wide settings. Crashing between "apply" and "revert"
//! would otherwise leave a machine pointing at a proxy that is no longer
//! running — a failure mode where the user's network appears broken and the
//! cause is invisible.
//!
//! Every change is written to the journal *before* it is applied, and removed
//! only after it has been successfully reverted. On start-up the journal is read
//! and anything still pending is surfaced to the user.
//!
//! ## Ordering matters
//!
//! Recording before applying means a crash can leave the journal claiming a
//! change that may not have happened. That direction is the safe one: reverting
//! an already-correct setting is a no-op, whereas losing the record of a real
//! change strands the user's configuration.

use serde::{Deserialize, Serialize};

use crate::paths::journal_path;
use crate::{HostError, Result};

/// What kind of change a journal entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalKind {
    /// System HTTP proxy settings.
    SystemProxy,
    /// System DNS resolver settings.
    DnsResolver,
}

/// One recorded change, holding everything needed to undo it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// What was changed.
    pub kind: JournalKind,
    /// Which platform the change was made on.
    pub platform: String,
    /// Milliseconds since the Unix epoch when the change was applied.
    pub applied_at_ms: u64,
    /// Serialized state that existed *before* the change.
    pub before: serde_json::Value,
    /// Serialized state that was applied.
    pub after: serde_json::Value,
    /// Human-readable description for the UI.
    pub description: String,
}

impl JournalEntry {
    /// Creates an entry stamped with the current time and platform.
    #[must_use]
    pub fn new(
        kind: JournalKind,
        before: serde_json::Value,
        after: serde_json::Value,
        description: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            platform: std::env::consts::OS.to_owned(),
            applied_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            before,
            after,
            description: description.into(),
        }
    }

    /// Reconstructs the pre-change state, if it deserializes.
    pub fn before_as<T: for<'de> Deserialize<'de>>(&self) -> Option<T> {
        serde_json::from_value(self.before.clone()).ok()
    }
}

/// A durable record of system changes that have not yet been reverted.
///
/// The file is written atomically — to a temporary file, then renamed — so a
/// crash mid-write cannot truncate the journal, which would be worse than
/// having none.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChangeJournal {
    entries: Vec<JournalEntry>,
}

impl ChangeJournal {
    /// Creates an empty in-memory journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads the journal from disk, returning an empty one if absent.
    pub fn load() -> Result<Self> {
        let path = journal_path()?;
        if !path.exists() {
            return Ok(Self::new());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| HostError::Journal(format!("{}: {e}", path.display())))?;
        serde_json::from_str(&text)
            .map_err(|e| HostError::Journal(format!("{}: {e}", path.display())))
    }

    /// Writes the journal to disk atomically.
    pub fn save(&self) -> Result<()> {
        let path = journal_path()?;
        let temp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| HostError::Journal(format!("serialize: {e}")))?;

        std::fs::write(&temp, text)
            .map_err(|e| HostError::Journal(format!("{}: {e}", temp.display())))?;
        std::fs::rename(&temp, &path)
            .map_err(|e| HostError::Journal(format!("{}: {e}", path.display())))?;
        Ok(())
    }

    /// Records a change and persists the journal.
    ///
    /// Call this *before* applying the change.
    pub fn record(&mut self, entry: JournalEntry) -> Result<()> {
        self.entries.push(entry);
        self.save()
    }

    /// Removes and persists the removal of every entry of a kind, after those
    /// changes were successfully reverted.
    pub fn clear_kind(&mut self, kind: JournalKind) -> Result<()> {
        self.entries.retain(|entry| entry.kind != kind);
        self.save()
    }

    /// Removes every entry.
    pub fn clear(&mut self) -> Result<()> {
        self.entries.clear();
        self.save()
    }

    /// Returns the recorded changes, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// Returns `true` when any change is still outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the most recent entry of a given kind.
    #[must_use]
    pub fn latest(&self, kind: JournalKind) -> Option<&JournalEntry> {
        self.entries.iter().rev().find(|entry| entry.kind == kind)
    }

    /// Returns `true` when a change of this kind is still outstanding.
    #[must_use]
    pub fn has_pending(&self, kind: JournalKind) -> bool {
        self.latest(kind).is_some()
    }

    /// Returns the kinds that currently have outstanding changes.
    #[must_use]
    pub fn pending_kinds(&self) -> Vec<JournalKind> {
        let mut kinds = Vec::new();
        for kind in [JournalKind::SystemProxy, JournalKind::DnsResolver] {
            if self.has_pending(kind) {
                kinds.push(kind);
            }
        }
        kinds
    }

    /// Loads the journal and reports outstanding changes for the UI.
    ///
    /// Returns an empty vector rather than an error when the journal cannot be
    /// read: a missing journal is the normal state, and a corrupt one should not
    /// prevent the application from starting.
    #[must_use]
    pub fn pending() -> Vec<JournalEntry> {
        match Self::load() {
            Ok(journal) => journal.entries().to_vec(),
            Err(err) => {
                tracing::warn!(error = %err, "could not read the change journal");
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_entry() -> JournalEntry {
        JournalEntry::new(
            JournalKind::SystemProxy,
            serde_json::json!({"enabled": false}),
            serde_json::json!({"enabled": true, "server": "127.0.0.1:8080"}),
            "system proxy routed through NullAD",
        )
    }

    #[test]
    fn recording_tracks_pending_changes() {
        let mut journal = ChangeJournal::new();
        assert!(!journal.has_pending(JournalKind::SystemProxy));

        // Insert directly to exercise the query logic without touching disk.
        journal.entries.push(proxy_entry());

        assert!(journal.has_pending(JournalKind::SystemProxy));
        assert!(!journal.has_pending(JournalKind::DnsResolver));
        assert!(journal.entries()[0].applied_at_ms > 0);
        assert_eq!(journal.pending_kinds(), vec![JournalKind::SystemProxy]);
    }

    #[test]
    fn latest_returns_the_most_recent_entry_of_that_kind() {
        let mut journal = ChangeJournal::new();
        journal.entries.push(proxy_entry());
        journal.entries.push(JournalEntry::new(
            JournalKind::DnsResolver,
            serde_json::json!([]),
            serde_json::json!(["127.0.0.1"]),
            "resolver pointed at NullAD",
        ));

        assert_eq!(
            journal.latest(JournalKind::DnsResolver).unwrap().description,
            "resolver pointed at NullAD"
        );
        assert_eq!(
            journal.latest(JournalKind::SystemProxy).unwrap().description,
            "system proxy routed through NullAD"
        );
        assert_eq!(journal.pending_kinds().len(), 2);
    }

    #[test]
    fn before_state_round_trips_for_restoration() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Previous {
            enabled: bool,
        }

        let entry = proxy_entry();
        let previous: Previous = entry.before_as().expect("deserialized");
        assert_eq!(previous, Previous { enabled: false });
    }

    #[test]
    fn journal_round_trips_through_json() {
        let mut journal = ChangeJournal::new();
        let original = proxy_entry();
        journal.entries.push(original.clone());

        let text = serde_json::to_string(&journal).unwrap();
        let restored: ChangeJournal = serde_json::from_str(&text).unwrap();
        assert_eq!(restored.entries().len(), 1);
        // Compare against the captured entry rather than a freshly built one,
        // because `JournalEntry::new` stamps the current time.
        assert_eq!(restored.entries()[0], original);
        assert_eq!(restored.entries()[0].platform, std::env::consts::OS);
    }

    #[test]
    fn clearing_a_kind_leaves_other_kinds_intact() {
        let mut journal = ChangeJournal::new();
        journal.entries.push(proxy_entry());
        journal.entries.push(JournalEntry::new(
            JournalKind::DnsResolver,
            serde_json::json!([]),
            serde_json::json!(["127.0.0.1"]),
            "resolver",
        ));

        journal.entries.retain(|e| e.kind != JournalKind::SystemProxy);

        assert!(!journal.has_pending(JournalKind::SystemProxy));
        assert!(journal.has_pending(JournalKind::DnsResolver));
    }
}
