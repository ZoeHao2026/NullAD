//! # NullAD Core
//!
//! Orchestration: this is where the pure engine, the interceptors, and the
//! platform adapters meet. It owns the application's state, its settings file,
//! and the lifecycle of the running protection.
//!
//! Everything a user interface needs is expressed through [`AppState`] and
//! [`AppHandle`]. A UI therefore never constructs sockets, reads the registry,
//! or parses rules — which is what keeps the GUI replaceable.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod settings;
pub mod state;
pub mod updater;

pub use settings::{AppSettings, ListEntry, ListSource};
pub use state::{AppHandle, AppState, ProtectionStatus, RunningProtection};
pub use updater::{ListLoader, LoadOutcome};

/// Re-exported so a UI crate only needs to depend on `nullad-core`.
pub use nullad_api::{FilterListInfo, LogEntry, ProtectionState, StatusReport};
pub use nullad_api::{RuleSetStatsDto, StatsSnapshotDto};
