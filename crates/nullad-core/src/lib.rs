//! # NullAD Core
//!
//! Orchestration: this is where the pure engine, the interceptors, and the
//! platform adapters meet. It owns the application's state, its settings file,
//! and the lifecycle of the running protection.
//!
//! Everything a user interface needs is expressed through [`AppState`] and
//! [`AppHandle`]. A UI therefore never constructs sockets, reads the registry,
//! or parses rules — which is what keeps the GUI replaceable.
//!
//! ## 中文说明
//!
//! 本 crate 是编排层：纯引擎、拦截器与平台适配在这里汇合。
//! 它持有应用状态、配置文件，以及防护运行期间的生命周期。
//!
//! 界面所需的一切都通过 [`AppState`] 与 [`AppHandle`] 暴露。
//! 因此 UI 永远不需要创建套接字、读取注册表或解析规则——
//! 这正是 GUI 可被替换的原因。

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod settings;
pub mod state;
pub mod updater;

pub use nullad_host::{RestoreItem, RestoreReport};
pub use settings::{normalize_allowed_hosts, AppSettings, ListEntry, ListSource, SettingsPatch};
pub use state::{AppHandle, AppState, ProtectionStatus, RunningProtection};
pub use updater::{ListLoader, LoadOutcome};

/// Re-exported so a UI crate only needs to depend on `nullad-core`.
pub use nullad_api::{FilterListInfo, HeuristicMode, LogEntry, ProtectionState, StatusReport};
pub use nullad_api::{RuleSetStatsDto, StatsSnapshotDto};

#[cfg(test)]
pub(crate) mod test_support {
    pub fn directory() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join(format!(
                "nullad-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }
}
