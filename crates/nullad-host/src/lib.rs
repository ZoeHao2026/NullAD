//! # NullAD Host Layer
//!
//! Everything that touches the operating system lives here, and nothing else
//! does. Keeping platform code in one crate is what allows the engine to stay
//! pure and the interception layer to stay portable.
//!
//! ## Change journaling
//!
//! NullAD modifies system-wide settings (the HTTP proxy, and optionally the DNS
//! resolver). A crash between "apply" and "revert" would otherwise leave a
//! user's machine pointing at a proxy that is no longer running, which is a
//! genuinely hostile failure mode.
//!
//! Every change is therefore written to a [`journal`] *before* it is applied,
//! and cleared only after it is successfully reverted. On start-up,
//! [`journal::ChangeJournal::pending`] reports anything left behind so the user
//! can put their system back exactly as it was.
//!
//! ## Privileges
//!
//! System proxy changes are per-user on Windows and need no elevation. DNS
//! changes and binding port 53 require elevation on every platform, so they are
//! opt-in and reported honestly when unavailable.
//!
//! ## 中文说明
//!
//! 所有需要接触操作系统的代码都集中在这里，别处没有任何平台相关代码。
//! 把平台代码收进单个 crate，正是引擎得以保持纯粹、
//! 拦截层得以保持可移植的原因。
//!
//! **变更日志（change journaling）**
//!
//! NullAD 会修改系统级设置（HTTP 代理，以及可选的 DNS 解析器）。
//! 如果进程在「已应用」与「已还原」之间崩溃，用户的机器就会指向一个
//! 已经不再运行的代理——这是一种极其恶劣的失效模式。
//!
//! 因此每一项变更都会**先写入** [`journal`] 再应用，且只在成功还原之后才被清除。
//! 启动时 [`journal::ChangeJournal::pending`] 会报告所有遗留项，
//! 让用户能把系统精确还原成原样。
//!
//! **权限**
//!
//! Windows 上的系统代理是每用户设置，无需提权。
//! 而 DNS 变更与绑定 53 端口在所有平台都需要提权，
//! 因此它们是选择性开启的，并且在不可用时如实汇报。

// `deny` rather than `forbid`: the Windows backend needs exactly one `unsafe`
// call to `InternetSetOptionW`, which has no safe wrapper in this dependency
// set. That single call carries its own safety comment, and `deny` keeps every
// other module unsafe-free while still failing the build on any new usage.
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod dns_config;
pub mod journal;
pub mod paths;
pub mod platform;
pub mod system_proxy;

pub use dns_config::{DnsConfigurator, DnsSettings};
pub use journal::{ChangeJournal, JournalEntry, JournalKind};
pub use system_proxy::{ProxySettings, SystemProxy};

/// Errors raised by platform adapters.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The platform cannot perform this operation at all.
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),

    /// The operation needs administrator or root rights.
    #[error("permission denied: {0} (try running with administrator rights)")]
    PermissionDenied(String),

    /// A platform command or API call failed.
    #[error("platform operation failed: {0}")]
    Platform(String),

    /// Reading or writing the change journal failed.
    #[error("change journal error: {0}")]
    Journal(String),

    /// Local configuration could not be read or written.
    #[error("configuration error: {0}")]
    Config(String),
}

/// Convenience result alias for this crate.
pub type Result<T, E = HostError> = std::result::Result<T, E>;

/// Returns `true` when the process has the rights needed to change system-wide
/// resolver settings.
///
/// This is advisory: it reports what the platform believes, so a UI can warn
/// before attempting an operation that would fail.
#[must_use]
pub fn has_elevated_privileges() -> bool {
    platform::has_elevated_privileges()
}

/// Returns a human-readable description of the running platform.
#[must_use]
pub fn platform_description() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}
