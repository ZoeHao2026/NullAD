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
