//! Platform-specific implementations for proxy and resolver changes.
//!
//! Only this module knows about operating-system APIs. Everything above it
//! works through the abstract operations declared here, which is what keeps the
//! rest of the host layer testable.

use crate::dns_config::DnsSettings;
use crate::system_proxy::ProxySettings;
use crate::Result;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{has_elevated_privileges, read_dns, read_proxy, write_dns, write_proxy};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{has_elevated_privileges, read_dns, read_proxy, write_dns, write_proxy};

#[cfg(all(unix, not(target_os = "macos")))]
mod linux;
#[cfg(all(unix, not(target_os = "macos")))]
pub use linux::{has_elevated_privileges, read_dns, read_proxy, write_dns, write_proxy};

#[cfg(not(any(windows, unix)))]
mod unsupported;
#[cfg(not(any(windows, unix)))]
pub use unsupported::{has_elevated_privileges, read_dns, read_proxy, write_dns, write_proxy};

/// Returns `true` when the process appears to have administrative rights.
///
/// Advisory only. It exists so a UI can warn before attempting a privileged
/// operation; the operation itself still validates.
#[must_use]
pub fn privileges_note() -> &'static str {
    if has_elevated_privileges() {
        "running with administrative rights"
    } else {
        "running without administrative rights; DNS changes will be refused"
    }
}

/// Reads the current system proxy settings.
pub fn read_proxy_settings() -> Result<ProxySettings> {
    read_proxy()
}

/// Writes system proxy settings.
pub fn write_proxy_settings(settings: &ProxySettings) -> Result<()> {
    write_proxy(settings)
}

/// Reads the current system DNS settings.
pub fn read_dns_settings() -> Result<DnsSettings> {
    read_dns()
}

/// Writes system DNS settings.
pub fn write_dns_settings(settings: &DnsSettings) -> Result<()> {
    write_dns(settings)
}
