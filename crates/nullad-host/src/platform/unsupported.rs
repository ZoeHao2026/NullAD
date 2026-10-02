//! Fallback implementation for platforms NullAD does not yet target natively.
//!
//! Everything reports an explicit "unsupported" error rather than silently
//! succeeding. A no-op that claims success would be far worse than a clear
//! failure, because the user would believe their traffic was being filtered
//! when it was not.

use crate::dns_config::DnsSettings;
use crate::system_proxy::ProxySettings;
use crate::{HostError, Result};

/// Reads the current system proxy settings.
pub fn read_proxy() -> Result<ProxySettings> {
    Err(HostError::Unsupported(
        "system proxy integration is not implemented for this platform",
    ))
}

/// Writes system proxy settings.
pub fn write_proxy(_settings: &ProxySettings) -> Result<()> {
    Err(HostError::Unsupported(
        "system proxy integration is not implemented for this platform",
    ))
}

/// Reads the current system DNS settings.
pub fn read_dns() -> Result<DnsSettings> {
    Err(HostError::Unsupported(
        "system DNS integration is not implemented for this platform",
    ))
}

/// Writes system DNS settings.
pub fn write_dns(_settings: &DnsSettings) -> Result<()> {
    Err(HostError::Unsupported(
        "system DNS integration is not implemented for this platform",
    ))
}

/// Returns `false`; privilege detection is not meaningful here.
pub fn has_elevated_privileges() -> bool {
    false
}
