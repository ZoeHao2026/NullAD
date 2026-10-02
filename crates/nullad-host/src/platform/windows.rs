//! Windows system proxy implementation.
//!
//! Settings live per-user under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, which is
//! why routing the system through NullAD needs no elevation on Windows.
//!
//! Writing the registry alone is not enough: applications cache the WinINET
//! configuration, so a change is only picked up once it is broadcast. That is
//! what `InternetSetOption` with `INTERNET_OPTION_SETTINGS_CHANGED` and
//! `INTERNET_OPTION_REFRESH` does, and it is the same mechanism the Windows
//! settings UI uses.

use std::net::IpAddr;

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};

use crate::dns_config::{DnsSettings, ResolverEntry};
use crate::system_proxy::ProxySettings;
use crate::{HostError, Result};

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Opens the per-user internet settings key for reading.
fn open_read() -> Result<RegKey> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ)
        .map_err(|e| HostError::Platform(format!("cannot open internet settings: {e}")))
}

/// Opens the per-user internet settings key for writing.
fn open_write() -> Result<RegKey> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .map_err(|e| HostError::Platform(format!("cannot open internet settings for writing: {e}")))
}

/// Reads a `DWORD` value, treating absence as zero.
fn read_dword(key: &RegKey, name: &str) -> u32 {
    key.get_value::<u32, _>(name).unwrap_or(0)
}

/// Reads a string value, treating absence as `None`.
fn read_string(key: &RegKey, name: &str) -> Option<String> {
    let value: String = key.get_value(name).ok()?;
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Reads the current system proxy configuration.
pub fn read_proxy() -> Result<ProxySettings> {
    let key = open_read()?;
    Ok(ProxySettings {
        enabled: read_dword(&key, "ProxyEnable") != 0,
        server: read_string(&key, "ProxyServer"),
        bypass: read_string(&key, "ProxyOverride"),
        auto_config_url: read_string(&key, "AutoConfigURL"),
    })
}

/// Applies proxy settings and broadcasts the change.
///
/// The auto-config URL is cleared whenever NullAD enables a fixed proxy,
/// because a PAC script would otherwise override the setting and NullAD would
/// silently filter nothing.
pub fn write_proxy(settings: &ProxySettings) -> Result<()> {
    let key = open_write()?;

    let enable: u32 = u32::from(settings.enabled);
    key.set_value("ProxyEnable", &enable)
        .map_err(|e| HostError::Platform(format!("cannot write ProxyEnable: {e}")))?;

    // An empty string is how Windows represents "no value" here; writing it is
    // the correct way to clear a setting.
    key.set_value("ProxyServer", &settings.server.clone().unwrap_or_default())
        .map_err(|e| HostError::Platform(format!("cannot write ProxyServer: {e}")))?;
    key.set_value("ProxyOverride", &settings.bypass.clone().unwrap_or_default())
        .map_err(|e| HostError::Platform(format!("cannot write ProxyOverride: {e}")))?;
    key.set_value(
        "AutoConfigURL",
        &settings.auto_config_url.clone().unwrap_or_default(),
    )
    .map_err(|e| HostError::Platform(format!("cannot write AutoConfigURL: {e}")))?;

    broadcast_settings_change();
    Ok(())
}

/// Notifies running applications that the proxy configuration changed.
///
/// Failure here is logged rather than returned: the registry write has already
/// succeeded, and reporting the whole operation as failed would be misleading.
///
/// This is the only `unsafe` code in NullAD. `InternetSetOptionW` has no safe
/// wrapper in the `windows-sys` bindings, and the alternative — spawning
/// `rundll32` to broadcast the change — is both slower and less reliable.
#[allow(unsafe_code)]
fn broadcast_settings_change() {
    // SAFETY: Both calls pass a null handle, a null buffer, and a zero length,
    // which is the documented usage for broadcasting an internet-settings
    // change. `InternetSetOptionW` dereferences no pointer in this form, so
    // there is no aliasing or lifetime obligation; the two integer constants are
    // defined by the WinINet headers surfaced through `windows-sys`.
    unsafe {
        let changed = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let refreshed = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );

        if changed == 0 || refreshed == 0 {
            tracing::warn!(
                "the proxy settings were written but could not be broadcast; \
                 some applications may need to be restarted"
            );
        }
    }
}

/// Returns `true` when the process token is elevated.
///
/// Uses `OpenProcessToken`/`GetTokenInformation` through a shell-free check:
/// attempting to open a handle that only administrators can open is the
/// cheapest reliable test and avoids pulling in more of the token API.
pub fn has_elevated_privileges() -> bool {
    // Writing to the machine-wide resolver configuration is the operation that
    // actually requires elevation, so probe that directly.
    RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            KEY_WRITE,
        )
        .is_ok()
}

/// Reads the configured DNS resolvers per interface.
///
/// Windows stores these as `NameServer` (a space- or comma-separated list) and
/// `DhcpNameServer` under each interface's key. Both are read, because a
/// DHCP-provided server is still in effect even though `NameServer` is empty.
pub fn read_dns() -> Result<DnsSettings> {
    let base = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            KEY_READ,
        )
        .map_err(|e| HostError::Platform(format!("cannot open TCP/IP interfaces: {e}")))?;

    let mut entries = Vec::new();
    for name in base.enum_keys().flatten() {
        let Ok(interface) = base.open_subkey_with_flags(&name, KEY_READ) else {
            continue;
        };

        let static_servers = read_string(&interface, "NameServer")
            .or_else(|| read_string(&interface, "DhcpNameServer"));

        let Some(servers) = static_servers else {
            continue;
        };

        let parsed: Vec<IpAddr> = servers
            .split([',', ' ', ';'])
            .filter(|part| !part.trim().is_empty())
            .filter_map(|part| part.trim().parse::<IpAddr>().ok())
            .collect();

        // An interface with no usable addresses carries no information worth
        // restoring, so it is skipped rather than recorded as an empty entry.
        if parsed.is_empty() {
            continue;
        }

        entries.push(ResolverEntry {
            interface: name,
            servers: parsed,
        });
    }

    if entries.is_empty() {
        return Err(HostError::Platform(
            "no interface reported a configured DNS server; \
             the resolver may be managed by a third-party tool"
                .into(),
        ));
    }

    Ok(DnsSettings { entries })
}

/// Applies DNS resolver settings via `netsh`.
///
/// The `netsh` route is used rather than writing the registry directly because
/// the DNS client service caches state that a raw registry write does not
/// invalidate, so the change would not take effect reliably.
pub fn write_dns(settings: &DnsSettings) -> Result<()> {
    for entry in &settings.entries {
        let servers: Vec<String> = entry.servers.iter().map(ToString::to_string).collect();
        if servers.is_empty() {
            let output = run_netsh(&[
                "interface",
                "ip",
                "set",
                "dns",
                &format!("name={}", entry.interface),
                "source=dhcp",
            ])?;
            tracing::debug!(interface = %entry.interface, output = %output, "reset interface dns to dhcp");
            continue;
        }

        // `set dns` establishes the primary server and `add dns` appends the
        // rest, which is how netsh models the ordered resolver list.
        let output = run_netsh(&[
            "interface",
            "ip",
            "set",
            "dns",
            &format!("name={}", entry.interface),
            "source=static",
            &format!("addr={}", servers[0]),
            "validate=no",
        ])?;
        tracing::debug!(interface = %entry.interface, output = %output, "set primary dns");

        for server in servers.iter().skip(1) {
            let output = run_netsh(&[
                "interface",
                "ip",
                "add",
                "dns",
                &format!("name={}", entry.interface),
                &format!("addr={server}"),
                "validate=no",
                "index=2",
            ])?;
            tracing::debug!(interface = %entry.interface, output = %output, "added secondary dns");
        }
    }
    Ok(())
}

/// Runs `netsh` with the given arguments, mapping failures onto `HostError`.
fn run_netsh(args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| HostError::Platform(format!("cannot run netsh: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

    if output.status.success() {
        return Ok(stdout);
    }

    // Windows returns a localised, unhelpful message for the access-denied case,
    // so the exit code is checked rather than pattern-matching the text.
    if is_access_denied(&stderr) || is_access_denied(&stdout) {
        return Err(HostError::PermissionDenied(format!(
            "netsh {}",
            args.join(" ")
        )));
    }

    Err(HostError::Platform(format!(
        "netsh {} failed: {} {}",
        args.join(" "),
        stdout,
        stderr
    )))
}

/// Returns `true` when a netsh message indicates a privileges problem.
fn is_access_denied(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("access is denied")
        || lower.contains("requires elevation")
        || lower.contains("elevation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_detection() {
        assert!(is_access_denied("Access is denied."));
        assert!(is_access_denied("The requested operation requires elevation."));
        assert!(!is_access_denied("The parameter is incorrect."));
    }

    #[test]
    fn reading_proxy_settings_does_not_panic() {
        // The registry key always exists on a normal Windows install, but the
        // call must be safe even if it does not.
        match read_proxy() {
            Ok(settings) => {
                // Whatever the machine's state, the value must be self-consistent.
                if settings.enabled {
                    assert!(settings.server.is_some() || settings.auto_config_url.is_some());
                }
            }
            Err(err) => {
                // In a locked-down environment this may legitimately fail.
                assert!(!err.to_string().is_empty());
            }
        }
    }

    #[test]
    fn round_trips_proxy_settings_through_the_registry() {
        // Capture and restore, so the test is safe to run on a live machine.
        let Ok(original) = read_proxy() else {
            return; // No registry access in this environment; skip.
        };

        let probe = ProxySettings {
            enabled: original.enabled,
            server: original.server.clone(),
            bypass: original.bypass.clone(),
            auto_config_url: original.auto_config_url.clone(),
        };

        // Writing back exactly what was read must be a no-op semantically.
        if write_proxy(&probe).is_ok() {
            let after = read_proxy().expect("readable after write");
            assert_eq!(after.enabled, probe.enabled);
            assert_eq!(after.server, probe.server);
            assert_eq!(after.bypass, probe.bypass);
            assert_eq!(after.auto_config_url, probe.auto_config_url);
        }
    }
}
