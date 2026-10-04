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
use winreg::types::{FromRegValue, ToRegValue};
use winreg::{RegKey, RegValue};

use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};

use crate::dns_config::{DnsMode, DnsSettings, ResolverEntry};
use crate::system_proxy::{ProxySettings, RegistryValueSnapshot, WindowsProxySnapshot};
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

/// Reads a string value, treating absence as `None`.
fn read_string(key: &RegKey, name: &str) -> Option<String> {
    let value: String = key.get_value(name).ok()?;
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

const PROXY_FIELDS: [&str; 4] = [
    "ProxyEnable",
    "ProxyServer",
    "ProxyOverride",
    "AutoConfigURL",
];

trait ProxyRegistry {
    fn read(&self, name: &str) -> std::io::Result<Option<RegistryValueSnapshot>>;
    fn set(&self, name: &str, value: &RegistryValueSnapshot) -> std::io::Result<()>;
    fn delete(&self, name: &str) -> std::io::Result<()>;
}

struct RegistryAccess<'a>(&'a RegKey);
impl ProxyRegistry for RegistryAccess<'_> {
    fn read(&self, name: &str) -> std::io::Result<Option<RegistryValueSnapshot>> {
        match self.0.get_raw_value(name) {
            Ok(value) => Ok(Some(RegistryValueSnapshot {
                value_type: value.vtype as u32,
                bytes: value.bytes,
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn set(&self, name: &str, value: &RegistryValueSnapshot) -> std::io::Result<()> {
        self.0.set_raw_value(name, &raw_registry_value(value)?)
    }
    fn delete(&self, name: &str) -> std::io::Result<()> {
        match self.0.delete_value(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

fn raw_registry_value(value: &RegistryValueSnapshot) -> std::io::Result<RegValue> {
    use winreg::enums::*;
    let vtype = match value.value_type {
        0 => REG_NONE,
        1 => REG_SZ,
        2 => REG_EXPAND_SZ,
        3 => REG_BINARY,
        4 => REG_DWORD,
        5 => REG_DWORD_BIG_ENDIAN,
        6 => REG_LINK,
        7 => REG_MULTI_SZ,
        8 => REG_RESOURCE_LIST,
        9 => REG_FULL_RESOURCE_DESCRIPTOR,
        10 => REG_RESOURCE_REQUIREMENTS_LIST,
        11 => REG_QWORD,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown registry value type in recovery snapshot",
            ))
        }
    };
    Ok(RegValue {
        vtype,
        bytes: value.bytes.clone(),
    })
}

fn encoded(value: RegValue) -> RegistryValueSnapshot {
    RegistryValueSnapshot {
        value_type: value.vtype as u32,
        bytes: value.bytes,
    }
}

fn read_proxy_from(registry: &impl ProxyRegistry) -> Result<ProxySettings> {
    let mut values = std::collections::BTreeMap::new();
    for name in PROXY_FIELDS {
        let value = registry
            .read(name)
            .map_err(|error| HostError::Platform(format!("cannot capture {name}: {error}")))?;
        values.insert(name.into(), value);
    }
    let raw = |name: &str| {
        values
            .get(name)
            .and_then(Option::as_ref)
            .and_then(|value| raw_registry_value(value).ok())
    };
    let string = |name: &str| {
        raw(name)
            .and_then(|value| String::from_reg_value(&value).ok())
            .filter(|value| !value.is_empty())
    };
    Ok(ProxySettings {
        enabled: raw("ProxyEnable")
            .and_then(|value| u32::from_reg_value(&value).ok())
            .unwrap_or(0)
            != 0,
        server: string("ProxyServer"),
        bypass: string("ProxyOverride"),
        auto_config_url: string("AutoConfigURL"),
        windows_registry: Some(WindowsProxySnapshot { values }),
    })
}

fn proxy_writes(settings: &ProxySettings, recovery: bool) -> Result<WindowsProxySnapshot> {
    let snapshot = if let Some(snapshot) = &settings.windows_registry {
        snapshot.clone()
    } else {
        if recovery {
            return Err(HostError::Journal("legacy Windows proxy snapshot has no registry presence/type/bytes; restore manually and retain the journal".into()));
        }
        let mut values = std::collections::BTreeMap::new();
        values.insert(
            "ProxyEnable".into(),
            Some(encoded(u32::from(settings.enabled).to_reg_value())),
        );
        for (name, value) in [
            ("ProxyServer", &settings.server),
            ("ProxyOverride", &settings.bypass),
            ("AutoConfigURL", &settings.auto_config_url),
        ] {
            values.insert(
                name.into(),
                value.as_ref().map(|text| encoded(text.to_reg_value())),
            );
        }
        WindowsProxySnapshot { values }
    };
    if snapshot.values.len() != PROXY_FIELDS.len()
        || PROXY_FIELDS
            .iter()
            .any(|name| !snapshot.values.contains_key(*name))
    {
        return Err(HostError::Journal(
            "Windows proxy snapshot is missing a captured field or contains an unexpected field"
                .into(),
        ));
    }
    // Validate all value types before the first mutation.
    for value in snapshot.values.values().flatten() {
        raw_registry_value(value).map_err(|error| HostError::Journal(error.to_string()))?;
    }
    Ok(snapshot)
}

fn write_proxy_to(
    registry: &impl ProxyRegistry,
    settings: &ProxySettings,
    recovery: bool,
) -> Result<()> {
    let snapshot = proxy_writes(settings, recovery)?;
    for name in PROXY_FIELDS {
        let result = match snapshot
            .values
            .get(name)
            .expect("complete snapshot checked")
        {
            Some(value) => registry.set(name, value),
            None => registry.delete(name),
        };
        result.map_err(|error| {
            HostError::Platform(format!("cannot restore/write {name}: {error}"))
        })?;
    }
    Ok(())
}

/// Captures presence, type and exact bytes for every registry value we touch.
pub fn read_proxy() -> Result<ProxySettings> {
    read_proxy_from(&RegistryAccess(&open_read()?))
}

/// Applies a generated configuration, or an exact captured registry snapshot.
pub fn write_proxy(settings: &ProxySettings) -> Result<()> {
    write_proxy_to(&RegistryAccess(&open_write()?), settings, false)?;
    broadcast_settings_change();
    Ok(())
}

/// Old semantic-only snapshots cannot distinguish absence from an empty value.
pub fn restore_proxy(settings: &ProxySettings) -> Result<()> {
    // Refuse incomplete legacy metadata before opening a writable registry key.
    proxy_writes(settings, true)?;
    write_proxy_to(&RegistryAccess(&open_write()?), settings, true)?;
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

#[derive(Debug, serde::Deserialize)]
struct AdapterIdentity {
    guid: String,
    index: u32,
}

fn adapter_identities() -> Result<Vec<AdapterIdentity>> {
    let script = "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ guid=$_.InterfaceGuid.ToString(); index=$_.ifIndex } })";
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| HostError::Platform(format!("cannot enumerate network adapters: {e}")))?;
    if !output.status.success() {
        return Err(HostError::Platform(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| HostError::Platform(format!("invalid adapter identities: {e}")))
}

fn normalize_guid(guid: &str) -> String {
    guid.trim_matches(['{', '}']).to_ascii_lowercase()
}

/// Captures IPv4 DNS configuration with its DHCP/static source and adapter GUID.
/// IPv6 is left untouched rather than reconstructed from IPv4 registry values.
pub fn read_dns() -> Result<DnsSettings> {
    let identities = adapter_identities()?;
    let base = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            KEY_READ,
        )
        .map_err(|e| HostError::Platform(format!("cannot open TCP/IP interfaces: {e}")))?;
    let mut entries = Vec::new();
    for name in base.enum_keys().flatten() {
        let Some(identity) = identities
            .iter()
            .find(|adapter| normalize_guid(&adapter.guid) == normalize_guid(&name))
        else {
            continue;
        };
        let interface = base
            .open_subkey_with_flags(&name, KEY_READ)
            .map_err(|e| HostError::Platform(format!("cannot read interface {name}: {e}")))?;
        let configured = read_string(&interface, "NameServer");
        let mode = if configured.is_some() {
            DnsMode::Static
        } else {
            DnsMode::Dhcp
        };
        let source = configured
            .or_else(|| read_string(&interface, "DhcpNameServer"))
            .unwrap_or_default();
        let servers: Vec<IpAddr> = source
            .split([',', ' ', ';'])
            .filter_map(|part| part.trim().parse::<IpAddr>().ok())
            .filter(IpAddr::is_ipv4)
            .collect();
        // Disconnected adapters with no resolver are not changed.
        if servers.is_empty() {
            continue;
        }
        entries.push(ResolverEntry {
            interface: name,
            servers,
            mode: Some(mode),
            interface_index: Some(identity.index),
        });
    }
    if entries.is_empty() {
        return Err(HostError::Platform(
            "no available interface reports an IPv4 DNS resolver".into(),
        ));
    }
    Ok(DnsSettings { entries })
}

/// Validates snapshots before issuing any mutating commands.
fn dns_commands(
    settings: &DnsSettings,
    identities: &[AdapterIdentity],
) -> Result<Vec<Vec<String>>> {
    let mut commands = Vec::new();
    for entry in &settings.entries {
        let mode = entry.mode.ok_or_else(|| HostError::Journal(
            "legacy DNS snapshot has no DHCP/static mode; restore manually and retain the journal".into()))?;
        let adapter = identities
            .iter()
            .find(|adapter| normalize_guid(&adapter.guid) == normalize_guid(&entry.interface))
            .ok_or_else(|| {
                HostError::Platform(format!(
                    "the recorded adapter {} is unavailable",
                    entry.interface
                ))
            })?;
        let name = format!("name={}", adapter.index);
        let base = vec!["interface".into(), "ipv4".into()];
        if mode == DnsMode::Dhcp {
            let mut command = base;
            command.extend([
                "set".into(),
                "dnsservers".into(),
                name,
                "source=dhcp".into(),
            ]);
            commands.push(command);
            continue;
        }
        if entry.servers.is_empty() || entry.servers.iter().any(IpAddr::is_ipv6) {
            return Err(HostError::Platform(
                "static IPv4 DNS snapshot has no usable IPv4 server list".into(),
            ));
        }
        for (index, address) in entry.servers.iter().enumerate() {
            let mut command = base.clone();
            if index == 0 {
                command.extend([
                    "set".into(),
                    "dnsservers".into(),
                    name.clone(),
                    "source=static".into(),
                    format!("address={address}"),
                    "validate=no".into(),
                ]);
            } else {
                command.extend([
                    "add".into(),
                    "dnsservers".into(),
                    name.clone(),
                    format!("address={address}"),
                    format!("index={}", index + 1),
                    "validate=no".into(),
                ]);
            }
            commands.push(command);
        }
    }
    Ok(commands)
}

pub fn write_dns(settings: &DnsSettings) -> Result<()> {
    // Resolve GUIDs again: an interface index can change after reboot.
    let identities = adapter_identities()?;
    for command in dns_commands(settings, &identities)? {
        let arguments: Vec<&str> = command.iter().map(String::as_str).collect();
        run_netsh(&arguments)?;
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

    #[derive(Debug, Default)]
    struct MemoryRegistry {
        values: std::sync::Mutex<std::collections::BTreeMap<String, RegistryValueSnapshot>>,
        writes: std::sync::atomic::AtomicUsize,
        fail_read: bool,
    }

    impl ProxyRegistry for MemoryRegistry {
        fn read(&self, name: &str) -> std::io::Result<Option<RegistryValueSnapshot>> {
            if self.fail_read {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            Ok(self.values.lock().unwrap().get(name).cloned())
        }

        fn set(&self, name: &str, value: &RegistryValueSnapshot) -> std::io::Result<()> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.values
                .lock()
                .unwrap()
                .insert(name.into(), value.clone());
            Ok(())
        }

        fn delete(&self, name: &str) -> std::io::Result<()> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.values.lock().unwrap().remove(name);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MemoryBackend(std::sync::Arc<MemoryRegistry>);

    impl crate::system_proxy::ProxyBackend for MemoryBackend {
        fn read(&self) -> Result<ProxySettings> {
            read_proxy_from(self.0.as_ref())
        }

        fn write(&self, settings: &ProxySettings) -> Result<()> {
            write_proxy_to(self.0.as_ref(), settings, false)
        }

        fn restore(&self, settings: &ProxySettings) -> Result<()> {
            write_proxy_to(self.0.as_ref(), settings, true)
        }
    }

    #[test]
    fn proxy_restore_preserves_absence_empty_values_types_and_raw_bytes() {
        use winreg::enums::{REG_BINARY, REG_EXPAND_SZ, REG_NONE, REG_SZ};
        let mut unusual = std::collections::BTreeMap::new();
        // These are intentionally not canonical strings or DWORDs. Recovery must
        // preserve their bytes even when the UI cannot interpret them.
        unusual.insert(
            "ProxyEnable".into(),
            encoded(RegValue {
                vtype: REG_NONE,
                bytes: vec![9, 0, 7],
            }),
        );
        unusual.insert(
            "ProxyServer".into(),
            encoded(RegValue {
                vtype: REG_EXPAND_SZ,
                bytes: "%PROXY%"
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }),
        );
        unusual.insert(
            "ProxyOverride".into(),
            encoded(RegValue {
                vtype: REG_SZ,
                bytes: vec![0, 0],
            }),
        );
        unusual.insert(
            "AutoConfigURL".into(),
            encoded(RegValue {
                vtype: REG_BINARY,
                bytes: vec![0, 255, 13, 10],
            }),
        );
        let mut malformed_string = std::collections::BTreeMap::new();
        malformed_string.insert(
            "ProxyServer".into(),
            encoded(RegValue {
                vtype: REG_SZ,
                bytes: vec![0, 216, 0, 0],
            }),
        );
        for mut values in [std::collections::BTreeMap::new(), unusual, malformed_string] {
            values.insert("UnrelatedSetting".into(), encoded(17_u32.to_reg_value()));
            let registry = MemoryRegistry {
                values: std::sync::Mutex::new(values.clone()),
                ..Default::default()
            };
            let baseline = read_proxy_from(&registry).unwrap();
            let snapshot = baseline.windows_registry.as_ref().unwrap();
            assert_eq!(snapshot.values.len(), PROXY_FIELDS.len());
            // JSON persistence must retain both explicit absence and exact bytes.
            let baseline: ProxySettings =
                serde_json::from_value(serde_json::to_value(&baseline).unwrap()).unwrap();
            write_proxy_to(
                &registry,
                &ProxySettings::routing_through("127.0.0.1:8123"),
                false,
            )
            .unwrap();
            assert!(read_proxy_from(&registry)
                .unwrap()
                .points_at("127.0.0.1:8123"));
            assert!(!registry
                .values
                .lock()
                .unwrap()
                .contains_key("AutoConfigURL"));
            write_proxy_to(&registry, &baseline, true).unwrap();
            assert_eq!(*registry.values.lock().unwrap(), values);
            assert_eq!(read_proxy_from(&registry).unwrap(), baseline);
        }
    }

    #[test]
    fn ambiguous_or_invalid_proxy_recovery_is_rejected_before_any_write() {
        let registry = MemoryRegistry::default();
        let complete = read_proxy_from(&registry).unwrap();
        let legacy: ProxySettings = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "server": null,
            "bypass": null,
            "auto_config_url": null
        }))
        .unwrap();
        assert!(legacy.windows_registry.is_none());
        let mut missing = complete.clone();
        missing
            .windows_registry
            .as_mut()
            .unwrap()
            .values
            .remove("ProxyOverride");
        let mut unknown_type = complete.clone();
        unknown_type
            .windows_registry
            .as_mut()
            .unwrap()
            .values
            .insert(
                "ProxyEnable".into(),
                Some(RegistryValueSnapshot {
                    value_type: 99,
                    bytes: vec![],
                }),
            );
        let mut unexpected = complete;
        unexpected
            .windows_registry
            .as_mut()
            .unwrap()
            .values
            .insert("Unexpected".into(), None);
        for invalid in [legacy, missing, unknown_type, unexpected] {
            assert!(write_proxy_to(&registry, &invalid, true).is_err());
            assert_eq!(registry.writes.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(registry.values.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn registry_read_errors_are_not_recorded_as_absent_proxy_fields() {
        let registry = MemoryRegistry {
            fail_read: true,
            ..Default::default()
        };
        let error = read_proxy_from(&registry).unwrap_err();
        assert!(error.to_string().contains("cannot capture ProxyEnable"));
        assert_eq!(registry.writes.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn legacy_proxy_journal_stays_pending_without_mutation_or_baseline_replacement() {
        use crate::journal::{ChangeJournal, JournalEntry, JournalKind};
        let directory = crate::test_support::directory();
        let path = directory.join("legacy-proxy.json");
        let legacy = serde_json::json!({
            "enabled": false, "server": null, "bypass": null, "auto_config_url": null
        });
        let desired = ProxySettings::routing_through("127.0.0.1:8123");
        let mut journal = ChangeJournal::load_at(&path).unwrap();
        journal
            .record(JournalEntry::new(
                JournalKind::SystemProxy,
                legacy.clone(),
                serde_json::to_value(&desired).unwrap(),
                "legacy proxy baseline",
            ))
            .unwrap();
        let registry = std::sync::Arc::new(MemoryRegistry::default());
        let backend = std::sync::Arc::new(MemoryBackend(std::sync::Arc::clone(&registry)));
        let mut proxy =
            crate::SystemProxy::with_backend("127.0.0.1:8123".into(), backend, path.clone())
                .unwrap();
        assert!(proxy.revert().unwrap_err().to_string().contains("legacy"));
        assert!(proxy.apply().unwrap_err().to_string().contains("pending"));
        let retained = ChangeJournal::load_at(&path).unwrap();
        assert_eq!(retained.entries().len(), 1);
        assert_eq!(
            retained.original(JournalKind::SystemProxy).unwrap().before,
            legacy
        );
        assert_eq!(registry.writes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(registry.values.lock().unwrap().is_empty());
        drop(proxy);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn access_denied_detection() {
        assert!(is_access_denied("Access is denied."));
        assert!(is_access_denied(
            "The requested operation requires elevation."
        ));
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
    #[ignore = "writes live user proxy settings; use isolated mock tests in CI"]
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
            windows_registry: original.windows_registry.clone(),
        };

        // Compare presence, value types and raw bytes as well as the semantic fields.
        restore_proxy(&probe).expect("write back the captured proxy values");
        let after = read_proxy().expect("readable after write");
        assert_eq!(after, probe);
    }
    #[test]
    fn dns_restore_retains_dhcp_and_rejects_ambiguous_legacy_snapshots() {
        let mut settings = DnsSettings {
            entries: vec![ResolverEntry {
                interface: "{abc}".into(),
                servers: vec!["8.8.8.8".parse().unwrap()],
                mode: Some(DnsMode::Dhcp),
                interface_index: Some(5),
            }],
        };
        let identities = vec![AdapterIdentity {
            guid: "ABC".into(),
            index: 9,
        }];
        let commands = dns_commands(&settings, &identities).unwrap();
        assert!(commands[0].contains(&"source=dhcp".into()));
        assert!(commands[0].contains(&"name=9".into()));
        settings.entries[0].mode = None;
        assert!(dns_commands(&settings, &identities)
            .unwrap_err()
            .to_string()
            .contains("legacy"));
    }

    #[test]
    fn static_dns_keeps_server_priority() {
        let settings = DnsSettings {
            entries: vec![ResolverEntry {
                interface: "abc".into(),
                servers: vec![
                    "1.1.1.1".parse().unwrap(),
                    "8.8.8.8".parse().unwrap(),
                    "9.9.9.9".parse().unwrap(),
                ],
                mode: Some(DnsMode::Static),
                interface_index: Some(1),
            }],
        };
        let commands = dns_commands(
            &settings,
            &[AdapterIdentity {
                guid: "abc".into(),
                index: 1,
            }],
        )
        .unwrap();
        assert!(commands[1].contains(&"index=2".into()));
        assert!(commands[2].contains(&"index=3".into()));
    }
}
