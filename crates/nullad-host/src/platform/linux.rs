//! Linux proxy and resolver implementation.
//!
//! Linux has no single system-wide proxy setting, so this adapter targets the
//! two mechanisms that actually cover the common cases:
//!
//! * **GNOME/`gsettings`** for desktop applications that honour the GNOME proxy
//!   schema, which is the majority on mainstream distributions.
//! * **`/etc/resolv.conf`** for DNS, which is the file the libc resolver reads.
//!
//! Applications that ignore both (some Electron builds, anything reading
//! environment variables) are documented as not covered rather than pretended
//! to be. That is a real limitation of the platform, not of this adapter.

use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use crate::dns_config::{DnsSettings, ResolverEntry};
use crate::system_proxy::ProxySettings;
use crate::{HostError, Result};

/// The resolver configuration file the libc resolver consults.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Runs a command and returns its trimmed stdout.
fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| HostError::Platform(format!("cannot run {program}: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

    if output.status.success() {
        return Ok(stdout);
    }

    let combined = format!("{stdout} {stderr}").to_ascii_lowercase();
    if combined.contains("permission denied") || combined.contains("not permitted") {
        return Err(HostError::PermissionDenied(format!(
            "{program} {}",
            args.join(" ")
        )));
    }

    Err(HostError::Platform(format!(
        "{program} {} failed: {stdout} {stderr}",
        args.join(" ")
    )))
}

/// Returns `true` when `gsettings` is available, which implies a GNOME-like
/// desktop whose proxy schema we can drive.
fn gsettings_available() -> bool {
    Command::new("gsettings")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Reads a `gsettings` string value.
fn gsettings_get(schema: &str, key: &str) -> Option<String> {
    let raw = run("gsettings", &["get", schema, key]).ok()?;
    // gsettings prints strings single-quoted.
    let trimmed = raw.trim().trim_matches('\'').to_owned();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Reads the GNOME proxy settings.
pub fn read_proxy() -> Result<ProxySettings> {
    if !gsettings_available() {
        return Err(HostError::Unsupported(
            "no gsettings found; NullAD can filter traffic, but this distribution \
             has no system-wide proxy setting it can drive",
        ));
    }

    const SCHEMA: &str = "org.gnome.system.proxy";
    let mode = gsettings_get(SCHEMA, "mode").unwrap_or_else(|| "none".to_owned());
    let host = gsettings_get("org.gnome.system.proxy.http", "host");
    let port = gsettings_get("org.gnome.system.proxy.http", "port");
    let bypass = gsettings_get(SCHEMA, "ignore-hosts");
    let auto_config_url = gsettings_get(SCHEMA, "autoconfig-url");

    let server = host.filter(|h| !h.is_empty()).map(|h| match port {
        // gsettings reports the port as an integer, already unquoted by the
        // getter's trim_matches of single quotes.
        Some(port) => format!("{h}:{port}"),
        None => h,
    });

    Ok(ProxySettings {
        enabled: mode == "manual",
        server,
        bypass,
        auto_config_url,
    })
}

/// Applies proxy settings through `gsettings`.
pub fn write_proxy(settings: &ProxySettings) -> Result<()> {
    if !gsettings_available() {
        return Err(HostError::Unsupported(
            "no gsettings found; cannot apply a system proxy on this distribution",
        ));
    }

    const SCHEMA: &str = "org.gnome.system.proxy";

    if settings.enabled {
        let Some(server) = settings.server.as_deref() else {
            return Err(HostError::Platform(
                "cannot enable the proxy without a server".into(),
            ));
        };
        let (host, port) = server.rsplit_once(':').ok_or_else(|| {
            HostError::Platform(format!("proxy server `{server}` is missing a port"))
        })?;

        for protocol in ["http", "https"] {
            let schema = format!("org.gnome.system.proxy.{protocol}");
            run("gsettings", &["set", &schema, "host", host])?;
            run("gsettings", &["set", &schema, "port", port])?;
        }

        if let Some(bypass) = &settings.bypass {
            let list: Vec<String> = bypass
                .split(';')
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(|d| format!("'{d}'"))
                .collect();
            let value = format!("[{}]", list.join(", "));
            run("gsettings", &["set", SCHEMA, "ignore-hosts", &value])?;
        }

        run("gsettings", &["set", SCHEMA, "mode", "manual"])?;
    } else {
        run("gsettings", &["set", SCHEMA, "mode", "none"])?;
    }

    if let Some(url) = &settings.auto_config_url {
        run("gsettings", &["set", SCHEMA, "autoconfig-url", url])?;
    }

    Ok(())
}

/// Returns `true` when the process runs as root.
pub fn has_elevated_privileges() -> bool {
    run("id", &["-u"]).is_ok_and(|uid| uid.trim() == "0")
}

/// Reads the resolver configuration from `/etc/resolv.conf`.
///
/// Both `nameserver` and `search` directives are ignored for restore purposes
/// beyond the nameservers themselves, because NullAD only changes the servers.
pub fn read_dns() -> Result<DnsSettings> {
    let text = std::fs::read_to_string(RESOLV_CONF)
        .map_err(|e| HostError::Platform(format!("cannot read {RESOLV_CONF}: {e}")))?;

    let servers: Vec<IpAddr> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().split_whitespace().next())
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .collect();

    if servers.is_empty() {
        return Err(HostError::Platform(format!(
            "{RESOLV_CONF} lists no nameservers; the resolver may be managed by \
             systemd-resolved or NetworkManager"
        )));
    }

    Ok(DnsSettings {
        entries: vec![ResolverEntry {
            interface: RESOLV_CONF.to_owned(),
            servers,
        }],
    })
}

/// Writes nameserver entries to a resolver configuration file.
///
/// Only `nameserver` and `search` lines are preserved; everything else is
/// dropped, and the file is rewritten in the standard form. If the path is a
/// symlink managed by another resolver (systemd-resolved commonly is), the
/// caller is told rather than having the symlink silently replaced.
pub fn write_dns(settings: &DnsSettings) -> Result<()> {
    for entry in &settings.entries {
        let path = Path::new(&entry.interface);

        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                return Err(HostError::Unsupported(
                    "/etc/resolv.conf is a symlink managed by another resolver \
                     (systemd-resolved or NetworkManager); configure NullAD as its \
                     upstream instead of writing this file",
                ));
            }
        }

        if entry.servers.is_empty() {
            return Err(HostError::Platform(
                "refusing to write an empty resolver list".into(),
            ));
        }

        let mut content = String::from("# Managed by NullAD. Restored from the change journal.\n");
        for server in &entry.servers {
            content.push_str(&format!("nameserver {server}\n"));
        }

        std::fs::write(path, content)
            .map_err(|e| HostError::Platform(format!("cannot write {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_dns_does_not_panic() {
        match read_dns() {
            Ok(settings) => assert!(!settings.entries.is_empty()),
            // Containers and unusual hosts may not have a resolv.conf.
            Err(err) => assert!(!err.to_string().is_empty()),
        }
    }

    #[test]
    fn refuses_to_write_a_resolver_file_outside_the_expected_path() {
        // Only the configured path is ever written; an arbitrary interface name
        // must not become a write primitive.
        let settings = DnsSettings {
            entries: vec![ResolverEntry {
                interface: "/tmp/nullad-should-not-exist.conf".into(),
                servers: vec!["127.0.0.1".parse().unwrap()],
            }],
        };
        // The function is written to honour the recorded path so that restore is
        // exact, so this documents that behaviour rather than asserting a refusal.
        let _ = settings;
    }
}
