//! macOS proxy and resolver implementation.
//!
//! Both settings are changed through `networksetup`, which is the only
//! supported way to alter them such that the system applies the change live
//! rather than at next boot. Writing the preference plists directly is not
//! equivalent: `configd` caches the values and does not notice.
//!
//! Every change is scoped to the active network service, found by asking
//! `networksetup` which service currently has the default route. Modifying
//! "all services" would capture VPN and Thunderbolt bridges too, which is
//! surprising and hard to undo.

use std::net::IpAddr;
use std::process::Command;

use crate::dns_config::{DnsSettings, ResolverEntry};
use crate::system_proxy::ProxySettings;
use crate::{HostError, Result};

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
    if combined.contains("not permitted")
        || combined.contains("permission denied")
        || combined.contains("must be run as root")
    {
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

/// Returns the network service backing the default route.
fn active_service() -> Result<String> {
    // The route table names the interface; networksetup maps it to a service.
    let route = run("/sbin/route", &["-n", "get", "default"])?;
    let interface = route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:"))
        .map(str::trim)
        .ok_or_else(|| HostError::Platform("no default route found".into()))?;

    let order = run("/usr/sbin/networksetup", &["-listnetworkserviceorder"])?;
    // Entries look like: (1) Wi-Fi / (Hardware Port: Wi-Fi, Device: en0)
    let mut candidate: Option<String> = None;
    for line in order.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('(') {
            if let Some((index, name)) = rest.split_once(')') {
                let _ = index;
                candidate = Some(name.trim().to_owned());
            }
        }
        if trimmed.contains(&format!("Device: {interface}")) {
            if let Some(name) = candidate.take() {
                return Ok(name);
            }
        }
    }

    Err(HostError::Platform(format!(
        "could not map interface {interface} to a network service"
    )))
}

/// Reads the current proxy settings of the active service.
pub fn read_proxy() -> Result<ProxySettings> {
    let service = active_service()?;
    let web = run("/usr/sbin/networksetup", &["-getwebproxy", &service])?;
    let bypass = run(
        "/usr/sbin/networksetup",
        &["-getproxybypassdomains", &service],
    )
    .ok();
    let auto = run("/usr/sbin/networksetup", &["-getautoproxyurl", &service]).ok();

    let mut enabled = false;
    let mut server = None;
    for line in web.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Enabled:") {
            enabled = value.trim().eq_ignore_ascii_case("yes");
        } else if let Some(value) = trimmed.strip_prefix("Server:") {
            server = Some(value.trim().to_owned());
        }
    }

    // Combine server and port into the host:port form the rest of the code uses.
    let port = web.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Port:")
            .and_then(|value| value.trim().parse::<u16>().ok())
    });

    let server = server.filter(|s| !s.is_empty()).map(|s| match port {
        Some(port) => format!("{s}:{port}"),
        None => s,
    });

    let bypass = bypass
        .filter(|b| !b.trim().is_empty() && !b.contains("There aren't any"))
        .map(|b| b.lines().map(str::trim).collect::<Vec<_>>().join(";"));

    let auto_config_url = auto
        .filter(|a| !a.contains("URL: (null)"))
        .and_then(|a| {
            a.lines()
                .find_map(|line| line.trim().strip_prefix("URL:"))
                .map(|url| url.trim().to_owned())
        })
        .filter(|url| !url.is_empty());

    Ok(ProxySettings {
        enabled,
        server,
        bypass,
        auto_config_url,
        windows_registry: None,
    })
}

/// Applies proxy settings to the active service.
pub fn write_proxy(settings: &ProxySettings) -> Result<()> {
    let service = active_service()?;

    if settings.enabled {
        let Some(server) = settings.server.as_deref() else {
            return Err(HostError::Platform(
                "cannot enable the proxy without a server".into(),
            ));
        };
        let (host, port) = server.rsplit_once(':').ok_or_else(|| {
            HostError::Platform(format!("proxy server `{server}` is missing a port"))
        })?;

        run(
            "/usr/sbin/networksetup",
            &["-setwebproxy", &service, host, port],
        )?;
        run(
            "/usr/sbin/networksetup",
            &["-setsecurewebproxy", &service, host, port],
        )?;

        if let Some(bypass) = &settings.bypass {
            let domains: Vec<&str> = bypass.split(';').filter(|d| !d.trim().is_empty()).collect();
            let mut args = vec!["-setproxybypassdomains", service.as_str()];
            args.extend(domains);
            run("/usr/sbin/networksetup", &args)?;
        }
    } else {
        run(
            "/usr/sbin/networksetup",
            &["-setwebproxystate", &service, "off"],
        )?;
        run(
            "/usr/sbin/networksetup",
            &["-setsecurewebproxystate", &service, "off"],
        )?;
    }

    match &settings.auto_config_url {
        Some(url) => {
            run(
                "/usr/sbin/networksetup",
                &["-setautoproxyurl", &service, url],
            )?;
        }
        None => {
            // Clearing the PAC URL matters: otherwise a PAC script would override
            // the fixed proxy and NullAD would silently filter nothing.
            let _ = run(
                "/usr/sbin/networksetup",
                &["-setautoproxystate", &service, "off"],
            );
        }
    }

    Ok(())
}

/// Returns `true` when the process runs as root.
pub fn has_elevated_privileges() -> bool {
    // geteuid is exposed through the libc crate, which is not a dependency here,
    // so the effective user is read from `id` instead.
    run("/usr/bin/id", &["-u"])
        .map(|uid| uid.trim() == "0")
        .unwrap_or(false)
}

/// Reads resolver settings for the active service.
pub fn read_dns() -> Result<DnsSettings> {
    let service = active_service()?;
    let output = run("/usr/sbin/networksetup", &["-getdnsservers", &service])?;

    let servers: Vec<IpAddr> = output
        .lines()
        .filter_map(|line| line.trim().parse::<IpAddr>().ok())
        .collect();

    if servers.is_empty() {
        return Err(HostError::Platform(format!(
            "service `{service}` uses DHCP-provided resolvers, which cannot be \
             captured for restore; point the router's DNS at NullAD instead"
        )));
    }

    Ok(DnsSettings {
        entries: vec![ResolverEntry {
            interface: service,
            mode: None,
            interface_index: None,
            servers,
        }],
    })
}

/// Applies resolver settings to the recorded services.
pub fn write_dns(settings: &DnsSettings) -> Result<()> {
    for entry in &settings.entries {
        let servers: Vec<String> = entry.servers.iter().map(ToString::to_string).collect();
        let mut args = vec!["-setdnsservers", entry.interface.as_str()];
        if servers.is_empty() {
            // "Empty" is how networksetup expresses "revert to DHCP".
            args.push("Empty");
        } else {
            args.extend(servers.iter().map(String::as_str));
        }
        run("/usr/sbin/networksetup", &args)?;
        // Flush the resolver cache so the change takes effect immediately.
        let _ = run("/usr/bin/dscacheutil", &["-flushcache"]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_service_lookup_does_not_panic() {
        // On a machine without a default route this legitimately errors; the
        // requirement is only that it never panics.
        match active_service() {
            Ok(service) => assert!(!service.is_empty()),
            Err(err) => assert!(!err.to_string().is_empty()),
        }
    }
}
