//! Explicitly opted-in Windows acceptance. Never run against real settings by default.
#![cfg(windows)]

use nullad_host::{ChangeJournal, DnsSettings, ProxySettings, SystemProxy};

struct ProxyCleanup {
    original: ProxySettings,
    armed: bool,
}

impl Drop for ProxyCleanup {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = nullad_host::platform::restore_proxy_settings(&self.original) {
                eprintln!("Emergency proxy restore failed: {error}; the recovery snapshot remains in NULLAD_HOME.");
            }
        }
    }
}

fn redacted_proxy(proxy: &ProxySettings) -> serde_json::Value {
    // Raw registry bytes can contain a PAC URL or other private values. The
    // deliverable records only presence, type and byte length; the isolated
    // recovery copy below retains the complete baseline.
    let fields = proxy.windows_registry.as_ref().map(|snapshot| {
        snapshot
            .values
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    serde_json::json!({
                        "present": value.is_some(),
                        "value_type": value.as_ref().map(|value| value.value_type),
                        "byte_length": value.as_ref().map(|value| value.bytes.len())
                    }),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>()
    });
    serde_json::json!({
        "enabled": proxy.enabled,
        "server": proxy.server,
        "bypass": proxy.bypass,
        "auto_config_url": proxy.auto_config_url.as_ref().map(|_| "<redacted>"),
        "windows_registry_fields": fields
    })
}

fn save_report(path: &std::path::Path, value: &serde_json::Value) {
    nullad_host::journal::atomic_write(path, &serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[test]
#[ignore = "changes live system proxy; requires explicit opt-in and an isolated NULLAD_HOME"]
fn live_windows_proxy_apply_restore_preserves_system_baseline() {
    assert_eq!(
        std::env::var("NULLAD_LIVE_SYSTEM_TEST").as_deref(),
        Ok("1"),
        "explicit opt-in is required"
    );
    let isolated = std::path::PathBuf::from(
        std::env::var_os("NULLAD_HOME").expect("isolated NULLAD_HOME required"),
    );
    assert!(isolated.is_absolute());
    let report_path = std::path::PathBuf::from(
        std::env::var_os("NULLAD_ACCEPTANCE_OUTPUT").expect("report path required"),
    );
    assert!(report_path.is_absolute());

    let before_proxy =
        nullad_host::platform::read_proxy().expect("capture complete proxy baseline");
    let raw_fields = &before_proxy
        .windows_registry
        .as_ref()
        .expect("exact Windows proxy snapshot required")
        .values;
    assert_eq!(raw_fields.len(), 4);
    for name in [
        "ProxyEnable",
        "ProxyServer",
        "ProxyOverride",
        "AutoConfigURL",
    ] {
        assert!(
            raw_fields.contains_key(name),
            "baseline must capture {name}, including absence"
        );
    }
    let before_dns = nullad_host::platform::read_dns().expect("capture DNS without mutation");
    let elevated = nullad_host::has_elevated_privileges();
    let mut report = serde_json::json!({
        "platform": "windows",
        "captured_at_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
        "elevated": elevated,
        "proxy_before": redacted_proxy(&before_proxy),
        "dns_before": before_dns,
        "proxy_apply_restore": "not_run",
        "dns_apply_restore": "unknown",
        "dns_reason": if elevated { "DNS mutation requires a separately selected privileged test" } else { "current process is not elevated; DNS was not modified" }
    });
    save_report(&report_path, &report);
    // The private copy retains all four fields with presence, type and raw bytes.
    let raw_baseline = serde_json::json!({ "proxy": before_proxy, "dns": before_dns });
    let private_path = nullad_host::paths::data_dir()
        .unwrap()
        .join("live-system-baseline.json");
    nullad_host::journal::atomic_write(
        &private_path,
        &serde_json::to_vec_pretty(&raw_baseline).unwrap(),
    )
    .unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let mut cleanup = ProxyCleanup {
        original: before_proxy.clone(),
        armed: true,
    };
    let mut proxy = SystemProxy::new(address.clone()).unwrap();
    assert!(
        proxy.journal().is_empty(),
        "live test refuses an existing isolated journal"
    );
    proxy
        .apply()
        .expect("apply temporary proxy with durable recovery snapshot");
    let applied = nullad_host::platform::read_proxy().expect("read applied proxy");
    assert!(applied.points_at(&address));
    assert!(proxy.revert().expect("restore original proxy").is_some());
    let after_proxy = nullad_host::platform::read_proxy().expect("verify proxy after restore");
    assert_eq!(
        after_proxy, before_proxy,
        "presence, type and raw bytes of all four proxy fields must match"
    );
    cleanup.armed = false;
    let after_dns: DnsSettings = nullad_host::platform::read_dns().expect("verify unchanged DNS");
    assert_eq!(
        after_dns, before_dns,
        "DNS was never changed by proxy acceptance"
    );
    assert!(ChangeJournal::load().unwrap().is_empty());
    report["proxy_apply_restore"] = serde_json::json!("pass");
    report["proxy_after"] = redacted_proxy(&after_proxy);
    report["dns_after"] = serde_json::to_value(after_dns).unwrap();
    report["proxy_restored_exactly"] = serde_json::json!(true);
    report["proxy_raw_fields_restored_exactly"] = serde_json::json!(true);
    report["dns_unchanged"] = serde_json::json!(true);
    report["pending_changes"] = serde_json::json!(0);
    save_report(&report_path, &report);
    println!("Windows live proxy apply/revert: PASS; all four registry fields restored with exact presence, types and bytes; DNS unchanged; pending journal = 0. DNS mutation: UNKNOWN (not tested).");
}
