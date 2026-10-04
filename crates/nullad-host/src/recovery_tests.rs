use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::dns_config::{DnsBackend, DnsConfigurator, DnsMode, DnsSettings, ResolverEntry};
use crate::system_proxy::{ProxyBackend, ProxySettings, SystemProxy};
use crate::{ChangeJournal, HostError, JournalEntry, JournalKind, Result};

#[derive(Debug)]
struct MockBackend {
    proxy: Mutex<ProxySettings>,
    dns: Mutex<DnsSettings>,
    proxy_failures: AtomicUsize,
    dns_failures: AtomicUsize,
    writes: AtomicUsize,
}

impl MockBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            proxy: Mutex::new(ProxySettings::disabled()),
            dns: Mutex::new(DnsSettings {
                entries: vec![
                    ResolverEntry {
                        interface: "wifi-guid".into(),
                        servers: vec!["192.168.1.1".parse().unwrap()],
                        mode: Some(DnsMode::Dhcp),
                        interface_index: Some(3),
                    },
                    ResolverEntry {
                        interface: "ethernet-guid".into(),
                        servers: vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()],
                        mode: Some(DnsMode::Static),
                        interface_index: Some(4),
                    },
                ],
            }),
            proxy_failures: AtomicUsize::new(0),
            dns_failures: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        })
    }
    fn fail(counter: &AtomicUsize) -> bool {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            })
            .is_ok()
    }
}

impl ProxyBackend for MockBackend {
    fn read(&self) -> Result<ProxySettings> {
        Ok(self.proxy.lock().unwrap().clone())
    }
    fn write(&self, value: &ProxySettings) -> Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.proxy.lock().unwrap() = value.clone();
        if Self::fail(&self.proxy_failures) {
            return Err(HostError::Platform("simulated partial proxy write".into()));
        }
        Ok(())
    }
}

impl DnsBackend for MockBackend {
    fn read(&self) -> Result<DnsSettings> {
        Ok(self.dns.lock().unwrap().clone())
    }
    fn write(&self, value: &DnsSettings) -> Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.dns.lock().unwrap() = value.clone();
        if Self::fail(&self.dns_failures) {
            return Err(HostError::Platform("simulated partial DNS write".into()));
        }
        Ok(())
    }
}

#[test]
fn partial_apply_rolls_back_but_retains_baseline_until_verified_recovery() {
    let path = crate::test_support::directory().join("journal.json");
    let backend = MockBackend::new();
    backend.proxy_failures.store(1, Ordering::SeqCst);
    let mut proxy =
        SystemProxy::with_backend("127.0.0.1:8080".into(), backend.clone(), path.clone()).unwrap();
    assert!(proxy.apply().is_err());
    assert_eq!(*backend.proxy.lock().unwrap(), ProxySettings::disabled());
    let journal = ChangeJournal::load_at(path.clone()).unwrap();
    assert_eq!(journal.entries().len(), 1);
    assert_eq!(
        journal
            .latest(JournalKind::SystemProxy)
            .unwrap()
            .before_as::<ProxySettings>()
            .unwrap(),
        ProxySettings::disabled()
    );
    // A new apply cannot silently replace an outstanding baseline.
    assert!(proxy.apply().is_err());
    assert_eq!(backend.writes.load(Ordering::SeqCst), 2);
    assert_eq!(proxy.revert().unwrap(), Some(ProxySettings::disabled()));
    assert!(ChangeJournal::load_at(path).unwrap().is_empty());
}

#[test]
fn failed_recovery_keeps_only_the_failed_kind_and_can_be_retried() {
    let path = crate::test_support::directory().join("journal.json");
    let backend = MockBackend::new();
    let original_dns = backend.dns.lock().unwrap().clone();
    // Construct before either applies to exercise stale adapter snapshots.
    let mut proxy =
        SystemProxy::with_backend("127.0.0.1:8080".into(), backend.clone(), path.clone()).unwrap();
    let mut dns =
        DnsConfigurator::with_backend("127.0.0.1".parse().unwrap(), backend.clone(), path.clone())
            .unwrap();
    proxy.apply().unwrap();
    dns.apply().unwrap();
    assert_eq!(
        ChangeJournal::load_at(path.clone())
            .unwrap()
            .entries()
            .len(),
        2
    );
    backend.proxy_failures.store(1, Ordering::SeqCst);
    assert!(proxy.revert().is_err());
    assert_eq!(dns.revert().unwrap(), Some(original_dns));
    let journal = ChangeJournal::load_at(path.clone()).unwrap();
    assert!(journal.has_pending(JournalKind::SystemProxy));
    assert!(!journal.has_pending(JournalKind::DnsResolver));
    proxy.revert().unwrap();
    assert!(ChangeJournal::load_at(path).unwrap().is_empty());
}

#[test]
fn dns_partial_apply_preserves_dhcp_mode_and_rollback_evidence() {
    let path = crate::test_support::directory().join("journal.json");
    let backend = MockBackend::new();
    let original = backend.dns.lock().unwrap().clone();
    backend.dns_failures.store(1, Ordering::SeqCst);
    let mut dns =
        DnsConfigurator::with_backend("127.0.0.1".parse().unwrap(), backend.clone(), path.clone())
            .unwrap();
    assert!(dns.apply().is_err());
    assert_eq!(*backend.dns.lock().unwrap(), original);
    assert!(ChangeJournal::load_at(path)
        .unwrap()
        .has_pending(JournalKind::DnsResolver));
    dns.revert().unwrap();
}

#[test]
fn pending_apply_never_replaces_the_original_proxy_snapshot() {
    let path = crate::test_support::directory().join("journal.json");
    let backend = MockBackend::new();
    let mut proxy =
        SystemProxy::with_backend("127.0.0.1:8080".into(), backend.clone(), path.clone()).unwrap();
    proxy.apply().unwrap();
    assert_eq!(proxy.apply().unwrap(), ProxySettings::disabled());
    let mut other =
        SystemProxy::with_backend("127.0.0.1:9090".into(), backend.clone(), path.clone()).unwrap();
    assert!(other.apply().is_err());
    let journal = ChangeJournal::load_at(path).unwrap();
    assert_eq!(journal.entries().len(), 1);
    assert_eq!(
        journal.entries()[0].before_as::<ProxySettings>().unwrap(),
        ProxySettings::disabled()
    );
}

#[test]
fn failed_journal_write_prevents_system_mutation() {
    let path = crate::test_support::directory()
        .join("missing-directory")
        .join("journal.json");
    let backend = MockBackend::new();
    let mut proxy =
        SystemProxy::with_backend("127.0.0.1:8080".into(), backend.clone(), path).unwrap();
    assert!(proxy.apply().is_err());
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn concurrent_journal_updates_do_not_lose_another_writer() {
    let path = crate::test_support::directory().join("journal.json");
    std::thread::scope(|scope| {
        for index in 0..8 {
            let path = path.clone();
            scope.spawn(move || {
                let mut journal = ChangeJournal::load_at(path).unwrap();
                journal
                    .record(JournalEntry::new(
                        if index % 2 == 0 {
                            JournalKind::SystemProxy
                        } else {
                            JournalKind::DnsResolver
                        },
                        serde_json::json!({"index": index}),
                        serde_json::json!({}),
                        "concurrent test",
                    ))
                    .unwrap();
            });
        }
    });
    assert_eq!(ChangeJournal::load_at(path).unwrap().entries().len(), 8);
}

#[test]
fn corrupt_journal_is_not_replaced_with_empty_recovery_state() {
    let path = crate::test_support::directory().join("journal.json");
    std::fs::write(&path, "{incomplete").unwrap();
    assert!(ChangeJournal::load_at(path.clone()).is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "{incomplete");
}

#[test]
fn multiple_legacy_entries_restore_the_original_baseline() {
    let path = crate::test_support::directory().join("journal.json");
    let backend = MockBackend::new();
    let mut journal = ChangeJournal::load_at(path.clone()).unwrap();
    let original = ProxySettings::disabled();
    let middle = ProxySettings::routing_through("127.0.0.1:8080");
    let newest = ProxySettings::routing_through("127.0.0.1:9090");
    for (before, after) in [(&original, &middle), (&middle, &newest)] {
        journal
            .record(JournalEntry::new(
                JournalKind::SystemProxy,
                serde_json::to_value(before).unwrap(),
                serde_json::to_value(after).unwrap(),
                "legacy multi-apply",
            ))
            .unwrap();
    }
    *backend.proxy.lock().unwrap() = newest;
    let mut proxy =
        SystemProxy::with_backend("127.0.0.1:9090".into(), backend.clone(), path.clone()).unwrap();
    assert_eq!(proxy.revert().unwrap(), Some(original.clone()));
    assert_eq!(*backend.proxy.lock().unwrap(), original);
    assert!(ChangeJournal::load_at(path).unwrap().is_empty());
}
