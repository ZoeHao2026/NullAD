//! One serialized lifecycle used by IPC, the tray and application exit.
use crate::DesktopState;
use nullad_api::ProtectionState;
use nullad_intercept::{DnsConfig, DnsServer, ProxyConfig, ProxyServer};
use std::{io, sync::Arc};
use tokio::sync::watch;

#[derive(Debug, Default)]
pub struct RunningTasks {
    cancel: Option<watch::Sender<bool>>,
    handles: Vec<tauri::async_runtime::JoinHandle<io::Result<()>>>,
}

impl RunningTasks {
    async fn stop(&mut self) -> Vec<String> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(true);
        }
        let mut errors = Vec::new();
        for handle in self.handles.drain(..) {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => errors.push(e.to_string()),
                Err(e) => errors.push(e.to_string()),
            }
        }
        errors
    }
}

pub async fn start(state: &DesktopState) -> Result<Vec<String>, String> {
    let mut tasks = state.tasks.lock().await;
    if state.exiting.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("Application is shutting down".into());
    }
    if state.app.status().protection.is_active() {
        return Ok(Vec::new());
    }
    let _ = tasks.stop().await;
    let settings = state.app.state().settings();
    if (!settings.proxy_enabled && !settings.dns_enabled)
        || (settings.proxy_enabled && settings.proxy_port == 0)
        || (settings.dns_enabled && settings.dns_port == 0)
        || (settings.intercept_system_proxy && !settings.proxy_enabled)
    {
        return Err(
            "Enable a listener with a non-zero port; system proxy requires HTTP proxy".into(),
        );
    }
    state
        .app
        .state()
        .set_runtime_status(ProtectionState::Starting, None, None, false, None);
    state.app.state().capture_startup_settings(settings.clone());
    let mut system_attempted = false;
    let result = async {
        let handle = state.app.state().engine_handle();
        let proxy = if settings.proxy_enabled {
            Some(Arc::new(
                ProxyServer::bind(
                    ProxyConfig {
                        listen: ([127, 0, 0, 1], settings.proxy_port).into(),
                        ..ProxyConfig::default()
                    },
                    handle.clone(),
                )
                .await
                .map_err(|e| format!("HTTP proxy: {e}"))?,
            ))
        } else {
            None
        };
        let dns = if settings.dns_enabled {
            let upstream = nullad_intercept::dns::resolve_upstream(&settings.dns_upstream)
                .ok_or_else(|| "Invalid DNS upstream".to_owned())?;
            Some(Arc::new(
                DnsServer::bind(
                    DnsConfig {
                        listen: ([127, 0, 0, 1], settings.dns_port).into(),
                        upstream,
                        nxdomain: settings.dns_nxdomain,
                        ..DnsConfig::default()
                    },
                    handle,
                )
                .await
                .map_err(|e| format!("DNS: {e}"))?,
            ))
        } else {
            None
        };
        let proxy_port = proxy
            .as_ref()
            .map(|p| p.local_addr().map(|a| a.port()))
            .transpose()
            .map_err(|e| e.to_string())?;
        let dns_port = dns
            .as_ref()
            .map(|p| p.local_addr().map(|a| a.port()))
            .transpose()
            .map_err(|e| e.to_string())?;
        let (cancel, receiver) = watch::channel(false);
        let (startup, ready) = watch::channel(false);
        tasks.cancel = Some(cancel.clone());
        if let Some(proxy) = proxy {
            let receiver = receiver.clone();
            tasks.handles.push(supervise(
                state.app.clone(),
                cancel.clone(),
                ready.clone(),
                "HTTP proxy",
                async move { proxy.run_until(receiver).await },
            ));
        }
        if let Some(dns) = dns {
            tasks.handles.push(supervise(
                state.app.clone(),
                cancel.clone(),
                ready,
                "DNS",
                async move { dns.run_until(receiver).await },
            ));
        }
        if settings.intercept_system_proxy {
            system_attempted = true;
            let port = settings.proxy_port;
            tauri::async_runtime::spawn_blocking(move || {
                let mut proxy = nullad_host::SystemProxy::new(format!("127.0.0.1:{port}"))?;
                proxy.apply()
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
            state.app.runtime().set_system_proxy_active(true);
        }
        state.app.runtime().set_dns_active(dns_port.is_some());
        state.app.state().set_runtime_status(
            ProtectionState::Running,
            proxy_port,
            dns_port,
            settings.intercept_system_proxy,
            None,
        );
        let _ = startup.send(true);
        Ok::<_, String>(vec!["Protection started".into()])
    }
    .await;
    if let Err(ref error) = result {
        let restore_error = if system_attempted {
            let app = state.app.clone();
            match tauri::async_runtime::spawn_blocking(move || {
                app.runtime().restore_system_changes()
            })
            .await
            {
                Ok(report) => report
                    .items
                    .into_iter()
                    .filter_map(|item| item.error)
                    .next(),
                Err(error) => Some(error.to_string()),
            }
        } else {
            None
        };
        let _ = tasks.stop().await;
        state.app.runtime().set_dns_active(false);
        state.app.state().set_runtime_status(
            ProtectionState::Failed,
            None,
            None,
            state.app.runtime().system_proxy_active(),
            Some(
                restore_error.map_or_else(|| error.clone(), |e| format!("{error}; recovery: {e}")),
            ),
        );
    }
    result
}

pub async fn stop(state: &DesktopState) -> Result<Vec<String>, String> {
    let mut tasks = state.tasks.lock().await;
    state.app.state().set_runtime_status(
        ProtectionState::Stopping,
        state.app.status().proxy_port,
        state.app.status().dns_port,
        state.app.runtime().system_proxy_active(),
        None,
    );
    let app = state.app.clone();
    let report =
        tauri::async_runtime::spawn_blocking(move || app.runtime().restore_system_changes()).await;
    let mut errors = tasks.stop().await;
    match report {
        Ok(report) => errors.extend(report.items.into_iter().filter_map(|item| item.error)),
        Err(error) => errors.push(error.to_string()),
    }
    state.app.runtime().set_dns_active(false);
    let error = (!errors.is_empty()).then(|| errors.join("; "));
    state.app.state().set_runtime_status(
        ProtectionState::Stopped,
        None,
        None,
        state.app.runtime().system_proxy_active(),
        error.clone(),
    );
    match error {
        Some(e) => Err(e),
        None => Ok(vec!["Protection stopped".into()]),
    }
}

/// A failed listener cancels siblings and recovers routing before its task completes.
fn supervise(
    app: nullad_core::AppHandle,
    cancel: watch::Sender<bool>,
    mut ready: watch::Receiver<bool>,
    name: &'static str,
    run: impl std::future::Future<Output = io::Result<()>> + Send + 'static,
) -> tauri::async_runtime::JoinHandle<io::Result<()>> {
    tauri::async_runtime::spawn(async move {
        if !*ready.borrow() && ready.changed().await.is_err() {
            return Ok(());
        }
        if *cancel.borrow() {
            return Ok(());
        }
        let result = run.await;
        if !*cancel.borrow() {
            let error = result.as_ref().err().map_or_else(
                || format!("{name} exited unexpectedly"),
                |error| format!("{name}: {error}"),
            );
            let _ = cancel.send(true);
            let recovery_app = app.clone();
            let recovery = tauri::async_runtime::spawn_blocking(move || {
                recovery_app.runtime().restore_system_changes()
            })
            .await;
            let recovery_errors = match recovery {
                Ok(report) => report
                    .items
                    .into_iter()
                    .filter_map(|item| item.error)
                    .collect::<Vec<_>>()
                    .join("; "),
                Err(error) => error.to_string(),
            };
            app.runtime().set_dns_active(false);
            app.state().set_runtime_status(
                ProtectionState::Failed,
                None,
                None,
                app.runtime().system_proxy_active(),
                Some(if recovery_errors.is_empty() {
                    error.clone()
                } else {
                    format!("{error}; recovery: {recovery_errors}")
                }),
            );
            return Err(io::Error::other(error));
        }
        result
    })
}

impl Drop for RunningTasks {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(true);
        }
    }
}
