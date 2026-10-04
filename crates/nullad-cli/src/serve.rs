//! The `serve` command: runs the interception layer.
//!
//! DNS is opt-in because binding port 53 and repointing the system resolver
//! both require elevation. The HTTP proxy and SNI listener need no privileges,
//! so the common case runs unelevated.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use nullad_engine::FilterEngine;
use nullad_host::SystemProxy;
use nullad_intercept::dns::resolve_upstream;
use nullad_intercept::{DnsConfig, DnsServer, EngineHandle, ProxyConfig, ProxyServer};

/// Starts the requested interceptors and runs until interrupted.
pub fn run(
    engine: Arc<FilterEngine>,
    proxy_port: u16,
    dns_port: Option<u16>,
    dns_upstream: &str,
    system_proxy: bool,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?;

    runtime.block_on(async move {
        let handle = EngineHandle::new(engine);

        let proxy_config = ProxyConfig {
            listen: format!("127.0.0.1:{proxy_port}").parse()?,
            ..ProxyConfig::default()
        };

        let proxy = Arc::new(
            ProxyServer::bind(proxy_config.clone(), handle.clone())
                .await
                .with_context(|| format!("failed to bind the HTTP proxy on port {proxy_port}"))?,
        );
        let bound = proxy.local_addr()?;
        println!();
        println!("HTTP proxy listening on http://{bound}");

        if dns_port.is_some() {
            println!();
            println!("  note: the DNS sinkhole needs permission to bind its port and,");
            println!("        to be useful, the system resolver must point at it.");
        }

        let dns = if let Some(port) = dns_port {
            let upstream = resolve_upstream(dns_upstream)
                .ok_or_else(|| anyhow::anyhow!("invalid DNS upstream `{dns_upstream}`"))?;
            let config = DnsConfig {
                listen: format!("127.0.0.1:{port}").parse()?,
                upstream,
                ..DnsConfig::default()
            };
            match DnsServer::bind(config, handle.clone()).await {
                Ok(server) => {
                    let server = Arc::new(server);
                    let addr = server.local_addr()?;
                    println!("DNS sinkhole listening on udp/tcp {addr} (upstream {upstream})");
                    Some(server)
                }
                Err(err) => {
                    if port < 1024 {
                        bail!(
                            "could not bind DNS on port {port}: {err}\n\
                             hint: ports below 1024 require administrator or root. \
                             Try --dns-port 5353 and point your resolver at it."
                        );
                    }
                    bail!("could not bind DNS on port {port}: {err}");
                }
            }
        } else {
            None
        };

        let signal = shutdown_signal().context("failed to register the shutdown signal")?;

        if let Ok(addr) = proxy.local_addr() {
            println!();
            println!("configure your client's HTTP proxy to {addr}");
        }
        // Every listener has bound successfully before touching OS settings.
        // An existing snapshot belongs to an earlier session; don't take over
        // its recovery or a running desktop application's system settings.
        let mut system_adapter = if system_proxy {
            let adapter = SystemProxy::new(bound.to_string())
                .context("failed to open the system proxy recovery journal")?;
            if adapter.pending().is_some() {
                bail!("a system proxy recovery snapshot is already pending; restore it in the desktop application before starting CLI system proxy mode");
            }
            Some(adapter)
        } else {
            None
        };

        let (stop, receiver) = tokio::sync::watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(proxy.run_until(receiver.clone()));
        if let Some(dns) = dns {
            tasks.spawn(dns.run_until(receiver));
        }

        let mut result = match system_adapter.as_mut() {
            Some(adapter) => adapter
                .apply()
                .map(|_| println!("system proxy routed through {bound}; previous settings journaled"))
                .context("failed to apply the system proxy"),
            None => Ok(()),
        };
        if result.is_ok() {
            println!();
            println!("running. press Ctrl+C to stop (Ctrl+Break also works on Windows).");
            result = tokio::select! {
                signal = signal => signal.context("could not wait for the shutdown signal"),
                ended = tasks.join_next() => match ended {
                    Some(Ok(result)) => result.context("interceptor listener failed"),
                    Some(Err(err)) => Err(anyhow::Error::new(err).context("interceptor task failed")),
                    None => Ok(()),
                },
            };
        }
        // Drain the owners of both listeners and all their connection tasks
        // before restoring the system settings, including after apply failure.
        let _ = stop.send(true);
        while let Some(ended) = tasks.join_next().await {
            let ended = match ended {
                Ok(result) => result.context("interceptor listener failed during shutdown"),
                Err(err) => {
                    Err(anyhow::Error::new(err).context("interceptor task failed during shutdown"))
                }
            };
            if result.is_ok() {
                result = ended;
            }
        }
        if let Some(adapter) = system_adapter.as_mut() {
            match adapter.revert() {
                Ok(Some(_)) => println!("previous system proxy settings restored and verified"),
                Ok(None) => {}
                Err(error) => {
                    let error = anyhow::Error::new(error).context(
                        "failed to restore the system proxy; recovery snapshot retained",
                    );
                    result = Err(match result {
                        Ok(()) => error,
                        Err(previous) => anyhow::anyhow!("{previous:#}; additionally, {error:#}"),
                    });
                }
            }
        }
        result
    })
}

fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = std::io::Result<()>>> {
    #[cfg(windows)]
    {
        let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
        let mut ctrl_break = tokio::signal::windows::ctrl_break()?;
        Ok(async move {
            tokio::select! {
                signal = ctrl_c.recv() => signal,
                signal = ctrl_break.recv() => signal,
            }
            .ok_or_else(|| std::io::Error::other("console shutdown signal listener closed"))
        })
    }
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                signal = interrupt.recv() => signal,
                signal = terminate.recv() => signal,
            }
            .ok_or_else(|| std::io::Error::other("Unix shutdown signal listener closed"))
        })
    }
    #[cfg(not(any(windows, unix)))]
    Ok(tokio::signal::ctrl_c())
}
