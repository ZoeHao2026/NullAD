//! The `serve` command: runs the interception layer.
//!
//! DNS is opt-in because binding port 53 and repointing the system resolver
//! both require elevation. The HTTP proxy and SNI listener need no privileges,
//! so the common case runs unelevated.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use nullad_engine::FilterEngine;
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

        if system_proxy {
            println!();
            println!("  --system-proxy was requested, but this build does not modify OS");
            println!("  settings from the CLI. Point your client at {bound} instead, or use");
            println!("  the desktop application, which journals and can undo every change.");
        }

        if let Some(port) = dns_port {
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
                    let dns = tokio::spawn(async move { server.run().await });

                    println!();
                    println!("running. press Ctrl+C to stop.");
                    tokio::select! {
                        _ = proxy.run() => {}
                        _ = dns => {}
                        _ = tokio::signal::ctrl_c() => {}
                    }
                    return Ok(());
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
        }

        if let Some(addr) = proxy.local_addr().ok() {
            println!();
            println!("configure your client's HTTP proxy to {addr}");
        }
        println!();
        println!("running. press Ctrl+C to stop.");

        tokio::select! {
            _ = proxy.run() => {}
            _ = tokio::signal::ctrl_c() => {}
        }

        Ok(())
    })
}
