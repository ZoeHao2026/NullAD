//! # NullAD Interception Layer
//!
//! Three independent mechanisms for putting the engine between a client and
//! the network. They are deliberately separate rather than layered, because
//! each has different capabilities and different privilege requirements:
//!
//! | Module | Blocks | Privilege |
//! |---|---|---|
//! | [`proxy`] | URLs and paths for plaintext HTTP | none |
//! | [`sni`] | whole TLS connections, by hostname | none |
//! | [`dns`] | domains, before any connection | needs port 53 + resolver change |
//!
//! A deliberate design note on the `sni` module: it inspects the Server Name
//! Indication field of the TLS ClientHello, which is sent in the clear. It
//! therefore **cannot** see into a TLS session and cannot filter encrypted
//! URLs. It is also blind to Encrypted Client Hello (ECH) connections, which
//! increasingly hide SNI entirely. None of this is a defect to be papered over:
//! full HTTPS URL filtering requires certificate-inspecting interception,
//! which is a different mechanism with a real security cost and is not part of
//! the MVP.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod dns;
pub mod http_proxy;
pub mod prefixed;
pub mod sni;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use nullad_engine::{FilterEngine, MatchScratch, Request, ResourceType};

pub use dns::{DnsConfig, DnsServer};
pub use http_proxy::{ProxyConfig, ProxyServer};
pub use sni::{SniConfig, SniListener};

/// A request that the engine decided on, for logging and the live UI feed.
#[derive(Debug, Clone)]
pub struct Decision {
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The URL, or `sni://host` for a connection-level decision.
    pub url: String,
    /// The hostname involved.
    pub host: String,
    /// Whether the request was blocked.
    pub blocked: bool,
    /// The deciding rule, rendered as text.
    pub rule: Option<String>,
    /// Which interceptor produced the decision.
    pub source: DecisionSource,
}

/// Which interceptor produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Plaintext HTTP proxy.
    Proxy,
    /// TLS SNI inspection.
    Sni,
    /// DNS sinkhole.
    Dns,
}

impl DecisionSource {
    /// Short lowercase label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Sni => "sni",
            Self::Dns => "dns",
        }
    }
}

/// Counters shared by every interceptor.
#[derive(Debug, Default)]
pub struct InterceptStats {
    proxy_requests: AtomicU64,
    proxy_blocked: AtomicU64,
    sni_connections: AtomicU64,
    sni_blocked: AtomicU64,
    dns_queries: AtomicU64,
    dns_blocked: AtomicU64,
    dns_forwarded: AtomicU64,
    dns_failed: AtomicU64,
}

impl InterceptStats {
    /// Creates zeroed counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one proxy request.
    pub fn record_proxy(&self, blocked: bool) {
        self.proxy_requests.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.proxy_blocked.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records one inspected TLS connection.
    pub fn record_sni(&self, blocked: bool) {
        self.sni_connections.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.sni_blocked.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records the outcome of one DNS query.
    pub fn record_dns(&self, outcome: DnsOutcome) {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
        match outcome {
            DnsOutcome::Blocked => self.dns_blocked.fetch_add(1, Ordering::Relaxed),
            DnsOutcome::Forwarded => self.dns_forwarded.fetch_add(1, Ordering::Relaxed),
            DnsOutcome::Failed => self.dns_failed.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Plaintext HTTP requests seen.
    #[must_use]
    pub fn proxy_requests(&self) -> u64 {
        self.proxy_requests.load(Ordering::Relaxed)
    }

    /// Plaintext HTTP requests blocked.
    #[must_use]
    pub fn proxy_blocked(&self) -> u64 {
        self.proxy_blocked.load(Ordering::Relaxed)
    }

    /// TLS connections inspected.
    #[must_use]
    pub fn sni_connections(&self) -> u64 {
        self.sni_connections.load(Ordering::Relaxed)
    }

    /// TLS connections blocked.
    #[must_use]
    pub fn sni_blocked(&self) -> u64 {
        self.sni_blocked.load(Ordering::Relaxed)
    }

    /// DNS queries seen.
    #[must_use]
    pub fn dns_queries(&self) -> u64 {
        self.dns_queries.load(Ordering::Relaxed)
    }

    /// DNS queries sinkholed.
    #[must_use]
    pub fn dns_blocked(&self) -> u64 {
        self.dns_blocked.load(Ordering::Relaxed)
    }

    /// DNS queries forwarded upstream.
    #[must_use]
    pub fn dns_forwarded(&self) -> u64 {
        self.dns_forwarded.load(Ordering::Relaxed)
    }

    /// DNS queries that could not be answered.
    #[must_use]
    pub fn dns_failed(&self) -> u64 {
        self.dns_failed.load(Ordering::Relaxed)
    }
}

/// Outcome of a DNS query, for statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOutcome {
    /// Sinkholed by a filter rule.
    Blocked,
    /// Answered by the upstream resolver.
    Forwarded,
    /// Neither possible; the client was told to retry or got an empty answer.
    Failed,
}

/// Shared state handed to every interceptor.
///
/// Cloning is cheap: the engine and counters are behind `Arc`.
#[derive(Clone)]
pub struct EngineHandle {
    /// The matching engine. Shared, because `FilterEngine` is not `Clone`.
    pub engine: Arc<FilterEngine>,
    /// Shared interceptor counters.
    pub stats: Arc<InterceptStats>,
    /// Optional sink for decision events.
    pub sink: Option<Arc<dyn DecisionSink>>,
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle")
            .field("rules", &self.engine.rule_count())
            .finish()
    }
}

impl EngineHandle {
    /// Wraps an engine.
    #[must_use]
    pub fn new(engine: Arc<FilterEngine>) -> Self {
        Self {
            engine,
            stats: Arc::new(InterceptStats::new()),
            sink: None,
        }
    }

    /// Attaches a decision sink.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn DecisionSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Publishes a decision to the sink, if one is attached.
    pub fn emit(&self, decision: Decision) {
        if let Some(sink) = &self.sink {
            sink.record(decision);
        }
    }

    /// Evaluates a request and records the outcome.
    ///
    /// The scratch buffer is created per call here because interceptors run one
    /// task per connection and holding a pooled scratch buffer per task would
    /// cost more memory than it saves. Callers with their own hot loop should
    /// use [`FilterEngine::check_with`] directly.
    pub fn decide(
        &self,
        url: &str,
        resource_type: ResourceType,
        page: Option<&str>,
        source: DecisionSource,
    ) -> bool {
        let mut request = Request::new(url, resource_type);
        if let Some(page) = page {
            request = request.with_page(page);
        }

        let mut scratch = MatchScratch::new();
        let result = self.engine.check_with(&request, &mut scratch);

        match source {
            DecisionSource::Proxy => self.stats.record_proxy(result.blocked),
            DecisionSource::Sni => self.stats.record_sni(result.blocked),
            DecisionSource::Dns => {}
        }

        self.emit(Decision {
            timestamp_ms: now_ms(),
            url: url.to_owned(),
            host: request.host.clone(),
            blocked: result.blocked,
            rule: result.matched_rule.as_ref().map(|r| r.raw.clone()),
            source,
        });

        result.blocked
    }

    /// Decides purely on a hostname, which is all the DNS layer has.
    pub fn decide_host(&self, host: &str) -> bool {
        let url = format!("http://{host}/");
        let blocked = self.decide(&url, ResourceType::Document, None, DecisionSource::Dns);
        // `decide` does not record DNS counters because it cannot know the
        // outcome; the DNS server records those after it has answered.
        blocked
    }
}

/// Receives every decision the interceptors make.
pub trait DecisionSink: Send + Sync + std::fmt::Debug {
    /// Records one decision.
    fn record(&self, decision: Decision);
}

/// Current time in milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Returns `true` when `ip` is a loopback or otherwise non-routable address.
///
/// Used to refuse proxy requests aimed back at NullAD itself, which would
/// otherwise create an infinite forwarding loop.
#[must_use]
pub fn is_local_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullad_engine::RuleSetBuilder;

    fn handle(list: &str) -> EngineHandle {
        let mut builder = RuleSetBuilder::new();
        builder.add_list_auto(list);
        EngineHandle::new(Arc::new(FilterEngine::from_rule_set(
            builder.build().expect("rule set"),
        )))
    }

    #[test]
    fn decides_and_counts_proxy_requests() {
        let handle = handle("||ads.example.com^");
        assert!(handle.decide(
            "http://ads.example.com/banner.gif",
            ResourceType::Image,
            None,
            DecisionSource::Proxy
        ));
        assert!(!handle.decide(
            "http://example.com/ok.gif",
            ResourceType::Image,
            None,
            DecisionSource::Proxy
        ));

        assert_eq!(handle.stats.proxy_requests(), 2);
        assert_eq!(handle.stats.proxy_blocked(), 1);
    }

    #[test]
    fn host_only_decisions_work() {
        let handle = handle("||tracker.example.com^");
        assert!(handle.decide_host("tracker.example.com"));
        assert!(!handle.decide_host("safe.example.com"));
    }

    #[test]
    fn local_addresses_are_recognised() {
        assert!(is_local_address("127.0.0.1".parse().unwrap()));
        assert!(is_local_address("::1".parse().unwrap()));
        assert!(!is_local_address("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn sink_receives_decisions() {
        #[derive(Debug, Default)]
        struct Collector(std::sync::Mutex<Vec<Decision>>);
        impl DecisionSink for Collector {
            fn record(&self, decision: Decision) {
                self.0.lock().unwrap().push(decision);
            }
        }

        let collector = Arc::new(Collector::default());
        let handle = handle("||ads.example.com^").with_sink(collector.clone());
        let _ = handle.decide(
            "http://ads.example.com/x",
            ResourceType::Other,
            None,
            DecisionSource::Proxy,
        );

        let recorded = collector.0.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].blocked);
        assert_eq!(recorded[0].host, "ads.example.com");
        assert_eq!(recorded[0].source, DecisionSource::Proxy);
    }
}
