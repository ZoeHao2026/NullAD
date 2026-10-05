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
//!
//! ## 中文说明
//!
//! 本层提供三种**彼此独立**的拦截机制，而非分层叠加的关系，
//! 因为它们的能力边界与权限要求各不相同：
//!
//! | 模块 | 拦截范围 | 权限 |
//! |---|---|---|
//! | [`http_proxy`] | 明文 HTTP 的完整 URL 与路径 | 无需提权 |
//! | [`sni`] | 按主机名拦截整条 TLS 连接 | 无需提权 |
//! | [`dns`] | 域名，发生在任何连接建立之前 | 需要 53 端口 + 改系统解析器 |
//!
//! 关于 [`sni`] 需要特别说明：它读取的是 TLS ClientHello 中以明文发送的
//! SNI 字段，因此**无法**看到 TLS 会话内部，也无法过滤加密后的 URL。
//! 它对 ECH（加密客户端问候）同样无能为力——ECH 正越来越普遍地
//! 把 SNI 整个隐藏起来。这不是需要掩盖的缺陷：要过滤完整 HTTPS URL，
//! 必须做基于证书检视的中间人拦截，那是另一套机制，
//! 伴随真实的安全代价，不在 MVP 范围内。

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod dns;
pub mod heuristic;
pub mod http_proxy;
mod lifecycle;
pub mod prefixed;
pub mod sni;
pub mod upstream;

use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use nullad_engine::{CheckResult, FilterEngine, MatchScratch, Request, ResourceType, Rule};
use smallvec::SmallVec;

thread_local! {
    // Matching is synchronous. Runtime workers reuse these buffers without
    // retaining a borrow across awaits or decision callbacks.
    static MATCH_SCRATCH: RefCell<MatchScratch> = RefCell::new(MatchScratch::new());
}

pub use dns::{DnsConfig, DnsServer};
pub use heuristic::DetectionPolicy;
pub use http_proxy::{ProxyConfig, ProxyServer};
pub use nullad_api::HeuristicMode;
pub use sni::{SniConfig, SniListener};
pub use upstream::UpstreamProxy;

/// Effective interception decision, with the original matching rule when applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub blocked: bool,
    pub matched_rule: Option<Arc<Rule>>,
    pub matched_rule_ids: SmallVec<[u32; 4]>,
    pub reason: Option<String>,
    pub score: Option<u8>,
}

impl Evaluation {
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    #[must_use]
    pub fn is_exception(&self) -> bool {
        !self.blocked
            && self
                .matched_rule
                .as_ref()
                .is_some_and(|rule| rule.action.is_allow())
    }
}

impl From<CheckResult> for Evaluation {
    fn from(result: CheckResult) -> Self {
        let reason = if result.is_exception() {
            Some("exception".to_owned())
        } else if result.blocked {
            Some("rule".to_owned())
        } else {
            None
        };
        Self {
            blocked: result.blocked,
            matched_rule: result.matched_rule,
            matched_rule_ids: result.matched_rule_ids,
            reason,
            score: None,
        }
    }
}

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
    pub reason: Option<String>,
    pub score: Option<u8>,
    /// Which interceptor produced the decision.
    pub source: DecisionSource,
}

/// Which interceptor produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Plaintext HTTP proxy.
    Proxy,
    /// A CONNECT tunnel reveals its destination host, not HTTPS resource URLs.
    Connect,
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
            Self::Connect => "connect",
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
    /// Shared policy can be updated without rebinding running listeners.
    pub policy: Arc<RwLock<DetectionPolicy>>,
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
            policy: Arc::new(RwLock::new(DetectionPolicy::default())),
        }
    }

    /// Attaches a decision sink.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn DecisionSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    #[must_use]
    pub fn with_policy(mut self, mut policy: DetectionPolicy) -> Self {
        for allowed in &mut policy.allowed_hosts {
            if !allowed.is_ascii() && !allowed.contains(['/', '?', '#', '@', '*', ':']) {
                if let Some(normalized) = nullad_engine::request::extract_host(allowed) {
                    *allowed = normalized;
                }
            }
        }
        self.policy = Arc::new(RwLock::new(policy));
        self
    }

    /// Evaluates without interception counters or decision callbacks.
    /// Engine counters retain their meaning as filter-rule evaluations.
    pub fn evaluate(
        &self,
        url: &str,
        resource_type: ResourceType,
        page: Option<&str>,
        source: DecisionSource,
    ) -> Evaluation {
        let mut request = Request::new(url, resource_type);
        if let Some(page) = page {
            request = request.with_page(page);
        }
        self.evaluate_request(&request, source)
    }

    fn evaluate_request(&self, request: &Request, source: DecisionSource) -> Evaluation {
        let (mode, explicitly_allowed) = {
            let policy = self
                .policy
                .read()
                .unwrap_or_else(|error| error.into_inner());
            (policy.mode, policy.allows_host(&request.host))
        };
        if explicitly_allowed {
            return Evaluation {
                blocked: false,
                matched_rule: None,
                matched_rule_ids: SmallVec::new(),
                reason: Some("allow_host".to_owned()),
                score: None,
            };
        }
        let checked = MATCH_SCRATCH
            .with(|scratch| self.engine.check_with(request, &mut scratch.borrow_mut()));
        let mut evaluation = Evaluation::from(checked);
        if !evaluation.blocked && !evaluation.is_exception() {
            if let Some(detected) = heuristic::detect(request, source, mode) {
                evaluation.blocked = true;
                evaluation.reason = Some(detected.reason.to_owned());
                evaluation.score = Some(detected.score);
            }
        }
        evaluation
    }

    /// Publishes a decision to the sink, if one is attached.
    pub fn emit(&self, decision: Decision) {
        if let Some(sink) = &self.sink {
            sink.record(decision);
        }
    }

    /// Evaluates a request and records the outcome.
    ///
    /// Runtime workers reuse their scratch buffer only while matching. No
    /// scratch borrow is retained while publishing a decision to a sink.
    pub fn decide(
        &self,
        url: &str,
        resource_type: ResourceType,
        page: Option<&str>,
        source: DecisionSource,
    ) -> bool {
        self.decide_result(url, resource_type, page, source).blocked
    }

    /// Evaluates and records a request, preserving the deciding rule for callers.
    pub fn decide_result(
        &self,
        url: &str,
        resource_type: ResourceType,
        page: Option<&str>,
        source: DecisionSource,
    ) -> Evaluation {
        let mut request = Request::new(url, resource_type);
        if let Some(page) = page {
            request = request.with_page(page);
        }
        let result = self.evaluate_request(&request, source);

        match source {
            DecisionSource::Proxy | DecisionSource::Connect => {
                self.stats.record_proxy(result.blocked)
            }
            DecisionSource::Sni => self.stats.record_sni(result.blocked),
            DecisionSource::Dns => {}
        }

        self.emit(Decision {
            timestamp_ms: now_ms(),
            url: request.url,
            host: request.host,
            blocked: result.blocked,
            rule: result.matched_rule.as_ref().map(|r| r.raw.clone()),
            reason: result.reason.clone(),
            score: result.score,
            source,
        });

        result
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

    #[test]
    fn scratch_reuse_matches_fresh_checks_across_rule_set_sizes_and_threads() {
        let handle = handle("||initial.example^");
        for count in [1, 1000, 3] {
            let mut builder = RuleSetBuilder::new();
            for index in 0..count {
                builder.add_list_auto(&format!("||ads{index}.example^\n/banner{index}.gif"));
            }
            handle.engine.swap(builder.build().unwrap());
            std::thread::scope(|scope| {
                for _ in 0..4 {
                    let handle = &handle;
                    scope.spawn(move || {
                        for url in [
                            "http://ads0.example/x",
                            "http://safe.example/banner0.gif",
                            "http://safe.example/clean",
                        ] {
                            for _ in 0..10 {
                                let request = Request::new(url, ResourceType::Other);
                                let expected = handle.engine.check(&request);
                                let actual = handle.decide_result(
                                    url,
                                    ResourceType::Other,
                                    None,
                                    DecisionSource::Proxy,
                                );
                                assert_eq!(actual, Evaluation::from(expected));
                            }
                        }
                    });
                }
            });
        }
    }

    #[test]
    fn decision_sink_can_reenter_matching_without_borrowing_scratch() {
        #[derive(Debug)]
        struct ReentrantSink(Arc<FilterEngine>);
        impl DecisionSink for ReentrantSink {
            fn record(&self, _decision: Decision) {
                let nested = EngineHandle::new(self.0.clone());
                assert!(nested.decide(
                    "http://blocked.example/x",
                    ResourceType::Other,
                    None,
                    DecisionSource::Proxy
                ));
            }
        }
        let handle = handle("||blocked.example^");
        let sink = Arc::new(ReentrantSink(handle.engine.clone()));
        assert!(handle.with_sink(sink).decide(
            "http://blocked.example/x",
            ResourceType::Other,
            None,
            DecisionSource::Proxy
        ));
    }

    #[test]
    fn evaluating_heuristics_preserves_rule_statistics_and_emits_only_on_decide() {
        #[derive(Debug, Default)]
        struct Collector(std::sync::Mutex<Vec<Decision>>);
        impl DecisionSink for Collector {
            fn record(&self, decision: Decision) {
                self.0.lock().unwrap().push(decision);
            }
        }
        let collector = Arc::new(Collector::default());
        let handle = EngineHandle::new(Arc::new(FilterEngine::new())).with_sink(collector.clone());
        let result = handle.evaluate(
            "http://ads.vendor.example/ad-loader.js",
            ResourceType::Script,
            Some("https://publisher.example/"),
            DecisionSource::Proxy,
        );
        assert!(result.blocked);
        assert_eq!(result.reason.as_deref(), Some("heuristic_ad_request"));
        assert_eq!(result.score, Some(100));
        assert!(result.matched_rule.is_none());
        assert!(result.matched_rule_ids.is_empty());
        assert_eq!(handle.engine.rule_count(), 0);
        assert_eq!(handle.engine.stats_snapshot().queries, 1);
        assert_eq!(handle.engine.stats_snapshot().blocked, 0);
        assert_eq!(handle.stats.proxy_requests(), 0);
        assert!(collector.0.lock().unwrap().is_empty());
        let recorded = handle.decide_result(
            "https://adserver.vendor.example/",
            ResourceType::Document,
            None,
            DecisionSource::Connect,
        );
        assert!(recorded.blocked);
        assert_eq!(handle.stats.proxy_requests(), 1);
        assert_eq!(handle.stats.proxy_blocked(), 1);
        let events = collector.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source.label(), "connect");
        assert_eq!(events[0].reason.as_deref(), Some("heuristic_ad_host"));
        assert_eq!(events[0].score, Some(85));
        assert!(events[0].rule.is_none());
    }

    #[test]
    fn explicit_allow_hosts_override_rules_only_at_domain_boundaries() {
        let handle = handle(
            "||adserver.vendor.example^$important\n||notvendor.example^\n||vendor.example.evil^",
        )
        .with_policy(DetectionPolicy {
            mode: HeuristicMode::Balanced,
            allowed_hosts: vec!["VENDOR.EXAMPLE.".into()],
        });
        let allowed = handle.evaluate(
            "http://adserver.vendor.example/ad-loader.js",
            ResourceType::Script,
            None,
            DecisionSource::Proxy,
        );
        assert!(!allowed.blocked);
        assert_eq!(allowed.reason.as_deref(), Some("allow_host"));
        assert!(allowed.matched_rule.is_none());
        assert!(allowed.score.is_none());
        assert_eq!(handle.engine.stats_snapshot().queries, 0);
        for host in ["notvendor.example", "vendor.example.evil"] {
            assert!(
                handle
                    .evaluate(
                        &format!("http://{host}/"),
                        ResourceType::Other,
                        None,
                        DecisionSource::Proxy
                    )
                    .blocked
            );
        }
    }

    #[test]
    fn filter_exceptions_precede_heuristics_and_off_keeps_filter_rules() {
        let handle = handle("@@||adserver.vendor.example^\n||blocked.example^");
        for source in [
            DecisionSource::Proxy,
            DecisionSource::Connect,
            DecisionSource::Dns,
            DecisionSource::Sni,
        ] {
            let allowed = handle.evaluate(
                "http://adserver.vendor.example/ad-loader.js",
                ResourceType::Script,
                None,
                source,
            );
            assert!(allowed.is_exception());
            assert!(!allowed.blocked);
            assert_eq!(allowed.reason.as_deref(), Some("exception"));
            assert_eq!(
                allowed.matched_rule.as_ref().unwrap().raw,
                "@@||adserver.vendor.example^"
            );
            assert!(allowed.score.is_none());
        }
        let cloned = handle.clone();
        handle.policy.write().unwrap().mode = HeuristicMode::Off;
        assert!(
            !cloned
                .evaluate(
                    "http://adserver.other.example/",
                    ResourceType::Other,
                    None,
                    DecisionSource::Connect
                )
                .blocked
        );
        let blocked = cloned.evaluate(
            "http://blocked.example/",
            ResourceType::Other,
            None,
            DecisionSource::Proxy,
        );
        assert!(blocked.blocked);
        assert_eq!(blocked.reason.as_deref(), Some("rule"));
        assert!(blocked.score.is_none());
    }

    #[test]
    fn policy_normalizes_unicode_domains_once_and_preserves_label_boundaries() {
        let handle =
            EngineHandle::new(Arc::new(FilterEngine::new())).with_policy(DetectionPolicy {
                mode: HeuristicMode::Balanced,
                allowed_hosts: vec!["BÜCHER.example.".into()],
            });
        assert_eq!(
            handle.policy.read().unwrap().allowed_hosts,
            ["xn--bcher-kva.example"]
        );
        for host in [
            "bücher.example",
            "ads.bücher.example",
            "xn--bcher-kva.example",
        ] {
            let result = handle.evaluate(
                &format!("http://{host}/ad-loader.js"),
                ResourceType::Script,
                None,
                DecisionSource::Proxy,
            );
            assert_eq!(result.reason.as_deref(), Some("allow_host"));
        }
        for host in ["notbücher.example", "bücher.example.evil"] {
            let result = handle.evaluate(
                &format!("http://{host}/safe.js"),
                ResourceType::Script,
                None,
                DecisionSource::Proxy,
            );
            assert_ne!(result.reason.as_deref(), Some("allow_host"));
        }
    }

    #[test]
    fn decision_sink_can_update_policy_and_reenter_the_same_handle_state() {
        #[derive(Debug)]
        struct ReentrantSink(EngineHandle);
        impl DecisionSink for ReentrantSink {
            fn record(&self, decision: Decision) {
                assert!(decision.blocked);
                self.0
                    .policy
                    .write()
                    .unwrap()
                    .allowed_hosts
                    .push("vendor.example".into());
                let nested = self.0.evaluate(
                    "http://adserver.vendor.example/ad-loader.js",
                    ResourceType::Script,
                    None,
                    DecisionSource::Proxy,
                );
                assert!(!nested.blocked);
                assert_eq!(nested.reason.as_deref(), Some("allow_host"));
            }
        }
        let handle = EngineHandle::new(Arc::new(FilterEngine::new()));
        let sink = Arc::new(ReentrantSink(handle.clone()));
        let handle = handle.with_sink(sink);
        assert!(handle.decide(
            "http://adserver.vendor.example/",
            ResourceType::Document,
            None,
            DecisionSource::Connect
        ));
        assert!(
            !handle
                .evaluate(
                    "http://adserver.vendor.example/",
                    ResourceType::Document,
                    None,
                    DecisionSource::Connect
                )
                .blocked
        );
    }
}
