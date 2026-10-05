//! Cost of optional detection on the real decide + bounded log path.
//! Five independent warmed processes per mode, latency and allocation builds
//! separately. This measures local decisions, not internet socket throughput.

use std::sync::Arc;
use std::time::Instant;

use nullad_api::HeuristicMode;
use nullad_core::state::{DecisionLog, DECISION_LOG_CAPACITY};
use nullad_engine::{FilterEngine, MatchScratch, Request, ResourceType, RuleSetBuilder};
use nullad_intercept::{DecisionSource, DetectionPolicy, EngineHandle};
use serde_json::{json, Value};

#[cfg(feature = "profiling")]
#[global_allocator]
static GLOBAL: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

struct Case {
    name: &'static str,
    request: Request,
    rule_blocked: bool,
    effective_blocked: bool,
}

fn cases(mode: HeuristicMode) -> Vec<Case> {
    [
        (
            "rule_hit",
            "http://rules.block.example/content.js",
            true,
            true,
        ),
        (
            "miss",
            "http://cdn.example/content.js?description=advertisement",
            false,
            false,
        ),
        (
            "exception",
            "http://ads.exception.example/ad-loader.js",
            false,
            false,
        ),
        (
            "allow_host",
            "http://adservice.trusted.example/resource.js",
            false,
            false,
        ),
        (
            "host_feature",
            "http://adservice.vendor.example/resource.js",
            false,
            mode != HeuristicMode::Off,
        ),
        (
            "http_features",
            "http://cdn.vendor.example/serve?adslot=1&creative_id=2",
            false,
            mode == HeuristicMode::Balanced,
        ),
        (
            "protected",
            "http://adservice.vendor.example/docs/ad-loader.js",
            false,
            false,
        ),
        (
            "sdk_feature",
            "http://cdn.example/vendor/prebid.min.js",
            false,
            mode != HeuristicMode::Off,
        ),
    ]
    .into_iter()
    .map(|(name, url, rule_blocked, effective_blocked)| Case {
        name,
        request: Request::new(url, ResourceType::Script).with_page("https://publisher.example/"),
        rule_blocked,
        effective_blocked,
    })
    .collect()
}

fn measure(iterations: usize, mut body: impl FnMut(usize) -> bool) -> Value {
    for index in 0..2000 {
        std::hint::black_box(body(index));
    }
    let mut samples = Vec::with_capacity(iterations);
    let started = Instant::now();
    let mut blocked = 0;
    for index in 0..iterations {
        let operation = Instant::now();
        blocked += usize::from(std::hint::black_box(body(index)));
        samples.push(operation.elapsed());
    }
    let elapsed = started.elapsed();
    samples.sort_unstable();
    #[cfg(feature = "profiling")]
    let allocations = {
        let region = stats_alloc::Region::new(GLOBAL);
        for index in 0..iterations {
            std::hint::black_box(body(index));
        }
        let stats = region.change();
        json!({"allocations_per_request":stats.allocations as f64 / iterations as f64,
            "bytes_per_request":stats.bytes_allocated as f64 / iterations as f64,
            "reallocations":stats.reallocations})
    };
    #[cfg(not(feature = "profiling"))]
    let allocations = Value::Null;
    json!({"blocked":blocked,"iterations":iterations,"warmup":2000,
        "throughput_per_sec":iterations as f64 / elapsed.as_secs_f64(),
        "mean_us":elapsed.as_secs_f64() * 1e6 / iterations as f64,
        "p50_us":samples[(iterations-1)/2].as_secs_f64()*1e6,
        "p95_us":samples[(iterations-1)*95/100].as_secs_f64()*1e6,
        "p99_us":samples[(iterations-1)*99/100].as_secs_f64()*1e6,
        "allocations":allocations})
}

fn run() -> anyhow::Result<()> {
    let mode = match std::env::args().nth(1).as_deref() {
        Some("off") => HeuristicMode::Off,
        Some("conservative") => HeuristicMode::Conservative,
        Some("balanced") | None => HeuristicMode::Balanced,
        _ => anyhow::bail!("usage: nullad-heuristic-perf [off|conservative|balanced]"),
    };
    let mut builder = RuleSetBuilder::new();
    builder.add_list_auto("||rules.block.example^\n@@||ads.exception.example^");
    let bundled = std::env::args().nth(2);
    if let Some(value) = bundled.as_deref() {
        anyhow::ensure!(value == "--bundled", "expected --bundled");
        builder.add_list_auto(include_str!("../../../lists/nullad-base.txt"));
        builder.add_list_auto(include_str!("../../../lists/nullad-hosts.txt"));
    }
    let engine = Arc::new(FilterEngine::from_rule_set(builder.build()?));
    let log = Arc::new(DecisionLog::new(DECISION_LOG_CAPACITY));
    let handle = EngineHandle::new(engine.clone())
        .with_policy(DetectionPolicy {
            mode,
            allowed_hosts: vec!["trusted.example".into(), "safe.example".into()],
        })
        .with_sink(log.clone());
    let cases = cases(mode);
    let mut scratch = MatchScratch::new();
    for case in &cases {
        anyhow::ensure!(
            engine.check_with(&case.request, &mut scratch).blocked == case.rule_blocked,
            "rule fixture {}",
            case.name
        );
        anyhow::ensure!(
            handle
                .evaluate(
                    &case.request.url,
                    case.request.resource_type,
                    Some("https://publisher.example/"),
                    DecisionSource::Proxy
                )
                .blocked
                == case.effective_blocked,
            "effective fixture {}",
            case.name
        );
    }
    let mut results = Vec::new();
    for name in [
        "rule_hit",
        "miss",
        "exception",
        "allow_host",
        "host_feature",
        "http_features",
        "protected",
        "sdk_feature",
        "mixed",
    ] {
        let cohort: Vec<_> = cases
            .iter()
            .filter(|case| name == "mixed" || case.name == name)
            .collect();
        let iterations = 14000;
        let rule_expected = (0..iterations)
            .filter(|index| cohort[index % cohort.len()].rule_blocked)
            .count();
        let effective_expected = (0..iterations)
            .filter(|index| cohort[index % cohort.len()].effective_blocked)
            .count();
        let matching = measure(iterations, |index| {
            engine
                .check_with(&cohort[index % cohort.len()].request, &mut scratch)
                .blocked
        });
        let live = measure(iterations, |index| {
            let case = cohort[index % cohort.len()];
            handle.decide(
                &case.request.url,
                case.request.resource_type,
                Some("https://publisher.example/"),
                DecisionSource::Proxy,
            )
        });
        anyhow::ensure!(
            matching["blocked"] == json!(rule_expected)
                && live["blocked"] == json!(effective_expected),
            "timed fixture changed: {name}"
        );
        results.push(json!({"cohort":name,"engine":matching,"decide_with_log":live}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"harness":"heuristic-cost-v2","mode":mode,"bundled":bundled.is_some(),
        "profiling":cfg!(feature="profiling"),"rules":engine.rule_count(),"log_capacity":DECISION_LOG_CAPACITY,
        "logged_entries":log.len(),"results":results})
        )?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
