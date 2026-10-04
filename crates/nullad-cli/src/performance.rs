//! Verified workloads for comparing the engine and the application's real
//! decision path. Compatible with the original engine/interceptor interfaces.
//!
//! Latency: cargo run --release -p nullad-cli --features performance --bin nullad-perf
//! Allocations: replace `performance` with `profiling`. Instrumented timing must
//! not be mixed with the uninstrumented latency results.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use nullad_core::state::{DecisionLog, DECISION_LOG_CAPACITY};
use nullad_engine::{FilterEngine, MatchScratch, Request, ResourceType, RuleSetBuilder};
use nullad_intercept::{DecisionSource, EngineHandle};
use serde_json::{json, Value};

#[cfg(feature = "profiling")]
#[global_allocator]
static GLOBAL: &stats_alloc::StatsAlloc<std::alloc::System> = &stats_alloc::INSTRUMENTED_SYSTEM;

#[derive(Debug)]
struct Case {
    name: &'static str,
    request: Request,
    page: Option<&'static str>,
    blocked: bool,
    exception: bool,
}

fn cases() -> Vec<Case> {
    let raw = [
        (
            "domain_hit",
            "https://ads0.example/banner",
            ResourceType::Other,
            None,
            true,
            false,
        ),
        (
            "domain_miss",
            "https://clean.example/content",
            ResourceType::Other,
            None,
            false,
            false,
        ),
        (
            "exception",
            "https://allowed.example/content",
            ResourceType::Other,
            None,
            false,
            true,
        ),
        (
            "typed_hit",
            "https://typed.example/x",
            ResourceType::Script,
            None,
            true,
            false,
        ),
        (
            "typed_miss",
            "https://typed.example/x",
            ResourceType::Image,
            None,
            false,
            false,
        ),
        (
            "substring_hit",
            "https://clean.example/ad-token.js",
            ResourceType::Script,
            None,
            true,
            false,
        ),
        (
            "regex_hit",
            "https://clean.example/tracker42.gif",
            ResourceType::Image,
            None,
            true,
            false,
        ),
        (
            "path_hit",
            "https://path.example/collect/x",
            ResourceType::Other,
            None,
            true,
            false,
        ),
        (
            "path_miss",
            "https://path.example/collecting",
            ResourceType::Other,
            None,
            false,
            false,
        ),
        (
            "important",
            "https://important.example/x",
            ResourceType::Other,
            None,
            true,
            false,
        ),
        (
            "third_party_hit",
            "https://party.example/x",
            ResourceType::Other,
            Some("https://other.example.org/"),
            true,
            false,
        ),
        (
            "first_party_miss",
            "https://party.example/x",
            ResourceType::Other,
            Some("https://party.example/"),
            false,
            false,
        ),
    ];
    raw.into_iter()
        .map(|(name, url, kind, page, blocked, exception)| {
            let mut request = Request::new(url, kind);
            if let Some(page) = page {
                request = request.with_page(page);
            }
            Case {
                name,
                request,
                page,
                blocked,
                exception,
            }
        })
        .collect()
}

fn engine(rule_count: usize) -> Result<Arc<FilterEngine>> {
    // The workload targets known rules rather than hoping independent random
    // generators happen to produce matching hosts.
    let mut text = String::from("||allowed.example^\n@@||allowed.example^\n||typed.example^$script\nad-token\n/tracker[0-9]+\\.gif/\n||path.example/collect^\n||important.example^$important\n@@||important.example^\n||party.example^$third-party\n");
    for index in 0..rule_count - 9 {
        if index % 5 == 4 {
            text.push_str(&format!("/background-token-{index}/pixel.gif\n"));
        } else {
            text.push_str(&format!("||ads{index}.example^\n"));
        }
    }
    let mut builder = RuleSetBuilder::with_capacity(rule_count);
    let stats = builder.add_list_auto(&text);
    if stats.accepted != rule_count || stats.failed() != 0 {
        bail!(
            "workload rules did not parse as expected: {} accepted, {} failed",
            stats.accepted,
            stats.failed()
        );
    }
    Ok(Arc::new(FilterEngine::from_rule_set(
        builder.build().context("compile workload rules")?,
    )))
}

fn measure(iterations: usize, warmup: usize, mut body: impl FnMut(usize) -> bool) -> Value {
    for index in 0..warmup {
        std::hint::black_box(body(index));
    }
    let mut samples = Vec::with_capacity(iterations);
    let started = Instant::now();
    let mut blocked = 0usize;
    for index in 0..iterations {
        let step = Instant::now();
        blocked += usize::from(std::hint::black_box(body(index)));
        samples.push(step.elapsed());
    }
    let elapsed = started.elapsed();
    samples.sort_unstable();
    let percentile = |q: f64| -> f64 {
        samples[((samples.len() - 1) as f64 * q).round() as usize].as_secs_f64() * 1e6
    };

    // Sample allocation traffic in a separate pass without timing vector or
    // JSON construction allocations. Reallocations are reported separately.
    #[cfg(feature = "profiling")]
    let allocations = {
        let region = stats_alloc::Region::new(GLOBAL);
        for index in 0..iterations {
            std::hint::black_box(body(index));
        }
        let stats = region.change();
        json!({
            "allocations": stats.allocations,
            "deallocations": stats.deallocations,
            "reallocations": stats.reallocations,
            "bytes_allocated": stats.bytes_allocated,
            "bytes_deallocated": stats.bytes_deallocated,
            "net_bytes_reallocated": stats.bytes_reallocated,
            "allocations_per_request": stats.allocations as f64 / iterations as f64,
            "bytes_allocated_per_request": stats.bytes_allocated as f64 / iterations as f64,
        })
    };
    #[cfg(not(feature = "profiling"))]
    let allocations = Value::Null;

    json!({
        "iterations": iterations,
        "warmup_iterations": warmup,
        "blocked": blocked,
        "total_ms": elapsed.as_secs_f64() * 1e3,
        "mean_us": elapsed.as_secs_f64() * 1e6 / iterations as f64,
        "p50_us": percentile(0.50),
        "p95_us": percentile(0.95),
        "p99_us": percentile(0.99),
        "throughput_per_sec": iterations as f64 / elapsed.as_secs_f64(),
        "allocations": allocations,
    })
}

fn run() -> Result<()> {
    let mut rules = 100_000usize;
    let mut iterations = 10_000usize;
    let mut warmup = 2_000usize;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        if argument == "--help" {
            println!("nullad-perf [--rules 100000] [--iterations 10000] [--warmup 2000]\nJSON is written to stdout; every workload is checked before timing.");
            return Ok(());
        }
        let value = args
            .next()
            .context("option needs an integer value")?
            .parse::<usize>()
            .context("invalid integer")?;
        match argument.as_str() {
            "--rules" => rules = value,
            "--iterations" => iterations = value,
            "--warmup" => warmup = value,
            _ => bail!("unknown option {argument}"),
        }
    }
    if !(10..=1_000_000).contains(&rules)
        || !(12..=2_000_000).contains(&iterations)
        || !(12..=2_000_000).contains(&warmup)
    {
        bail!("rules must be 10..=1000000; iterations and warmup must be 12..=2000000");
    }
    let engine = engine(rules)?;
    let log = Arc::new(DecisionLog::new(DECISION_LOG_CAPACITY));
    let handle = EngineHandle::new(engine.clone()).with_sink(log.clone());
    let cases = cases();
    let mut scratch = MatchScratch::new();
    let mut verified = Vec::new();
    for case in &cases {
        let actual = engine.check_with(&case.request, &mut scratch);
        if actual.blocked != case.blocked || actual.is_exception() != case.exception {
            bail!("engine semantics failed for {}", case.name);
        }
        let live = handle.decide(
            &case.request.url,
            case.request.resource_type,
            case.page,
            DecisionSource::Proxy,
        );
        if live != case.blocked {
            bail!("live decision semantics failed for {}", case.name);
        }
        verified.push(json!({"case": case.name, "blocked": actual.blocked, "exception": actual.is_exception(), "rule": actual.matched_rule.as_ref().map(|rule| rule.raw.as_str())}));
    }
    log.clear();
    let mut results = Vec::new();
    for cohort in ["domain_hit", "domain_miss", "exception", "mixed"] {
        let workload: Vec<&Case> = cases
            .iter()
            .filter(|case| cohort == "mixed" || case.name == cohort)
            .collect();
        let expected_blocked = (0..iterations)
            .filter(|index| workload[index % workload.len()].blocked)
            .count();
        let expected_exceptions = (0..iterations)
            .filter(|index| workload[index % workload.len()].exception)
            .count();
        let matching = measure(iterations, warmup, |index| {
            engine
                .check_with(&workload[index % workload.len()].request, &mut scratch)
                .blocked
        });
        let live = measure(iterations, warmup, |index| {
            let case = workload[index % workload.len()];
            handle.decide(
                &case.request.url,
                case.request.resource_type,
                case.page,
                DecisionSource::Proxy,
            )
        });
        if matching["blocked"] != json!(expected_blocked)
            || live["blocked"] != json!(expected_blocked)
        {
            bail!("decision count changed during measurement of {cohort}");
        }
        results.push(json!({"workload": cohort, "expected_blocked": expected_blocked, "expected_exceptions": expected_exceptions, "engine_check_with": matching, "decide_with_log": live}));
    }
    let report = json!({
        "schema_version": 1,
        "harness": "nullad-perf-v1",
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "profiling": cfg!(feature = "profiling"),
        "rules": engine.rule_count(),
        "rule_mix": "9 semantic fixtures; each remaining five-rule cycle has four domain rules and one substring rule",
        "domain_rules": engine.rule_set().stats().domain_rules,
        "domain_path_rules": engine.rule_set().stats().domain_path_rules,
        "fragment_rules": engine.rule_set().stats().fragment_rules,
        "regex_rules": engine.rule_set().stats().regex_rules,
        "log_capacity": DECISION_LOG_CAPACITY,
        "logged_entries": log.len(),
        "workload_validation": verified,
        "results": results,
        "timing_note": "one thread; request construction excluded from check_with and included in decide; Instant sampling overhead included; allocation pass is separate; instrumented and uninstrumented timings must remain separate",
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fixed_workloads_have_the_declared_decisions() {
        let engine = engine(1000).unwrap();
        let mut scratch = MatchScratch::new();
        for case in cases() {
            let result = engine.check_with(&case.request, &mut scratch);
            assert_eq!(result.blocked, case.blocked, "{}", case.name);
            assert_eq!(result.is_exception(), case.exception, "{}", case.name);
        }
    }

    #[test]
    fn measurement_returns_consistent_counts_and_percentiles() {
        let result = measure(120, 12, |index| index % 3 == 0);
        assert_eq!(result["blocked"], 40);
        assert!(result["p50_us"].as_f64().unwrap() <= result["p95_us"].as_f64().unwrap());
        assert!(result["p95_us"].as_f64().unwrap() <= result["p99_us"].as_f64().unwrap());
    }
}
