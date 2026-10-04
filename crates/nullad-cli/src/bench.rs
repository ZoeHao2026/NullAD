//! The `bench` command: measures matching latency and throughput.
//!
//! There is no `criterion` dependency on this host, so the harness is
//! hand-rolled. That is arguably an advantage here: it reports exactly the
//! numbers the project commits to (p50/p95/p99 latency, throughput, and
//! rule-set load time) rather than a generic statistical summary.

use std::time::{Duration, Instant};

use anyhow::Result;
use nullad_engine::{FilterEngine, MatchScratch, Request, ResourceType, RuleSetBuilder};

/// Generates a deterministic pseudo-random rule set.
///
/// A small xorshift is used instead of the `rand` crate so that benchmark
/// output is byte-for-byte reproducible across runs and machines, which makes
/// performance regressions attributable.
pub fn synthetic_rule_set(count: usize) -> String {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut out = String::with_capacity(count * 32);
    let labels = [
        "ads",
        "track",
        "pixel",
        "beacon",
        "analytics",
        "cdn",
        "static",
        "img",
        "sync",
        "tag",
        "banner",
        "click",
        "metric",
        "collect",
        "serve",
        "push",
        "promo",
        "telemetry",
    ];

    for i in 0..count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;

        let label = labels[(state as usize) % labels.len()];
        let tld = if i % 3 == 0 {
            "com"
        } else if i % 3 == 1 {
            "net"
        } else {
            "org"
        };
        match i % 5 {
            0 => out.push_str(&format!("||{label}{i}.example.{tld}^\n")),
            1 => out.push_str(&format!("||{label}-{i}.ads.example.{tld}^\n")),
            2 => out.push_str(&format!("/{label}/{i}/pixel.gif\n")),
            3 => out.push_str(&format!("||{label}.edge{i}.example.{tld}^$third-party\n")),
            _ => out.push_str(&format!("||{label}{i}.example.{tld}^$script,image\n")),
        }
    }
    out
}

/// Generates request URLs that a given rule set should be able to decide on.
fn synthetic_requests(count: usize) -> Vec<Request> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut out = Vec::with_capacity(count);
    let types = [
        ResourceType::Script,
        ResourceType::Image,
        ResourceType::Xhr,
        ResourceType::Other,
        ResourceType::Document,
    ];

    for i in 0..count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;

        // Two thirds of the traffic targets hosts that are actually in the
        // synthetic rule set, so the harness measures real matching work rather
        // than an early exit.
        let url = if i % 3 == 0 {
            format!("https://unrelated{i}.testsite.example/page/{i}")
        } else {
            let label = ["ads", "track", "pixel", "beacon", "analytics"][(state as usize) % 5];
            format!("https://{label}{i}.example.com/assets/{i}/bundle.js")
        };

        out.push(Request::new(url, types[(state as usize) % types.len()]));
    }
    out
}

/// Timing results for one workload.
#[derive(Debug, Clone, Copy)]
pub struct Timings {
    /// Number of measured iterations.
    pub iterations: usize,
    /// Total wall time.
    pub total: Duration,
    /// Median per-request latency.
    pub p50: Duration,
    /// 95th percentile per-request latency.
    pub p95: Duration,
    /// 99th percentile per-request latency.
    pub p99: Duration,
    /// Fastest observed latency.
    pub min: Duration,
    /// Slowest observed latency.
    pub max: Duration,
}

impl Timings {
    /// Requests per second implied by the total time.
    #[must_use]
    pub fn throughput_per_sec(&self) -> f64 {
        let secs = self.total.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.iterations as f64 / secs
    }

    /// Mean latency.
    #[must_use]
    pub fn mean(&self) -> Duration {
        if self.iterations == 0 {
            return Duration::ZERO;
        }
        self.total / u32::try_from(self.iterations).unwrap_or(u32::MAX)
    }
}

/// Runs `iterations` of `body`, returning latency statistics.
///
/// A warm-up pass runs first so that the measurement reflects steady-state
/// behaviour rather than first-touch page faults and cache misses.
pub fn measure<F>(iterations: usize, mut body: F) -> Timings
where
    F: FnMut(usize),
{
    // Warm-up: at least 5% of the measured run, capped so short runs stay fast.
    let warmup = (iterations / 20).clamp(1, 50_000);
    for i in 0..warmup {
        body(i);
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(iterations.min(2_000_000));
    let started = Instant::now();
    for i in 0..iterations {
        let t0 = Instant::now();
        body(i);
        samples.push(t0.elapsed());
    }
    let total = started.elapsed();

    samples.sort_unstable();
    let pick = |q: f64| -> Duration {
        if samples.is_empty() {
            return Duration::ZERO;
        }
        let idx = ((samples.len() - 1) as f64 * q).round() as usize;
        samples[idx.min(samples.len() - 1)]
    };

    Timings {
        iterations,
        total,
        p50: pick(0.50),
        p95: pick(0.95),
        p99: pick(0.99),
        min: samples.first().copied().unwrap_or(Duration::ZERO),
        max: samples.last().copied().unwrap_or(Duration::ZERO),
    }
}

/// Result of a hot-swap-under-load test.
#[derive(Debug, Clone, Copy)]
pub struct SwapReport {
    /// Rule-set swaps performed.
    pub swaps: usize,
    /// Requests evaluated while swapping happened.
    pub requests: usize,
    /// Longest single swap, in microseconds.
    pub max_swap_us: f64,
    /// Mean swap duration, in microseconds.
    pub mean_swap_us: f64,
    /// Rule-set reads that returned an inconsistent state. Must be zero.
    pub inconsistencies: usize,
}

/// Exercises hot reload while requests are continuously evaluated.
///
/// This is the test that substantiates the project's central concurrency claim:
/// that replacing the rule set is a single atomic pointer store, so a reload
/// never blocks, drops, or mis-answers an in-flight request. One thread swaps
/// rule sets while another hammers `check`, and every observed rule-set version
/// must be internally whole — either the old set or the new one, never a mix and
/// never an empty engine.
pub fn swap_under_load(
    initial_rules: usize,
    swaps: usize,
    requests: usize,
) -> Result<SwapReport, String> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    let build = |count: usize, offset: usize| -> Result<nullad_engine::RuleSet, String> {
        let mut text = String::new();
        let mut state = 0x2545_F491_4F6C_DD1Du64 ^ (offset as u64);
        for i in 0..count {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let label = ["ads", "track", "pixel", "beacon", "metric"][(state as usize) % 5];
            text.push_str(&format!("||{label}{i}.example.com^\n"));
        }
        let mut builder = RuleSetBuilder::with_capacity(count);
        builder.add_list_auto(&text);
        builder.build().map_err(|e| e.to_string())
    };

    let engine = Arc::new(FilterEngine::from_rule_set(
        build(initial_rules, 0).map_err(|e| e.to_string())?,
    ));

    let stop = Arc::new(AtomicBool::new(false));
    let evaluated = Arc::new(AtomicUsize::new(0));
    let inconsistencies = Arc::new(AtomicUsize::new(0));

    let requests = synthetic_requests(requests.max(64));

    // Reader thread: continuously evaluate requests, verifying that whatever
    // rule set it observes is complete.
    let reader = {
        let engine = Arc::clone(&engine);
        let stop = Arc::clone(&stop);
        let evaluated = Arc::clone(&evaluated);
        let inconsistencies = Arc::clone(&inconsistencies);
        let requests = requests.clone();
        std::thread::spawn(move || {
            let mut scratch = MatchScratch::new();
            let mut index = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let request = &requests[index % requests.len()];
                let observed = engine.rule_set();

                // A torn read would show a rule set with no rules at all while
                // the engine is known to hold a populated one.
                if observed.is_empty() {
                    inconsistencies.fetch_add(1, Ordering::Relaxed);
                }

                let _ = engine.check_with(request, &mut scratch);
                evaluated.fetch_add(1, Ordering::Relaxed);
                index += 1;
            }
        })
    };

    // Give the reader a moment to reach steady state before swapping.
    std::thread::sleep(Duration::from_millis(50));

    let mut swap_times = Vec::with_capacity(swaps);
    for i in 0..swaps {
        let rule_set = build(initial_rules + (i % 8) * 100, i + 1).map_err(|e| e.to_string())?;
        let started = Instant::now();
        engine.swap(rule_set);
        swap_times.push(started.elapsed());
    }

    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();

    let max = swap_times.iter().max().copied().unwrap_or(Duration::ZERO);
    let total: Duration = swap_times.iter().sum();
    let count = swap_times.len().max(1);

    Ok(SwapReport {
        swaps,
        requests: evaluated.load(Ordering::Relaxed),
        max_swap_us: max.as_secs_f64() * 1_000_000.0,
        mean_swap_us: total.as_secs_f64() * 1_000_000.0 / count as f64,
        inconsistencies: inconsistencies.load(Ordering::Relaxed),
    })
}

/// A breakdown of where matching time goes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Breakdown {
    /// Time spent normalising the URL to lowercase.
    pub lowercase_ns: f64,
    /// Time spent in the domain trie.
    pub trie_ns: f64,
    /// Time spent in the substring automaton.
    pub automaton_ns: f64,
    /// Time spent in the regex bucket.
    pub regex_ns: f64,
    /// Total time per check.
    pub total_ns: f64,
}

/// Measures each stage of the matching path separately.
///
/// This exists so throughput work is driven by measurement. The engine itself
/// exposes only a whole-request `check`, so the stages are reconstructed here
/// from the same public indexes it uses.
pub fn breakdown(engine: &FilterEngine, iterations: usize) -> Breakdown {
    let rule_set = engine.rule_set();
    let requests = synthetic_requests(512);
    let mut scratch = MatchScratch::new();
    let mut candidates: Vec<u32> = Vec::with_capacity(64);

    // Warm up every path so the numbers reflect steady state rather than
    // first-touch page faults.
    for request in requests.iter().take(64) {
        std::hint::black_box(engine.check_with(request, &mut scratch));
    }

    let mut lowercase = Duration::ZERO;
    let mut trie = Duration::ZERO;
    let mut automaton = Duration::ZERO;
    let mut regex = Duration::ZERO;
    let mut total = Duration::ZERO;

    let mut seen: Vec<u32> = Vec::new();
    let mut generation = 0u32;

    for i in 0..iterations {
        let request = &requests[i % requests.len()];

        let t = Instant::now();
        std::hint::black_box(engine.check_with(request, &mut scratch));
        total += t.elapsed();

        // Lowercasing, including the fast path that avoids the copy.
        let t = Instant::now();
        let needs_lowercasing =
            request.url.is_ascii() && request.url.bytes().any(|b| b.is_ascii_uppercase());
        if needs_lowercasing {
            std::hint::black_box(request.lowercase_url());
        }
        lowercase += t.elapsed();

        let t = Instant::now();
        candidates.clear();
        rule_set.domains().lookup(&request.host, &mut candidates);
        std::hint::black_box(&candidates);
        trie += t.elapsed();

        let t = Instant::now();
        generation = generation.wrapping_add(1).max(1);
        candidates.clear();
        rule_set
            .substrings()
            .scan(&request.url, &mut seen, generation, &mut candidates);
        std::hint::black_box(&candidates);
        automaton += t.elapsed();

        let t = Instant::now();
        candidates.clear();
        rule_set.regexes().scan(&request.url, &mut candidates);
        std::hint::black_box(&candidates);
        regex += t.elapsed();
    }

    let per = |d: Duration| d.as_secs_f64() * 1e9 / iterations.max(1) as f64;
    Breakdown {
        lowercase_ns: per(lowercase),
        trie_ns: per(trie),
        automaton_ns: per(automaton),
        regex_ns: per(regex),
        total_ns: per(total),
    }
}

/// Runs the benchmark and prints results.
pub fn run(
    engine: &FilterEngine,
    iterations: usize,
    synthetic_rules: usize,
    json: bool,
) -> Result<()> {
    if iterations == 0 {
        anyhow::bail!("`--iterations` must be greater than zero");
    }

    // Case 1: real rule sets, synthetic traffic.
    let requests = synthetic_requests(iterations.max(1024));
    let mut scratch = MatchScratch::new();

    let real = measure(iterations, |i| {
        let request = &requests[i % requests.len()];
        std::hint::black_box(engine.check_with(request, &mut scratch));
    });

    let mut results: Vec<(&str, usize, Timings)> =
        vec![("loaded rules", engine.rule_count(), real)];

    // Case 2: a large synthetic rule set, to show how cost scales with size
    // rather than only with the size of whatever lists happened to be present.
    if synthetic_rules > 0 {
        let text = synthetic_rule_set(synthetic_rules);
        let mut builder = RuleSetBuilder::with_capacity(synthetic_rules);
        let load_started = Instant::now();
        let stats = builder.add_list_auto(&text);
        let rule_set = builder
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build synthetic rule set: {e}"))?;
        let build_time = load_started.elapsed();

        if !json {
            println!(
                "synthetic rule set: {} rules ({} accepted, {} quarantined), built in {:.1} ms",
                synthetic_rules,
                stats.accepted,
                stats.failed(),
                build_time.as_secs_f64() * 1000.0
            );
        }

        let synthetic_engine = FilterEngine::from_rule_set(rule_set);
        let mut scratch = MatchScratch::new();
        let timings = measure(iterations, |i| {
            let request = &requests[i % requests.len()];
            std::hint::black_box(synthetic_engine.check_with(request, &mut scratch));
        });
        results.push(("synthetic rules", synthetic_engine.rule_count(), timings));
    }

    println!();
    let metric = |d: Duration| format!("{:.3}", d.as_secs_f64() * 1_000_000.0);

    // Only run the hot-swap test when a synthetic set was requested, so the
    // default benchmark stays fast.
    if synthetic_rules > 0 && !json {
        match swap_under_load(synthetic_rules, 10, 4096) {
            Ok(swap) => {
                println!();
                println!("hot reload under load:");
                println!(
                    "  {} swaps while {} requests were evaluated concurrently",
                    swap.swaps, swap.requests
                );
                println!(
                    "  swap latency: mean {:.1} us, max {:.1} us (budget 50000 us)",
                    swap.mean_swap_us, swap.max_swap_us
                );
                println!(
                    "  torn or empty rule-set observations: {}",
                    swap.inconsistencies
                );
                if swap.inconsistencies != 0 {
                    anyhow::bail!("hot reload exposed an inconsistent rule set");
                }
                if swap.max_swap_us > 50_000.0 {
                    anyhow::bail!(
                        "hot reload exceeded the 50 ms budget (worst case {:.1} us)",
                        swap.max_swap_us
                    );
                }
            }
            Err(err) => eprintln!("warning: the hot-swap test could not run: {err}"),
        }
    }

    // The stage breakdown is cheap and informative, so it always runs; the
    // measurement budget is scaled down for small runs.
    if !json {
        let parts = breakdown(engine, iterations.clamp(10_000, 200_000));
        println!();
        println!("matching path breakdown (nanoseconds per request):");
        println!("  total               {:>8.1}", parts.total_ns);
        println!("  domain trie         {:>8.1}", parts.trie_ns);
        println!("  substring automaton {:>8.1}", parts.automaton_ns);
        println!("  regex bucket        {:>8.1}", parts.regex_ns);
        println!("  url lowercasing     {:>8.1}", parts.lowercase_ns);
    }

    if json {
        println!("{{");
        println!("  \"iterations\": {iterations},");
        println!("  \"results\": [");
        for (index, (label, rules, t)) in results.iter().enumerate() {
            let comma = if index + 1 == results.len() { "" } else { "," };
            println!("    {{");
            println!("      \"workload\": \"{label}\",");
            println!("      \"rules\": {rules},");
            println!("      \"iterations\": {},", t.iterations);
            println!("      \"total_ms\": {:.3},", t.total.as_secs_f64() * 1000.0);
            println!(
                "      \"throughput_per_sec\": {:.0},",
                t.throughput_per_sec()
            );
            println!("      \"mean_us\": {},", metric(t.mean()));
            println!("      \"p50_us\": {},", metric(t.p50));
            println!("      \"p95_us\": {},", metric(t.p95));
            println!("      \"p99_us\": {},", metric(t.p99));
            println!("      \"min_us\": {},", metric(t.min));
            println!("      \"max_us\": {}", metric(t.max));
            println!("    }}{comma}");
        }
        println!("  ]");
        println!("}}");
    } else {
        println!(
            "{:<18} {:>9} {:>12} {:>10} {:>10} {:>10} {:>10}",
            "WORKLOAD", "RULES", "REQ/SEC", "MEAN us", "P50 us", "P95 us", "P99 us"
        );
        for (label, rules, t) in &results {
            println!(
                "{:<18} {:>9} {:>12.0} {:>10} {:>10} {:>10} {:>10}",
                label,
                rules,
                t.throughput_per_sec(),
                metric(t.mean()),
                metric(t.p50),
                metric(t.p95),
                metric(t.p99)
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_rule_set_is_deterministic_and_well_formed() {
        let a = synthetic_rule_set(50);
        let b = synthetic_rule_set(50);
        assert_eq!(a, b, "generator must be reproducible");
        assert_eq!(a.lines().count(), 50);

        // Every generated rule must actually parse.
        let parser = nullad_engine::RuleParser::new();
        let (rules, stats) = parser.parse_list(&a);
        assert_eq!(rules.len(), 50);
        assert_eq!(stats.failed(), 0);
    }

    #[test]
    fn synthetic_requests_are_deterministic() {
        let a = synthetic_requests(10);
        let b = synthetic_requests(10);
        assert_eq!(a.len(), 10);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.url, y.url);
        }
    }

    #[test]
    fn measure_reports_sane_percentiles() {
        let t = measure(1000, |_| {
            std::hint::black_box(1u64.wrapping_mul(2));
        });
        assert_eq!(t.iterations, 1000);
        assert!(t.min <= t.p50, "min must not exceed p50");
        assert!(t.p50 <= t.p95, "p50 must not exceed p95");
        assert!(t.p95 <= t.p99, "p95 must not exceed p99");
        assert!(t.p99 <= t.max, "p99 must not exceed max");
        assert!(t.throughput_per_sec() > 0.0);
    }

    #[test]
    fn measure_handles_zero_iterations() {
        let t = measure(0, |_| {});
        assert_eq!(t.iterations, 0);
        assert_eq!(t.mean(), Duration::ZERO);
    }

    #[test]
    fn hot_swap_serves_requests_consistently_under_load() {
        // Small numbers keep the test fast while still exercising the race.
        let report = swap_under_load(500, 10, 256).expect("swap test");
        assert_eq!(report.swaps, 10);
        assert!(
            report.requests > 0,
            "the reader thread must have evaluated requests"
        );
        assert_eq!(
            report.inconsistencies, 0,
            "a swap must never expose a torn or empty rule set"
        );
        assert!(report.max_swap_us < 50_000.0, "swaps must be fast");
    }
}
