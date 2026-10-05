# Performance validation / 性能实测

## Local detection cost (2026-10-05)

The new default Balanced path performs additional detection. Five independent
warmed release processes per mode alternate order on the same Windows machine;
latency and allocation builds are separate. Eight fixed cohorts cover rule hit,
miss, exception, allow-host, ad service, HTTP features, protected paths and mixed
traffic. Each cohort runs 2,000 warmups and 14,000 operations and asserts expected
decisions. Two rules and the actual bounded 500-entry decision log are used.
Full raw runs, binary hashes and per-cohort metrics: [heuristic-performance.json](heuristic-performance.json).

| Mode | Engine mixed req/s | Actual decide/log req/s | Mean us | P95 us | Allocations/request | Bytes/request |
|---|---:|---:|---:|---:|---:|---:|
| Off | 7,401,142 | 1,307,202 | 0.765 | 0.9 | 8.000 | 240.571 |
| Conservative | 7,731,389 | 1,092,120 | 0.916 | 1.1 | 8.286 | 245.429 |
| Balanced (default) | 7,702,465 | 1,026,581 | 0.974 | 1.2 | 8.571 | 251.143 |

These are medians of five local decision runs, including Instant sampling, not
internet or socket throughput. Balanced adds approximately 0.21 us to the mean
and lowers measured decision throughput by 21% versus Off in this workload; it
is **not a performance improvement over disabling detection**. Its additional
coverage is the benefit. The rule engine lane uses prebuilt requests and has no
allocations in these cohorts. Normal lowercase paths/query keys are borrowed;
percent decoding/ASCII folding allocate only when needed. Thread-local matching
scratch and bounded logs remain in the real interception path.

```powershell
cargo build --release -p nullad-cli --features performance --bin nullad-heuristic-perf --locked
# Copy the binary to perf-binaries/heuristic-latency.exe.
cargo build --release -p nullad-cli --features profiling --bin nullad-heuristic-perf --locked
# Copy the binary to perf-binaries/heuristic-alloc.exe.
python tests/heuristic-performance.py --binaries ./perf-binaries --output ./cost.json
```

This harness differs from the historical large-rule experiment below. Do not
compare their absolute throughput, allocations or use the old 11x figure to
describe the new Balanced default. Browser DOM/DNR cost is not measured by this
native decision harness.

## Historical scratch reuse comparison (before local detection)

Baseline: `56103aed8a62c58f0d3be251cf7c68eda838d056`. Windows x86_64, Rust 1.96.0. Each configuration ran in five independent release processes after warm-up. Baseline and optimized runs alternate. Latency and `stats_alloc` allocation measurements use separate builds. Full raw data: [performance-comparison.json](performance-comparison.json).

| Rules | Path (mixed load) | Baseline req/s | Optimized req/s | Ratio | P95 us before/after | Bytes allocated/request before/after |
|---|---|---:|---:|---:|---|---|
| 1,000 | `engine_check_with` | 2,764,569 | 2,776,390 | 1.004x | 0.5 / 0.5 | 5.081 / 5.081 |
| 1,000 | `decide_with_log` | 1,177,884 | 1,327,404 | 1.127x | 1.1 / 1.0 | 4930.491 / 115.825 |
| 100,000 | `engine_check_with` | 2,783,654 | 2,867,137 | 1.030x | 0.5 / 0.4 | 5.081 / 5.081 |
| 100,000 | `decide_with_log` | 121,166 | 1,391,614 | 11.485x | 8.6 / 1.0 | 480130.491 / 115.825 |

The workload contains fixed domain hits, misses, exceptions, important overrides, type and party conditions, path boundaries, substring and regex matches. Every fixture asserts its expected decision before timing; matching and live decision counts are checked again. Remaining rules are 80% domain anchors and 20% substring patterns. This is a controlled synthetic workload, not a claim about all subscription lists or socket throughput.

`engine_check_with` uses prebuilt requests and a warmed caller scratch buffer. `decide_with_log` uses the actual interception decision API, constructs requests and writes to the real bounded `DecisionLog` (capacity 500). The previous `decide` allocated scratch proportional to the rule count on every request. Thread-local reuse removes that repeated allocation; the already reused engine path changes only modestly.

Timing includes per-operation `Instant` sampling overhead. Results are medians of five runs; the JSON also preserves P95 ranges. Allocation passes exclude JSON/timing sample storage. OS scheduling, hardware and workload alter results. There is no general 11x networking throughput claim.

## Reproduce

Build an unchanged baseline checkout, adding only `crates/nullad-cli/src/performance.rs` and its `performance`/`profiling` CLI manifest entries. Do not copy engine, core or intercept modifications into the baseline. Build each tree twice:

```powershell
cargo build --release -p nullad-cli --features performance --bin nullad-perf --locked
# Copy target/release/nullad-perf.exe to baseline-latency.exe or optimized-latency.exe.
cargo build --release -p nullad-cli --features profiling --bin nullad-perf --locked
# Copy the binary to baseline-alloc.exe or optimized-alloc.exe.
python tests/performance.py --binaries ./perf-binaries --output ./comparison.json --runs 5 --rules 1000 100000 --iterations 10000 --warmup 2000
```

The baseline lockfile needs the optional `stats_alloc` dependency resolution. Normal GUI/CLI builds do not enable profiling. All four binary hashes, configurations and measured raw results are in the JSON.
