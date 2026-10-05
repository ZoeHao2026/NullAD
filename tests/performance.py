"""Compare identical release harnesses in alternating independent processes.

Build nullad-perf in both source trees with --features performance, and copy
each binary to BASELINE-latency.exe / OPTIMIZED-latency.exe in --binaries.
Repeat with --features profiling, copying to BASELINE-alloc.exe and
OPTIMIZED-alloc.exe. Naming is lowercase; on Unix omit the .exe suffix.

The baseline needs only src/performance.rs and the CLI manifest additions from
the optimized tree. Its engine/interceptor sources must remain unchanged.
"""

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--warmup", type=int, default=2000)
    parser.add_argument("--rules", type=int, nargs="+", default=[1000, 100000])
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    suffix = ".exe" if platform.system() == "Windows" else ""
    paths = {
        f"{version}-{mode}": args.binaries / f"{version}-{mode}{suffix}"
        for version in ("baseline", "optimized")
        for mode in ("latency", "alloc")
    }
    for path in paths.values():
        if not path.is_file():
            parser.error(f"missing binary: {path}")
    started = time.time()
    runs = []
    for mode in ("latency", "alloc"):
        for rules in args.rules:
            for run in range(1, args.runs + 1):
                order = ("baseline", "optimized") if run % 2 else ("optimized", "baseline")
                for version in order:
                    key = f"{version}-{mode}"
                    command = [str(paths[key].resolve()), "--rules", str(rules), "--iterations", str(args.iterations), "--warmup", str(args.warmup)]
                    process = subprocess.run(command, check=True, capture_output=True, text=True, timeout=180)
                    report = json.loads(process.stdout)
                    assert report["profiling"] == (mode == "alloc")
                    assert report["rules"] == rules
                    assert report["logged_entries"] == min(args.iterations + args.warmup, report["log_capacity"])
                    runs.append({"version": version, "mode": mode, "run": run, "report": report})
                    print(f"measured {key} rules={rules} run={run}/{args.runs}", flush=True)
    summary = []
    for rules in args.rules:
        workloads = [result["workload"] for result in runs[0]["report"]["results"]]
        for workload in workloads:
            for api in ("engine_check_with", "decide_with_log"):
                row = {"rules": rules, "workload": workload, "api": api}
                for version in ("baseline", "optimized"):
                    latency = [next(item for item in run["report"]["results"] if item["workload"] == workload)[api]
                               for run in runs if run["version"] == version and run["mode"] == "latency" and run["report"]["rules"] == rules]
                    allocation = [next(item for item in run["report"]["results"] if item["workload"] == workload)[api]["allocations"]
                                  for run in runs if run["version"] == version and run["mode"] == "alloc" and run["report"]["rules"] == rules]
                    row[version] = {
                        metric: statistics.median(item[metric] for item in latency)
                        for metric in ("mean_us", "p50_us", "p95_us", "p99_us", "throughput_per_sec")
                    }
                    row[version].update({
                        "median_bytes_allocated_per_request": statistics.median(item["bytes_allocated_per_request"] for item in allocation),
                        "median_allocations_per_request": statistics.median(item["allocations_per_request"] for item in allocation),
                        "p95_us_min": min(item["p95_us"] for item in latency),
                        "p95_us_max": max(item["p95_us"] for item in latency),
                    })
                row["throughput_ratio"] = row["optimized"]["throughput_per_sec"] / row["baseline"]["throughput_per_sec"]
                before = row["baseline"]["median_bytes_allocated_per_request"]
                after = row["optimized"]["median_bytes_allocated_per_request"]
                row["allocation_bytes_reduction_percent"] = (before - after) / before * 100 if before else None
                summary.append(row)
    output = {
        "schema_version": 1,
        "baseline_ref": "56103aed8a62c58f0d3be251cf7c68eda838d056",
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "runs_per_configuration": args.runs,
        "elapsed_seconds": time.time() - started,
        "method": "Alternating independent release processes, each warming every API/cohort; latency uses uninstrumented binaries; allocations use stats_alloc binaries and a separate pass. Summary uses medians of independent runs. No OS proxy/DNS changes.",
        "binaries": {key: {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for key, path in paths.items()},
        "summary": summary,
        "runs": runs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"saved {args.output}")


if __name__ == "__main__":
    main()
