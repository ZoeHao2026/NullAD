"""Aggregate five warmed release processes per detection mode.

Build nullad-heuristic-perf separately with performance and profiling features,
copy the binaries as heuristic-latency.exe and heuristic-alloc.exe, then run:
  python tests/heuristic-performance.py --binaries ./perf-binaries --output ./cost.json
"""
import argparse
import hashlib
import json
import platform
import statistics
import subprocess
from datetime import date
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--bundled', action='store_true', help='Include the current bundled production lists')
    args = parser.parse_args()
    names = ['heuristic-latency.exe', 'heuristic-alloc.exe']
    runs = []
    for name in names:
        for repeat in range(5):
            order = ['off', 'conservative', 'balanced']
            order = order[repeat % 3:] + order[:repeat % 3]
            for mode in order:
                command = [str((args.binaries / name).resolve()), mode] + (['--bundled'] if args.bundled else [])
                result = json.loads(subprocess.check_output(command, text=True))
                result['repeat'] = repeat + 1
                runs.append(result)
    medians = []
    for mode in ['off', 'conservative', 'balanced']:
        for cohort in [x['cohort'] for x in runs[0]['results']]:
            entry = {'mode': mode, 'cohort': cohort}
            for lane in ['engine', 'decide_with_log']:
                timing = [next(x for x in run['results'] if x['cohort'] == cohort)[lane] for run in runs if run['mode'] == mode and not run['profiling']]
                alloc = [next(x for x in run['results'] if x['cohort'] == cohort)[lane]['allocations'] for run in runs if run['mode'] == mode and run['profiling']]
                entry[lane] = {key: statistics.median(x[key] for x in timing) for key in ['throughput_per_sec', 'mean_us', 'p50_us', 'p95_us', 'p99_us']}
                entry[lane].update({key: statistics.median(x[key] for x in alloc) for key in ['allocations_per_request', 'bytes_per_request']})
            medians.append(entry)
    data = {'date': str(date.today()), 'machine': platform.platform(), 'rust': subprocess.check_output(['rustc', '--version'], text=True).strip(), 'rules':runs[0]['rules'], 'bundled':args.bundled, 'method': 'five independent warmed processes per mode, alternating order; two fixed rules plus current bundled lists when requested, nine cohorts including SDK, 2000 warmup and 14000 measured requests per cohort; latency and stats_alloc builds separate; local decisions with actual bounded log, not network throughput', 'binary_sha256': {name: hashlib.sha256((args.binaries / name).read_bytes()).hexdigest() for name in names}, 'medians': medians, 'runs': runs}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + '\n', encoding='utf8')
    for row in medians:
        if row['cohort'] == 'mixed':
            print(json.dumps(row))


if __name__ == '__main__':
    main()
