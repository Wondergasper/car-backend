#!/usr/bin/env python3
"""
run_tests.py  -  CAR-Bot Parallel Backend Test Runner
======================================================
Runs every test module concurrently using Python's ThreadPoolExecutor
(each subprocess gets its own pytest process), then collates the results
into a single summary report.

Usage
-----
  python run_tests.py                   # parallel (default, 4 workers)
  python run_tests.py --serial          # sequential, for debugging
  python run_tests.py --module auth     # single module
  python run_tests.py --workers 6       # control parallelism
  python run_tests.py --failfast        # stop on first failure
"""

import argparse
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List

# ANSI colours (disabled automatically if not a TTY)
_USE_COLOR = sys.stdout.isatty()
def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

GREEN  = lambda t: _c("92", t)
RED    = lambda t: _c("91", t)
YELLOW = lambda t: _c("93", t)
CYAN   = lambda t: _c("96", t)
BOLD   = lambda t: _c("1",  t)

ROOT = Path(__file__).parent

TEST_MODULES = [
    "tests/test_health.py",
    "tests/test_auth.py",
    "tests/test_audits.py",
    "tests/test_connectors.py",
    "tests/test_users.py",
    "tests/test_chat.py",
    "tests/test_webhooks.py",
    "tests/test_scheduled_audits.py",
    "tests/test_rag.py",
    "tests/test_frameworks.py",
    "tests/test_api_keys.py",
]


@dataclass
class ModuleResult:
    module: str
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    duration: float = 0.0
    output: str = ""
    returncode: int = 0

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.errors + self.skipped

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _parse_pytest_output(output: str) -> dict:
    counts = {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
    import re
    for line in reversed(output.splitlines()):
        if any(kw in line for kw in ("passed", "failed", "error")):
            for key in counts:
                m = re.search(rf"(\d+) {key}", line)
                if m:
                    counts[key] = int(m.group(1))
            break
    return counts


def run_module(module_path: str, extra_args: List[str]) -> ModuleResult:
    result = ModuleResult(module=Path(module_path).stem)
    cmd = [
        sys.executable, "-m", "pytest",
        module_path,
        "--tb=short",
        "-v",
        "--no-header",
        *extra_args,
    ]
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    result.duration = time.perf_counter() - t0
    result.returncode = proc.returncode
    result.output = proc.stdout + proc.stderr

    counts = _parse_pytest_output(result.output)
    result.passed  = counts["passed"]
    result.failed  = counts["failed"]
    result.errors  = counts["error"]
    result.skipped = counts["skipped"]
    return result


def print_module_summary(r: ModuleResult, idx: int, total: int):
    status = GREEN("PASS") if r.ok else RED("FAIL")
    bar = "#" * r.passed + "-" * r.failed + "." * r.skipped
    line = (
        f"  [{idx:>2}/{total}] {BOLD(f'{r.module:<28}')} "
        f"{status}  "
        f"{GREEN(f'{r.passed} ok')} "
        f"{RED(f'{r.failed} fail')} "
        f"{YELLOW(f'{r.skipped} skip')}  "
        f"({r.duration:.1f}s)  {bar}"
    )
    print(line)


def print_full_report(results: List[ModuleResult]):
    sep = "=" * 72
    print(f"\n{CYAN(sep)}")
    print(BOLD("  CAR-Bot Backend  --  Full Parallel Test Report"))
    print(f"{CYAN(sep)}\n")

    total_p = sum(r.passed  for r in results)
    total_f = sum(r.failed  for r in results)
    total_e = sum(r.errors  for r in results)
    total_s = sum(r.skipped for r in results)
    total_t = sum(r.total   for r in results)
    total_d = sum(r.duration for r in results)

    for i, r in enumerate(results, 1):
        print_module_summary(r, i, len(results))

    print(f"\n{CYAN('=' * 72)}")
    print(
        f"  {BOLD('TOTAL')}  "
        f"{GREEN(f'{total_p} passed')}  "
        f"{RED(f'{total_f} failed')}  "
        f"{YELLOW(f'{total_s} skipped')}  "
        f"{total_t} tests  ({total_d:.1f}s)"
    )

    failed_modules = [r for r in results if not r.ok]
    if failed_modules:
        print(f"\n{RED(BOLD('[RESULTS] Failures in: ' + ', '.join(r.module for r in failed_modules)))}")
        for r in failed_modules:
            print(f"\n{BOLD('-' * 72)}")
            print(f"  Output: {r.module}")
            print("-" * 72)
            for line in r.output.splitlines():
                if any(kw in line for kw in ("FAILED", "ERROR", "AssertionError", "assert ", "E ")):
                    print(f"  {line}")
    else:
        print(f"\n{GREEN(BOLD('[PASS] All modules passed!'))}")

    print(f"\n{CYAN('=' * 72)}\n")


def main():
    parser = argparse.ArgumentParser(description="CAR-Bot parallel test runner")
    parser.add_argument("--serial",   action="store_true", help="Run serially instead of parallel")
    parser.add_argument("--module",   default=None,        help="Run only this module (name without .py)")
    parser.add_argument("--workers",  type=int, default=4, help="Max parallel workers (default 4)")
    parser.add_argument("--failfast", action="store_true", help="Stop on first failure")
    args = parser.parse_args()

    modules = TEST_MODULES
    if args.module:
        modules = [m for m in TEST_MODULES if args.module in m]
        if not modules:
            print(RED(f"No module matching '{args.module}'"))
            sys.exit(1)

    extra = ["-x"] if args.failfast else []

    print(f"\n{BOLD('CAR-Bot Backend Test Suite')}")
    label = "serially" if args.serial else f"in parallel (workers={args.workers})"
    print(f"Running {len(modules)} module(s) {label}\n")

    results: List[ModuleResult] = []
    wall_start = time.perf_counter()

    if args.serial or len(modules) == 1:
        for i, mod in enumerate(modules, 1):
            print(f"  Running {Path(mod).stem}...")
            r = run_module(mod, extra)
            results.append(r)
            print_module_summary(r, i, len(modules))
    else:
        futures = {}
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for mod in modules:
                fut = pool.submit(run_module, mod, extra)
                futures[fut] = mod

            done_count = 0
            for fut in as_completed(futures):
                done_count += 1
                r = fut.result()
                results.append(r)
                print_module_summary(r, done_count, len(modules))
                if args.failfast and not r.ok:
                    print(f"\n{RED('--failfast: aborting remaining tests.')}")
                    pool.shutdown(wait=False, cancel_futures=True)
                    break

    wall_time = time.perf_counter() - wall_start
    print_full_report(results)
    print(f"  Wall-clock time: {wall_time:.1f}s\n")

    sys.exit(0 if all(r.ok for r in results) else 1)


if __name__ == "__main__":
    main()
