#!/usr/bin/env python3
"""Analyze benchmark results and generate findings.md report.

Reads results/metrics.csv and results/raw/ JSON findings.
Produces results/findings.md with summary tables.
"""
from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR / "results"
RAW_DIR = RESULTS_DIR / "raw"
CSV_PATH = RESULTS_DIR / "metrics.csv"
ENV_PATH = RESULTS_DIR / "environment.txt"
FINDINGS_MD = RESULTS_DIR / "findings.md"
UNMAPPED_PATH = SCRIPT_DIR / "configs" / "unmapped-rules.txt"

SCANNERS = ["scanner-rs", "kingfisher", "trufflehog", "gitleaks"]
REPOS = ["node", "vscode", "linux", "rocksdb", "tensorflow", "Babylon.js", "gcc", "jdk"]


def load_csv() -> list[dict]:
    """Load metrics.csv into list of dicts with numeric conversions."""
    rows = []
    with open(CSV_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            for key in ("wall_time_s", "user_time_s", "sys_time_s", "throughput_mib_s"):
                try:
                    row[key] = float(row[key])
                except (ValueError, KeyError):
                    row[key] = 0.0
            for key in ("max_rss_kb", "bytes_scanned", "findings_count"):
                try:
                    row[key] = int(row[key])
                except (ValueError, KeyError):
                    row[key] = 0
            rows.append(row)
    return rows


def fmt_time(s: float) -> str:
    """Format seconds as human-readable string."""
    if s < 60:
        return f"{s:.1f}s"
    m = int(s // 60)
    sec = s % 60
    return f"{m}m{sec:.0f}s"


def fmt_throughput(mib_s: float) -> str:
    if mib_s >= 1000:
        return f"{mib_s/1024:.1f} GiB/s"
    return f"{mib_s:.1f} MiB/s"


def fmt_rss(kb: int) -> str:
    if kb >= 1_048_576:
        return f"{kb/1_048_576:.1f} GiB"
    return f"{kb/1024:.0f} MiB"


def load_environment() -> str:
    """Load the environment description file."""
    if ENV_PATH.exists():
        return ENV_PATH.read_text()
    return "(environment.txt not found — run benchmarks first)"


def load_unmapped_rules() -> str:
    """Load unmapped rules documentation."""
    if UNMAPPED_PATH.exists():
        return UNMAPPED_PATH.read_text()
    return "(unmapped-rules.txt not found — run generate_rule_mapping.py first)"


def build_findings_table(rows: list[dict]) -> str:
    """Findings count per scanner × repo × mode."""
    lines = []
    lines.append("| Repo | Mode | " + " | ".join(SCANNERS) + " |")
    lines.append("|------|------|" + "|".join(["------:"] * len(SCANNERS)) + "|")

    for repo in REPOS:
        for mode in ("git", "fs"):
            cells = [f"{repo}", f"{mode}"]
            for scanner in SCANNERS:
                match = [r for r in rows
                         if r["scanner"] == scanner and r["repo"] == repo
                         and r["mode"] == mode and r["cache"] == "warm"]
                if match:
                    cells.append(f"{match[0]['findings_count']:,}")
                else:
                    # Fall back to cold
                    match = [r for r in rows
                             if r["scanner"] == scanner and r["repo"] == repo
                             and r["mode"] == mode and r["cache"] == "cold"]
                    cells.append(f"{match[0]['findings_count']:,}" if match else "—")
            lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def build_performance_table(rows: list[dict]) -> str:
    """Wall time + throughput per scanner × repo × mode × cache."""
    lines = []
    lines.append("| Repo | Mode | Cache | " +
                 " | ".join(f"{s} time" for s in SCANNERS) + " | " +
                 " | ".join(f"{s} MiB/s" for s in SCANNERS) + " |")
    sep = "|------|------|-------|" + "|".join(["------:"] * len(SCANNERS)) + "|" + "|".join(["------:"] * len(SCANNERS)) + "|"
    lines.append(sep)

    for repo in REPOS:
        for mode in ("git", "fs"):
            for cache in ("cold", "warm"):
                cells = [repo, mode, cache]
                time_cells = []
                tp_cells = []
                for scanner in SCANNERS:
                    match = [r for r in rows
                             if r["scanner"] == scanner and r["repo"] == repo
                             and r["mode"] == mode and r["cache"] == cache]
                    if match:
                        time_cells.append(fmt_time(match[0]["wall_time_s"]))
                        tp_cells.append(fmt_throughput(match[0]["throughput_mib_s"]))
                    else:
                        time_cells.append("—")
                        tp_cells.append("—")
                lines.append("| " + " | ".join(cells + time_cells + tp_cells) + " |")

    return "\n".join(lines)


def build_memory_table(rows: list[dict]) -> str:
    """Peak RSS per scanner × repo (max across all modes/caches)."""
    lines = []
    lines.append("| Repo | " + " | ".join(f"{s} peak RSS" for s in SCANNERS) + " |")
    lines.append("|------|" + "|".join(["------:"] * len(SCANNERS)) + "|")

    for repo in REPOS:
        cells = [repo]
        for scanner in SCANNERS:
            match = [r for r in rows
                     if r["scanner"] == scanner and r["repo"] == repo]
            if match:
                peak = max(r["max_rss_kb"] for r in match)
                cells.append(fmt_rss(peak))
            else:
                cells.append("—")
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def build_speedup_summary(rows: list[dict]) -> str:
    """Compute scanner-rs speedup vs each competitor for warm git mode."""
    lines = []
    lines.append("| Repo | vs Kingfisher | vs TruffleHog | vs Gitleaks |")
    lines.append("|------|------:|------:|------:|")

    for repo in REPOS:
        cells = [repo]
        sr_match = [r for r in rows
                    if r["scanner"] == "scanner-rs" and r["repo"] == repo
                    and r["mode"] == "git" and r["cache"] == "warm"]
        if not sr_match:
            cells.extend(["—", "—", "—"])
            lines.append("| " + " | ".join(cells) + " |")
            continue

        sr_time = sr_match[0]["wall_time_s"]
        for competitor in ("kingfisher", "trufflehog", "gitleaks"):
            c_match = [r for r in rows
                       if r["scanner"] == competitor and r["repo"] == repo
                       and r["mode"] == "git" and r["cache"] == "warm"]
            if c_match and sr_time > 0:
                speedup = c_match[0]["wall_time_s"] / sr_time
                cells.append(f"{speedup:.1f}×")
            else:
                cells.append("—")
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def main():
    if not CSV_PATH.exists():
        print(f"ERROR: {CSV_PATH} not found. Run benchmarks first.")
        return

    rows = load_csv()
    print(f"Loaded {len(rows)} rows from {CSV_PATH}")

    env_text = load_environment()
    unmapped_text = load_unmapped_rules()

    # ── Generate findings.md ─────────────────────────────────────────
    with open(FINDINGS_MD, "w") as f:
        f.write("# Scanner Comparison Benchmark Results\n\n")
        f.write(f"Generated: {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

        # Test environment
        f.write("## 1. Test Environment\n\n")
        f.write("```\n")
        f.write(env_text)
        f.write("```\n\n")

        # Summary: findings per scanner
        f.write("## 2. Findings Count (per scanner × repo × mode)\n\n")
        f.write("Values shown for warm cache runs (cold fallback if warm unavailable).\n\n")
        f.write(build_findings_table(rows))
        f.write("\n\n")

        # Performance: wall time + throughput
        f.write("## 3. Performance (wall time + throughput)\n\n")
        f.write(build_performance_table(rows))
        f.write("\n\n")

        # Speedup summary
        f.write("## 4. Speedup Summary (warm git mode, scanner-rs as baseline)\n\n")
        f.write("Values show how many times slower each competitor is vs scanner-rs.\n\n")
        f.write(build_speedup_summary(rows))
        f.write("\n\n")

        # Memory
        f.write("## 5. Peak Memory Usage\n\n")
        f.write("Maximum resident set size across all modes and cache states.\n\n")
        f.write(build_memory_table(rows))
        f.write("\n\n")

        # Rule coverage notes
        f.write("## 6. Rule Coverage Notes\n\n")
        f.write("```\n")
        f.write(unmapped_text)
        f.write("\n```\n\n")

        # Notes
        f.write("## 7. Notes\n\n")
        f.write("- **Cold cache**: `sync && echo 3 > /proc/sys/vm/drop_caches` + 2s settle\n")
        f.write("- **Warm cache**: throwaway run first, then measured second run\n")
        f.write("- **Offline validation only**: no live HTTP checks for any scanner\n")
        f.write("- **Archive scanning**: enabled for all scanners\n")
        f.write("- **Decode depth**: 2 for scanner-rs/Gitleaks, default for Kingfisher/TruffleHog\n")
        f.write("- **Kingfisher**: runs with all 277 default rules (superset of scanner-rs)\n")
        f.write("- **TruffleHog**: filtered to matched detectors via `--include-detectors`\n")
        f.write("- **Gitleaks**: custom TOML config with only scanner-rs-matched rules\n")

    print(f"\nWrote {FINDINGS_MD}")


if __name__ == "__main__":
    main()
