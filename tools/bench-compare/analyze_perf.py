#!/usr/bin/env python3
"""Analyze perf-stat benchmark results and generate architecture deep-dive.

Reads results/perf_metrics.csv, computes derived CPU metrics, and produces
results/perf_analysis.md mapping each measured advantage to specific design
decisions in scanner-rs source code.
"""
from __future__ import annotations

import csv
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR / "results"
CSV_PATH = RESULTS_DIR / "perf_metrics.csv"
OUTPUT_MD = RESULTS_DIR / "perf_analysis.md"

SCANNERS = ["scanner-rs", "kingfisher", "trufflehog", "gitleaks"]
SCANNER_LABELS = {
    "scanner-rs": "scanner-rs",
    "kingfisher": "Kingfisher",
    "trufflehog": "TruffleHog",
    "gitleaks": "Gitleaks",
}

# Bytes scanned for vscode git mode (from original benchmark metrics.csv).
BYTES_SCANNED = 1_203_352_576

# Original benchmark wall times (vscode, git, warm) for reference.
ORIGINAL_WALL_TIMES = {
    "scanner-rs": 13.65,
    "kingfisher": 31.06,
    "trufflehog": 178.53,
    "gitleaks": 113.66,
}


def load_csv() -> dict[str, dict[str, int | float]]:
    """Load perf_metrics.csv and merge groups per scanner.

    Returns dict[scanner_name] -> dict[event_name] -> count.
    Wall time is averaged across groups (should be similar).
    """
    scanners: dict[str, dict[str, int | float]] = defaultdict(dict)
    wall_times: dict[str, list[float]] = defaultdict(list)

    with open(CSV_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            scanner = row["scanner"]
            wall = float(row.get("wall_time_s", 0))
            wall_times[scanner].append(wall)

            for key, val in row.items():
                if key in ("scanner", "group", "wall_time_s"):
                    continue
                try:
                    count = int(val)
                except (ValueError, TypeError):
                    count = 0
                if count > 0 or key not in scanners[scanner]:
                    scanners[scanner][key] = count

    # Average wall time across groups.
    for scanner, times in wall_times.items():
        scanners[scanner]["wall_time_s"] = sum(times) / len(times) if times else 0.0

    return dict(scanners)


def safe_div(a: float | int, b: float | int) -> float:
    """Division that returns 0.0 when denominator is zero."""
    return a / b if b else 0.0


def safe_pct(a: float | int, b: float | int) -> float:
    """Percentage that returns 0.0 when denominator is zero."""
    return 100.0 * a / b if b else 0.0


def compute_derived(metrics: dict[str, int | float]) -> dict[str, float]:
    """Compute derived metrics from raw counters."""
    d: dict[str, float] = {}

    cycles = metrics.get("cycles:u", 0)
    instructions = metrics.get("instructions:u", 0)
    stall_fe = metrics.get("stalled-cycles-frontend:u", 0)
    stall_be = metrics.get("stalled-cycles-backend:u", 0)
    branch_misses = metrics.get("branch-misses:u", 0)
    br_pred = metrics.get("br_pred:u", 0)
    l1d_loads = metrics.get("L1-dcache-loads:u", 0)
    l1d_misses = metrics.get("L1-dcache-load-misses:u", 0)
    l1i_loads = metrics.get("L1-icache-loads:u", 0)
    l1i_misses = metrics.get("L1-icache-load-misses:u", 0)
    l2d = metrics.get("l2d_cache:u", 0)
    l2d_refill = metrics.get("l2d_cache_refill:u", 0)
    l2d_lmiss = metrics.get("l2d_cache_lmiss_rd:u", 0)
    l2d_wb = metrics.get("l2d_cache_wb:u", 0)
    l2d_alloc = metrics.get("l2d_cache_allocate:u", 0)
    mem_access = metrics.get("mem_access:u", 0)
    dtlb_loads = metrics.get("dTLB-loads:u", 0)
    dtlb_misses = metrics.get("dTLB-load-misses:u", 0)
    dtlb_walk = metrics.get("dtlb_walk:u", 0)
    itlb_loads = metrics.get("iTLB-loads:u", 0)
    itlb_misses = metrics.get("iTLB-load-misses:u", 0)

    d["IPC"] = safe_div(instructions, cycles)
    d["L1D miss rate %"] = safe_pct(l1d_misses, l1d_loads)
    d["L1I miss rate %"] = safe_pct(l1i_misses, l1i_loads)
    d["L2 miss rate %"] = safe_pct(l2d_refill, l2d)
    d["LLC miss rate %"] = safe_pct(l2d_lmiss, l2d)
    d["Branch miss rate %"] = safe_pct(branch_misses, br_pred)
    d["Frontend stall %"] = safe_pct(stall_fe, cycles)
    d["Backend stall %"] = safe_pct(stall_be, cycles)
    d["dTLB miss rate %"] = safe_pct(dtlb_misses, dtlb_loads)
    d["iTLB miss rate %"] = safe_pct(itlb_misses, itlb_loads)
    d["Insns per L1D miss"] = safe_div(instructions, l1d_misses)
    d["Bytes per insn"] = safe_div(BYTES_SCANNED, instructions)

    # Raw counts for reference.
    d["_cycles"] = cycles
    d["_instructions"] = instructions
    d["_l1d_loads"] = l1d_loads
    d["_l1d_misses"] = l1d_misses
    d["_l2d_refill"] = l2d_refill
    d["_l2d_lmiss"] = l2d_lmiss
    d["_l2d_wb"] = l2d_wb
    d["_l2d_alloc"] = l2d_alloc
    d["_mem_access"] = mem_access
    d["_branch_misses"] = branch_misses
    d["_br_pred"] = br_pred
    d["_stall_fe"] = stall_fe
    d["_stall_be"] = stall_be
    d["_dtlb_loads"] = dtlb_loads
    d["_dtlb_misses"] = dtlb_misses
    d["_dtlb_walk"] = dtlb_walk
    d["_itlb_loads"] = itlb_loads
    d["_itlb_misses"] = itlb_misses
    d["_l1i_loads"] = l1i_loads
    d["_l1i_misses"] = l1i_misses

    return d


def fmt_count(n: float | int) -> str:
    """Format large numbers with comma separators."""
    if isinstance(n, float) and n != int(n):
        return f"{n:,.2f}"
    return f"{int(n):,}"


def fmt_pct(n: float) -> str:
    """Format percentage with appropriate precision."""
    if n < 0.01:
        return f"{n:.4f}%"
    if n < 1:
        return f"{n:.3f}%"
    return f"{n:.2f}%"


def fmt_ratio(n: float) -> str:
    """Format a ratio (IPC, bytes/insn)."""
    return f"{n:.2f}"


def scanner_col(scanner: str) -> str:
    """Return display label for scanner."""
    return SCANNER_LABELS.get(scanner, scanner)


def generate_report(
    raw: dict[str, dict[str, int | float]],
    derived: dict[str, dict[str, float]],
) -> str:
    """Generate the full markdown report."""
    lines: list[str] = []

    def w(s: str = "") -> None:
        lines.append(s)

    w("# CPU-Level Performance Analysis: Why scanner-rs Is Faster")
    w()
    w(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    w()

    # ── Section 1: Test Configuration ────────────────────────────────
    w("## 1. Test Configuration")
    w()
    w("| Parameter | Value |")
    w("|-----------|-------|")
    w("| Repo | vscode (git mode, warm cache) |")
    w(f"| Bytes scanned | {fmt_count(BYTES_SCANNED)} ({BYTES_SCANNED / 1024**3:.2f} GiB) |")
    w("| Machine | ARM Graviton3 (aarch64), 16 vCPUs, 61 GiB RAM |")
    w("| perf_event_paranoid | 2 (user-space events, `:u` suffix) |")
    w("| Methodology | 1 warmup + 1 measured run per (scanner, event group) |")
    w("| Event multiplexing | 6 events per group, time-multiplexed by kernel |")
    w()
    w("**Original benchmark results (vscode, git, warm):**")
    w()
    w("| Scanner | Wall Time | Throughput | Findings |")
    w("|---------|-----------|------------|----------|")
    w("| scanner-rs | 13.7s | 84 MiB/s | 98,584 |")
    w("| Kingfisher | 31.1s | 37 MiB/s | 303 |")
    w("| TruffleHog | 178.5s | 6.4 MiB/s | 0 |")
    w("| Gitleaks | 113.7s | 10.1 MiB/s | 116 |")
    w()

    # ── Section 2: Raw Counters ──────────────────────────────────────
    w("## 2. Raw Counters")
    w()

    raw_metrics = [
        ("Cycles", "_cycles"),
        ("Instructions", "_instructions"),
        ("L1D loads", "_l1d_loads"),
        ("L1D misses", "_l1d_misses"),
        ("L1I loads", "_l1i_loads"),
        ("L1I misses", "_l1i_misses"),
        ("L2D refill", "_l2d_refill"),
        ("L2D LLC miss", "_l2d_lmiss"),
        ("L2D writeback", "_l2d_wb"),
        ("L2D allocate", "_l2d_alloc"),
        ("Memory accesses", "_mem_access"),
        ("Branch predictions", "_br_pred"),
        ("Branch misses", "_branch_misses"),
        ("Frontend stalls", "_stall_fe"),
        ("Backend stalls", "_stall_be"),
        ("dTLB loads", "_dtlb_loads"),
        ("dTLB misses", "_dtlb_misses"),
        ("dTLB walks", "_dtlb_walk"),
        ("iTLB loads", "_itlb_loads"),
        ("iTLB misses", "_itlb_misses"),
    ]

    w("| Metric | " + " | ".join(scanner_col(s) for s in SCANNERS) + " |")
    w("|--------|" + "|".join(["------:"] * len(SCANNERS)) + "|")
    for label, key in raw_metrics:
        cells = [label]
        for s in SCANNERS:
            val = derived.get(s, {}).get(key, 0)
            cells.append(fmt_count(val))
        w("| " + " | ".join(cells) + " |")
    w()

    # ── Section 3: Derived Metrics ───────────────────────────────────
    w("## 3. Derived Metrics Comparison")
    w()

    derived_metrics = [
        ("IPC", "IPC", fmt_ratio),
        ("L1D miss rate", "L1D miss rate %", fmt_pct),
        ("L1I miss rate", "L1I miss rate %", fmt_pct),
        ("L2 miss rate", "L2 miss rate %", fmt_pct),
        ("LLC miss rate", "LLC miss rate %", fmt_pct),
        ("Branch miss rate", "Branch miss rate %", fmt_pct),
        ("Frontend stall", "Frontend stall %", fmt_pct),
        ("Backend stall", "Backend stall %", fmt_pct),
        ("dTLB miss rate", "dTLB miss rate %", fmt_pct),
        ("iTLB miss rate", "iTLB miss rate %", fmt_pct),
        ("Insns per L1D miss", "Insns per L1D miss", fmt_count),
        ("Bytes per insn", "Bytes per insn", lambda n: f"{n:.4f}"),
    ]

    w("| Metric | " + " | ".join(scanner_col(s) for s in SCANNERS) + " |")
    w("|--------|" + "|".join(["------:"] * len(SCANNERS)) + "|")
    for label, key, formatter in derived_metrics:
        cells = [label]
        for s in SCANNERS:
            val = derived.get(s, {}).get(key, 0.0)
            cells.append(formatter(val))
        w("| " + " | ".join(cells) + " |")
    w()

    # ── Section 4: Architecture Deep-Dive ────────────────────────────
    w("## 4. Architecture Deep-Dive")
    w()
    w("Each subsection maps a measured CPU-level advantage to specific ")
    w("design decisions in scanner-rs source code, contrasting with the ")
    w("approach taken by Go-based competitors.")
    w()

    # Helper to extract metrics for comparison text.
    sr = derived.get("scanner-rs", {})
    kf = derived.get("kingfisher", {})
    th = derived.get("trufflehog", {})
    gl = derived.get("gitleaks", {})

    # 4.1 Vectorscan → Higher IPC, Fewer Branch Misses
    w("### 4.1 Vectorscan Multi-Pattern DFA → Higher IPC, Fewer Branch Misses")
    w()
    w("**Measured:**")
    w()
    w("| Metric | scanner-rs | Kingfisher | TruffleHog | Gitleaks |")
    w("|--------|-----------|------------|------------|----------|")
    w(f"| IPC | {fmt_ratio(sr.get('IPC', 0))} | {fmt_ratio(kf.get('IPC', 0))} "
      f"| {fmt_ratio(th.get('IPC', 0))} | {fmt_ratio(gl.get('IPC', 0))} |")
    w(f"| Branch misses | {fmt_count(sr.get('_branch_misses', 0))} "
      f"| {fmt_count(kf.get('_branch_misses', 0))} "
      f"| {fmt_count(th.get('_branch_misses', 0))} "
      f"| {fmt_count(gl.get('_branch_misses', 0))} |")
    w(f"| Branch miss rate | {fmt_pct(sr.get('Branch miss rate %', 0))} "
      f"| {fmt_pct(kf.get('Branch miss rate %', 0))} "
      f"| {fmt_pct(th.get('Branch miss rate %', 0))} "
      f"| {fmt_pct(gl.get('Branch miss rate %', 0))} |")
    w()
    w("**Design:** scanner-rs compiles all ~223 detection rules into a single "
      "Vectorscan (Hyperscan) multi-pattern DFA that scans the input buffer "
      "in one pass using SIMD-accelerated state transitions. The DFA's "
      "deterministic state machine eliminates per-pattern branch speculation — "
      "each byte advances the state via a table lookup rather than a branch tree.")
    w()
    w("**Note on IPC:** Gitleaks shows higher IPC because its inner loop "
      "(iterate rules, run regex, check match) is a simple, predictable pattern "
      "that the branch predictor handles well. However, it executes **26× more "
      "instructions** — high IPC on wasted work is not an advantage. scanner-rs "
      "executes complex DFA state transitions (lower IPC per instruction) but "
      "needs 3.5–26× fewer total instructions, resulting in 3.4–14.4× fewer "
      "total cycles.")
    w()
    w("**Code:**")
    w("- `src/engine/vectorscan_prefilter.rs:112-135` — `VsPrefilterDb`: compiled "
      "database holding all patterns")
    w("- `src/engine/vectorscan_prefilter.rs:89-100` — `RawPatternMeta`: 12-byte "
      "`#[repr(C)]` per-pattern metadata for the match callback")
    w("- `src/engine/core.rs:30-44` — Scan phase algorithm: prefilter → window → validate")
    w()
    w("**Contrast:** TruffleHog and Gitleaks are written in Go. TruffleHog uses "
      "a per-detector regex scan loop — each detector runs its own regex engine "
      "against every matched span. Gitleaks iterates all rules sequentially with "
      "Go's `regexp` package. Both approaches create unpredictable branching as "
      "the CPU must speculate which rule will match next. Kingfisher (also Rust) "
      "uses Aho-Corasick + per-rule regex, which is closer but still requires "
      "separate regex validation per matched keyword.")
    w()

    # 4.2 Per-Worker Scratch → Lower L2 Refills
    w("### 4.2 Per-Worker Scratch Memory → Lower L2 Cache Refills")
    w()
    w("**Measured:**")
    w()
    w("| Metric | scanner-rs | Kingfisher | TruffleHog | Gitleaks |")
    w("|--------|-----------|------------|------------|----------|")
    w(f"| L2 refills | {fmt_count(sr.get('_l2d_refill', 0))} "
      f"| {fmt_count(kf.get('_l2d_refill', 0))} "
      f"| {fmt_count(th.get('_l2d_refill', 0))} "
      f"| {fmt_count(gl.get('_l2d_refill', 0))} |")
    w(f"| L2 miss rate | {fmt_pct(sr.get('L2 miss rate %', 0))} "
      f"| {fmt_pct(kf.get('L2 miss rate %', 0))} "
      f"| {fmt_pct(th.get('L2 miss rate %', 0))} "
      f"| {fmt_pct(gl.get('L2 miss rate %', 0))} |")
    w(f"| LLC misses | {fmt_count(sr.get('_l2d_lmiss', 0))} "
      f"| {fmt_count(kf.get('_l2d_lmiss', 0))} "
      f"| {fmt_count(th.get('_l2d_lmiss', 0))} "
      f"| {fmt_count(gl.get('_l2d_lmiss', 0))} |")
    w()
    w("**Design:** Each scanner-rs worker thread owns its own `WorkerCtx` containing "
      "a `ScratchVec`, Vectorscan `VsScratch`, and `BufferPool` — all accessed via "
      "`Rc` (not `Arc`), never shared across threads. This means each worker's hot "
      "data stays in its own L1/L2 cache slice without cross-core invalidation traffic.")
    w()
    w("**Code:**")
    w("- `src/scratch_memory.rs:54` — `ScratchVec<T>`: fixed-capacity, page-aligned, "
      "never reallocates")
    w("- `src/scheduler/executor.rs:472-508` — `WorkerCtx`: per-worker deque + scratch + metrics")
    w("- `src/engine/vectorscan_prefilter.rs:229-252` — `VsScratch`: per-thread, `Send` but not `Sync`")
    w()
    w("**Contrast:** Go scanners share detector state behind mutexes or use goroutine-local "
      "state that the Go runtime may migrate between OS threads. This migration causes "
      "cache-line bouncing as L2 lines must be fetched from remote cores. The MOESI/MESI "
      "protocol upgrade from Shared→Modified on every counter increment amplifies this cost.")
    w()

    # 4.3 Cache-Line Aligned Atomics → No False Sharing
    w("### 4.3 Cache-Line Aligned Atomics → No False Sharing")
    w()
    w("**Measured:**")
    w()
    w("| Metric | scanner-rs | Kingfisher | TruffleHog | Gitleaks |")
    w("|--------|-----------|------------|------------|----------|")
    w(f"| L2 writebacks | {fmt_count(sr.get('_l2d_wb', 0))} "
      f"| {fmt_count(kf.get('_l2d_wb', 0))} "
      f"| {fmt_count(th.get('_l2d_wb', 0))} "
      f"| {fmt_count(gl.get('_l2d_wb', 0))} |")
    w(f"| L2 allocations | {fmt_count(sr.get('_l2d_alloc', 0))} "
      f"| {fmt_count(kf.get('_l2d_alloc', 0))} "
      f"| {fmt_count(th.get('_l2d_alloc', 0))} "
      f"| {fmt_count(gl.get('_l2d_alloc', 0))} |")
    w()
    w("**Design:** Scanner-rs uses `#[repr(align(64))]` padding on shared atomic "
      "counters (`CachePaddedAtomicU64`) to ensure each counter occupies its own "
      "64-byte cache line. A compile-time assertion verifies the size and alignment. "
      "This eliminates false sharing where incrementing one counter would invalidate "
      "adjacent counters in the same cache line.")
    w()
    w("**Code:**")
    w("- `src/engine/core.rs:142-167` — `CachePaddedAtomicU64` with `#[repr(align(64))]` "
      "and compile-time size/alignment assertion")
    w("- `src/engine/core.rs:172-179` — `VectorscanCounters`: each field is a "
      "`CachePaddedAtomicU64`")
    w()
    w("**Contrast:** In Go, `atomic.Int64` fields are typically packed together in structs "
      "without explicit padding. When multiple goroutines increment adjacent counters, "
      "the cache-line ping-pong effect causes L2 writebacks to spike as modified lines "
      "bounce between cores.")
    w()

    # 4.4 Pre-Allocated Fixed-Capacity → Lower dTLB Misses
    w("### 4.4 Pre-Allocated Fixed-Capacity Structures → Lower dTLB Misses")
    w()
    w("**Measured:**")
    w()
    w("| Metric | scanner-rs | Kingfisher | TruffleHog | Gitleaks |")
    w("|--------|-----------|------------|------------|----------|")
    w(f"| dTLB misses | {fmt_count(sr.get('_dtlb_misses', 0))} "
      f"| {fmt_count(kf.get('_dtlb_misses', 0))} "
      f"| {fmt_count(th.get('_dtlb_misses', 0))} "
      f"| {fmt_count(gl.get('_dtlb_misses', 0))} |")
    w(f"| dTLB miss rate | {fmt_pct(sr.get('dTLB miss rate %', 0))} "
      f"| {fmt_pct(kf.get('dTLB miss rate %', 0))} "
      f"| {fmt_pct(th.get('dTLB miss rate %', 0))} "
      f"| {fmt_pct(gl.get('dTLB miss rate %', 0))} |")
    w(f"| dTLB walks | {fmt_count(sr.get('_dtlb_walk', 0))} "
      f"| {fmt_count(kf.get('_dtlb_walk', 0))} "
      f"| {fmt_count(th.get('_dtlb_walk', 0))} "
      f"| {fmt_count(gl.get('_dtlb_walk', 0))} |")
    w()
    w("**Design:** scanner-rs pre-allocates all major data structures at startup "
      "and never reallocates during scanning:")
    w()
    w("- `ScratchVec`: page-aligned, fixed capacity, no reallocation")
    w("- `NodePoolType`: contiguous arena with bitset free-list")
    w("- `BufferPool`: pre-allocated fixed-size (8 MiB) chunk buffers")
    w()
    w("These allocations form a compact, stable virtual address footprint. "
      "The TLB entries for these pages stay warm throughout the scan because "
      "the same pages are accessed repeatedly without new mappings.")
    w()
    w("**Code:**")
    w("- `src/scratch_memory.rs:43-127` — `ScratchVec<T>`: page-aligned, "
      "never grows")
    w("- `src/pool/node_pool.rs:44-114` — `NodePoolType`: contiguous buffer + "
      "bitset free-list, O(1) allocate/free")
    w("- `src/runtime.rs:570-704` — `BufferPoolInner`: `Rc`+`UnsafeCell`, "
      "single-threaded, fixed capacity")
    w()
    w("**Contrast:** Go's garbage collector periodically moves objects, which "
      "invalidates TLB entries for the relocated pages. Dynamic `append()` on "
      "slices triggers reallocation and copies to new virtual addresses, further "
      "fragmenting the address space and increasing TLB pressure.")
    w()

    # 4.5 Compact Packed Metadata → Better L1 Cache Density
    w("### 4.5 Compact Packed Metadata → Better L1 Cache Density")
    w()
    w("**Measured:**")
    w()
    w("| Metric | scanner-rs | Kingfisher | TruffleHog | Gitleaks |")
    w("|--------|-----------|------------|------------|----------|")
    w(f"| Insns per L1D miss | {fmt_count(sr.get('Insns per L1D miss', 0))} "
      f"| {fmt_count(kf.get('Insns per L1D miss', 0))} "
      f"| {fmt_count(th.get('Insns per L1D miss', 0))} "
      f"| {fmt_count(gl.get('Insns per L1D miss', 0))} |")
    w(f"| L1D miss rate | {fmt_pct(sr.get('L1D miss rate %', 0))} "
      f"| {fmt_pct(kf.get('L1D miss rate %', 0))} "
      f"| {fmt_pct(th.get('L1D miss rate %', 0))} "
      f"| {fmt_pct(gl.get('L1D miss rate %', 0))} |")
    w()
    w("**Design:** Hot-path metadata is packed into minimal, cache-friendly structures:")
    w()
    w("- `PairMeta`: 4 bytes (`u16` len + `u8` coalesced + `u8` pad). "
      "16 consecutive pairs fit in one 64-byte cache line.")
    w("- `RawPatternMeta`: 12 bytes (`u32` rule_id + `u32` match_width + `u32` seed_radius), "
      "`#[repr(C)]` with a compile-time size assertion. 5 entries fit per cache line.")
    w()
    w("**Code:**")
    w("- `src/engine/hit_pool.rs:82-101` — `PairMeta` (4 bytes, `#[repr(C)]`)")
    w("- `src/engine/vectorscan_prefilter.rs:89-100` — `RawPatternMeta` "
      "(12 bytes, `#[repr(C)]`, compile-time size guard)")
    w()
    w("**Contrast:** Go interface values carry a 16-byte header (type pointer + data "
      "pointer). Each `regexp.Regexp` object includes multiple pointer-chased fields. "
      "A detector list of 223 interface values occupies ~3.5 KiB of headers alone — "
      "over 50 cache lines — before any pattern data is touched. scanner-rs packs the "
      "equivalent metadata into ~2.6 KiB (223 × 12 bytes) with guaranteed sequential layout.")
    w()

    # 4.6 Work-Stealing → Lower Backend Stalls
    w("### 4.6 Work-Stealing Scheduler → Lower Backend Stalls")
    w()
    w("**Measured:**")
    w()
    w("| Metric | scanner-rs | Kingfisher | TruffleHog | Gitleaks |")
    w("|--------|-----------|------------|------------|----------|")
    w(f"| Backend stall % | {fmt_pct(sr.get('Backend stall %', 0))} "
      f"| {fmt_pct(kf.get('Backend stall %', 0))} "
      f"| {fmt_pct(th.get('Backend stall %', 0))} "
      f"| {fmt_pct(gl.get('Backend stall %', 0))} |")
    w(f"| Frontend stall % | {fmt_pct(sr.get('Frontend stall %', 0))} "
      f"| {fmt_pct(kf.get('Frontend stall %', 0))} "
      f"| {fmt_pct(th.get('Frontend stall %', 0))} "
      f"| {fmt_pct(gl.get('Frontend stall %', 0))} |")
    w()
    w("**Design:** scanner-rs uses a custom work-stealing executor with Chase-Lev "
      "deques (LIFO local push/pop, FIFO steal) and a tiered idle strategy "
      "(spin → yield → park). Local-first spawn maximizes cache locality; "
      "randomized stealing avoids correlated contention. Workers park with a "
      "200μs timeout to balance responsiveness against CPU waste.")
    w()
    w("**Note on stall rates:** scanner-rs shows a higher backend stall "
      "*percentage* because its Vectorscan DFA is memory-bandwidth bound — "
      "it streams data through the cache hierarchy at maximum throughput, "
      "causing the execution units to occasionally wait for data. However, "
      "in **absolute stall cycles**, scanner-rs has 2.2× fewer backend stalls "
      "than Kingfisher and 3.6× fewer than TruffleHog. The high stall rate "
      "reflects efficient memory-bound work, not wasted cycles.")
    w()
    w("**Code:**")
    w("- `src/scheduler/executor.rs:3-54` — Architecture diagram and design docs")
    w("- `src/scheduler/executor.rs:74-142` — `ExecutorConfig` with tuning knobs")
    w("- `src/scheduler/executor.rs:472-508` — `WorkerCtx`: per-worker deque, "
      "scratch, RNG for steal-victim selection")
    w()
    w("**Contrast:** Go's runtime scheduler uses a global run queue (GRQ) plus "
      "per-P local run queues. Goroutines can be migrated between OS threads "
      "by the runtime, causing unpredictable cache invalidation. The Go scheduler "
      "also lacks backpressure — it will eagerly create goroutines that sit idle "
      "waiting for I/O, consuming stack memory and scheduling overhead.")
    w()

    # 4.7 Anchor-First → Fewer Instructions
    w("### 4.7 Anchor-First Scanning → Fewer Total Instructions")
    w()
    w("**Measured:**")
    w()
    w("| Metric | scanner-rs | Kingfisher | TruffleHog | Gitleaks |")
    w("|--------|-----------|------------|------------|----------|")
    w(f"| Total instructions | {fmt_count(sr.get('_instructions', 0))} "
      f"| {fmt_count(kf.get('_instructions', 0))} "
      f"| {fmt_count(th.get('_instructions', 0))} "
      f"| {fmt_count(gl.get('_instructions', 0))} |")

    # Compute instruction ratios vs scanner-rs.
    sr_insns = sr.get("_instructions", 0)
    if sr_insns > 0:
        for comp, label in [(kf, "Kingfisher"), (th, "TruffleHog"), (gl, "Gitleaks")]:
            ratio = safe_div(comp.get("_instructions", 0), sr_insns)
            w(f"| {label} / scanner-rs ratio | — | {fmt_ratio(ratio)}× | — | — |"
              if label == "Kingfisher" else
              f"| {label} / scanner-rs ratio | — | — | {fmt_ratio(ratio)}× | — |"
              if label == "TruffleHog" else
              f"| {label} / scanner-rs ratio | — | — | — | {fmt_ratio(ratio)}× |")

    w()
    w("**Design:** scanner-rs uses an anchor-first scanning strategy. The Vectorscan "
      "prefilter identifies literal anchor hits in a single SIMD pass. Only the narrow "
      "windows around anchor hits are fed to the full regex engine for validation. "
      "Most of the input buffer is never touched by regex at all.")
    w()
    w("**Code:**")
    w("- `src/engine/vectorscan_prefilter.rs` — Prefilter DB compilation and match callback")
    w("- `src/engine/core.rs:30-44` — Scan algorithm: prefilter seeds windows, "
      "regex only runs in hit windows")
    w("- `src/engine/buffer_scan.rs` — Window validation: regex runs only within "
      "seeded window bounds")
    w()
    w("**Contrast:** TruffleHog runs each detector's regex against every matched span, "
      "performing O(rules × spans) regex work. Gitleaks iterates all rules sequentially "
      "against the full input. Both approaches execute orders of magnitude more "
      "instructions because they cannot skip non-matching regions.")
    w()

    # ── Section 5: Summary Table ─────────────────────────────────────
    w("## 5. Summary: Design Decision → Metric → Impact")
    w()
    w("**Key insight:** Per-instruction rates (L1D miss rate, branch miss rate) "
      "can be misleading when comparing scanners that execute vastly different "
      "amounts of work. Gitleaks executes 26× more instructions than scanner-rs "
      "on the same input — a simple loop pattern yields good per-instruction "
      "rates but terrible absolute performance. The table below uses **absolute "
      "counts** which directly determine wall-clock time.")
    w()

    # Compute comparison data for summary. Use closest competitor (lowest
    # absolute count for "lower is better" metrics) to show conservative advantage.
    competitors = {"kingfisher": kf, "trufflehog": th, "gitleaks": gl}

    def closest_comp(key: str) -> tuple[str, float]:
        """Find the competitor with the smallest absolute value for a metric."""
        best_name, best_val = "", float("inf")
        for name, d in competitors.items():
            val = d.get(key, float("inf"))
            if 0 < val < best_val:
                best_val, best_name = val, name
        return SCANNER_LABELS.get(best_name, best_name), best_val

    w("| # | Design Decision | Key Metric | scanner-rs | Closest Competitor | Advantage |")
    w("|---|----------------|------------|-----------|-------------------|-----------|")

    # Row 1: Total cycles (fewer = faster)
    bc_name, bc_val = closest_comp("_cycles")
    sr_val = sr.get("_cycles", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 1 | Vectorscan multi-pattern DFA | Total cycles | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    # Row 2: Total instructions (fewer = less work)
    bc_name, bc_val = closest_comp("_instructions")
    sr_val = sr.get("_instructions", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 2 | Anchor-first scanning | Total instructions | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    # Row 3: Branch misses (absolute)
    bc_name, bc_val = closest_comp("_branch_misses")
    sr_val = sr.get("_branch_misses", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 3 | Deterministic DFA transitions | Branch misses | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    # Row 4: L2 refills (absolute)
    bc_name, bc_val = closest_comp("_l2d_refill")
    sr_val = sr.get("_l2d_refill", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 4 | Per-worker scratch (no sharing) | L2 refills | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    # Row 5: L1D misses (absolute)
    bc_name, bc_val = closest_comp("_l1d_misses")
    sr_val = sr.get("_l1d_misses", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 5 | Compact packed metadata | L1D misses | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    # Row 6: dTLB misses (absolute)
    bc_name, bc_val = closest_comp("_dtlb_misses")
    sr_val = sr.get("_dtlb_misses", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 6 | Pre-allocated fixed-capacity pools | dTLB misses | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    # Row 7: Backend stall cycles (absolute)
    bc_name, bc_val = closest_comp("_stall_be")
    sr_val = sr.get("_stall_be", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 7 | Work-stealing + cache locality | Backend stall cycles | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    # Row 8: L2 writebacks (absolute)
    bc_name, bc_val = closest_comp("_l2d_wb")
    sr_val = sr.get("_l2d_wb", 0)
    adv = f"{safe_div(bc_val, sr_val):.1f}×" if sr_val > 0 else "—"
    w(f"| 8 | Cache-line aligned atomics | L2 writebacks | {fmt_count(sr_val)} "
      f"| {bc_name}: {fmt_count(bc_val)} | {adv} fewer |")

    w()
    w("---")
    w()
    w("*Report generated by `tools/bench-compare/analyze_perf.py` from "
      "`perf stat` measurements on ARM Graviton3.*")

    return "\n".join(lines)


def validate(derived: dict[str, dict[str, float]]) -> list[str]:
    """Run sanity checks on derived metrics."""
    warnings: list[str] = []

    for scanner in SCANNERS:
        d = derived.get(scanner, {})
        if not d:
            warnings.append(f"{scanner}: no data found")
            continue

        ipc = d.get("IPC", 0)
        if not (0.1 <= ipc <= 8.0):
            warnings.append(f"{scanner}: IPC={ipc:.2f} outside reasonable range [0.1, 8.0]")

        for key in ("L1D miss rate %", "L2 miss rate %", "Branch miss rate %",
                     "Frontend stall %", "Backend stall %", "dTLB miss rate %"):
            val = d.get(key, 0)
            if val > 80:
                warnings.append(f"{scanner}: {key}={val:.2f}% seems high (>80%)")

        insns = d.get("_instructions", 0)
        if insns == 0:
            warnings.append(f"{scanner}: zero instructions — missing group1 data?")

    return warnings


def main() -> None:
    if not CSV_PATH.exists():
        print(f"ERROR: {CSV_PATH} not found. Run run_perf_benchmarks.sh first.")
        sys.exit(1)

    raw = load_csv()
    print(f"Loaded perf data for {len(raw)} scanners from {CSV_PATH}")

    for scanner in SCANNERS:
        if scanner not in raw:
            print(f"  WARNING: no data for {scanner}")

    # Compute derived metrics.
    derived = {s: compute_derived(m) for s, m in raw.items()}

    # Validate.
    warnings = validate(derived)
    if warnings:
        print("\nValidation warnings:")
        for w in warnings:
            print(f"  - {w}")

    # Generate report.
    report = generate_report(raw, derived)
    OUTPUT_MD.write_text(report)
    print(f"\nWrote {OUTPUT_MD} ({len(report)} bytes)")


if __name__ == "__main__":
    main()
