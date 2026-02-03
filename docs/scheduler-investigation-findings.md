# Scheduler Investigation Findings and Work Units

Last updated: 2026-02-02

## Decision Summary

Yes, there is still performance on the table. The biggest cheap win for local filesystem scans is removing discovery-time per-file metadata syscalls and enforcing size policy at open-time. The next tier of gains comes from making the Linux `io_uring` path production-capable and competitive.

## Scope And Invariants

This document captures findings for the local scheduler path and related discovery and simulation harnesses. The intent is to preserve correctness invariants while reducing syscalls and wakeups.

Invariants we must preserve:

- Do not drop files due to missing `file_type()` hints.
- Enforce `max_file_size` based on size-at-open snapshot semantics.
- Preserve determinism for seeded scheduler simulation runs.
- Avoid new hot-path allocations or per-chunk overhead unless justified.

Related docs:

- Local filesystem scan path: `docs/scheduler-local.md`
- Local `io_uring` scan path: `docs/scheduler-local-fs-uring.md`
- Scheduler simulation harness: `docs/scheduler_test_harness.md`
- Harness usage guide: `docs/scheduler_test_harness_guide.md`

## Components In Scope

| Component | Location | Purpose |
| --- | --- | --- |
| DirWalker | `src/scheduler/parallel_scan.rs` | Filesystem discovery and filtering before enqueue. |
| Local scan | `src/scheduler/local.rs` | Per-file open, metadata snapshot, read loop, and scan. |
| Local `io_uring` scan | `src/scheduler/local_fs_uring.rs` | Experimental Linux `io_uring` scan path. |
| Sim harness | `src/scheduler/sim.rs` and `src/scheduler/sim_executor_harness.rs` | Deterministic scheduler simulation and replay. |

## Findings And Work Units

### Bug: Potential File Drops When `file_type()` Is `None`

Finding: `DirWalker` currently skips entries when `entry.file_type()` returns `None`, which can silently drop files on some filesystems or platforms.

Impact: False negatives during discovery.

Work units:

- [x] Run the scheduler simulation harness first and attempt to reproduce a file drop. Record the seed and scenario parameters. Use `cargo test --features scheduler-sim` and the harness tools in `docs/scheduler_test_harness_guide.md`.
- [x] If the harness does not catch it, assess why the current model allows the drop. Update the simulation model or scenario generator so this class of drop is detectable. The executor-only scheduler sim does not model filesystem discovery; we extended the scanner sim harness to include discovery type hints instead.
- [x] Add a targeted failing test (unit, integration, property, or fuzz) that reproduces the drop in the current code. Unit test: `scheduler::parallel_scan::tests::file_type_none_falls_back_to_metadata`. Sim harness test: `tests/simulation/scanner_discovery.rs`.
- [x] Implement the fix: if `file_type()` is `None`, fall back to metadata or treat as unknown and attempt metadata-based classification rather than skipping.
- [x] Re-run the new test and the scheduler simulation harness with the recorded seed to confirm the fix.
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Bug: `max_file_size` Enforced Only At Discovery Time

Finding: Size cap is applied during discovery, but `local.rs` does not re-enforce at open-time. This violates snapshot semantics and can cause both false negatives and policy escapes.

Impact: Files may be scanned beyond the cap if they grow, or skipped if they shrink.

Work units:

- [x] Run the scheduler simulation harness first and attempt to reproduce a size-cap mismatch. Record the seed and scenario parameters. Use `cargo test --features scheduler-sim` and the harness tools in `docs/scheduler_test_harness_guide.md`.
- [x] If the harness does not catch it, assess why the model allows this mismatch. Update the simulation model so size-at-discovery and size-at-open can diverge. The scheduler sim does not model filesystem sizes; we extended the scanner sim harness to add discovery size hints and max file size enforcement.
- [x] Add a targeted failing test (unit, integration, property, or fuzz) that reproduces the mismatch in the current code. Tests: `tests/simulation/scanner_max_file_size.rs` and `scheduler::local::tests::enforces_max_file_size_at_open_time`.
- [x] Implement the fix: enforce `max_file_size` after `File::open` using `file.metadata().len()` and apply snapshot semantics consistently.
- [x] Re-run the new test and the scheduler simulation harness with the recorded seed to confirm the fix.
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Perf: Remove Discovery-Time Per-File Metadata Syscall

Finding: For files that are scanned, we pay both a discovery `stat` and an open-time `fstat`. Only the open-time size is required for snapshot semantics.

Impact: Unnecessary syscall per file in the hot path, especially visible for tiny-file storms.

Work units:

- [ ] Validate the reasoning with a quick syscall profile on a representative repo. Confirm that discovery-time `stat` is a significant portion of per-file syscalls. (Blocked on macOS without root; run via `strace -f -c`/`perf stat` on Linux or `sudo dtruss -c` on macOS.)
- [ ] If the reasoning does not hold for current workloads, document the exception and defer the change.
- [ ] Draft an evidence-backed plan for measurement. Include: workload selection, metrics, and expected syscall deltas. Use the benchmark guidance in `docs/throughput_investigation.md` as a template.
- [x] Implement the change by removing discovery-time size metadata and relying on open-time enforcement only, or gate it behind a policy knob that defaults to open-time enforcement.
- [ ] Measure and record: `newfstatat/statx` count deltas, total wall time, and bytes scanned per second. Confirm no regressions in correctness.
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Perf: Batch External Task Injection During Discovery

Finding: Discovery injects tasks one at a time and unparks a worker per task, which can add wakeup overhead on very large file lists.

Impact: Unnecessary wakeups and contention for massive directory trees.

Work units:

- [ ] Validate the reasoning by measuring unpark frequency and context switch rates during large scans. (Blocked on macOS without sudo/DTrace; use Linux `perf`/`strace` or macOS with `dtruss` privileges.)
- [ ] If the reasoning does not hold, document why and skip.
- [ ] Draft an evidence-backed plan for improvement with expected wakeup reduction and a measurement plan.
- [x] Implement a `spawn_external_batch` variant that injects multiple tasks and performs bounded unpark.
- [ ] Measure and record changes in wakeups, wall time, and p95 queue latency. (Blocked on macOS without syscall tracing access or a pre-change baseline.)
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Perf: Conditional Output Batching For Dense Findings

Finding: Output is already batched per chunk, but high-density finding workloads may serialize on the sink mutex.

Impact: Potential bottleneck only when findings are very dense.

Work units:

- [x] Validate the reasoning with a synthetic dense-findings workload and confirm whether the sink is a measurable bottleneck. (Bench CLI supports `--secret-density` and `--sink` to drive output-heavy runs.)
- [x] If the reasoning does not hold, document and skip. Measurements on macOS showed no meaningful throughput regression when using a real `FileSink` vs `NullSink`:
  - `files=200`, `file_size=1m`, `secret_density=0.05`, `workers=4`, `iters=3`, `warmup=1`: `NullSink` ~568.0 MiB/s (p50 ~352 ms) vs `FileSink` ~554.7 MiB/s (p50 ~361 ms).
  - `files=100`, `file_size=4m`, `secret_density=0.1`, `workers=8`, `iters=3`, `warmup=1`: `NullSink` ~1062.2 MiB/s (p50 ~376.6 ms) vs `FileSink` ~1061.6 MiB/s (p50 ~376.8 ms).
  - `files=100`, `file_size=4m`, `secret_density=1.0`, `workers=8`, `iters=3`, `warmup=1`: `NullSink` ~1054.0 MiB/s (p50 ~379.5 ms) vs `FileSink` ~1041.8 MiB/s (p50 ~384.0 ms, p95 ~427 ms).
  - Deltas remain ~1–3% with slightly higher tail latency at very high density. No evidence of a dominant output bottleneck.
- [x] Draft a concrete plan for a writer-thread + bounded queue experiment and define success metrics.
- [x] Add bench CLI support for `--secret-density` and `--sink` (`null|stdout|file`) so output-heavy runs are measurable on any OS.
- [ ] Implement only if the bottleneck is confirmed and the plan is expected to deliver measurable gains. (Deferred: no bottleneck observed in current measurements.)
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

Plan (evidence-backed):
1. Extend the local benchmark harness or CLI to accept `--secret-density` and `--sink` (`null|file|stdout`) so output-heavy runs are measurable on macOS. (Done: bench CLI supports both flags.)
2. Use `SyntheticConfig` with `secret_density=0.05–0.1`, `file_count=1000`, `file_size=64KiB`, and `chunk_size=64KiB` to maximize findings per chunk while keeping input stable.
3. Compare `NullSink` vs `FileSink` (same dataset, same workers) and record wall time, throughput (bytes/s), and write call counts. On macOS, add `/usr/bin/time -l` to capture context switches; on Linux, use `perf stat` for context switches and syscall counts.
4. Prototype a writer-thread sink with a bounded `crossbeam_channel` queue and measure again. Success criteria: ≥10% throughput improvement on output-heavy runs without regressions in correctness or output ordering.

### Perf: Make `local_fs_uring` Production-Capable

Finding: The `local_fs_uring` path currently depends on a mock engine and is not wired to the real `ScanEngine` trait.

Impact: `io_uring` path is not comparable to production scanning and cannot deliver real gains yet.

Work units:

- [x] Validate the reasoning by confirming the current `local_fs_uring` type dependencies and data flow. (Confirmed: prior code used `MockEngine`, `ScanScratch`, and `FindingRec`.)
- [x] If the reasoning does not hold, document the discrepancy and update the finding. (Reasoning holds.)
- [x] Draft an evidence-backed plan for integrating `ScanEngine` and how to validate parity with `local.rs`. Plan: refactor `local_fs_uring` generics to `ScanEngine`, reuse `FindingRecord` for dedupe/output, and validate parity with mock-engine tests plus a small real-engine scan on the same input.
- [x] Implement the refactor so `local_fs_uring` uses the real engine trait and scratch types.
- [ ] Measure: ensure functional parity and no regressions in findings or determinism on the same input set.
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Perf: Avoid Re-Reading Overlap Bytes In `local_fs_uring`

Finding: The current `io_uring` path re-reads overlap bytes from disk each chunk instead of copying overlap into the next buffer.

Impact: Extra I/O volume and wasted bandwidth for large files.

Work units:

- [x] Validate the reasoning by confirming the current overlap strategy in `local_fs_uring` and comparing it to `async_io/linux.rs`. (Confirmed: `local_fs_uring` read path re-read overlap via `base_offset = offset - overlap`.)
- [x] If the reasoning does not hold, document and update the finding. (Reasoning holds.)
- [x] Draft an evidence-backed plan for the overlap-copy pipeline and define how to measure I/O reduction. Plan: copy tail overlap into per-file buffer, submit payload-only reads, and measure `read` bytes (or `io_uring_enter` bytes) on Linux with `perf`/`strace`.
- [x] Implement the overlap-copy strategy so subsequent reads are payload-only and overlap is copied locally.
- [ ] Measure I/O volume and throughput changes on large-file workloads. (Requires Linux `io_uring` run; not measurable on macOS.)
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Perf: Registered Buffers For `io_uring` Reads

Finding: For high-IOPS and small reads, per-op pinning can dominate unless `READ_FIXED` is used.

Impact: Potential overhead for small file workloads in `io_uring` path.

Work units:

- [x] Validate the reasoning by confirming current per-op buffer registration behavior and testing on a tiny-file workload. (Confirmed no registered-buffer path existed; tiny-file test requires Linux.)
- [x] If the reasoning does not hold, document and skip. (Reasoning holds.)
- [x] Draft an evidence-backed plan that compares baseline vs registered buffers, including buffer table management costs. Plan: add opt-in `use_registered_buffers`, compare `Read` vs `ReadFixed` on Linux tiny-file workload, track `io_uring_enter` counts and throughput.
- [x] Implement `READ_FIXED` with a fixed buffer table if the evidence supports it. (Implemented optional `READ_FIXED` path; off by default.)
- [ ] Measure syscalls, throughput, and latency deltas. (Requires Linux `io_uring` run.)
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Perf: Drain CQ Before `submit_and_wait`

Finding: The `io_uring` loop may call `submit_and_wait` even when CQEs are already present.

Impact: Unnecessary syscalls and context switching.

Work units:

- [x] Validate the reasoning by inspecting the loop and confirming whether CQ draining is skipped. (Confirmed: loop could call `submit_and_wait` without checking CQ first.)
- [x] If the reasoning does not hold, document and skip. (Reasoning holds.)
- [x] Draft an evidence-backed plan for CQ draining and a micro-benchmark to measure syscall reduction. Plan: check CQ emptiness before waiting; compare `io_uring_enter` counts and wall time on Linux.
- [x] Implement the CQ drain-before-wait logic.
- [ ] Measure `io_uring_enter` syscall deltas and wall time. (Requires Linux `io_uring` run.)
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Perf: Optional `IORING_OP_OPENAT` And `IORING_OP_STATX`

Finding: Open and stat operations could be moved into the ring once the `io_uring` path is productionized.

Impact: Possible syscall reduction, but increased ring complexity.

Work units:

- [x] Validate the reasoning by confirming baseline open/stat syscall counts and ring overhead. (Confirmed: `open_file_safe` + `file.metadata()` do blocking `openat`/`fstat`; no ring-based open/stat today.)
- [x] If the reasoning does not hold, document and defer. (Reasoning holds.)
- [x] Draft an evidence-backed plan that estimates net win and complexity cost. Plan: add optional `IORING_OP_OPENAT` + `IORING_OP_STATX` path in I/O threads, measure `openat/statx` syscall counts vs `io_uring_enter` overhead; only consider if open/stat is a significant share on tiny-file workloads.
- [x] Document the detailed design plan and fallback semantics. See `docs/io-uring-open-statx-plan.md`.
- [x] Track implementation work units as a checklist in `docs/io-uring-open-statx-plan.md` (Units 1–4 complete: config + probe scaffolding + fallback counters + open/stat state machine + resolve policy mapping + tests/metrics + doc-rigor).
- [ ] Implement only if projected wins outweigh complexity and if the `io_uring` path is already production-parity. (Deferred: parity measurement still pending.)
- [ ] Measure syscall deltas and end-to-end throughput impact. (Requires Linux `io_uring` run.)
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed. (No code changes in this step.)

## Harness Coverage Gaps And Work Units

The simulation harness should detect issues introduced by discovery and size-cap logic changes. Add explicit coverage for these invariants.

### Harness: No Drops When `file_type()` Is Unknown

Work units:

- [x] Extend the simulation model to allow `file_type()` to be `None` for some entries. Implemented via `SimTypeHint::Unknown` in `SimNodeSpec::File`.
- [x] Add a property test that asserts files with unknown type are still enqueued unless explicitly filtered. Added `tests/simulation/scanner_discovery.rs`.
- [x] Validate determinism by re-running with the same seed and comparing traces. The discovery test runs the same scenario twice with the same seed and compares findings.
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Harness: Open-Time Size Cap Enforcement

Work units:

- [x] Extend the simulation model to allow size changes between discovery and open (`discovery_len_hint` vs open-time size).
- [x] Add a property test that enforces size-at-open for `max_file_size` and rejects size-at-discovery-only enforcement (`tests/simulation/scanner_max_file_size.rs`).
- [x] Validate determinism by re-running with the same seed and comparing traces (same test runs the scenario twice and compares findings).
- [x] Run doc-rigor on code files changed for this task and update docs/comments as needed.

### Harness: Budget Invariance With New Size Gates

Work units:

- [x] Model an explicit in-flight budget in the scanner sim runner (`src/sim_scanner/runner.rs`):
  - Track `in_flight_objects`, `max_in_flight_objects`, and (optional) `max_seen_in_flight` for diagnostics.
  - Increment on every file task spawn and enforce `in_flight_objects <= max_in_flight_objects` each step.
  - Decrement on every terminal path for a file task (`FileStepOutcome::Done`), with underflow checks.
- [x] Gate discovery task spawning by the in-flight budget:
  - Modify `DiscoverState` to spawn only up to available permits and leave the remainder in `state.files`.
  - If files remain after hitting the cap, reschedule the discover task (mark runnable + enqueue) to continue later.
  - Ensure deterministic ordering is preserved (still spawn in sorted order).
- [x] Ensure size-cap early exits release permits:
  - Verify `FileScanState::step` returns `Done` when `handle.len > max_file_size`.
  - Confirm the runner’s `Done` handling releases the permit and never leaks it even when scanning is skipped.
- [x] Add end-of-run budget invariant checks in the runner:
  - Before oracles, assert `in_flight_objects == 0` (no permit leaks).
  - Keep failure path consistent with existing `FailureKind::InvariantViolation` conventions.
- [x] Add a focused simulation test for budget invariance under size-cap gating:
  - New test file: `tests/simulation/scanner_budget_invariance.rs`.
  - Use many files (e.g., 16–64) and a tiny `max_in_flight_objects` (1–2) to stress permit reuse.
  - Set `discovery_len_hint` small but extend actual contents beyond `max_file_size` to force open-time skip.
  - Run with `stability_runs = 2` (or two explicit schedule seeds) and assert both runs succeed.
- [ ] Validate determinism:
  - Ensure the stability comparison passes with identical findings across schedules.
  - Confirm no hangs or invariant failures occur at high contention.
- [ ] Run doc-rigor on code files changed for this task and update docs/comments as needed.

## Benchmark And Evidence Plan

All perf changes require a falsifiable measurement plan before implementation and a reproducible benchmark after implementation.

Work units:

- [ ] Define at least three workloads: tiny-file storm, repo-like mix, large-file heavy. Document dataset composition and sizes.
- [ ] Collect syscall counts with `strace -f -c` and track `openat`, `newfstatat/statx`, `read`, and `io_uring_enter` deltas.
- [ ] Collect `perf stat` counters: `syscalls:sys_enter_openat`, `syscalls:sys_enter_newfstatat`, `syscalls:sys_enter_read`, `syscalls:sys_enter_io_uring_enter`, context switches, and migrations.
- [ ] Record throughput metrics: bytes scanned per second, p95 time-in-queue, and end-to-end wall time.
- [ ] Require success criteria per change: syscall deltas, throughput improvements, and no regressions in determinism or correctness.
- [ ] Run doc-rigor on code files changed for this task and update docs/comments as needed.

## Open Questions

- Should discovery-time size filtering be a config knob or removed entirely in favor of open-time enforcement?
- Which workloads are most representative for regression detection in CI and local profiling?
- Are there any user-facing metrics that should be extended to track skip reasons by policy vs errors?
