# Git Scanning Pipeline

This document describes the end-to-end Git scanning pipeline and its
deterministic persistence contract.

## Flow Diagram

```mermaid
flowchart LR
    Preflight["Preflight (metadata only)"] --> RepoOpen["Repo Open + Watermarks"]
    RepoOpen --> CommitWalk["Commit Walk"]
    CommitWalk --> TreeDiff["Tree Diff"]
    TreeDiff --> Spill["Spill + Dedupe"]
    Spill --> Mapping["MIDX Mapping"]
    Mapping --> PackPlan["Pack Planning"]
    PackPlan --> PackExec["Pack Decode + Exec"]
    PackExec --> EngineAdapter["Engine Adapter"]
    EngineAdapter --> Finalize["Finalize Ops"]
    Finalize --> Persist["Persist (Data then Watermarks)"]
```

## Pipeline Components

| Component | Location | Purpose |
| --- | --- | --- |
| Preflight | `src/git_scan/preflight.rs` | Metadata-only readiness check for commit-graph and MIDX |
| Repo Open | `src/git_scan/repo_open.rs` | Resolve repo layout, mmap metadata, load start set + watermarks |
| Commit Walk | `src/git_scan/commit_walk.rs` | `(watermark, tip]` traversal and topo ordering |
| Tree Diff | `src/git_scan/tree_diff.rs` | OID-only tree diffs that emit blob candidates |
| Spill + Dedupe | `src/git_scan/spiller.rs` | Global dedupe + seen-blob filtering |
| MIDX Mapping | `src/git_scan/mapping_bridge.rs` | Map unique blobs to pack offsets or loose fallback |
| Pack Planning | `src/git_scan/pack_plan.rs` | Build per-pack decode plans with delta closure |
| Pack Exec | `src/git_scan/pack_exec.rs` | Decode candidates with bounded buffers |
| Engine Adapter | `src/git_scan/engine_adapter.rs` | Overlap-safe chunked scanning with deterministic finding keys |
| Finalize | `src/git_scan/finalize.rs` | Build write ops for blob_ctx, finding, seen_blob, and watermarks |
| Persist | `src/git_scan/persist.rs` | Two-phase persistence (data ops then watermarks) |
| Runner | `src/git_scan/runner.rs` | End-to-end orchestration of all stages |

## Determinism and Safety Invariants

- Preflight and repo open read metadata only; no blob payloads are read before pack decoding.
- Preflight/repo open detect maintenance lock files and capture artifact fingerprints; runner revalidates before pack exec.
- Metadata artifacts are accessed through read-only byte views (mmap-backed in production).
- Preflight reports pack-count maintenance recommendations separately; pack count does not block scans.
- Pack execution mmaps are bounded by explicit pack count and total byte limits.
- Candidate ordering is deterministic and stable across spill boundaries.
- Findings are deduped per blob and stored as `(start, end, rule_id, norm_hash)`.
- No raw secret bytes are persisted; only hashes and metadata are stored.
- Persistence is atomic: data ops and (when complete) watermark ops are committed together.
- Loose candidates are scanned via bounded loose-object decode; non-blob or
  missing loose objects are recorded as explicit skips.
- Any decode skips or missing/corrupt loose objects result in `FinalizeOutcome::Partial`.
- Skipped candidates are reported with explicit reasons; pack exec reports contain detailed decode errors.
- Pack decoding can be driven via a read-at reader for deterministic fault injection.

## Concurrency and Backpressure

Most stages before pack execution (preflight, repo open, commit walk, tree diff,
spill/dedupe, mapping) run **single-threaded**. Blob introduction (ODB-blob
mode) and pack planning/execution introduce parallelism:

- **Blob introduction** (ODB-blob mode only) can run in parallel when
  `blob_intro_workers > 1`. The commit plan is pre-partitioned into
  `~4 × worker_count` chunks. Workers claim chunks via an atomic counter
  (work-stealing pattern), each with its own `ObjectStore` and
  `PackCandidateCollector`. A shared `AtomicSeenSets` (lock-free bitmap)
  ensures each tree/blob is claimed by exactly one worker. Cache budgets
  (tree cache, delta cache, spill arena, packed cap, loose cap, path arena)
  are divided per worker with floor/cap clamping. After all workers finish,
  results are merged and global caps are re-validated.

- **Pack planning** runs on a dedicated thread (`std::thread::scope`) that
  streams `PackPlan` values through a bounded `sync_channel(1)` while the
  main thread consumes and executes plans.
- **Pack execution** shards each plan's candidate indices across
  `pack_exec_workers` threads (default 2) using `shard_ranges()`. Each
  worker owns its own `PackCache` and `EngineAdapter`; results are merged in
  shard order to preserve deterministic output.

There are no in-flight queues between the serial stages; instead, each stage
enforces explicit bounds:

- Spill/dedupe caps (`SpillLimits`) limit candidate count and spill bytes.
- Mapping caps (`MappingBridgeConfig`) bound packed/loose candidate buffers.
- Pack planning limits (`PackPlanConfig`) bound delta expansion worklists.
- Pack execution limits (`PackMmapLimits`, `PackDecodeLimits`) bound mmaps and
  inflate sizes.

## Persistence Contract

Finalize produces two batches:

- `data_ops`: `bc\0` (blob_ctx), `fn\0` (finding), `sb\0` (seen_blob)
- `watermark_ops`: `rw` (ref_watermark)

Persist commits `data_ops` and (when complete) `watermark_ops` in a single
atomic batch. If the run is partial, watermark ops are skipped to avoid
advancing ref tips past unscanned blobs.

## Simulation Harness

The Git simulation harness exercises this pipeline deterministically using a
semantic repo model and optional pack artifacts. It replays `.case.json`
artifacts and supports bounded random runs.

```bash
# Replay Git simulation corpus
cargo test --features sim-harness --test simulation git_scan_corpus

# Run bounded random Git simulations
cargo test --features sim-harness --test simulation git_scan_random
```

Corpus cases live in `tests/corpus/git_scan/*.case.json`. Replay failures emit
artifacts to `tests/failures/` for triage and minimization.

## Related Docs

- `docs/architecture-overview.md`
- `docs/detection-engine.md`
- `docs/git_simulation_harness_guide.md`
