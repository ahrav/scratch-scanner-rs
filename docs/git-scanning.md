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
- Candidate ordering is deterministic and stable across spill boundaries.
- Findings are deduped per blob and stored as `(start, end, rule_id, norm_hash)`.
- No raw secret bytes are persisted; only hashes and metadata are stored.
- Persistence is two-phase: write data ops first and write watermarks only for complete runs.
- Any decode skips or loose-object fallbacks result in `FinalizeOutcome::Partial`.

## Persistence Contract

Finalize produces two batches:

- `data_ops`: `bc\0` (blob_ctx), `fn\0` (finding), `sb\0` (seen_blob)
- `watermark_ops`: `rw` (ref_watermark)

Persist always writes `data_ops` first. If the run is partial, watermark ops
are skipped to avoid advancing ref tips past unscanned blobs.

## Related Docs

- `docs/architecture-overview.md`
- `docs/detection-engine.md`
