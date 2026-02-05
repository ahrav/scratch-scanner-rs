# Design: Git Scan Fallback Without On-Disk Commit-Graph or MIDX

## Status
Draft

## Problem Statement
Our Git scan pipeline hard-requires on-disk `commit-graph` and `multi-pack-index` artifacts. In environments where Git maintenance cannot be run or those files are missing, the scan returns `NeedsMaintenance` and never runs. We need a read-only fallback that still produces deterministic results and compatible persistence output.

## Goals
- Run a full-history Git scan without `commit-graph` or MIDX.
- Preserve deterministic output for identical repo state and config.
- Preserve `FinalizeOutput` schema and persistence behavior.
- Maintain `(watermark, tip]` semantics when watermarks are present and valid.
- Bound memory and IO with explicit limits similar to the current pipeline.

## Non-Goals
- Matching the throughput of the current pack-planned execution path.
- Avoiding all new dependencies if they materially reduce implementation time.
- Supporting partial or incremental scans beyond current watermark semantics.

## Background and Current Constraints
- `RunContext.commit_id` encodes a commit-graph position and is used in spill ordering and finalize (`src/git_scan/run_format.rs`, `src/git_scan/finalize.rs`).
- Commit traversal uses generation numbers for pruning and deterministic ordering (`src/git_scan/commit_walk.rs`).
- Object lookup for tree and blob data relies on MIDX for OID -> pack offset resolution (`src/git_scan/object_store.rs`, `src/git_scan/mapping_bridge.rs`, `src/git_scan/pack_candidates.rs`, `src/git_scan/pack_plan.rs`, `src/git_scan/pack_io.rs`).

The fallback must reintroduce these semantics without the on-disk artifacts.

## Proposed Approach
Add a new fallback scan mode that is activated when artifacts are missing and a policy flag is enabled. The fallback builds an in-memory commit order, first-seen blob attribution, and uses a non-MIDX object loader to decode blobs directly.

## High-Level Data Flow
1. Resolve repo paths, object format, start set, and watermarks without requiring commit-graph or MIDX.
2. Enumerate reachable commits and build a stable topological order with generation numbers.
3. Traverse trees to discover first-seen blobs and a representative path per blob.
4. Load blob bytes directly from pack or loose objects without MIDX.
5. Scan blobs via `EngineAdapter` and build `FinalizeOutput` with deterministic ordering.

## Key Design Decisions
### Commit ID Semantics
`RunContext.commit_id` must remain deterministic. The fallback assigns commit positions using a stable topological order with a deterministic tie-breaker (commit OID lexicographic order). This mapping must be stable across runs for identical repo state.

### Watermark Semantics
Watermarks are stored by commit OID. The fallback reuses the same `(watermark, tip]` semantics by computing ancestry in the in-memory commit graph and honoring watermarks only when they are valid ancestors.

### Object Loading Strategy
Two implementation variants are viable.
- Variant A uses `gix` ODB APIs to enumerate and decode objects.
- Variant B parses pack `.idx` files and reuses existing pack decode primitives to load objects by offset.

Variant A is faster to implement but introduces a new dependency and potentially different decode behavior. Variant B is closer to the current decode path but requires new index parsing logic.

### Determinism Guarantees
- Commit order: stable topo sort with deterministic tie-breaks.
- Tree traversal: use existing Git tree ordering logic to match current semantics.
- Candidate ordering: preserve the same OID and path ordering rules as the current pipeline.

## New or Modified Components
- `GitScanMode::OdbFallback` and config flag to enable fallback on missing artifacts.
- Repo open path that skips artifact mmaps while still resolving start set and watermarks.
- `odb_enumerator` module to build commit order and first-seen blob list.
- `odb_object_loader` module to decode commits, trees, and blobs without MIDX.
- Runner branch that integrates fallback enumeration, scanning, and finalize.
- Metrics additions in `GitScanStageNanos` for fallback stages.

## Error Handling and Limits
- Enforce bounded file reads for `.git`, `commondir`, and `alternates` as today.
- Enforce max object size limits for tree and blob inflations.
- Treat missing or corrupt objects as explicit skips and mark `FinalizeOutcome::Partial` when appropriate.

## Performance Expectations
- Lower throughput than current pack-planned execution due to less sequential IO.
- Comparable to ODB enumerators like Kingfisher depending on decode implementation.

## Risks and Mitigations
- Risk: nondeterministic commit ordering breaks spill output.
Mitigation: stable topo order with deterministic tie-breaks and explicit tests.
- Risk: attribution mismatch vs current ODB-blob path.
Mitigation: reuse existing first-seen semantics and tree traversal ordering rules.
- Risk: regressions for watermark-based incremental semantics.
Mitigation: reuse `CommitPlanIter` ancestry logic against the in-memory graph.

## Testing Plan
- Integration tests comparing fallback findings vs current ODB-blob mode on small repos.
- Determinism tests for stable ordering across runs.
- Edge-case tests for corrupt loose objects, missing packs, and alternates.
- Performance benchmarks on a representative repo to quantify throughput delta.

## Rollout Plan
1. Land fallback behind a feature flag or config toggle.
2. Add metrics to compare fallback and current mode on the same repos.
3. Expand usage only after correctness parity tests pass.

## Open Questions
1. Should fallback be automatic when artifacts are missing, or opt-in only?
2. Is adding `gix` acceptable, or do we prefer a custom `.idx` parser?
3. What is the precise deterministic tie-break rule for topo ordering?
4. Is full-history scan acceptable when watermark ancestry cannot be validated?
