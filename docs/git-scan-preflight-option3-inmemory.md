# Design: In-Memory Commit-Graph and MIDX Artifacts

## Status
Draft

## Problem Statement
The current Git scan pipeline hard-requires on-disk `commit-graph` and `multi-pack-index` artifacts. When those files are missing, we do not scan at all. We want to preserve current pipeline semantics and determinism by building in-memory equivalents when disk artifacts are unavailable.

## Goals
- Preserve current pipeline semantics and deterministic ordering.
- Avoid writing to repositories or running Git maintenance in the scan process.
- Reuse existing pack planning, delta closure, and pack execution stages.
- Maintain compatibility with the persistence schema and watermarks.

## Non-Goals
- Eliminating the cost of building commit metadata and pack indices at runtime.
- Guaranteeing the same cold-start performance as when on-disk artifacts exist.
- Changing scan mode defaults without a separate rollout decision.

## Background and Current Constraints
- `RunContext.commit_id` encodes commit-graph positions and is used in spill ordering and finalize (`src/git_scan/run_format.rs`, `src/git_scan/finalize.rs`).
- Commit traversal relies on commit-graph generation numbers (`src/git_scan/commit_walk.rs`).
- MIDX is used across object store, mapping, pack planning, and pack IO for OID -> offset resolution (`src/git_scan/object_store.rs`, `src/git_scan/mapping_bridge.rs`, `src/git_scan/pack_candidates.rs`, `src/git_scan/pack_plan.rs`, `src/git_scan/pack_io.rs`).

The in-memory artifacts must provide identical semantics to these stages.

## Proposed Approach
Introduce an artifact policy in `GitScanConfig` to allow building in-memory equivalents for missing `commit-graph` and MIDX. Refactor MIDX consumers to accept a `MidxLike` trait. Build a real-repo `CommitGraphMem` and in-memory MIDX from pack `.idx` files, then feed them into the existing pipeline unchanged.

## High-Level Data Flow
1. Resolve repo paths, object format, start set, and watermarks as usual.
2. If on-disk artifacts are missing and policy allows, build in-memory commit graph and MIDX.
3. Run the existing pipeline using the in-memory artifacts as providers.

## Artifact Policy
Add an `ArtifactPolicy` enum in `GitScanConfig`.
- `Required` preserves current behavior.
- `BuildInMemory` allows missing artifacts and triggers in-memory construction.

## MIDX Abstraction
Introduce a `MidxLike` trait with the methods used today.
- `pack_count`, `object_count`, `oid_len`.
- `pack_names`, `oid_at`, `offset_at`.
- `find_oid`, `find_oid_sorted`.

Refactor these modules to accept `MidxLike` instead of `MidxView`.
- `src/git_scan/object_store.rs`
- `src/git_scan/mapping_bridge.rs`
- `src/git_scan/pack_candidates.rs`
- `src/git_scan/pack_plan.rs`
- `src/git_scan/pack_io.rs`
- `src/git_scan/runner.rs` and helper functions

Update `OidIndex::from_midx` to accept a generic MIDX provider.

## In-Memory MIDX Builder
Build a `MidxMem` structure from pack `.idx` files.
- Enumerate pack directories using existing helpers (`collect_pack_dirs`, `list_pack_files`).
- Parse v2 `.idx` files and collect `(oid, pack_id, offset)` entries.
- Build a deterministic PNAM list and pack ordering rule.
- Sort OIDs, build fanout table, and build offset table with LOFF support.
- Resolve duplicate OIDs across packs using an explicit tie-break rule.

## Commit Graph Abstraction
Introduce a `CommitGraphMeta` trait that provides `commit_oid`, `root_tree_oid`, and `committer_timestamp`.
- Update `CommitGraphIndex::build` to accept a generic `CommitGraphMeta` implementation.
- Implement `CommitGraphMem` that satisfies the existing `CommitGraph` trait and the new metadata trait.

## Commit Graph Builder
- Enumerate commits reachable from the start set.
- Load commit objects to extract parents, root tree OIDs, and committer timestamps.
- Assign deterministic positions using a stable topological order with tie-break by commit OID.
- Compute generation numbers as `max(parent_gen) + 1` to preserve pruning in `CommitPlanIter`.

## Commit Object Loader
Implement a commit loader using pack and loose object decoding.
- Use the in-memory MIDX to locate pack offsets, or parse `.idx` directly.
- Enforce bounded decode limits to mirror existing tree and blob limits.

## Repo Job State Changes
Extend `RepoJobState` to hold disk-backed or in-memory artifact providers.
- `commit_graph: CommitGraphSource` and `midx: MidxSource` as enums or trait objects.
- `artifacts_unchanged()` should return false or use pack fingerprints when artifacts are in memory.

## Determinism and Compatibility
- Commit positions must be stable across runs for identical repo state.
- Pack ordering must be deterministic across platforms.
- Duplicate OID resolution must be deterministic and documented.
- Downstream stages should observe no behavioral differences except cold-start time.

## Performance and Memory
- Building in-memory MIDX and commit graph adds a cold-start cost.
- After build, the pipeline should behave similarly to the on-disk artifact path.
- Memory usage increases due to in-memory index structures; update `docs/memory-management.md` accordingly.

## Risks and Mitigations
- Risk: pack ordering drift across platforms.
Mitigation: define a stable pack ordering rule and enforce it in tests.
- Risk: duplicate OID resolution changes attribution.
Mitigation: define a deterministic tie-break rule and validate on known repos.
- Risk: concurrent maintenance changes pack files during scan.
Mitigation: reuse lock detection and add pack fingerprints before pack exec.

## Testing Plan
- Unit tests for in-memory MIDX parsing and lookup correctness.
- Integration tests comparing in-memory vs on-disk artifact behavior on small repos.
- Simulation tests using `sim_git_scan` to validate deterministic commit ordering.
- Regression tests for duplicate OID handling and pack ordering rules.

## Rollout Plan
1. Land the new artifact policy behind a config toggle.
2. Add a diagnostic mode to compare outputs with on-disk artifacts when available.
3. Enable in-memory artifacts by default only after parity tests pass.

## Open Questions
1. What deterministic pack ordering rule should we standardize on?
2. How should duplicate OIDs across packs be resolved?
3. Do we accept the cold-start overhead for large monorepos, or require explicit opt-in?
4. Should in-memory artifacts be cached across scans, or rebuilt each run?
