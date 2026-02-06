# Hot-Path Struct Decomposition + Aggressive Packing Plan

## Summary
Refactor hot scanner state to reduce cache pressure and shrink per-item queue/window records with explicit bit-packing.
Primary targets are `ScanScratch` hot-loop state, `WorkItem`, and stream-window records.
Validation will require both correctness and performance evidence.

## Current Hotspot Baseline (from repo inspection)
- `ScanScratch`: `2792B` (`src/engine/scratch.rs`), contains both hot-loop fields and large cold/stateful members.
- `WorkItem`: `104B` (`src/engine/work_items.rs`), inflated by `Option<Range<usize>>` and enum layout.
- `VsStreamWindow`: `40B` (`src/engine/vectorscan_prefilter.rs`), has avoidable padding and separate flag bytes.
- `PendingWindow`: `32B` (`src/engine/work_items.rs`), mostly tight already.
- `HitAccPool`: `144B` header (`src/engine/hit_pool.rs`), backing vectors dominate runtime memory.
- `Engine`: `640B` (`src/engine/core.rs`), not first optimization priority.

## Public API / Type Changes
- Breaking API changes are allowed for this work.
- Planned API-affecting change:
1. Replace public `FindingRec` field `dedupe_with_span: bool` with packed flags:
   - Add `flags: u32` (or `u16`) and define `FINDING_FLAG_DEDUPE_WITH_SPAN`.
   - Keep semantics identical.
- All internal packed types will use explicit constants (`NONE_U32 = u32::MAX`) and bit masks.

## Implementation Plan

### 1. Split `ScanScratch` into hot vs cold regions
Files: `src/engine/scratch.rs`, touch call sites in `src/engine/core.rs`, `src/engine/buffer_scan.rs`, `src/engine/stream_decode.rs`, `src/engine/window_validate.rs`.

1. Introduce:
- `ScanScratchHot`: work queue head/tail, hit accumulators, window scratch vectors, decode/work budget counters, root map pointer, touched lists.
- `ScanScratchStream`: stream decode ring, pending timing wheel, stream match vectors, stream counters.
- `ScanScratchCold`: materialization buffers, capture locations, Vectorscan scratch handles, capacity-validation metadata, last-chunk/file metadata, stats-only fields.

2. Change `ScanScratch` to:
- `hot: ScanScratchHot`
- `stream: ScanScratchStream`
- `cold: Box<ScanScratchCold>` (boxed to keep hot struct compact and stable in cache lines).

3. Update methods:
- `new`, `reset_for_scan`, finding push/drain/materialize methods, chunk overlap helpers.
- Ensure hot loops operate mostly on `scratch.hot` (and `scratch.stream` where needed), minimizing `scratch.cold` touches.

4. Maintain behavior:
- No algorithmic changes.
- Capacity validation logic remains in cold path only.

### 2. Replace `WorkItem` enum with packed representation
Files: `src/engine/work_items.rs`, `src/engine/core.rs`, `src/engine/stream_decode.rs`.

1. Replace `WorkItem` with `WorkItemPacked` (fixed-size struct, target 32-40B):
- `kind_flags: u16` (variant + option flags + buf/enc source tags).
- `depth: u16`.
- `step_id: u32`.
- `transform_idx: u32` (`NONE_U32` when absent).
- `buf_lo`, `buf_hi`: `u32`.
- `enc_lo`, `enc_hi`: `u32`.
- `root_lo`, `root_hi`: `u32` (`NONE_U32` sentinel when absent).

2. Add helpers:
- `WorkItemPacked::scan_root(...)`, `scan_slab(...)`, `decode_span_root(...)`, `decode_span_slab(...)`.
- decode/extract helpers for current match logic.

3. Invariants:
- All ranges are `u32`-bounded (already required by engine chunking constraints).
- Validate with `debug_assert!` at construction.

### 3. Pack stream windows for bitwise ops and lower footprint
Files: `src/engine/vectorscan_prefilter.rs`, `src/engine/work_items.rs`, `src/engine/stream_decode.rs`.

1. Replace `VsStreamWindow` layout with packed flags:
- `lo: u64`, `hi: u64`, `anchor_hint: u64`, `rule_flags: u32`.
- `rule_flags` layout:
  - bits `0..=23`: `rule_id` (or full `u32` if preferred, then use separate `u8` flags).
  - bits for `variant_idx` (2 bits).
  - bit for `force_full`.

2. Do same style for `PendingWindow`:
- keep `u64` offsets.
- pack `rule_id + variant` into one field to avoid small-field padding and enable bit masking.

3. Replace field accesses with inline bit extractors (`#[inline(always)]`).

### 4. Pack `FindingRec` flags
Files: `src/api.rs`, affected consumers in `src/engine/*`, `src/scheduler/*`, `src/git_scan/*`, tests.

1. Replace bool field with bit flags field.
2. Update constructors/comparators/serialization paths accordingly.
3. Keep record size acceptable; goal here is branchless flag checks and consistency with new packing scheme, not guaranteed size shrink.

### 5. Tighten hot-path field ordering
Files: `src/engine/scratch.rs`, `src/engine/core.rs`, `src/engine/work_items.rs`, `src/engine/vectorscan_prefilter.rs`.

1. Reorder fields so frequently co-accessed counters/pointers sit together.
2. Ensure flag fields are adjacent and consumed with mask ops.
3. Add compile-time layout checks where stable:
- `const _: () = assert!(core::mem::size_of::<WorkItemPacked>() <= 40);`
- similar checks for window structs.

### 6. Documentation updates
- Run `/doc-rigor` skill on changed Rust modules.
- Update docs for architecture/layout changes:
  - `docs/architecture-overview.md`
  - `docs/detection-engine.md`
  - `docs/memory-management.md`
  - `docs/transform-chain.md`
- Add a short "hot/cold scratch split + packed records" section with data-flow impact.

## Test Cases and Validation

### Correctness
1. `cargo test` full unit suite.
2. Focused regression tests:
- Work queue ordering and depth-limit behavior in `scan_chunk_into`.
- Stream decode fallback transitions and pending-window draining.
- UTF-16 stream variant handling (`variant_idx` packing correctness).
- Finding dedupe semantics with new `FindingRec` flags.
- Range conversion and sentinel handling (`NONE_U32`) for root/slab refs.
3. Property tests with `--features stdx-proptest` for packed encode/decode roundtrips.

### Build/quality gates (required by repo workflow)
1. `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features`

### Performance
1. Build optimized binary:
- `RUSTFLAGS="-C target-cpu=native" cargo build --release`
2. Baseline and compare (3x each) per project workflow:
- scanner runs on `../gitleaks`, `../linux`, `../tigerbeetle`
- `cargo bench --bench scanner_throughput -- --save-baseline before`
- `cargo bench --bench vectorscan_overhead -- --save-baseline before`
- compare with `--baseline before`
3. Acceptance thresholds:
- <2% regression: acceptable
- 2-5%: require explicit rationale
- >5%: rework packing/split decisions before merge

## Assumptions and Defaults
- Aggressive packing is explicitly desired.
- Breaking API changes are allowed.
- Performance + correctness validation is mandatory.
- Input chunk invariant (`len <= u32::MAX`) remains enforced and is used to justify packed `u32` ranges.
- If any packed-field range risks overflow in edge cases, fail fast with debug assertions and preserve correctness over compactness.
