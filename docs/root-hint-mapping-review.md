# Root Hint Mapping Review (Stream Decode + Nested Transforms)
Date: February 3, 2026
Status: Draft, actionable

## Summary
Stream-decode currently sets `RootSpanMapCtx` only when the encoded span is backed by `EncRef::Root`. For nested transforms, child encoded spans live in the decode slab (`EncRef::Slab`), so the stream path never installs a mapping context and `window_validate` falls back to a coarse parent `root_hint`. That produces imprecise `root_span_hint` values, skips URL-trigger drop-boundary widening, and relies on coarse dedupe behavior across chunk boundaries. The fallback path (`ScanBuf`) does attempt slab-backed mapping when the root hint length equals the encoded span length, so stream and fallback behavior are inconsistent.

This document captures the current behavior, why it matters, and tests that would make the gap visible. It also outlines two fix tiers: a short-term parity fix (slab mapping when 1:1) and a longer-term chain mapping fix for length-changing parents (e.g., Base64 → URL).

## Relevant Components
| Component | Location | Purpose |
| --- | --- | --- |
| `scan_chunk_into` / `WorkItem::ScanBuf` | `src/engine/core.rs` | Builds `RootSpanMapCtx` for buffer scans and computes child `root_hint` for nested transforms. |
| `decode_stream_and_scan` | `src/engine/stream_decode.rs` | Streaming decode path; optionally installs `RootSpanMapCtx` via `root_hint_maps_encoded`. |
| `window_validate` | `src/engine/window_validate.rs` | Computes `root_span_hint` for findings; uses `RootSpanMapCtx` when available. |
| `drop_prefix_findings` | `src/engine/scratch.rs` | Uses `root_hint_end` / `drop_hint_end` to suppress overlap-prefix duplicates. |
| `RootSpanMapCtx` | `src/engine/scratch.rs` | Maps decoded offsets to root offsets for a single transform layer. |

See also: `docs/engine-stream-decode.md`, `docs/engine-window-validation.md`, `docs/transform-chain.md`.

## Current Behavior (Detailed)
1. **Root-span mapping for ScanBuf (fallback path).**
   `WorkItem::ScanBuf` installs `RootSpanMapCtx` when:
   - Encoded bytes are in the root buffer and `root_hint` matches that span; or
   - Encoded bytes are in the slab and `root_hint` length equals the encoded span length.

   This is the only place that allows slab-backed mapping today.

2. **Stream path maps only root-backed spans.**
   In `WorkItem::DecodeSpan`, `root_hint_maps_encoded` is computed as:
   - `true` only when `EncRef::Root(span)` and `root_hint` equals that span.
   - `false` for `EncRef::Slab` regardless of length equality.

   `decode_stream_and_scan` uses `root_hint_maps_encoded` to set `scratch.root_span_map_ctx` for the entire stream decode. If false, window validation has no mapping context.

3. **Nested transform emission in stream path.**
   `decode_stream_and_scan` emits nested spans during stream decoding. It computes a child `root_hint` by mapping the parent decoded offsets through the parent transform (`map_decoded_offset`) and then offsetting by the parent `root_hint.start`.

   Those child spans are slab-backed (`EncRef::Slab`). The subsequent `WorkItem::DecodeSpan` for the child will re-enter the stream path and **will not** set `RootSpanMapCtx` (because slab-backed). As a result, findings in the child decode are mapped via the fallback `root_hint` instead of the match span.

4. **Window validation fallback.**
   When `RootSpanMapCtx` is absent, `window_validate` uses `root_hint` directly:
   - `root_span_hint = root_hint.unwrap_or(match_span)`
   - `drop_hint_end = root_span_hint.end` (no URL-trigger extension)
   - `dedupe_with_span = true` (include decoded span because root span is coarse)

## Findings
1. **Stream path ignores slab-backed mapping even when it would be safe.**
   The stream path cannot install `RootSpanMapCtx` for slab-backed encoded spans, even if the root hint length exactly matches the encoded span length (the same condition used in `ScanBuf`). This is an inconsistency between stream and fallback paths.

2. **Nested transforms always lose mapping context in stream decode.**
   Child transforms emitted by stream decode are always slab-backed. As a result:
   - `root_span_hint` becomes the parent `root_hint` (coarse container span).
   - URL-percent `drop_hint_end` widening is skipped because it requires `RootSpanMapCtx`.
   - Deduplication falls back to including decoded spans, which reduces collapse risk but loses “root-level” identity and chunk alignment stability.

3. **No composed mapping for length-changing parents.**
   The current `RootSpanMapCtx` is single-layer: it maps decoded offsets → encoded offsets for one transform. When the parent transform changes length (e.g., Base64), the child transform cannot translate its decoded offsets to root without a chained mapping context. The existing `root_hint` range is insufficient to reconstruct the parent mapping.

4. **Tests do not cover nested-transform root-span precision.**
   Current tests emphasize oracle coverage (containment) and single-transform scenarios. There is no test that:
   - Forces a nested transform to use the stream path, and
   - Asserts that `root_span_hint` is precise (or at least not the entire parent span), and
   - Exercises chunk-boundary dedupe behavior for nested transforms.

## Impact / Risk
- **Incorrect root offsets in findings.**
  Root-span hints are used for reporting and downstream tooling; returning the entire parent span for nested transforms is a precision loss.

- **Chunk boundary semantics degrade.**
  `drop_hint_end` is used to suppress overlap-prefix duplicates. When the hint is coarse and URL-trigger widening is skipped, drop boundaries become less meaningful and dedupe relies more on probabilistic sets and decoded-span identity.

- **Future regressions are likely.**
  If a future change ever flips `dedupe_with_span` to `false` for slab-backed nested transforms (or improves slab mapping in a partial way), coarse root hints could collapse distinct matches. A test should lock in the intended behavior.

## Fix Options
### Option A: Short-term parity fix (low risk)
**Goal:** Make stream decode honor the same slab-backed mapping predicate as `ScanBuf`.

Implementation idea:
- Extend `root_hint_maps_encoded` logic in `WorkItem::DecodeSpan` to treat `EncRef::Slab` as mappable **only when** the root hint length equals the encoded span length.
- Use the same condition as `ScanBuf` to avoid incorrect root offsets.

Notes:
- This only helps when the parent transform is effectively 1:1 for the specific span.
- With current transforms (URL-percent, Base64), this case may be rare, but the parity is still correct and future-proof.

### Option B: Chained root-span mapping (full fix)
**Goal:** Map decoded offsets through multiple transform layers even when parents are length-changing.

Design sketch:
- Introduce a `RootSpanMapCtxChain` (or extend `RootSpanMapCtx`) that can map a decoded span through multiple transform steps.
- Each layer needs:
  - Transform config pointer (`TransformConfig`).
  - Encoded bytes for that step (stable slice; root buffer or slab).
  - Root start offset for that encoded slice (absolute root offset).
- Mapping a decoded span becomes:
  1. Map decoded → encoded offset for the child layer (using child’s encoded bytes).
  2. Feed that encoded offset into the parent layer mapping (which uses the parent’s encoded bytes).
  3. Continue until the root layer is reached.

Operationally, this could be implemented by:
- Capturing a chain in `WorkItem::DecodeSpan` (or a stack in `ScanScratch`) so the child decode can access the parent mapping context.
- Ensuring encoded byte slices remain valid (root buffer or slab append-only segments).
- Adding explicit `# Safety` notes about lifetime and non-reallocation invariants.

## Test Cases to Add
These tests are designed to be explicit and deterministic. They should live in `src/engine/tests.rs` near existing chunking/transform tests.

### 1) Nested transform root-span precision (stream path)
**Purpose:** Ensure root-span hints are not the entire parent span when nested transform mapping is possible after a chain-mapping fix.

Setup:
- Rule: anchor `TOK0_`, regex `TOK0_[A-Z0-9]{8}`.
- Transforms: `[UrlPercent, Base64]` (URL outer, Base64 inner), both `TransformMode::Always`, `Gate::AnchorsInDecoded`.
- Input: `prefix + url_percent_encode_all(b64_encode(token)) + suffix`.
- Force stream path by ensuring `engine.vs_stream.is_some()`; skip test if not (or clone engine and ensure it is enabled).

Assertions:
- Materialized finding has `root_span_hint` equal to the precise root span of the URL-encoded bytes that correspond to the Base64-encoded substring which produced the match.
- The `root_span_hint` should be significantly smaller than the full URL-encoded span (i.e., not the entire parent container).

Expected current behavior:
- Fails until chained mapping is implemented.

Implementation hint:
- Use `scan_chunk_materialized` to get `Finding` with `decode_steps`.
- Add a helper to map `Finding.span` back to root by replaying decode steps and calling `map_decoded_offset` per layer. The final mapped range is the expected `root_span_hint`.

### 2) Stream vs fallback parity for slab-backed mapping (if/when 1:1 case exists)
**Purpose:** Ensure stream decode and fallback decode produce identical root-span hints when a slab-backed span can be mapped 1:1.

Setup:
- Build an input that yields a nested transform where the child encoded span length equals its root hint length (this may require a future length-preserving transform or a targeted test transform).
- Run with default engine (stream path) and with `engine.vs_stream = None` (forced fallback).

Assertions:
- `root_hint_start`/`root_hint_end` match between paths.

Expected current behavior:
- Fails until `root_hint_maps_encoded` includes the slab case.

### 3) Nested transform chunking: no spurious suppression
**Purpose:** Ensure chunked scans don’t lose findings when nested transforms cross chunk boundaries.

Setup:
- Use the same nested chain as test (1).
- Create a base64 string that contains **two** tokens (e.g., `TOK0_ABCDEFGH` and `TOK0_QWERTYUI`) separated by padding/whitespace.
- URL-encode the base64 output, embed in a buffer with a chunk boundary between the two tokens in decoded space.
- Use `scan_in_chunks_with_overlap` (or a `ChunkPlan::fixed`) with `overlap >= engine.required_overlap()`.

Assertions:
- `scan_one_chunk_records` (oracle) returns both tokens.
- Chunked scan returns the same count, with distinct spans (no suppression).

Expected current behavior:
- Likely passes today, but documents desired invariant and prevents regressions if dedupe behavior changes.

### 4) URL-trigger drop-boundary under nested transforms
**Purpose:** Ensure URL-percent drop-boundary widening works even when the URL transform is nested and slab-backed.

Setup:
- Construct a URL-encoded string where the match occurs before the first `%` (raw prefix) and the `%` appears after the match.
- Encode that URL string inside Base64 and place it in the root buffer (Base64 outer, URL inner).
- Chunk the buffer so the `%` trigger is in the next chunk.

Assertions:
- Findings before the trigger are **not** duplicated across chunks (requires `drop_hint_end_for_match` to run with a mapping context).

Expected current behavior:
- Fails today because `RootSpanMapCtx` is missing in the nested URL decode path.

## Open Questions / Clarifications
- Is `root_span_hint` intended to be “exact match span when possible” or “outermost container span” for nested transforms? The API docs describe “outermost container span,” while `window_validate` explicitly uses full-match spans to support chunked dedupe. The intended semantics should be clarified before implementing chained mapping.
- Are there constraints on additional per-scan allocations for chained mapping (e.g., avoid heap allocations in the hot path)?
- Should chained mapping be applied to UTF-16 window transforms as well, or only transform-to-transform chains?

## References
- `docs/engine-stream-decode.md`
- `docs/engine-window-validation.md`
- `docs/transform-chain.md`
