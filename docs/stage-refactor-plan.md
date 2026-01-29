* **Today:** decode spans → **materialize full decoded output into a slab** → scan that decoded buffer again (VS block or anchor buckets) → then validate.
* **Recommendation:** decode spans → **scan decoded bytes while they’re produced** (VS stream) → **materialize only windows that must be verified**.

That difference is the throughput lever.

---

## Streaming Vectorscan parity checklist (vs `@blah`)

Goal: converge our streaming decode path with the `@blah` implementation in **priority order**. This list is the checklist we’ll implement *one item at a time*. Each item includes scope, invariants, and acceptance checks.

### P0 — correctness + safety (do first)

- [ ] **Window loss recovery when the ring can’t serve `[lo, hi)`**
  - **Why:** Our current streaming path silently drops windows when the ring doesn’t retain the range; `@blah` re-decodes just the window and only falls back if that fails.
  - **Target behavior:** If `ByteRing` cannot provide the window, re-decode the encoded span to reconstruct `[lo, hi)`. If that fails, force full-materialize fallback for this span.
  - **Code touchpoints:** `src/engine/mod.rs`, `src/stdx/byte_ring.rs` (helper if needed).
  - **Acceptance:** `engine::tests::prop_engine_matches_reference` and tiger boundary tests stay green; add a new regression that forces ring eviction on a window.

- [ ] **Per-rule stream hit caps + force-full fallback**
  - **Why:** Unbounded stream hits can blow up pending window queues; `@blah` caps per-rule stream hits and flips to full verification.
  - **Target behavior:** Track per `(rule, variant)` hit counts during streaming decode. If the cap (`tuning.max_windows_per_rule_variant`) is exceeded, mark the span as “force full verify” and fall back to materialized decode.
  - **Code touchpoints:** `src/engine/mod.rs` (stream scratch + enqueue logic), `src/engine/vectorscan_prefilter.rs` (stream callback context).
  - **Acceptance:** Stress inputs do not grow memory unbounded; perf tests remain stable.

- [ ] **Unbounded expression sentinel handling in stream mode**
  - **Why:** Stream prefilter for regexes with unbounded width cannot safely seed bounded windows. `@blah` marks whole-buffer verify on hit.
  - **Target behavior:** If stream metadata indicates “whole-buffer on hit”, mark force-full verification for that rule/span.
  - **Code touchpoints:** `src/engine/vectorscan_prefilter.rs` (meta encoding), `src/engine/mod.rs` (handling).
  - **Acceptance:** `prop_engine_matches_reference` stays green on unbounded patterns; no missing detections.

- [ ] **Nested span capture fallback (don’t drop spans)**
  - **Why:** If nested spans fall out of the ring, we currently drop them; `@blah` flips to full-materialize for correctness.
  - **Target behavior:** If capturing a nested span fails, mark force-full fallback for the span.
  - **Code touchpoints:** `src/engine/mod.rs` (nested span capture).
  - **Acceptance:** Nested transforms remain correct when spans straddle ring boundaries.

### P1 — streaming completeness + perf

- [ ] **UTF‑16 anchor scanning in decoded streams (lazy stream DB)**
  - **Why:** `@blah` scans UTF‑16 anchors in streaming mode with lazy enablement on first NUL, replaying the ring to avoid missed prefixes. Our current path materializes full decoded output for UTF‑16.
  - **Target behavior:** Use a UTF‑16 stream DB; enable on first NUL; replay current ring; feed subsequent chunks into the UTF‑16 stream. Remove full decoded materialization for UTF‑16 in streaming mode.
  - **Code touchpoints:** `src/engine/vectorscan_prefilter.rs`, `src/engine/mod.rs`, `src/stdx/byte_ring.rs`.
  - **Acceptance:** `engine::tests::base64_utf16_aws_key_is_detected` and `base64_gate_utf16be_anchor_straddles_stream_boundary` pass without full decoded slab.

- [ ] **Decoded gate parity (optional `VsGateDb`)**
  - **Why:** `@blah` has a dedicated Vectorscan gate DB for decoded-space “anchors in decoded” gating. We currently treat stream prefilter hits as the gate.
  - **Target behavior:** Add optional decoded-gate DB and apply it before accepting a decoded stream (still keep base64 encoded pre-gate). Decide whether to keep “stream prefilter == gate” or align with `@blah`.
  - **Code touchpoints:** `src/engine/vectorscan_prefilter.rs`, `src/engine/mod.rs`.
  - **Acceptance:** Behavior remains equivalent in tests; base64 gate stats show fewer wasted decodes.

### P2 — polish + observability

- [ ] **Stream pending window cap telemetry**
  - **Why:** When force-full fallback happens, we should be able to see why.
  - **Target behavior:** Counters for “stream_force_full” and “stream_window_cap_exceeded”.
  - **Code touchpoints:** `src/engine/mod.rs` stats, `src/bin/perf_hotspots.rs` logging.

Below is what I’ve confirmed so far, what needs to change, and the concrete code I’ve drafted. I did **not finish the full codebase rewrite in this response** (tool time limit hit while editing), and no Stage 4/5 “ring + stream scan” primitives are landed in the repo yet. I’ll also include the full plan and invariants so the remaining code changes can be completed deterministically.

---

## Phase 1: Offset normalization + window math (lock this down first)

**Shared invariants (match every engine path):**

* Offsets are **byte offsets** in the current buffer/stream.
* Ranges are half-open: `[lo, hi)` with `hi` **exclusive**.
* If a matcher reports an **inclusive** end, normalize to `end_excl = end + 1`.

**Window math:**

* **Anchor hits (start + end known):**

  * `seed_radius_bytes = seed_radius * scale`, where `scale = 1` (raw) or `2` (UTF-16).
  * `lo = start.saturating_sub(seed_radius_bytes)`
  * `hi = min(end + seed_radius_bytes, buf_len)`
  * Two-phase: after confirm, expand by `extra = full_radius_bytes - seed_radius_bytes`.
* **Prefilter hits (end only):**

  * `max_width` is the maximum possible match length (bytes) for the rule.
  * If `max_width` is unavailable, use a conservative bound (e.g., `2 * full_radius_bytes`)
    or skip end-only windowing for that rule.
  * `lo = end_excl.saturating_sub(max_width + seed_radius_bytes)`
  * `hi = min(end_excl + seed_radius_bytes, buf_len)`
  * Window length is `max_width + 2 * seed_radius_bytes`.

**Ring sizing:**

* `W >= max(max_width + 2 * seed_radius_bytes)` across rules/variants
  (or `2 * full_radius_bytes` for two-phase rules).

**Overlap rules:**

* Required chunk overlap is
  `max_window_diameter_bytes + (max_anchor_pat_len - 1)`.
* `max_anchor_pat_len` is computed over the **raw + UTF-16** anchor pattern set,
  so UTF-16 overlap is already covered unless UTF-16 anchors are excluded at build time.

---

## Phase 2: Transform spans + Base64 pre-gate invariants (anchor in current code)

**Where this lives today:**

* `src/engine/mod.rs` (transform loop, gating, decode budgets):
  `scan_chunk_into`, `transform_quick_trigger`, `find_spans_into`,
  `decode_stream_gated_into_slab`, `Base64YaraGate` usage.
* `src/engine/transform.rs` (span finders + streaming decoders):
  `find_url_spans_into`, `find_base64_spans_into`, `stream_decode_url_percent`,
  `stream_decode_base64`.
* `src/pipeline.rs` + `src/runtime.rs` (overlap + offsets):
  pipeline uses `Engine::required_overlap()` and runtime defines that
  `Chunk::base_offset` includes the overlap region.

**Span discovery invariants (must keep):**

* Spans are half-open `[start, end)` in encoded byte space.
* URL spans require at least one escape (or `+` when enabled); `min_len`/`max_len`
  apply to encoded length.
* Base64 spans are permissive: allow configured whitespace, trim trailing whitespace,
  and split runs at `max_len` to bound work.
* `transform_quick_trigger` is skip-only; the span finders are authoritative.

**Base64 pre-gate invariants (must keep):**

* Only used when `tc.gate == Gate::AnchorsInDecoded` (see `scan_chunk_into`).
* Skip-only: it can prevent decode work but never replace decoded-space checks.
* Built from the same anchor universe as decoded scanning (raw + UTF-16), so
  a failed pre-gate cannot exclude any decoded buffer that would contain an anchor.

**Pipeline/runtime coupling (do not break):**

* `Engine::required_overlap()` is applied in `src/pipeline.rs`; changing window
  math must update this formula and keep pipeline overlap in sync.
* Findings use `base_offset` from `Chunk` (runtime); `base_offset` counts from the
  start of the chunk **including overlap**, so window offsets must remain consistent.

---

## Phase 3: Stream-scan decoded bytes + window-only materialization

**Where this lives today:**

* `src/engine/mod.rs`: `scan_chunk_into` transform loop, `WorkItem`/`BufRef`,
  `DecodeSlab`, `decode_stream_gated_into_slab`, `GateScratch`, `StepArena`,
  `hash128` dedupe (`scratch.seen`), and decode budget enforcement.
* `src/runtime.rs` + `src/pipeline.rs`: `Engine::required_overlap()` and
  `drop_prefix_findings` rely on consistent `root_hint` and window offsets.

**Invariants to preserve while replacing slab-based decode:**

* **Budgets:** `max_transform_depth`, `max_work_items`, `max_spans_per_buffer`,
  `max_total_decode_output_bytes`, and per-span `max_decoded_bytes` must still
  bound work deterministically.
* **Provenance:** `DecodeStep::Transform { parent_span }` currently records the
  **encoded** span; `child_root_hint` falls back to that span when none exists.
  New window-only verification must keep this mapping so
  `drop_prefix_findings` remains correct.
* **Gate semantics:** `decode_stream_gated_into_slab` uses a tail window of
  `max_anchor_pat_len - 1` (`GateScratch`) to avoid missing anchors across
  decoder chunk boundaries. The stream-scanning path must keep equivalent
  lookbehind.
* **Dedupe:** today dedupe hashes the full decoded buffer (`hash128` on slab
  slice). If decoded buffers are no longer materialized, define the new
  dedupe scope (e.g., encoded-span hash or window-hash) and document the trade.
* **Failure semantics:** decode errors/truncation roll back decode budget and
  skip the transform entirely (fail-closed).

**Refactor outline:**

* Replace `DecodeSlab` outputs with a ring buffer keyed by absolute decoded
  offsets; feed decoded chunks directly into the stream matcher.
* Replace `WorkItem { buf: BufRef::Slab }` with
  `DecodeSpan { transform_idx, enc_ref, parent_step_id, root_hint }`.
* Track pending verification windows (min-heap by `hi`) and materialize only
  those windows for regex validation once `hi` bytes have been produced.

---

## Phase 4: UTF-16 handling in root + decoded streams

**Where this lives today:**

* `src/engine/mod.rs`: `Anchors::select` (NUL-based raw vs raw+UTF16 choice),
  `scan_rules_on_buffer` (anchor scan), `run_rule_on_window` (UTF-16 decode +
  regex), `tuning.max_utf16_decoded_bytes_per_window`.
* `src/engine/helpers.rs`: `utf16le_bytes`, `utf16be_bytes`,
  `decode_utf16le_to_buf`, `decode_utf16be_to_buf` (replacement semantics + caps).
* `src/engine/tests.rs`: property tests that encode UTF-16 bytes and then Base64
  (decoded streams must still find these).

**Invariants to preserve:**

* UTF-16 anchor patterns **always include a NUL byte**, so NUL-free windows can
  skip UTF-16 variants (`Anchors::select` fast path).
* UTF-16 window decode ignores a trailing odd byte and replaces invalid code
  units with `U+FFFD` (`decode_utf16*_to_buf`).
* UTF-16 decode is bounded by `max_utf16_decoded_bytes_per_window`; overflows
  drop the window (fail-closed).
* `confirm_all` / `keywords` are encoded to UTF-16 variants so they can gate
  **before** decoding.

**Required behavior in the refactor:**

* Apply UTF-16 anchor detection on **decoded streams**, not just root buffers,
  to preserve existing correctness tests.
* Preserve the `max_anchor_pat_len - 1` lookbehind when streaming decoded bytes
  so UTF-16 anchors that straddle decode chunk boundaries are still detected.

---

## Phase 5: Measurement plan (wire to existing benches)

**Existing benchmark anchors:**

* `benches/scan.rs`: end-to-end `Engine::scan_chunk` throughput and base64 gate
  microbenches (`bench_engine_scan`, `bench_base64_gate`).
* `benches/hotspots.rs`: span-finder throughput and Aho anchor scan costs
  (`bench_transform_spans`, `bench_ac_anchors`, size sweeps).
* `benches/ring_buffer.rs`: ring buffer microbench patterns (use as a template
  for `ByteRing` once introduced).

**Microbench additions (targeted):**

* Add a `ByteRing` bench (push + window extraction) alongside
  `benches/ring_buffer.rs` or in a new `benches/byte_ring.rs`.
* Add a decode+scan streaming skeleton bench (decode only + stream matcher),
  likely in `benches/scan.rs` where other engine-level benches live.

**End-to-end checks (runtime/pipeline):**

* Use `ScannerRuntime::scan_file_sync` (runtime) and/or `Pipeline` scan path to
  measure GB/s on representative corpora with overlap enabled
  (`Engine::required_overlap()`).
* Track `PipelineStats` and (when enabled) `Base64DecodeStats` to ensure:
  - decode budget and work item caps are respected,
  - gated decodes decrease `decoded_bytes_wasted_no_anchor`,
  - findings stay consistent.

**Metrics to record:**

* Throughput (GB/s), allocations (should remain ~0 on hot paths).
* Perf counters: cycles/byte, branch misses, L1 miss rate (e.g., `perf stat`).
* Percent time split: decode vs scan vs regex validation (via profiling).

**Success criteria (tie to refactor goals):**

* No full decoded-buffer rescans in the decoded pipeline.
* Decoded bytes materialized only for verification windows.
* Equal or improved throughput on large corpora, with unchanged findings.

---

## Next steps

* Implement Phase 3 changes (stream-scan + window-only materialization).
* Apply Phase 4 UTF-16 handling inside decoded streams.
* Run Phase 5 measurement suite to validate throughput and correctness.
