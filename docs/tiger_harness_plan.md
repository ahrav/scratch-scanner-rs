# Tiger Harness Plan

## Purpose

Add a deterministic, simulation-style test harness that models runtime chunking
semantics. The harness treats segmentation as input nondeterminism and asserts
that chunked scanning does not lose oracle findings under a correctness-oriented
engine configuration.

## Scope (Harness + Proptests)

In-scope:
- In-memory chunk runner that mirrors runtime semantics (prefix + payload,
  base_offset math, drop_prefix_findings, per-chunk drain).
- Deterministic chunk plan abstraction (fixed, alternating, random range,
  explicit sequence, optional first-chunk shift).
- Coverage assertion (every oracle finding is covered by some chunked finding).
- Correctness-focused engine builder with raised caps to avoid budget-driven
  divergence in tests.
- Two proptests:
  - Segmentation invariance across multiple chunk plans.
  - Boundary no-miss for matches that begin in the prefix and end in payload.

Out-of-scope for initial harness:
- Persisted regression corpus and replay tests.
- Fuzz harnesses or corpus replay.
- Performance tuning or allocation strategy changes.

## Invariants the harness must mirror

- Chunk buffer = overlap prefix + payload.
- Prefix bytes are the last `Engine::required_overlap()` bytes of the previous
  chunk buffer (shorter on the first few chunks if the file is small).
- `base_offset` equals file offset of the chunk buffer start: payload_offset -
  prefix_len.
- After each scan, `ScanScratch::drop_prefix_findings(new_bytes_start)` is
  called, where `new_bytes_start` is the payload start offset in the file.
- Findings are drained per chunk and appended to the cumulative output.

## Plan (implementation steps)

1. Create `src/tiger_harness.rs` gated for tests.
   - Document the goal, invariants, and how the oracle and chunked runners
     compare outputs.
   - Implement:
     - `correctness_engine()` that increases caps (max spans, decode sizes,
       findings, work items) to reduce budget-driven divergences.
     - `ChunkPattern` and `ChunkPlan` with deterministic length generation and
       optional first-chunk shift.
     - `scan_one_chunk_records()` as the oracle runner.
     - `scan_chunked_records()` that mirrors runtime chunk processing.
     - `check_oracle_covered()` using rule id + root-span coverage.

2. Wire the module into the crate for tests.
   - Add `#[cfg(test)] mod tiger_harness;` in `src/lib.rs` near `test_utils`.

3. Add tiger-style proptests in `src/engine/tests.rs`.
   - Import the harness helpers.
   - Add `prop_tiger_chunk_plans_cover_oracle` (multiple deterministic plans).
   - Add `prop_tiger_boundary_crossing_not_dropped` (prefix vs payload boundary).

4. Validate.
   - Run `cargo fmt`.
   - Run `cargo test`.
   - Run `cargo clippy`.

## Safety Blanket Extensions (Planned)

5. Regression bank (deterministic replay).
   - On a proptest failure, serialize `{seed, chunk_plan, input_bytes}` to
     `tests/regressions/tiger_chunking/*.json`.
   - Store bytes as base64 so the JSON is stable and diffable.
   - Add a normal `#[test]` that loads all regression JSON files and replays
     oracle vs chunked coverage.
   - Consider gating writes behind an env var (e.g. `SCANNER_WRITE_REGRESSIONS=1`)
     to keep CI hermetic while still enabling local capture.

6. Dedicated chunk-plan fuzz target (cargo-fuzz).
   - Add `fuzz/fuzz_targets/fuzz_tiger_chunking.rs`.
   - Parse `(seed, bytes)` from the fuzzer input (e.g. first 8 bytes as seed).
   - Derive 2–3 deterministic plans from the seed and compare oracle vs chunked
     coverage using the harness helpers.

7. Boundary-specific construction in tests.
   - Add explicit cases that force:
     - `%` at end-of-chunk with hex digits in the next chunk.
     - Base64 padding `=` split across boundary.
     - UTF-16 odd-byte boundary splits for ASCII anchors.

## Notes / design choices

- Coverage uses root-span containment rather than strict equality to tolerate
  benign differences in span rooting between chunked and non-chunked scans.
- The correctness engine keeps gates intact; the goal is to validate chunking
  semantics, not to bypass normal validation logic.
- The harness must be deterministic and side-effect free so failing cases are
  reproducible from seeds alone.
- Extensions are intentionally structured to make failures replayable
  without relying on proptest's built-in regression files.
