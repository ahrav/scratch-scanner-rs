## Correctness

### 1. `FindingRec.step_id` is unusable (and actively misleading) across chunks

* **What happens**

  * `Engine::scan_chunk_into` resets the scratch state every time it scans a buffer, including resetting the `StepArena`.
    Evidence (lib.rs):

    ```rust
    // lib.rs:L1129
    scratch.reset_for_scan(self);

    // lib.rs:L972
    self.step_arena.reset();
    ```
  * The pipeline and `scan_file_sync` reuse the same `scratch` across multiple chunks, and they **store** `FindingRec` records from earlier chunks after the arena has been reset for later chunks.
    Evidence (lib.rs):

    ```rust
    // lib.rs:L591-L600
    self.engine.scan_chunk_into(..., &mut scratch);
    scratch.drain_findings_into(&mut batch);
    out.append(&mut batch);
    ```
* **Why this is a correctness bug**

  * `FindingRec` carries `step_id: StepId` (lib.rs:L176-L189). That ID indexes into `scratch.step_arena.nodes`.
  * You clear `step_arena.nodes` at the start of every chunk scan. That means every previously-emitted `FindingRec.step_id` becomes a dangling index the moment the next chunk is scanned.
  * Today you “get away with it” only because `pipeline.rs` never uses `step_id` (it prints only `root_hint_start/end` and `rule`). But the struct claims it supports provenance reconstruction. It does not.
* **Fix options**

  * **Option A (simplest, MVP-honest):** Remove `step_id` from `FindingRec` entirely. If you do not output provenance, don’t pretend you have it.
  * **Option B (make it real):** Make provenance data self-contained per finding:

    * Store `Vec<DecodeStep>` (or a compact representation) in the emitted record, not a scratch-local ID.
    * Or, materialize findings immediately (while arena is still valid) before draining them out of scratch.
  * **Option C (arena lifetime fix):** Stop resetting `step_arena` per chunk. Reset it per file (or per scan run) so emitted IDs stay valid. You then need a hard cap or compaction strategy.

This is the highest-severity issue because it’s not “suboptimal design”. It’s an API that lies.

---

### 2. `required_overlap()` is wrong for UTF-16 scanning, and can cause false negatives at chunk boundaries

* **What happens**

  * You scan three variants: raw, UTF-16LE, UTF-16BE. The UTF-16 variants scale window radii by 2.
    Evidence (lib.rs:L1356-L1361):

    ```rust
    let scale = variant.scale();               // Utf16* -> 2
    let seed_radius_bytes = seed_r.saturating_mul(scale);
    let lo = m.start().saturating_sub(seed_radius_bytes);
    let hi = (m.end() + seed_radius_bytes).min(buf.len());
    ```
  * Before fix, overlap computation did not account for that scale.
    Evidence (old code):

    ```rust
    // OLD (before fix): only raw radius accounted for
    max_window_radius_bytes = max_window_radius_bytes.max(base.saturating_mul(2));

    pub fn required_overlap(&self) -> usize {
        self.max_window_radius_bytes + (self.max_anchor_pat_len - 1)
    }
    ```
* **Why this can be incorrect**

  * For a given anchor hit, the window size in bytes is:

    * `window_bytes = anchor_len_bytes + 2 * radius_bytes`
  * For UTF-16 variants:

    * `anchor_len_bytes` is doubled (because the anchor patterns are doubled bytes).
    * `radius_bytes` is doubled (because you multiply by `scale = 2`).
  * Therefore the worst-case UTF-16 window size is roughly:

    * `2*anchor_len + 4*radius`
  * Your overlap is effectively approximating:

    * `max_anchor_len_bytes + 2*radius` (not `+4*radius`)
* **Concrete proof of “can miss”**

  * If overlap `< window_bytes - 1`, there exists an anchor position near a chunk boundary where the full window does not fit in either adjacent chunk. In that configuration, your window is truncated in both chunks, and any regex match requiring the truncated portion becomes undetectable.
  * Since UTF-16 uses `radius_bytes = 2*radius`, the safe bound becomes `overlap >= (2*anchor_len + 4*radius - 1)`. Your computed bound is smaller by `2*radius` for UTF-16.
* **Fix**

  * Compute overlap using the **largest window diameter in bytes across all variants**, not just raw:

    * For each rule, consider `base = radius or full_radius`
    * Consider both scales: `scale=1` and `scale=2`
    * Track `max_window_diameter_bytes = max(max_window_diameter_bytes, 2 * base * scale)`
    * Then `required_overlap = max_window_diameter_bytes + max_anchor_pat_len - 1`
  * Add a test that forces a UTF-16-encoded secret across a chunk boundary and asserts detection.

* **Status**

  * Fixed: `required_overlap()` now accounts for UTF-16 scaled window diameter.
  * Test: `utf16_overlap_accounts_for_scaled_radius`.

This is the second highest-severity issue because it’s a real false-negative vector.

---

### 3. Duplicate findings across chunk boundaries are guaranteed with the current chunk strategy

* **What happens**

  * Each chunk (after the first) includes an overlap prefix from the previous chunk (`Chunk.prefix_len`).
    Evidence (lib.rs:L325-L356).
  * But scanning uses `chunk.data()` which includes the overlap, not `chunk.payload()` which excludes it.
    Evidence (pipeline.rs:L385-L390):

    ```rust
    engine.scan_chunk_into(
        chunk.data(),        // includes overlap bytes
        chunk.file_id,
        chunk.base_offset,
        &mut self.scratch,
    );
    ```
* **Why this produces duplicates**

  * Any secret entirely within the overlap region will be scanned in both chunk N (as part of its payload) and chunk N+1 (as part of its prefix).
  * Your output stage prints `root_hint_start/end`, so the duplicates will be byte-identical and will appear as repeated lines.
* **Fix**

  * Filter results on the scanning side:

    * Compute `new_bytes_start = chunk.base_offset + chunk.prefix_len`
    * Drop any finding where `rec.root_hint_end <= new_bytes_start` (entirely in prefix).
    * Keep findings that overlap the boundary (start < new_bytes_start < end).
  * Or scan only `payload()` and adjust engine design to preserve correctness across boundaries (harder, because anchors can start in prefix and end in payload).

* **Status**

  * Fixed: `drop_prefix_findings(new_bytes_start)` filters prefix-only hits in both pipeline scanning and `scan_file_sync`.
  * Test: `scan_file_sync_drops_prefix_duplicates`.

This is correctness in the “output correctness / user trust” sense. The tool will look broken when it prints duplicates.

---

### 4. Decoded-buffer dedupe used a non-robust hash and can cause false negatives (adversarially)

* **What happens (before fix)**

  * You dedupe decoded outputs via a 64-bit FNV-1a style hash.
    Evidence (lib.rs:L2307-L2314):

    ```rust
    // OLD (before fix): 64-bit FNV-1a
    fn hash64(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }
    ```
* **Why this is correctness-risky**

  * A collision means you skip scanning a distinct decoded buffer (`seen.insert(hash64(decoded))`), which is a direct false negative.
  * FNV-1a is not collision-resistant. If an attacker can craft inputs (and scanners often run on untrusted repos), it is not safe to assume collisions are “astronomically unlikely”.
* **Fix**

  * Use a collision-resistant 128-bit hash and store 128-bit keys.
  * If you want “no false negatives”, avoid relying on a single 64-bit hash:

    * Store `(len, hash)` and also compare a small fingerprint (e.g. first 16 bytes + last 16 bytes) on collision.
    * Or store a 128-bit hash.

* **Status**

  * Fixed: decoded buffer dedupe uses `hash128()` (AEGIS-128L tag) and `FixedSet128`.
  * Tests: `hash128_deterministic`, `hash128_collision_resistant`.

---

### 5. UTF-16 decoding windows do not enforce alignment, which can cause missed or spurious results

* **What happens**

  * UTF-16 anchors are matched as raw byte sequences. There is no check that matches land on a 2-byte boundary.
  * Then you decode the window by pairing bytes from the window start (`input[0],input[1]`, etc).
    Evidence (lib.rs:L1758-L1774 and L1811-L1827).
* **Why this matters**

  * If a UTF-16 anchor match occurs at an odd byte offset, decoding from that point produces wrong code units (pairs are shifted), likely preventing correct regex matching.
  * Real UTF-16 text is typically aligned, but scanners should not bake in “typically” as correctness.
* **Fix**

  * When processing UTF-16 variants, only accept anchor hits where `m.start() % 2 == 0` (and maybe `m.end() % 2 == 0`).
  * Or attempt both alignments when decoding a UTF-16 window (decode starting at `w.start` and `w.start+1`) with a strict budget.

---

### 6. Error accounting is incomplete and misleading

* **What happens**

  * `PipelineStats.errors` increments only on `File::open` failures.
    Evidence (pipeline.rs:L296-L303).
  * Directory walking failures (`symlink_metadata`, `read_dir`) are silently ignored.
    Evidence (pipeline.rs walker code uses `if let Ok(...)` patterns and drops errors).
* **Why this is correctness-relevant**

  * A scanner that silently skips files or directories but reports “0 errors” is lying.
* **Fix**

  * Count walk errors and read errors separately.
  * Emit structured diagnostics (path + error kind) behind a verbosity flag.

* **Status**

  * Fixed (counters): `PipelineStats` now tracks `walk_errors` and `open_errors`, and `errors` aggregates them.
  * Test: `pipeline_counts_walk_and_open_errors`.
