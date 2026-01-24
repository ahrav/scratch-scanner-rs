## Performance

### 1. The memory footprint is wildly oversized for a single-threaded pipeline

* **What happens**

  * `BUFFER_LEN_MAX = 2 MiB` (lib.rs:L361-L364).
  * Pipeline pool capacity is `PIPE_CHUNK_RING_CAP + 8 = 136` (pipeline.rs:L26-L31).
  * Buffer pool allocates `136 * 2 MiB = 272 MiB` up front, every run.
* **Why this is bad**

  * This dominates runtime memory regardless of repo size.
  * It is not buying you parallelism because the pipeline is single-threaded.
* **Fix**

  * Size buffers to actual `buf_len = overlap + chunk_size`, not `BUFFER_LEN_MAX`.
  * Slash `PIPE_CHUNK_RING_CAP` in single-threaded mode (2-8 is more than enough).
  * If you want future multi-threading, make this a runtime knob, not hard constants.

### 2. The stage scheduling reads far ahead and hoards buffers

* **What happens**

  * `ReaderStage::pump` fills `chunk_ring` until full (pipeline.rs:L284-L320).
  * `ScanStage::pump` processes at most **one** chunk per pipeline iteration (pipeline.rs:L380-L396).
* **Why this is bad**

  * You can end up with up to 128 chunks buffered (256 MiB of chunk buffers) while scanning lags.
  * You lose locality: you read a bunch of data, then scan it later, which tends to be worse for cache behavior.
* **Fix**

  * In single-threaded mode, remove the chunk ring entirely and do “read one chunk, scan it, repeat”.
  * If you keep staging, let the scanner drain multiple chunks per pump call until output backpressure stops it.

### 3. Rule processing scales as O(rules * variants) per buffer even when nothing matches

* **What happens**

  * After anchor scan, you iterate all rules and all variants and call `acc.take_into` etc.
    Evidence (lib.rs:L1367-L1376).
* **Why this matters**

  * Today you have ~10 rules. Real scanners have hundreds to thousands.
  * You are paying a fixed cost per buffer that grows linearly with rule count, even if only a handful of rules have anchors in that buffer.
* **Fix**

  * Track “touched” `(rule_id, variant)` pairs during the anchor scan and only process those accumulators.
  * This is a big win at scale.

* **Status**

  * Fixed: anchor scan marks touched pairs in a `DynamicBitSet`, collects them into a `ScratchVec<u32>`, and only processes those accumulators.

### 4. Base64 transform span scanning runs on every buffer

* **What happens**

  * `transform_quick_trigger` returns `true` for Base64 unconditionally.
    Evidence (lib.rs:L2236-L2245):

    ```rust
    TransformId::Base64 => true, // span finder is the real filter
    ```
* **Why this matters**

  * You always do a base64 span pass over the buffer, even if it contains no plausible base64 regions.
* **Fix**

  * Add a cheap trigger:

    * Require a minimum count of base64-only chars (`+`, `/`, `=`, `-`, `_`) or a long run of `[A-Za-z0-9]` with limited punctuation.
  * Or gate on entropy heuristics, but keep it cheap and bounded.
