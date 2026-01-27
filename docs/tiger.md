## 2) “No allocations after startup” is currently violated (even before performance tuning)

If you want TigerStyle compliance, this is the first gate. Right now it fails.

### Pipeline allocations after startup

* Per-file overlap buffer allocates on every new file:

  * `tail: vec![0u8; overlap]` in `FileReader::new` (pipeline.rs:203-210)
* Path cloning allocates per file open:

  * `let path = files.path(file_id).clone();` (pipeline.rs:296)
* FileTable capacity is now set to `max_files` (default 100k), preallocated at startup.

* Walker stack uses a fixed capacity (`WALKER_STACK_CAP = 1024`) based on directory depth, not file count.
  DFS stack depth is bounded by tree depth (~255 path components max), so 1024 is generous.

This is not “edge case”. On any non-trivial tree it allocates.

TigerStyle-aligned fixes:

* Remove per-file `tail: Vec<u8>` allocation:

  * Put `tail: Vec<u8>` in `ReaderStage`, allocate it once in `ReaderStage::new`, reuse across files.
  * Or better: reuse the same chunk buffer and use `copy_within` for overlap (see performance section).
* Remove the path clone:

  * Use `File::open(files.path(file_id))` directly.
* If you want strict “no allocations during scan” including traversal:

  * You cannot use `std::fs::read_dir` + `DirEntry::path()` without allocations. That API returns owned `PathBuf`.
  * TigerStyle-consistent options:

    * Accept allocations in the “enumeration layer” and enforce no allocations in the “scan layer”.
    * Or implement a low-level walker using OS syscalls (Linux `getdents64` + `openat`) and a preallocated path arena. That is a big scope increase and you should be honest about it.

### Engine allocations after startup (this is the big one)

Status update: the scan hot path now uses fixed-capacity scratch buffers and explicit caps.

* Fixed:

  * `HitAccumulator` uses `ScratchVec` with `max_anchor_hits_per_rule_variant` capacity.
  * `scratch.windows`/`expanded`/`spans` use `ScratchVec` with fixed capacity.
  * `utf16_buf` is preallocated to `max_utf16_decoded_bytes_per_window`; decode uses the same buffer.
  * Findings are capped by `max_findings_per_chunk` and dropped counts are tracked.

---

## 3) Performance in a single thread: push the real bottlenecks, not the vibes

You can absolutely chase “theoretical max single-thread” without multi-threading, but the current pipeline structure is not doing that yet.

### A. Your staged rings do not add throughput with blocking reads

* Evidence:

  * Reader stage does `File::read` synchronously (pipeline.rs:226-229).
  * Scanner runs after the read completes (pipeline.rs:385-395).
* Result:

  * There is no overlap between IO and scanning. Reading ahead just increases memory footprint and harms locality.

If you want maximum single-thread throughput with blocking IO:

* Collapse the pipeline to a tight loop:

  * Read chunk into one reusable buffer
  * Scan it immediately
  * Emit findings immediately
* That reduces:

  * ring churn
  * buffer pool size requirements
  * memory footprint
  * cache misses

If you want “TigerBeetle-style single-threaded but overlapped IO”:

* You need async IO with an explicit submission/completion queue (io_uring/kqueue style), still one user thread. ([tigerbeetle.com][3])
* That is how you get concurrency without multi-threading. With `std::fs::File::read`, you cannot.

### B. You pay a 2x overlap copy per chunk

* Evidence:

  * Copy tail into the next chunk: `buf[..tail_len].copy_from_slice(tail)` (pipeline.rs:222-224)
  * Copy end-of-chunk into tail: `tail.copy_from_slice(&buf[start..total_len])` (pipeline.rs:234-237)
* That is two copies of up to `overlap` bytes per chunk.
* Your overlap is not small (private-key full radius is 16 KiB, and required overlap will be on the order of 32 KiB plus anchors).

Max-throughput single-thread fix:

* Use a single reusable buffer per file:

  * After scanning, `buf.copy_within(total_len - overlap .. total_len, 0)`
  * Then read the next payload into `buf[overlap .. overlap + chunk_size]`
* One copy instead of two, and no per-file `tail` allocation.

### C. Treat stdout as a performance hazard

* Evidence:

  * Output uses `writeln!` per finding (pipeline.rs:421-433).
* In a scanner, printing can dominate runtime.
* For “theoretical max scan throughput”, you need either:

  * output off by default
  * or buffered output with bounded memory and periodic flush
  * or write to a file descriptor with larger buffering

This is not an argument for threads. It is an argument for controlling IO.

---

## 4) Extensibility under TigerStyle: you can extend, but only with explicit bounds

You can add more scanning sources without giving up the constraints, but you must design the “physics” up front. That is a core TigerStyle motivation. ([tigerstyle.dev][1])

Practical pattern:

* Define a `Source` interface that never allocates during scanning:

  * Source state is allocated at init (startup).
  * Source yields `(artifact_id, chunk_bytes, base_offset, prefix_len)` into a buffer you provide.
* Keep it single-thread:

  * pipeline is a state machine calling `source.next_chunk(&mut buf)` then `engine.scan_chunk_into(...)`
* Artifact identification:

  * Do not bake `PathBuf` into the core engine output.
  * Use an `ArtifactId` that can represent file path, git blob id, s3 key, etc.
  * Under strict TigerStyle, store those IDs in a preallocated arena with explicit max total bytes.

---

## 5) One hard recommendation: enforce “no allocations after init” in debug builds

If this requirement matters, treat it as an invariant and make violations crash loudly.

* Implement a global allocator wrapper that:

  * allows allocations during startup
  * flips a flag after init
  * panics on any allocation once the flag is flipped (debug builds)

This gives you:

* proof you are actually following the philosophy
* zero ambiguity about “did we accidentally allocate in the hot loop”

This is exactly the sort of “make the system’s physics explicit” move TigerStyle pushes you toward. ([tigerstyle.dev][1])
