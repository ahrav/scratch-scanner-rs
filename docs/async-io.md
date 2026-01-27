# Async IO Design (Max Perf, O_DIRECT, Per-Worker IO+Scan)

This doc captures the design for async file IO on Linux (io_uring) and macOS
(POSIX AIO) with a **single-thread** implementation first, and a clean path
to **per-worker IO+scan** for multi-core scaling. The focus is theoretical max
throughput, not "good enough."

## Goals

- Overlap IO and scanning on **one user thread** (single-worker baseline).
- Use **O_DIRECT** on Linux without extra overlap scanning (no redundant work).
- Keep zero/near-zero allocations on the hot path.
- Extend to multi-core by giving **each worker its own IO + scan** pipeline.
- Make performance knobs explicit and benchmarkable.

## Non-goals

- Guarantee "single core" execution at the system level (kernel interrupts and
  device DMA are unavoidable).
- Implement multi-core now; this doc defines the architecture.

## Key Decisions

1) **O_DIRECT strategy**: use **split-buffer overlap** with aligned read offsets
   and **no redundant overlap scanning**.
2) **Multi-core strategy**: **per-worker IO + scan** for locality and minimal
   cross-thread coordination.

---

## Core Idea (Single Worker)

Use double buffering with io_uring:

1) Submit async read for chunk N+1 into buffer B.
2) Scan buffer A.
3) Reap completion for buffer B; if not ready, wait briefly.
4) Swap A/B and repeat.

This turns `T_read + T_scan` into `max(T_read, T_scan)` in the ideal case.

### Pseudocode (single-thread)

```
init io_uring, buffers, file list
current = read first chunk into buf A (sync or async + wait)
next = submit read for buf B (offset = next)

loop:
  scan(current)
  wait for next completion if not ready
  swap(current, next)
  submit next read into the other buffer if file not done
```

---

## Linux io_uring: O_DIRECT + Split-Buffer Overlap (No Redundant Scan)

### Problem

O_DIRECT requires **aligned** buffer pointers and **aligned** file offsets.
The current overlap strategy reads into `buf[overlap..]`, which is unaligned
when `overlap` is not a multiple of 4 KiB, so O_DIRECT fails.

### Solution: Aligned Payload Offset With Prefix Slot

We keep a **contiguous scan slice** without scanning padding by:

- Compute `payload_off = align_up(overlap, ALIGN)`.
- Read **payload** into `buf[payload_off .. payload_off + chunk_size]`.
- Store the **true overlap bytes** in `buf[payload_off - overlap .. payload_off]`.
- Scan the contiguous slice:

```
scan_slice = buf[payload_off - overlap .. payload_off + read_len]
prefix_len = overlap
base_offset = file_offset - overlap
```

The padding between `overlap` and `payload_off` is unused and never scanned.

### Buffer Layout

```
| padding (<= ALIGN-1) | overlap (N bytes) | payload (chunk_size bytes) |
^ buffer start         ^ payload_off - N   ^ payload_off (aligned)
```

### Constraints

- `payload_off + chunk_size <= BUFFER_LEN_MAX`
- `chunk_size` must be aligned to `ALIGN` for O_DIRECT
- File offsets must be aligned (read at aligned offsets)

### Tail Handling (EOF)

O_DIRECT may not accept unaligned final reads. Options:

1) **Direct fast-path + buffered tail**:
   - Use O_DIRECT for aligned portion.
   - Read the final unaligned tail with a second buffered fd.
2) **Aligned short read**:
   - Issue aligned-length read and accept short read at EOF if supported.

We should implement option (1) explicitly for correctness.

---

## macOS: POSIX AIO (Async, Thread-Backed)

macOS has no io_uring. The most direct async file IO path available without
private APIs is POSIX AIO (`aio_read`, `aio_error`, `aio_return`), which is
thread-backed under the hood.

### Design

- Each worker owns a small fixed read-ahead window (AIO slots).
- Reads land into our preallocated buffers; overlap prefix is stitched
  in after completion so we can submit read-ahead without waiting.
- Completions are polled and ordered by sequence number to preserve
  deterministic chunk emission.

### Notes

- POSIX AIO is still implemented via system threads on macOS.
- Dispatch I/O could be explored later, but it does not expose buffer reuse.

---

## Per-Worker IO + Scan (Multi-Core Path)

Each worker is **self-contained**:

- Owns its **io_uring** (Linux) or dispatch queue (macOS).
- Owns its **BufferPool** and **ScanScratch**.
- Reads and scans files **without sharing buffers**.

### Work Distribution

**Preferred**: shard file IDs by hash or round-robin into per-worker queues.

This minimizes contention and preserves locality (each worker reads sequentially
within its own file set).

### Output

For max throughput:

- Disable stdout by default in perf runs, or
- Write per-worker outputs to separate buffers and merge at the end.

---

## API Shape (Proposed)

Introduce an IO abstraction with a non-allocating pump interface:

```
trait AsyncSource {
  fn pump(&mut self, out: &mut SpscRing<Chunk, N>) -> io::Result<bool>;
  fn is_done(&self) -> bool;
}
```

For single-thread max perf, we can bypass rings entirely and return
`Option<Chunk>` directly.

### Worker Runtime

```
struct Worker {
  engine: Arc<Engine>,
  source: Box<dyn AsyncSource>,
  scratch: ScanScratch,
  output: OutputSink,
}

fn run(&mut self) {
  while !source.is_done() {
    if let Some(chunk) = source.next_chunk()? {
      scan(chunk);
    } else {
      source.poll_completions()?;
    }
  }
}
```

---

## io_uring Performance Knobs (Linux)

Expose config options (benchable, not all defaults):

- Queue depth (QD)
- Fixed/registered buffers (`READ_FIXED`)
- `IORING_SETUP_SINGLE_ISSUER`
- `IORING_SETUP_COOP_TASKRUN` / `IORING_SETUP_DEFER_TASKRUN`
- Optional SQPOLL / IOPOLL (only for controlled experiments)

These should be behind a config struct and **measured**, not assumed.

---

## Bench Plan (perf-playground Alignment)

Use the existing io_uring sweep harness as a reference:

- Sweep QD with fixed buffers on/off
- Buffered vs O_DIRECT
- Chunk size sweep (aligned)
- CPU pinning for stable results

We should treat benchmark configs as first-class artifacts.

---

## Integration Plan (Phased)

1) **Single-thread Linux io_uring** with split-buffer overlap + O_DIRECT.
2) **macOS POSIX AIO** backend with async completion integration.
3) **Per-worker runtime** (multi-core ready) with per-worker IO+scan.
4) Bench and tune the knobs; lock in defaults.

---

## Open Questions

- Do we require strict "no allocations after init" on macOS?
  (POSIX AIO can keep allocations low, but completion polling still allocates
   unless we pre-size all internal buffers.)
- How to handle very small files where O_DIRECT overhead dominates?
- Should we support fallback to buffered IO on Linux for the final tail only?
