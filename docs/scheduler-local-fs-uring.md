# Local Filesystem Scanner with io_uring

The io_uring backend provides Linux-native asynchronous I/O for high-concurrency file scanning. Unlike blocking reads, io_uring enables dozens of concurrent read operations per I/O thread with minimal kernel overhead, making it ideal for cold-storage workloads (NVMe, network mounts, or high-latency devices).

## Module Purpose

`src/scheduler/local_fs_uring.rs` implements Linux io_uring-based file scanning with work-stealing CPU executors. The module separates I/O and CPU work across dedicated thread pools:

- **I/O threads** use io_uring to manage asynchronous reads with batched syscalls
- **CPU threads** run the work-stealing executor to scan chunks and emit findings
- **Buffer pool** transfers ownership: I/O threads acquire, CPU threads release

The architecture emphasizes:
- **High concurrency**: Hundreds of in-flight operations via efficient batch submission
- **Work conservation**: Never drops discovered files; uses backpressure instead
- **Correctness guarantees**: Chunk overlap, deduplication, exactly-once scanning semantics
- **Platform parity**: Single unified interface with blocking `local.rs` backend

## Why io_uring?

### Traditional Read Syscall Limitations

Blocking `read()` and `pread()` provide one I/O operation per syscall. For N concurrent files:
- **High syscall overhead**: Each thread must block until its single operation completes
- **Low utilization**: CPU and I/O threads must scale linearly with concurrency
- **Latency bound**: Long-latency storage (network mounts) stalls the thread

### io_uring Advantages

io_uring provides **kernel-level completion queue semantics** borrowed from hardware queues (NVMe, networking):

```
Traditional Blocking Reads:       io_uring Approach:
┌──────────────────────────┐     ┌──────────────────────────┐
│  read(fd, buf, 8KB)      │     │  Submit 128 reads at once│
│    [BLOCK on kernel]     │     │     (SQ entries)         │
│  (single op in flight)   │     │   [RETURN IMMEDIATELY]   │
└──────────────────────────┘     │ in_flight_ops = 128      │
                                 │                          │
   [Latency bound]               │  [Loop checks]           │
                                 │  - Submit more SQEs      │
                                 │  - Reap CQEs in batches  │
                                 │  - Spawn CPU tasks       │
                                 └──────────────────────────┘

                                 [Throughput bound]
```

**Benefits**:
- **Batched syscalls**: 1–2 syscalls per epoch regardless of concurrency (default: ~128 ops/batch)
- **CPU concurrency**: I/O threads stay active; CPU threads never block on I/O
- **High device utilization**: Hardware can parallelize; kernel queues disambiguate ordering
- **Tunable depth**: `io_depth` parameter controls latency/throughput tradeoff

### When to Use Each Backend

| Scenario | Backend | Reason |
|----------|---------|--------|
| Everything in page cache | `local.rs` (blocking) | Syscall overhead dominates; kernel optimizations (hugepages, prefetch) shine |
| Tiny files | `local.rs` | Context-switch overhead > I/O latency |
| Cold storage (NVMe, network) | `io_uring` | Kernel can parallelize; reduces thread count & context switches |
| High concurrency (1000+ files) | `io_uring` | Single I/O thread handles what blocking needs 64+ threads for |
| Latency-sensitive | `io_uring` | Bounded by device, not thread scheduling |

**Guidance**: Profile both backends on your actual workload. io_uring wins most on cold storage at high concurrency; blocking is simpler and sometimes faster on hot data.

## Architecture Overview

```mermaid
flowchart TB
    subgraph Discovery["Discovery Phase (main thread)"]
        Source["FileSource trait<br/>(VecFileSource)"]
        Walk["DFS file walk<br/>symlink-safe"]
        Budget["CountBudget<br/>max_in_flight_files"]
        Queue["Bounded channel<br/>file_queue_cap"]
    end

    subgraph IoPool["I/O Worker Threads (io_threads)"]
        IOW1["I/O Worker 0<br/>io_uring ring"]
        IOW2["I/O Worker 1<br/>io_uring ring"]
        IOwN["I/O Worker N<br/>io_uring ring"]
        FileState["Per-file state:<br/>size, offset, in_flight"]
        OpSlots["SQ/CQ slots<br/>io_depth entries"]
    end

    subgraph BufferPool["Shared Buffer Pool<br/>(FixedBufferPool)"]
        BufAcq["Try acquire()<br/>I/O thread"]
        BufRel["Release on drop<br/>CPU thread"]
    end

    subgraph CpuPool["CPU Worker Threads (cpu_workers)"]
        CPUW1["CPU Worker 0<br/>scan_chunk()"]
        CPUW2["CPU Worker 1<br/>scan_chunk()"]
        CpuWN["CPU Worker N<br/>scan_chunk()"]
    end

    subgraph Processing["Per-Chunk Processing"]
        Scan["engine.scan_chunk_into()"]
        DropPrefix["drop_prefix_findings()<br/>dedup overlap"]
        Emit["emit_findings_formatted()"]
    end

    subgraph Output["Output"]
        Sink["OutputSink<br/>(stdout, file, vec)"]
    end

    Source --> Walk
    Walk --> Budget
    Budget --> Queue
    Queue --> IOW1 & IOW2 & IOwN

    IOW1 & IOW2 & IOwN --> BufAcq
    BufAcq --> OpSlots
    OpSlots --> |"CQE completion"| Processing

    Processing --> Scan
    Scan --> DropPrefix
    DropPrefix --> Emit
    Emit --> Output

    Processing --> BufRel
    BufRel --> BufferPool

    style Discovery fill:#e3f2fd
    style IoPool fill:#fff3e0
    style BufferPool fill:#f3e5f5
    style CpuPool fill:#c8e6c9
    style Processing fill:#e8f5e9
    style Output fill:#ffccbc
```

## Queue Management: SQE and CQE Semantics

io_uring uses two ring buffers (user-space to kernel communication):

### Submission Queue (SQ)

The **submission queue** holds read requests pending kernel processing:

```rust
// Build a read request
let entry = opcode::Read::new(types::Fd(fd), ptr, len)
    .offset(base_offset)
    .build()
    .user_data(op_slot as u64);  // Correlation ID

// Push into SQ (user-space, lockfree)
ring.submission().push(&entry)?;

// Flush to kernel (syscall only if needed)
ring.submit()?;
```

**Key properties**:
- **User-space**: No syscall to add entries (until flush)
- **Lockfree**: Thread-safe ring buffer; tail advances atomically
- **Correlation**: `user_data` field lets us match CQEs back to ops
- **Batching**: Fill multiple SQEs before calling `submit()` (amortizes syscall)

### Completion Queue (CQ)

The **completion queue** reports finished operations:

```rust
// Reap all completed operations
for cqe in ring.completion() {
    let op_slot = cqe.user_data() as usize;  // Recover op_slot
    let result = cqe.result();                // Read syscall result or error

    if result < 0 {
        // Syscall error
        stats.read_errors += 1;
    } else {
        let bytes_read = result as usize;
        // Process buffer (bytes_read of data now available)
    }
}
```

**Key properties**:
- **User-space readable**: No syscall to read CQEs
- **Ordered**: Within each I/O thread, CQEs arrive in submission order
- **Reusable**: After processing a CQE, the entry is freed for next operation
- **Batched**: Loop reaps all pending CQEs; use `submit_and_wait(1)` if none available

### I/O Depth and Ring Sizing

```
┌──────────────────────────────────────────────────┐
│           io_uring Ring (cfg.ring_entries)       │
│                                                  │
│  ┌─────────────────────────┐                     │
│  │  Submission Queue (SQ)  │  <-- Add entries    │
│  │  - Up to io_depth       │                     │
│  │  - Batched push()       │                     │
│  └─────────────────────────┘                     │
│                                                  │
│  ┌─────────────────────────┐                     │
│  │  Completion Queue (CQ)  │  <-- Reap CQEs     │
│  │  - Ordered results      │                     │
│  │  - user_data matching   │                     │
│  └─────────────────────────┘                     │
└──────────────────────────────────────────────────┘

Default sizing: ring_entries=256, io_depth=128
Invariant: io_depth <= ring_entries - 1
```

| Parameter | Meaning | Tuning |
|-----------|---------|--------|
| `ring_entries` | Total SQ+CQ capacity | Larger = more concurrent ops, more kernel memory |
| `io_depth` | Max simultaneous reads per I/O thread | Tradeoff: higher = more parallelism, but diminishing returns |
| In-flight ops | Dynamically tracked; capped at `io_depth` | Prevents SQ overflow and kernel saturation |

## Integration with Scheduler

### FileSource Trait Integration

Like the blocking `local.rs` backend, io_uring respects the `FileSource` trait for discovery:

```rust
pub trait FileSource: Send + 'static {
    fn next_file(&mut self) -> Option<LocalFile>;
}
```

**Discovery flow**:
1. Main thread calls `source.next_file()` in a loop
2. For each file, acquire a `CountBudget` permit (blocks if `max_in_flight_files` reached)
3. Wrap file path + permit in `FileToken`, send to I/O thread
4. I/O threads process files from bounded channel
5. Token (and permit) stays alive until all chunks complete

This ensures: **No discovered files are dropped; all eventually scanned or errored.**

### CPU Task Spawning

When a read completes, the I/O worker spawns a CPU task:

```rust
let task = CpuTask::ScanChunk {
    token: Arc::clone(&st.token),      // Keeps file permit alive
    base_offset: op.base_offset,       // Overlap bytes
    prefix_len: actual_prefix as u32,  // Bytes to drop in findings
    len,                               // Total buffer length
    buf: op.buf,                       // Buffer handle (RAII)
};

if cpu.spawn(task).is_err() {
    // CPU executor shut down; mark file as failed
    stopping = true;
    st.failed = true;
    st.done = true;
} else {
    // Spawned successfully; re-queue file for next chunk if needed
    if !st.done && !st.failed && st.next_offset < st.size {
        ready.push_back(op.file_slot);
    }
}
```

### Overlap Carry and Chunk Stitching

Like blocking I/O, io_uring carries overlap bytes forward:

```
I/O Worker:                          CPU Worker:
┌──────────────────────┐            ┌──────────────────────┐
│ Read [base..base+len)│            │ scan_chunk_into()    │
│ into buffer          │            │                      │
└──────────────────────┘            └──────────────────────┘
        │                                     │
        └─────────────────────────────────────┘
                     Task spawn
                     (CpuTask::ScanChunk)

CPU:
- prefix_len bytes overlap
- Drop findings in [0..prefix_len)
- Emit findings in [prefix_len..len)
- Buffer released (RAII) when task completes
```

### FindingRecord Deduplication

Findings are deduplicated within each chunk by `(rule_id, root_hint, span)`:

```rust
fn dedupe_pending_in_place(p: &mut Vec<FindingRec>) {
    p.sort_unstable_by(|a, b| {
        (a.rule_id, a.root_hint_start, a.root_hint_end, a.span_start, a.span_end)
            .cmp(&(...))
    });
    p.dedup_by(|a, b| {
        a.rule_id == b.rule_id
            && a.root_hint_start == b.root_hint_start
            && a.root_hint_end == b.root_hint_end
            && a.span_start == b.span_start
            && a.span_end == b.span_end
    });
}
```

**Purpose**: Overlap regions can generate duplicate findings across chunks. Sorting + dedup ensures each finding is reported once per chunk.

## Setup and Configuration

### LocalFsUringConfig Structure

```rust
pub struct LocalFsUringConfig {
    // Concurrency
    pub cpu_workers: usize,              // CPU worker threads for scanning
    pub io_threads: usize,               // I/O threads running io_uring

    // I/O tuning
    pub ring_entries: u32,               // SQ/CQ size (e.g., 256)
    pub io_depth: usize,                 // Max concurrent ops per thread (reads + open/stat)

    // Memory and chunking
    pub chunk_size: usize,               // Payload bytes per chunk (e.g., 256 KB)
    pub max_in_flight_files: usize,      // Hard cap on discovered-but-not-done files
    pub file_queue_cap: usize,           // Bounded channel size: discovery → I/O
    pub pool_buffers: usize,             // Total buffers in global pool
    pub use_registered_buffers: bool,    // Use READ_FIXED (registered buffers)
    pub open_stat_mode: OpenStatMode,    // io_uring open/stat vs blocking
    pub resolve_policy: ResolvePolicy,   // openat2 resolve policy (Linux)

    // Safety options
    pub follow_symlinks: bool,           // O_NOFOLLOW if false
    pub max_file_size: Option<u64>,      // Skip files larger than N bytes
    pub seed: u64,                       // Executor determinism

    // Deduplication
    pub dedupe_within_chunk: bool,       // Dedupe findings per chunk
}
```

Open/stat controls:
- `open_stat_mode`: `UringPreferred` (default), `BlockingOnly`, or `UringRequired`.
- `resolve_policy`: Only applies to `openat2` when supported. `Default` matches current behavior; `NoSymlinks` and `BeneathRoot` are opt-in. When `openat2` is unavailable, resolve policy is ignored and the blocking open path is used.

### Default Configuration

```rust
pub fn default() -> Self {
    Self {
        cpu_workers: 8,                  // 8 CPU threads for scanning
        io_threads: 4,                   // 4 I/O threads with io_uring
        ring_entries: 256,               // SQ+CQ capacity
        io_depth: 128,                   // Up to 128 concurrent ops per I/O thread
        chunk_size: 256 * 1024,          // 256 KB chunks
        max_in_flight_files: 512,        // Cap on in-flight objects
        file_queue_cap: 256,             // Bounded discovery → I/O queue
        pool_buffers: 256,               // 256 buffers (>= io_threads * io_depth)
        use_registered_buffers: false,   // Off by default
        open_stat_mode: OpenStatMode::UringPreferred, // io_uring open/stat
        resolve_policy: ResolvePolicy::Default,       // No extra resolution constraints
        follow_symlinks: false,          // Safe default: O_NOFOLLOW
        max_file_size: None,             // No size filter
        seed: 1,                         // Deterministic executor
        dedupe_within_chunk: true,       // Dedupe by default
    }
}
```

### Configuration Validation

The `validate()` method enforces invariants:

```rust
pub fn validate<E: ScanEngine>(&self, engine: &E) {
    // Basic sizes
    assert!(self.cpu_workers > 0);
    assert!(self.io_threads > 0);
    assert!(self.ring_entries >= 8);

    // Buffer sizing
    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(self.chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);  // 4 MiB limit

    // io_depth must fit in ring
    let max_depth = (self.ring_entries as usize).saturating_sub(1);
    assert!(self.io_depth <= max_depth);

    // Pool must handle I/O saturation
    let min_pool = self.io_threads.saturating_mul(self.io_depth);
    assert!(
        self.pool_buffers >= min_pool,
        "pool_buffers >= io_threads * io_depth"
    );

    if self.use_registered_buffers {
        assert!(self.pool_buffers <= u16::MAX as usize);
    }
}
```

### Sizing Guidelines

| Parameter | Guidance | Example |
|-----------|----------|---------|
| `cpu_workers` | Match CPU cores for CPU-bound scanning; increase if I/O ops block on CPU | 8–16 |
| `io_threads` | 1–4 per NUMA node; io_uring thread scales well | 4 |
| `ring_entries` | 256–1024; larger allows more concurrent ops but uses more kernel memory | 256 |
| `io_depth` | 64–256; tradeoff between parallelism and latency | 128 |
| `chunk_size` | 64–256 KiB; larger reduces syscalls but increases memory per file | 256 KiB |
| `max_in_flight_files` | 100–1000; bounds discovery depth and memory | 512 |
| `file_queue_cap` | 64–256; bounded channel size to avoid unbounded discovery | 256 |
| `pool_buffers` | Must be >= `io_threads * io_depth`; recommend 2x for CPU pipeline headroom | 256–512 |

### Buffer Pool Configuration

The buffer pool is configured as a fixed global pool:

```rust
let pool = FixedBufferPool::new(
    buf_len,            // overlap + chunk_size
    cfg.pool_buffers,   // global total
);
```

**Why fixed global-only?**
- I/O threads and CPU threads share a single buffer table
- Global acquisition/release simplifies handoff
- Required for optional `READ_FIXED` (registered buffers)

**Memory bound**: Peak memory = `pool_buffers * (overlap + chunk_size)` ≈ 256 × 260 KB ≈ 67 MB

**Registered buffers**: When `use_registered_buffers` is true, `pool_buffers` must be <= `u16::MAX` (io_uring buffer table limit).

## Submission and Completion Flow

### Per-I/O-Thread Event Loop

Each I/O worker thread runs an event loop:

```
┌─────────────────────────────────────────────────────┐
│            I/O Worker Event Loop                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Check stop flag (signal for clean shutdown)    │
│                                                     │
│  2. Pull new files from bounded channel (batch)    │
│     - Calls open_file_safe() with O_NOFOLLOW       │
│     - Skips empty files                            │
│     - Creates FileState entry                      │
│     - Adds to 'ready' queue                        │
│                                                     │
│  3. Fill SQ up to io_depth:                        │
│     - Pop file from 'ready'                        │
│     - Try acquire buffer                          │
│     - Copy overlap prefix into buffer             │
│     - Submit payload-only read (Read/ReadFixed)   │
│     - Push to SQ (lockfree)                        │
│     - Store Op metadata in ops[]                  │
│     - Increment in_flight_ops                     │
│                                                     │
│  4. Flush SQ to kernel (syscall)                   │
│     - ring.submit()                                │
│                                                     │
│  5. Drain CQ; wait only if empty:                  │
│     - ring.completion().is_empty()                 │
│     - ring.submit_and_wait(1) if empty             │
│     - Or yield if buffers exhausted                │
│                                                     │
│  6. Reap all completed ops:                        │
│     - For each CQE:                               │
│       - Match to Op via user_data                 │
│       - If success: spawn CPU task (ScanChunk)    │
│       - If error or short read: mark file done    │
│       - Re-queue file for next chunk (if needed)  │
│       - Release buffer to pool (RAII)             │
│                                                     │
│  7. Decide next step:                              │
│     - If stop && in_flight == 0: exit loop       │
│     - If channel closed && no ready files: exit   │
│     - Else: continue (go to step 1)              │
│                                                     │
│  8. Drain any remaining in-flight ops             │
│     - block.submit_and_wait(N) until all done     │
│     - Safety: ensures kernel finishes before drop │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### File State Tracking

Each file has a `FileState` entry tracking its progress:

```rust
struct FileState {
    file: File,                  // Open file descriptor
    size: u64,                   // Size captured at open (snapshot)
    next_offset: u64,            // Offset for next chunk (monotonic)
    in_flight: u32,              // 0 or 1 (exactly one chunk in-flight)
    done: bool,                  // Reached EOF (monotonic)
    failed: bool,                // Read error or truncation (monotonic)
    token: Arc<FileToken>,       // Keeps permit alive
    overlap_buf: Box<[u8]>,      // Tail overlap bytes
    overlap_len: usize,          // Valid bytes in overlap_buf
}

// Invariants (enforced by loop):
// - in_flight is always 0 or 1 (single-chunk-in-flight per file)
// - done and failed are monotonic (once true, never reset)
// - next_offset only advances (never seeks backward)
```

### Operation Tracking

Each in-flight read operation has an `Op` entry:

```rust
struct Op {
    file_slot: usize,             // FileState index (for completion lookup)
    base_offset: u64,             // Offset of buffer[0] in file
    prefix_len: usize,            // Overlap bytes (dropped in findings)
    payload_len: usize,           // Bytes read from kernel
    buf: FixedBufferHandle,       // Buffer (must stay valid until CQE)
}

// Invariant: ops[user_data] is Some() while in-flight, None after completion
// Lifetime coupling: buffer stays valid via ops[] until CQE is reaped
```

### SQE Submission Example

```rust
// Calculate read region (payload-only; overlap already copied)
let offset = st.next_offset;                           // Current file offset
let prefix_len = st.overlap_len;                       // Bytes to skip in findings
let payload_len = (st.size - offset).min(chunk_size as u64) as usize;

// Build and push SQE (Read or ReadFixed)
let entry = opcode::Read::new(types::Fd(fd), ptr, payload_len as u32)
    .offset(offset)
    .build()
    .user_data(op_slot as u64);  // Correlation ID

ring.submission().push(&entry)?;  // Lockfree push
ops[op_slot] = Some(Op { ... });  // Record metadata
in_flight_ops += 1;
```

### CQE Completion Handling

```rust
// Reap completed reads
for cqe in ring.completion() {
    let op_slot = cqe.user_data() as usize;
    let result = cqe.result();  // Bytes read (or negative error)

    let op = ops[op_slot].take().unwrap();  // Remove from ops[]

    if result < 0 {
        // Syscall error (-ENOENT, -EIO, etc.)
        stats.read_errors += 1;
        st.failed = true;
        st.done = true;
    } else if result == 0 {
        // Unexpected EOF (file shrank)
        stats.read_errors += 1;
        st.failed = true;
        st.done = true;
    } else {
        let n = result as usize;
        if n < op.requested_len {
            // Short read (file truncated between reads)
            stats.short_reads += 1;
            st.done = true;  // Don't trust offset for next chunk
        }

        // Spawn CPU task to scan this chunk
        let actual_prefix = op.prefix_len.min(n);
        let task = CpuTask::ScanChunk {
            token: Arc::clone(&st.token),
            base_offset: op.base_offset,
            prefix_len: actual_prefix as u32,
            len: n as u32,
            buf: op.buf,  // Ownership transfer to CPU task
        };

        if cpu.spawn(task).is_ok() {
            // Task spawned; re-queue file if more chunks to read
            if !st.done && !st.failed && st.next_offset < st.size {
                ready.push_back(op.file_slot);
            } else {
                st.done = true;
            }
        }
    }

    free_ops.push(op_slot);
    in_flight_ops -= 1;
}
```

## Error Handling and Resilience

### Open Failures

Files that cannot be opened are tracked but not scanned:

```rust
let file = match open_file_safe(&w.path, cfg.follow_symlinks) {
    Ok(f) => f,
    Err(_) => {
        stats.files_open_failed += 1;
        drop(w.token);  // Permit released; file budget unblocked
        return;
    }
};
```

**Metrics**: `files_open_failed` counter incremented; file skipped without blocking discovery.

### Read Errors

Transient read errors (EIO, EAGAIN) mark the file as failed:

```rust
if result < 0 {
    // Syscall failed
    stats.read_errors += 1;
    st.failed = true;    // Don't retry or seek forward
    st.done = true;      // Clean up file on next iteration
}
```

**No retry logic**: Each I/O error is treated as fatal for that file (partial scans are unreliable). Discovery continues.

### Short Reads

If fewer bytes arrive than requested, the file is marked done:

```rust
if n < op.requested_len {
    // File shrank between size check and read
    stats.short_reads += 1;
    st.done = true;  // Don't trust next_offset
}
```

**Rationale**: Trusting `next_offset` after a short read could skip data or read past new EOF. Safer to abort and report what we got.

### Buffer Pool Starvation

If buffer pool is exhausted, I/O workers yield:

```rust
let Some(buf) = pool.try_acquire() else {
    // No buffers available; yield to CPU workers
    std::thread::yield_now();
    continue;  // Retry next loop iteration
};
```

**Invariant**: `pool_buffers >= io_threads * io_depth` ensures this isn't a deadlock (CPU workers eventually complete tasks and release buffers).

### Channel Closure

If the file queue channel closes, I/O workers drain in-flight operations:

```rust
match rx.try_recv() {
    Ok(w) => add_file(...),
    Err(chan::TryRecvError::Disconnected) => {
        channel_closed = true;
        // Continue processing ready files and draining in-flight
    }
}

// Later: if no ready files, exit loop (clean shutdown)
```

### Drain Before Exit

Before any I/O worker returns, all in-flight operations **must** complete:

```rust
// SAFETY: Drain any remaining in-flight ops before returning.
// This ensures the kernel finishes writing before we drop buffers.
if in_flight_ops > 0 {
    drain_in_flight(&mut ring, &mut ops, &mut in_flight_ops, &mut stats)?;
}

fn drain_in_flight(
    ring: &mut IoUring,
    ops: &mut [Option<Op>],
    in_flight_ops: &mut usize,
    stats: &mut UringIoStats,
) -> io::Result<()> {
    while *in_flight_ops > 0 {
        ring.submit_and_wait(1)?;
        for cqe in ring.completion() {
            // Reap and drop buffers
            let op_slot = cqe.user_data() as usize;
            if let Some(op) = ops.get_mut(op_slot).and_then(|o| o.take()) {
                drop(op.buf);  // Buffer returns to pool
                *in_flight_ops = in_flight_ops.saturating_sub(1);
            }
        }
    }
    Ok(())
}
```

**Why essential**: The kernel writes into buffers until CQEs are reaped. If we drop buffers before collecting CQEs, the kernel may write into freed memory (use-after-free).

## Platform Requirements

### Kernel Version

io_uring was introduced in **Linux 5.1 (2019)**. Minimum supported versions:

- **5.1+**: Basic io_uring, `Read` opcode
- **5.10+**: Faster ring polling, better edge cases
- **5.15+**: Fully stable for production use

Most modern distributions (Ubuntu 20.04+, Fedora 32+, RHEL 8.3+) meet requirements.

### Feature Gate

The module is **feature-gated** behind `io-uring`:

```toml
# Cargo.toml
[features]
io-uring = ["io-uring-crate"]  # Conditional compilation
```

```rust
#![cfg(all(target_os = "linux", feature = "io-uring"))]
```

**Effect**: Code only compiles on Linux with feature enabled. On other platforms or without feature, `io_uring` backend is unavailable (blocking `local.rs` backend always available).

### Kernel Capabilities

io_uring operations require **no special capabilities** (CAP_SYS_ADMIN). Regular unprivileged processes can use io_uring for file I/O.

However, some workloads may be restricted by:
- **AppArmor/SELinux**: File access policies still enforced
- **seccomp**: `io_uring` syscall may be blocked if not whitelisted
- **Namespace restrictions**: File visibility determined by mount namespace

### Fallback on Unavailable Kernels

If io_uring initialization fails (kernel too old, feature disabled), the error propagates:

```rust
let mut ring = IoUring::new(cfg.ring_entries)?;
// Returns io::Error if kernel doesn't support io_uring
```

**Recommendation**: Use blocking `local.rs` backend as fallback on older systems, or add version detection to gate feature use.

## Key Types and Functions

### Configuration

```rust
pub struct LocalFsUringConfig {
    pub cpu_workers: usize,
    pub io_threads: usize,
    pub ring_entries: u32,
    pub io_depth: usize,
    pub chunk_size: usize,
    pub max_in_flight_files: usize,
    pub file_queue_cap: usize,
    pub pool_buffers: usize,
    pub use_registered_buffers: bool,
    pub follow_symlinks: bool,
    pub max_file_size: Option<u64>,
    pub seed: u64,
    pub dedupe_within_chunk: bool,
}

impl LocalFsUringConfig {
    pub fn validate<E: ScanEngine>(&self, engine: &E);  // Panics on invalid config
}
```

### Statistics

```rust
pub struct LocalFsSummary {
    pub files_seen: u64,           // Total files discovered
    pub files_enqueued: u64,       // Files sent to I/O threads
    pub walk_errors: u64,          // Directory walk errors
    pub open_errors: u64,          // Files that couldn't be opened
    pub read_errors: u64,          // Read syscall errors
    pub files_skipped_size: u64,   // Files exceeding max_file_size
}

pub struct UringIoStats {
    pub files_started: u64,        // Files opened by I/O threads
    pub files_open_failed: u64,    // Open failures
    pub reads_submitted: u64,      // SQEs submitted to kernel
    pub reads_completed: u64,      // CQEs reaped
    pub read_errors: u64,          // Syscall errors or short reads
    pub short_reads: u64,          // File truncation between reads
}
```

### Entry Point

```rust
pub fn scan_local_fs_uring<E: ScanEngine>(
    engine: Arc<E>,
    roots: &[PathBuf],
    cfg: LocalFsUringConfig,
    out: Arc<dyn OutputSink>,
) -> io::Result<(LocalFsSummary, UringIoStats, MetricsSnapshot)>;
```

**Returns**: Tuple of discovery summary, I/O thread stats, and CPU executor metrics (chunks scanned, bytes scanned, wall-clock time).

**Errors**: Returns `io::Error` if:
- io_uring initialization fails (kernel too old)
- An I/O thread panics (unwrap/panic propagated)
- File discovery fails (permission denied on root)

### Internal Types

```rust
struct FileToken {
    _permit: CountPermit,           // Holds budget permit alive
    file_id: FileId,                // Unique file ID for output
    display: Arc<[u8]>,             // File path bytes (cheap clone)
}

struct FileWork {
    path: PathBuf,                  // Path to open
    size: u64,                      // Discovered size (double-checked at open)
    token: Arc<FileToken>,          // Permit + ID
}

struct FileState {
    file: File,                     // Opened file descriptor
    size: u64,                      // Actual file size (from fstat)
    next_offset: u64,               // Next chunk offset
    in_flight: u32,                 // 0 or 1 (single in-flight per file)
    done: bool,                     // Monotonic: reached EOF
    failed: bool,                   // Monotonic: read error
    token: Arc<FileToken>,
    overlap_buf: Box<[u8]>,         // Tail overlap bytes
    overlap_len: usize,             // Valid bytes in overlap_buf
}

struct Op {
    file_slot: usize,               // FileState index
    base_offset: u64,               // Offset of buffer[0] in file
    prefix_len: usize,              // Overlap bytes prepended
    payload_len: usize,             // Bytes read from disk
    buf: FixedBufferHandle,         // Buffer (lifetime to CQE)
}

enum CpuTask {
    ScanChunk {
        token: Arc<FileToken>,
        base_offset: u64,
        prefix_len: u32,
        len: u32,
        buf: FixedBufferHandle,
    },
}
```

### Core Functions

```rust
// Main loop for I/O worker thread
fn io_worker_loop<E: ScanEngine>(
    _wid: usize,
    rx: chan::Receiver<FileWork>,      // File queue
    pool: Arc<FixedBufferPool>,         // Shared buffer pool
    cpu: ExecutorHandle<CpuTask>,       // CPU executor handle
    engine: Arc<E>,
    cfg: LocalFsUringConfig,
    stop: Arc<AtomicBool>,              // Graceful shutdown flag
) -> io::Result<UringIoStats>;

// Discovery DFS walk
fn walk_and_send_files(
    root: &Path,
    cfg: &LocalFsUringConfig,
    budget: &Arc<CountBudget>,         // In-flight file limit
    tx: &chan::Sender<FileWork>,
    next_file_id: &mut u32,
    summary: &mut LocalFsSummary,
) -> io::Result<()>;

// Safe file open with O_NOFOLLOW option
fn open_file_safe(path: &Path, follow_symlinks: bool) -> io::Result<File>;

// Drain pending in-flight operations (called at shutdown)
fn drain_in_flight(
    ring: &mut IoUring,
    ops: &mut [Option<Op>],
    in_flight_ops: &mut usize,
    stats: &mut UringIoStats,
) -> io::Result<()>;

// CPU worker task runner
fn cpu_runner<E: ScanEngine>(task: CpuTask, ctx: &mut WorkerCtx<CpuTask, CpuScratch<E>>);

// Deduplication helper
fn dedupe_pending_in_place<F: FindingRecord>(p: &mut Vec<F>);

// Output formatting
fn emit_findings_formatted<E: ScanEngine, F: FindingRecord>(
    engine: &E,
    out: &Arc<dyn OutputSink>,
    out_buf: &mut Vec<u8>,
    display: &[u8],
    recs: &[F],
);
```

## Usage Example

```rust
use std::path::PathBuf;
use std::sync::Arc;

// Setup
let engine = Arc::new(MockEngine::default());
let roots = vec![PathBuf::from("/data")];
let cfg = LocalFsUringConfig {
    cpu_workers: 8,
    io_threads: 4,
    ring_entries: 256,
    io_depth: 128,
    chunk_size: 256 * 1024,
    max_in_flight_files: 512,
    file_queue_cap: 256,
    pool_buffers: 256,
    use_registered_buffers: false,
    open_stat_mode: OpenStatMode::UringPreferred,
    resolve_policy: ResolvePolicy::Default,
    follow_symlinks: false,
    max_file_size: Some(100 * 1024 * 1024),  // 100 MB max
    seed: 1,
    dedupe_within_chunk: true,
};
let output = Arc::new(VecSink::new());

// Validate
cfg.validate(&engine);

// Scan
let (summary, io_stats, cpu_metrics) =
    scan_local_fs_uring(engine, &roots, cfg, output)?;

// Results
println!("Files seen: {}", summary.files_seen);
println!("Files enqueued: {}", summary.files_enqueued);
println!("Open ops submitted: {}", io_stats.open_ops_submitted);
println!("Stat ops submitted: {}", io_stats.stat_ops_submitted);
println!("Open/stat fallbacks: {}", io_stats.open_stat_fallbacks);
println!("Reads completed: {}", io_stats.reads_completed);
println!("Chunks scanned: {}", cpu_metrics.chunks_scanned);
```

## Correctness and Invariants

### Single-Chunk-In-Flight Per File

**Invariant**: At most 1 read operation in-flight per file at any time.

**Why**: Allows deduplication logic to assume prefix-drop is valid (no gaps from out-of-order completions).

**Enforcement**:
```rust
// Files in 'ready' queue always have in_flight == 0
debug_assert_eq!(st.in_flight, 0);

// After push to SQ:
st.in_flight = 1;

// After CQE reaped:
st.in_flight = 0;
```

### Monotonic State Transitions

**Invariant**: `done` and `failed` flags are monotonic (once true, never reset to false).

**Why**: Simplifies state machine; once a file is finalized, it stays finalized.

**Enforcement**:
```rust
// Only set to true, never reset:
st.failed = true;
st.done = true;

// Check prevents double-processing:
if st.done || st.failed { continue; }
```

### Buffer Lifetime Coupling

**Invariant**: Buffer referenced by kernel must remain valid until CQE is reaped.

**Why**: io_uring kernel code writes to buffer asynchronously; freeing the buffer while write is in-flight causes use-after-free.

**Enforcement**:
```rust
// Buffer stored in ops[] until completion:
ops[op_slot] = Some(Op { buf, ... });

// On CQE:
let op = ops[op_slot].take();  // Remove from ops[]
drop(op.buf);                   // Now safe to free
```

### Drain Before Return

**Invariant**: All in-flight operations must complete before I/O worker returns.

**Why**: Ensures kernel finishes writing before buffers are freed (via pool cleanup).

**Enforcement**:
```rust
// At end of io_worker_loop:
if in_flight_ops > 0 {
    drain_in_flight(&mut ring, &mut ops, &mut in_flight_ops, &mut stats)?;
}
assert_eq!(in_flight_ops, 0);
```

### Budget Permit Lifetime

**Invariant**: FileToken (holding budget permit) stays alive as long as any chunk is queued or in-flight.

**Why**: Ensures `max_in_flight_files` backpressure remains in effect; prevents discovery from unbounded racing ahead.

**Enforcement**:
```rust
// Token created at discovery time:
let token = Arc::new(FileToken { _permit: permit, ... });

// Spawned CPU task holds Arc clone:
CpuTask::ScanChunk { token: Arc::clone(&token), ... }

// Permit released when last Arc is dropped (after scan completes)
```

## Testing

The module includes integration tests for correctness:

```rust
#[test]
fn uring_finds_boundary_spanning_match() {
    // Verify findings spanning chunk boundaries are detected
    // Pattern "SECRET" placed at offset 4 in 16-byte file
    // With chunk_size=8, pattern spans chunks [0..8) and [8..16)
    // Overlap carry ensures both pieces are scanned together
}

#[test]
fn global_only_pool_works() {
    // Verify buffer pool in global-only mode doesn't panic
    // and correctly acquires/releases buffers
}
```

## Performance Characteristics

### Throughput

io_uring typically achieves **higher throughput** than blocking I/O on:
- Cold cache (NVMe, network mounts): 2–10x improvement
- High concurrency (1000+ files): 5–50x improvement due to reduced thread count
- Hot cache: Blocking I/O often comparable or faster (syscall batching overhead)

### Latency

io_uring provides **latency isolation**:
- Individual file scans are not delayed by slow peers (no thread starvation)
- CPU workers are never blocked on I/O
- Bounded queue depths prevent runaway memory

### Memory

- **Peak memory**: `pool_buffers * (overlap + chunk_size)` ≈ 256 × 260 KB ≈ 67 MB
- **Per-thread overhead**: ~1 MB for ring buffer + file table
- **Total estimate**: 67 MB + 4 threads × 1 MB ≈ 71 MB

### Scalability

| Workload | Bottleneck | Optimization |
|----------|-----------|--------------|
| CPU-bound (large files) | CPU time | Increase `cpu_workers` |
| I/O-bound (many small files) | I/O throughput | Increase `io_depth` or `io_threads` |
| Memory-constrained | Buffer pool | Reduce `pool_buffers` or `chunk_size` |
| Discovery-constrained | File enumeration | Increase discovery thread priority or parallelize walk |

## Future Improvements

- **Conditional ring polling**: Use poll-based completion for ultra-low latency
- **Per-NUMA ring allocation**: Pin rings to NUMA nodes for better locality
- **Retry on transient errors**: Distinguish permanent vs. transient read errors
- **Adaptive io_depth**: Adjust based on real-time latency/throughput metrics
