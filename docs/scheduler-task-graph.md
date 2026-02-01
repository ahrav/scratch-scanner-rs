# Task Graph: Scheduler Object Lifecycle

## Module Overview

The `task_graph` module defines a **typed, state-machine-based task model** for the scanner scheduler. Rather than generic closures, tasks are explicit Rust enum variants that track object context, frontier permits, and buffer lifetimes. This design ensures memory safety, enables introspection for metrics, and avoids unnecessary heap allocations.

**Core abstraction**: Objects flow through a deterministic state machine as they are discovered, fetched, and scanned. Each state transition is triggered by specific events (discovery, I/O completion, scan completion).

---

## State Machine: Object Lifecycle FSM

### High-Level Flow

```
                              ┌─────────────────────────────────┐
                              │   Frontier Permit Acquired      │
                              │  (Object Context Created)       │
                              └────────────┬────────────────────┘
                                           │
                                           ▼
                                    ┌────────────────┐
                                    │  FetchSync(0)  │
                                    │  Read Chunk 0  │
                                    └────────┬───────┘
                                             │
                        ┌────────────────────┼────────────────────┐
                        │                    │                    │
                        ▼                    ▼                    ▼
                   ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐
                   │ Scan(0)      │  │FetchSync(N)  │  │ Archive Entry?  │
                   │ Process Data │  │ Read Next    │  │ Spawn Enumerate │
                   └──────┬───────┘  │              │  │ for Nested Objs │
                          │          └──────┬───────┘  └─────────────────┘
                          │                 │
                          │                 ▼
                          │          ┌──────────────┐
                          │          │ Scan(N)      │
                          │          │ Final Chunk  │
                          │          └──────┬───────┘
                          │                 │
                          └────────┬────────┘
                                   │
                                   ▼
                        ┌────────────────────────────┐
                        │ ObjectCtx Last Ref Dropped │
                        │ Frontier Permit Released   │
                        │ Object Lifecycle Complete  │
                        └────────────────────────────┘
```

### State Definitions

#### Enumerate → FetchSync Transition
- **Trigger**: Enumeration discovers objects from a source
- **Precondition**: `frontier.try_acquire_ctx()` succeeds
- **Action**:
  - Create `ObjectCtx` wrapping `ObjectDescriptor` + `ObjectPermit`
  - Wrap in `Arc<ObjectCtx>` (ObjectRef)
  - Enqueue `FetchSync { obj, offset: 0 }`
- **Postcondition**: Frontier in_flight count increments

#### FetchSync → Scan Transition
- **Trigger**: Read of a buffer from storage completes
- **Action**:
  - Clone `ObjectRef` for Scan task
  - Enqueue `Scan { obj, buffer, base_offset, len, prefix_len }`
  - If more data remains: clone `ObjectRef` and enqueue next `FetchSync`
- **Key Point**: `ObjectRef` is cloned (atomic increment), not deep copied

#### Scan → (Detection/Findings)
- **Trigger**: Scan task execution
- **Action**:
  - Run detection engine on buffer
  - Emit findings
  - Return buffer to pool
  - May spawn `FetchSync` or `Enumerate` for nested objects (archives)
- **Postcondition**: Scan task drops its `ObjectRef`

#### Permit Release (All References Dropped)
- **Trigger**: Last task holding `ObjectRef` completes
- **Mechanism**: `Arc::drop()` detects ref count = 0, calls `ObjectCtx::drop()`
- **Effect**: `ObjectPermit` in `ObjectCtx` drops, releases frontier quota
- **Guarantee**: Exactly once per object

---

## Transition Rules

### Prerequisite: Frontier Acquisition

Before an object can transition from **Enumerate** to **FetchSync**, a frontier permit must be acquired:

```rust
// In Enumerate task
if let Some(obj_ref) = frontier.try_acquire_ctx(descriptor, file_id) {
    spawn(Task::FetchSync { obj: obj_ref, offset: 0 });
} else {
    // Frontier at capacity; re-enqueue self for later
    spawn(Task::Enumerate { source_id, cursor });
    return;
}
```

**Non-blocking requirement**: `Enumerate` MUST use `try_acquire_ctx()`, never `acquire()`. Blocking on frontier from executor threads causes deadlock.

### FetchSync → Scan Spawning

```rust
// After successful read
let obj_for_scan = Arc::clone(&obj);
spawn(Task::Scan {
    obj: obj_for_scan,
    buffer,
    base_offset,
    len,
    prefix_len
});

// If more data remains
if offset + CHUNK_SIZE < file_size {
    let obj_for_next = Arc::clone(&obj);
    spawn(Task::FetchSync {
        obj: obj_for_next,
        offset: offset + CHUNK_SIZE
    });
}
```

**Arc cloning**: Each clone increments the reference count atomically. The original `obj` can drop without releasing the permit as long as other clones exist.

### Nested Object Handling (Archives)

During `Scan`, if detection finds an archive or nested container:

```rust
// Inside Scan task
if detection_finds_archive(buffer) {
    // Spawn Enumerate for archive contents
    spawn(Task::Enumerate {
        source_id: nested_source_id,
        cursor: EnumCursor::Start
    });
}
```

The nested enumeration acquires its own frontier permits independently.

### Re-enqueueing on Backpressure

When the frontier is at capacity, `Enumerate` does not block or drop work:

```rust
// Try to spawn objects
for object in batch {
    if let Some(obj_ref) = frontier.try_acquire_ctx(descriptor, file_id) {
        spawn(Task::FetchSync { obj: obj_ref, offset: 0 });
        spawned_count += 1;
    } else {
        // Frontier full; re-enqueue Enumerate and stop
        let remaining_cursor = EnumCursor::Continue(Box::new(updated_state));
        spawn(Task::Enumerate { source_id, cursor: remaining_cursor });
        break;
    }
}
```

This is **work-conserving**: no objects are dropped, only delayed.

---

## Invariants

### Work-Conserving
- **Guarantee**: Every discovered object eventually scans (or is explicitly cancelled).
- **Mechanism**: Frontier permits are refcounted; `Enumerate` re-enqueues on backpressure.
- **Violation**: If an object's `Arc` is dropped without releasing its permit, frontier capacity leaks.

### Bounded Frontier
- **Guarantee**: Number of in-flight objects ≤ `frontier.capacity()`
- **Mechanism**: `frontier.try_acquire()` returns `None` if capacity exhausted.
- **Verification**: Enumerate re-enqueues; never blocks waiting for space.

### Leak-Free Permit Lifetime
- **Guarantee**: Each frontier permit is released exactly once.
- **Mechanism**: `ObjectPermit` is RAII; lives inside `ObjectCtx`. When `Arc<ObjectCtx>` strong count reaches 0, `ObjectCtx::drop()` runs, releasing the permit.
- **Invariant**: The permit lifetime exactly matches the lifetime of all tasks touching the object.

**Chain example** (3-chunk object, 2 scans):
```
FetchSync(0)  [obj_ref count = 1, permit held]
  ├─ clone → FetchSync(1) [count = 2]
  ├─ clone → Scan(0)      [count = 3]
  └─ drop   [FetchSync(0) completes, count = 2]

FetchSync(1)  [count = 2, permit held]
  ├─ clone → Scan(1)      [count = 3]
  └─ drop   [FetchSync(1) completes, count = 2]

Scan(0)       [count = 2, permit held]
  └─ drop    [Scan(0) completes, count = 1]

Scan(1)       [count = 1, permit held]
  └─ drop    [Scan(1) completes, count = 0]
             [ObjectCtx drops, permit released]
```

### Bounded Task Queue Memory
- **Guarantee**: Task queue size is predictable.
- **Mechanism**:
  - `ObjectRef` is 8 bytes (just an Arc pointer), not 24+ bytes (PathBuf).
  - Tasks are packed efficiently into deques.
  - `MAX_FETCH_SPAWNS_PER_ENUM = ENUM_BATCH_SIZE = 32` limits spawning burst.
- **Effect**: A single Enumerate can queue ≤ 32 FetchSync tasks, then re-enqueues itself.

### Non-Blocking Enumerate
- **Guarantee**: Enumerate tasks never block on frontier.acquire().
- **Mechanism**: Uses `try_acquire_ctx()` only; re-enqueues on failure.
- **Correctness**: Prevents deadlock when all executor threads are running Enumerate tasks.

---

## Object Types and Their Flow

### Regular Files

1. **Enumerate**: Discover file path, size hint
2. **FetchSync(0)**: Read first chunk (0..CHUNK_SIZE)
3. **Scan(0)**: Detect patterns, emit findings
4. **FetchSync(1)**: (if file > CHUNK_SIZE) Read next chunk
5. **Scan(1)**: Continue scanning with overlap prefix for pattern boundary crossing
6. ...repeat until EOF...
7. **All tasks drop → ObjectCtx drops → Permit released**

### Archive Files (ZIP, TAR, etc.)

1. **Enumerate**: Discover archive.zip
2. **FetchSync(0)**: Read archive chunks
3. **Scan(0)**: Detection recognizes archive structure
   - **Spawns**: `Enumerate { source_id: nested_source_id, ... }`
4. **Nested Enumerate**: Extract and enumerate archive contents
5. **For each nested object**: Repeat regular file flow above
6. **Archive object + nested objects**: Each maintains own frontier permit

### Chunks within a Single Object

Within a single file:
- **Chunk 0**: offset [0, CHUNK_SIZE), base_offset = 0
- **Chunk 1**: offset [CHUNK_SIZE, 2*CHUNK_SIZE), base_offset = CHUNK_SIZE
- **Chunk N**: offset with overlap prefix for deduplication

**Overlap prefix** (prefix_len):
- Allows patterns to span chunk boundaries
- Scan task receives: `buffer[0..len]` where `buffer[0..prefix_len]` is copy-on-write from previous chunk
- `bytes_scanned` metric counts only non-overlap bytes

---

## Coordination with Executor

### Task Dispatch

The executor runs tasks from work-stealing deques:

```
┌──────────────────────────────┐
│   Executor (N worker threads)│
├──────────────────────────────┤
│ Global task queue            │
│ ┌────────────────────────────┤
│ │ Enumerate { source_id, ..} │
│ │ FetchSync { obj, offset }  │
│ │ Scan { obj, buffer, ... }  │
│ └────────────────────────────┤
└──────────────────────────────┘
         │
    Dequeue
         │
         ▼
┌──────────────────────────────┐
│  Match Task variant          │
├──────────────────────────────┤
│ Enumerate → enumerate()      │
│ FetchSync → fetch_sync()     │
│ Scan      → scan()           │
└──────────────────────────────┘
```

### Frontier and Backpressure Integration

```
Executor Threads        ObjectFrontier (Arc<CountBudget>)
────────────────                 │
    │                            │
Enumerate task ─try_acquire_ctx─▶│
    │                  ┌─────────┼─────────┐
    │                  │         │         │
    ├─ Success ──────▶ │ Spawn   │ Deduct  │
    │   (Some)        │ FetchSync│ quota   │
    │                 │         │         │
    ├─ Failure ──────▶│ Re-enq  │ Return  │
    │   (None)        │ self    │ later   │
    │                 └─────────┼─────────┘
    │
FetchSync task
    │ (completes)
    ▼
 Arc clone
    │ (dropped)
    │ (if last ref)
    ▼
ObjectCtx::drop()
    │
    ▼
ObjectPermit::drop()
    │
    ▼
CountBudget::release(1)
```

### Lock-Free Coordination

- **ObjectFrontier**: Backed by `Arc<CountBudget>` (atomic counter, no locks)
- **ObjectRef cloning**: Atomic increment (no locks)
- **Task enqueueing**: Work-stealing deque operations (minimal synchronization)

---

## Key Structures and Their Roles

### ObjectCtx
- **Role**: Anchor for all metadata about an in-flight object
- **Fields**:
  - `descriptor: ObjectDescriptor` - path, size hint, IDs
  - `permit: ObjectPermit` - RAII slot in frontier (not readable, just held)
  - `file_id: FileId` - handle for scan engine
- **Lifetime**: Created when frontier permit acquired, dropped when last `Arc<ObjectCtx>` drops
- **Cloning**: Wrapped in `Arc` for cheap sharing across tasks

### ObjectRef
- **Type**: `Arc<ObjectCtx>`
- **Role**: Cheap shared reference to object state
- **Size**: 8 bytes (just a pointer)
- **Clone cost**: Atomic increment (~10ns)

### Task Enum
- **Size**: ~64-80 bytes (fits in 2 cache lines)
- **Variants**:
  ```rust
  enum Task {
      Enumerate { source_id, cursor },
      FetchSync { obj, offset },
      Scan { obj, buffer, base_offset, len, prefix_len },
  }
  ```
- **Role**: Typed representation of work unit
- **Advantage**: Introspectable for metrics; no heap indirection vs boxed closure

### ObjectDescriptor
- **Size**: ~40 bytes
- **Role**: Metadata about discovered object
- **Fields**:
  - `path: PathBuf` - filesystem or URI path
  - `size_hint: u64` - discovered size (may differ from actual)
  - `object_id: ObjectId` - run-scoped unique ID
  - `source_id: SourceId` - which source this came from

### ObjectFrontier
- **Role**: Bounded in-flight object quota
- **Backed by**: `Arc<CountBudget>` (lock-free atomic counter)
- **API**:
  - `try_acquire_ctx()` - non-blocking, returns `Option<ObjectRef>`
  - `acquire()` - blocking, use only from non-executor threads
  - `in_flight()` / `capacity()` / `available()` - metrics queries

### EnumCursor
- **Role**: Resumable enumeration state
- **Variants**:
  - `Start` - begin enumeration
  - `Continue(Box<CursorState>)` - resume at this state
  - `Done` - enumeration complete
- **CursorState** (source-specific):
  - `FsDir { dirs, entries }` - filesystem traversal stack + batch
  - `Offset(u64)` - byte offset for streaming sources
  - `Token(String)` - pagination token for APIs (S3, etc.)
- **Important**: Does NOT implement Clone; moving cursor is explicit

### TsBufferHandle
- **Role**: Handle to buffer from thread-safe pool
- **Lifetime**: Owned by Scan task; returned to pool on drop
- **Size**: Capped at 4MB (`BUFFER_LEN_MAX`)

### TaskMetrics
- **Role**: Per-worker aggregate statistics
- **Fields**:
  - `enumerate_count` - total Enumerate tasks run
  - `objects_discovered` - count of objects handed to FetchSync
  - `enumerate_backpressure` - re-enqueues due to frontier full
  - `fetch_sync_count` - FetchSync tasks run
  - `bytes_fetched` - total bytes read (includes overlap)
  - `scan_count` - Scan tasks run
  - `bytes_scanned` - payload bytes (excludes overlap prefix)
  - `objects_completed` - objects with permit released
- **Aggregation**: Per-worker metrics merged after executor shutdown

---

## Performance Characteristics

| Operation | Cost | Notes |
|-----------|------|-------|
| Task dispatch (match variant + call) | ~5ns | Single match statement, CPU branch prediction |
| ObjectRef clone | ~10ns | Atomic increment, no allocation |
| FetchSync spawning | ~20ns each | One Arc clone per task, queue enqueue |
| Task enqueue | ~50ns | Work-stealing deque operation |
| Frontier try_acquire | ~5ns | Atomic compare-and-swap, no lock |
| Frontier permit drop | ~10ns | Atomic decrement |

**Memory Layout**:
- Task enum: 64-80 bytes (fits 2 cache lines)
- ObjectDescriptor: ~40 bytes
- ObjectRef: 8 bytes (just Arc pointer)
- ObjectCtx: ~80 bytes (descriptor + permit + file_id)

---

## Correctness Guarantees

### Property: Work-Conserving Under Backpressure

**Statement**: If the frontier is full, `Enumerate` will re-enqueue itself and the object will not be lost.

**Proof**:
1. Frontier capacity is finite and known: `frontier.capacity()`
2. `Enumerate` uses `try_acquire_ctx()`, which returns `None` when `in_flight >= capacity`
3. On `None`, Enumerate re-enqueues itself with updated cursor state
4. Updated cursor state preserves the batch being processed
5. Eventually, permits are released (as objects complete) and `try_acquire_ctx()` succeeds

### Property: Permit Released Exactly Once

**Statement**: Each object's frontier permit is released exactly once, never earlier and never twice.

**Proof**:
1. Permit is created when `frontier.try_acquire_ctx()` succeeds (once per object)
2. Permit is wrapped in `ObjectPermit`, which is moved into `ObjectCtx`, not cloned
3. `ObjectCtx` is wrapped in `Arc`, shared across tasks
4. Permit lifetime is linked to `ObjectCtx` lifetime via RAII
5. `ObjectCtx` drops only when `Arc::strong_count()` reaches 0 (once)
6. `ObjectPermit::drop()` releases the permit exactly once

### Property: Non-Blocking Enumerate (Deadlock Prevention)

**Statement**: No executor thread running `Enumerate` will block waiting for frontier permits.

**Proof**:
1. `Enumerate` uses only `frontier.try_acquire_ctx()`, never `frontier.acquire()`
2. `try_acquire_ctx()` returns immediately: `Some(ctx)` or `None`
3. If `None`, Enumerate re-enqueues itself and returns (no wait)
4. Therefore, no executor thread blocks on frontier permits

**Consequence**: If all N executor threads are running, and all are in the Enumerate handler, each will re-enqueue and yield. One will eventually dequeue a non-Enumerate task.

---

## Testing Strategy

The module includes comprehensive tests validating state machine correctness:

1. **Frontier Acquisition**: `frontier_try_acquire_does_not_block()`
   - Verifies `try_acquire()` returns `None` at capacity

2. **Permit Lifetime**: `object_ctx_releases_permit_on_drop()`
   - Single object; drop ObjectCtx; verify permit released

3. **Multi-Chunk Permit Lifetime**: `multi_chunk_object_permit_lifetime()`
   - Simulate FetchSync → FetchSync → Scan → Scan chain
   - Verify permit released only after all tasks drop

4. **Concurrent Completion**: `concurrent_object_completion()`
   - 10 threads acquiring 10 objects concurrently
   - Verify all permits released when all objects done

5. **Size Assertions**:
   - Task size ≤ 128 bytes
   - ObjectDescriptor size ≤ 64 bytes
   - Ensures cache efficiency

---

## Summary

The task graph module implements a **typed, state-machine-driven scheduler** with these key features:

1. **Explicit State Machine**: Enumerate → FetchSync → Scan → Completion
2. **Refcounted Permits**: `Arc<ObjectCtx>` ensures permit release exactly once
3. **Work-Conserving Backpressure**: Enumerate re-enqueues on frontier full, never drops work
4. **Non-Blocking Coordination**: All frontier operations are non-blocking; Enumerate uses `try_acquire()`
5. **Introspectable Tasks**: Typed enum enables metrics and debugging
6. **Efficient Memory**: ObjectRef is 8 bytes, tasks fit in 2 cache lines
7. **Lock-Free**: Atomic counters, no locks in critical paths

This design ensures memory safety, prevents deadlocks, bounds resource consumption, and makes correct behavior automatic through RAII.
