# Memory Management

Buffer lifecycle and pool management in scanner-rs.

```mermaid
flowchart TB
    subgraph Init["Initialization"]
        PoolInit["BufferPool::new(136)"]
        NodeInit["NodePoolType::init(136)"]
        BitInit["DynamicBitSet::empty(136)"]
        Alloc["alloc(136 * 2MB, 4096)"]
    end

    subgraph Pool["BufferPool State"]
        Inner["BufferPoolInner"]
        NodePool["NodePoolType<br/>2MB nodes, 4KB align"]
        Available["available: Cell&lt;u32&gt;"]
        Bitset["DynamicBitSet<br/>free slot tracking"]
    end

    subgraph Acquire["Acquire Flow"]
        TryAcq["try_acquire()"]
        CheckAvail{{"available > 0?"}}
        FindFree["find_first_set()"]
        UnsetBit["free.unset(idx)"]
        CalcPtr["ptr = buffer + idx * NODE_SIZE"]
        Handle["BufferHandle { pool, ptr }"]
    end

    subgraph Release["Release Flow"]
        Drop["BufferHandle::drop()"]
        ValidatePtr["Validate ptr in range"]
        CalcIdx["idx = (ptr - buffer) / NODE_SIZE"]
        SetBit["free.set(idx)"]
        IncAvail["available += 1"]
    end

    subgraph Usage["Buffer Usage"]
        Reader["ReaderStage"]
        Chunk["Chunk { buf: BufferHandle }"]
        Scanner["ScanStage"]
    end

    PoolInit --> NodeInit
    NodeInit --> BitInit
    BitInit --> Alloc

    Inner --> NodePool
    Inner --> Available
    NodePool --> Bitset

    TryAcq --> CheckAvail
    CheckAvail --> |"no"| None["None"]
    CheckAvail --> |"yes"| FindFree
    FindFree --> UnsetBit
    UnsetBit --> CalcPtr
    CalcPtr --> Handle

    Handle --> Reader
    Reader --> Chunk
    Chunk --> Scanner
    Scanner --> Drop

    Drop --> ValidatePtr
    ValidatePtr --> CalcIdx
    CalcIdx --> SetBit
    SetBit --> IncAvail

    style Init fill:#e3f2fd
    style Pool fill:#fff3e0
    style Acquire fill:#e8f5e9
    style Release fill:#ffebee
    style Usage fill:#f3e5f5
```

## Pool Structure

```mermaid
classDiagram
    class BufferPool {
        -Rc~BufferPoolInner~ inner
        +new(capacity: usize) BufferPool
        +try_acquire() Option~BufferHandle~
        +acquire() BufferHandle
        +buf_len() usize
    }

    class BufferPoolInner {
        -UnsafeCell~NodePoolType~ pool
        -Cell~u32~ available
        -u32 capacity
        +acquire_slot() NonNull~u8~
        +release_slot(ptr: NonNull~u8~)
    }

    class NodePoolType {
        -NonNull~u8~ buffer
        -usize len
        -DynamicBitSet free
        +init(node_count: u32) Self
        +acquire() NonNull~u8~
        +release(node: NonNull~u8~)
        +reset()
        +deinit()
    }

    class BufferHandle {
        -Rc~BufferPoolInner~ pool
        -NonNull~u8~ ptr
        +as_slice() &[u8]
        +as_mut_slice() &mut [u8]
        +clear()
    }

    class DynamicBitSet {
        -Vec~u64~ words
        -usize bit_length
        +is_set(idx: usize) bool
        +set(idx: usize)
        +unset(idx: usize)
        +iter_set() Iterator
    }

    BufferPool --> BufferPoolInner
    BufferPoolInner --> NodePoolType
    NodePoolType --> DynamicBitSet
    BufferHandle --> BufferPoolInner
```

## Memory Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                    NodePoolType Buffer                           │
│                    (136 * 2MB = 272MB)                          │
├─────────────┬─────────────┬─────────────┬───────┬─────────────┤
│   Node 0    │   Node 1    │   Node 2    │  ...  │   Node 135  │
│   2MB       │   2MB       │   2MB       │       │   2MB       │
│   align=4K  │   align=4K  │   align=4K  │       │   align=4K  │
└─────────────┴─────────────┴─────────────┴───────┴─────────────┘

DynamicBitSet (136 bits = 3 u64 words):
┌─────────────────────────────────────────────────────────────────┐
│ word[0]: bits 0-63    │ word[1]: bits 64-127 │ word[2]: 128-135│
│ 1=free, 0=acquired    │                      │ (8 valid bits)  │
└─────────────────────────────────────────────────────────────────┘
```

## Constants

```rust
pub const BUFFER_LEN_MAX: usize = 2 * 1024 * 1024;  // 2MB per buffer
pub const BUFFER_ALIGN: usize = 4096;               // 4KB alignment

pub const PIPE_CHUNK_RING_CAP: usize = 128;         // Max chunks in flight
pub const PIPE_POOL_CAP: usize = PIPE_CHUNK_RING_CAP + 8;  // 136 buffers
```

## Chunk Structure

```mermaid
graph TB
    subgraph ChunkLayout["Chunk Data Layout"]
        Prefix["prefix_len bytes<br/>(overlap from previous)"]
        Payload["payload bytes<br/>(new data read)"]
    end

    subgraph ChunkStruct["Chunk Fields"]
        FileId["file_id: FileId"]
        BaseOffset["base_offset: u64"]
        Len["len: u32 (total)"]
        PrefixLen["prefix_len: u32"]
        Buf["buf: BufferHandle"]
    end

    Prefix --> |"data()[..prefix_len]"| ChunkStruct
    Payload --> |"payload()[prefix_len..]"| ChunkStruct
```

```rust
pub struct Chunk {
    pub file_id: FileId,
    pub base_offset: u64,    // File offset where chunk starts
    pub len: u32,            // Total bytes (prefix + payload)
    pub prefix_len: u32,     // Overlap bytes from previous chunk
    pub buf: BufferHandle,   // Owned buffer handle
}

impl Chunk {
    // Full data including overlap prefix
    pub fn data(&self) -> &[u8] {
        &self.buf.as_slice()[..self.len as usize]
    }

    // Payload only (excludes overlap)
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_slice()[self.prefix_len as usize..self.len as usize]
    }
}
```

## Overlap Preservation

```mermaid
sequenceDiagram
    participant File as File
    participant Reader as FileReader
    participant Tail as tail: Vec<u8>
    participant Buf as BufferHandle

    Note over Reader: Chunk 1 (offset=0)
    File->>Buf: read 1MB
    Buf->>Tail: copy last `overlap` bytes
    Reader->>Pipeline: emit Chunk { prefix_len: 0 }

    Note over Reader: Chunk 2 (offset=1MB)
    Tail->>Buf: copy to buf[0..overlap]
    File->>Buf: read 1MB at buf[overlap..]
    Buf->>Tail: copy last `overlap` bytes
    Reader->>Pipeline: emit Chunk { prefix_len: overlap }

    Note over Reader: Pattern spanning chunks
    Note over Reader: Original: [....PATTERN....]
    Note over Reader: Chunk 1:  [....PATT]
    Note over Reader: Chunk 2:  [PATTERN....] (prefix has PATT)
```

The overlap ensures patterns that span chunk boundaries are detected:
- `overlap = engine.required_overlap()`
- `required_overlap = max_window_diameter_bytes + max_anchor_pat_len - 1`

## ScanScratch Per-Chunk State

```rust
pub struct ScanScratch {
    out: Vec<FindingRec>,           // Output findings
    work_q: Vec<WorkItem>,          // Transform work queue
    work_head: usize,               // Current work item index
    slab: DecodeSlab,               // Decoded buffer storage
    seen: FixedSet128,              // Deduplication set
    total_decode_output_bytes: usize,
    work_items_enqueued: usize,
    accs: Vec<[HitAccumulator; 3]>, // Per-rule, per-variant accumulators
    touched_pairs: ScratchVec<u32>, // Scratch list of touched (rule, variant)
    touched: DynamicBitSet,         // Bitset of touched (rule, variant)
    windows: ScratchVec<SpanU32>,   // Temp window storage
    expanded: ScratchVec<SpanU32>,  // Expanded two-phase windows
    spans: ScratchVec<SpanU32>,     // Transform span candidates
    gate: GateScratch,              // Gate streaming scratch
    step_arena: StepArena,          // Decode provenance
    utf16_buf: Vec<u8>,             // UTF-16 decode output
    steps_buf: Vec<DecodeStep>,     // Finding materialization temp
}
```

All vectors are reused across chunks via `reset_for_scan()`:
- Vectors are cleared but retain capacity
- `seen` uses generation-based O(1) reset
- Avoids per-chunk allocation overhead
