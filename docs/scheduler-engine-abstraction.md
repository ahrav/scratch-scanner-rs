# Scheduler Engine Abstraction Layer

## Module Purpose

The `scheduler::engine_trait` module defines a trait-based abstraction layer that decouples the scheduler from specific detection engine implementations. This abstraction enables the scheduler to work seamlessly with both **mock engines** (for testing) and **real production engines** (for actual secret scanning).

The module exports three core traits:
- **`ScanEngine`** - The primary scanning interface
- **`EngineScratch`** - Per-worker scratch state management
- **`FindingRecord`** - Finding representation abstraction

This design allows the scheduler logic to remain engine-agnostic while supporting different underlying implementations with varying data types and behaviors.

---

## ScanEngine Trait

### Purpose

`ScanEngine` defines the primary interface that the scheduler uses to perform chunk-based scanning operations. It abstracts the core functionality without coupling to a specific engine implementation.

### Key Characteristics

- **Stateless Design**: The engine itself is immutable and can be safely shared across all worker threads (`Send + Sync`)
- **Per-Worker State**: All mutable state is isolated in the associated `Scratch` type, ensuring thread safety without synchronization overhead
- **Overlapping Chunks**: The engine declares a `required_overlap()` that the scheduler must respect when dividing work

### Core Methods

#### `required_overlap() -> usize`

**Purpose**: Returns the minimum byte overlap required between consecutive chunks.

**Contract**: The scheduler guarantees that if chunk N spans `[base, base + len)`, chunk N+1 will start no later than `base + len - overlap`, ensuring no findings are missed at boundaries.

**Example**: If a rule needs to match across boundaries, it might require 100 bytes of overlap to capture patterns that span chunk edges.

#### `new_scratch(&self) -> Self::Scratch`

**Purpose**: Creates a fresh `Scratch` instance for a worker thread.

**Contract**: Called once per worker at startup. The returned scratch is reused across all chunks processed by that worker, avoiding repeated allocations.

**Usage**: The scheduler calls this during worker thread initialization to set up per-thread state.

#### `scan_chunk_into(&self, data: &[u8], file_id: FileId, base_offset: u64, scratch: &mut Self::Scratch)`

**Purpose**: Scans a data buffer and appends findings to the scratch space.

**Parameters**:
- `data`: The chunk to scan
- `file_id`: Identifier of the file being scanned (for attribution)
- `base_offset`: Absolute byte offset of `data[0]` in the original file
- `scratch`: The worker's per-thread scratch space to accumulate findings

**Contract**: Findings are reported with absolute byte offsets (not relative to the chunk). The scheduler is responsible for deduplication via `scratch.drop_prefix_findings()`.

#### `rule_name(&self, rule_id: u32) -> &str`

**Purpose**: Retrieves the human-readable name of a rule by its ID.

**Contract**: Returns the rule name on success; returns `"<unknown-rule>"` for invalid IDs. Used for output formatting and reporting.

---

## EngineScratch Trait

### Purpose

`EngineScratch` abstracts the per-worker scratch memory used to accumulate findings during scanning. Each worker thread has its own scratch instance, ensuring thread-safe finding collection without locks.

### Key Characteristics

- **Thread-Local**: One instance per worker, never shared across threads
- **Reusable**: Scratch is cleared and reused across chunks to minimize allocations
- **Deduplication-Aware**: Provides methods to manage findings at chunk boundaries

### Associated Type

#### `type Finding: FindingRecord`

Specifies the finding type produced by this scratch. This associated type allows different engines to use their own finding representations while maintaining a common trait interface.

### Core Methods

#### `clear(&mut self)`

**Purpose**: Clears all accumulated findings, preparing the scratch for a new scan.

**Contract**: After calling `clear()`, `drain_findings_into()` yields no findings.

**Typical Usage**: Called once per file before processing that file's chunks.

#### `drop_prefix_findings(&mut self, new_bytes_start: u64)`

**Purpose**: Implements overlap-based deduplication by removing findings that "belong" to the previous chunk.

**Parameters**:
- `new_bytes_start`: Absolute byte offset where "new" (non-overlapping) bytes begin

**Semantics**: A finding is dropped if `finding.root_hint_end() < new_bytes_start` because:
- That finding will already be detected by the chunk that covers those bytes
- Keeping it would result in duplicate reports

**Example**: If chunk 1 spans bytes [0, 1000) and chunk 2 spans [900, 1800):
- Overlap region: [900, 1000)
- Findings with `root_hint_end < 900` are dropped (duplicates from chunk 1)
- Findings with `root_hint_end >= 900` are kept (only found in chunk 2's new bytes)

#### `drain_findings_into(&mut self, out: &mut Vec<Self::Finding>)`

**Purpose**: Transfers all remaining findings from the scratch to an output vector.

**Contract**: This operation should avoid reallocation when possible (e.g., by swapping internal buffers). After draining, the scratch is logically empty but may retain allocated capacity.

**Usage**: Called after processing each chunk to extract findings for output or further processing.

---

## FindingRecord Trait

### Purpose

`FindingRecord` abstracts the representation of a single finding (a matched secret/pattern), allowing different engines to use their own finding types. It defines the common interface for querying finding metadata.

### Type Constraints

- **`Clone`**: Findings must be cloneable for efficient buffer accumulation
- **`Send`**: Findings must be sendable across thread boundaries (though used thread-locally)
- **`'static`**: No borrowed data; findings are self-contained

### Required Methods

#### `rule_id(&self) -> u32`

**Purpose**: Returns the ID of the rule that matched.

**Returns**: A `u32` rule ID (normalized across different engine types)

#### `root_hint_start(&self) -> u64`

**Purpose**: Returns the start byte offset of the finding in the original buffer.

**Usage**: Used for cross-chunk deduplication. A finding belongs to a previous chunk if its `root_hint_end <= overlap_boundary`.

#### `root_hint_end(&self) -> u64`

**Purpose**: Returns the end byte offset (exclusive) of the finding's "root hint" region.

**Semantics**: This is the critical deduplication boundary. Findings are deduplicated using `root_hint_end < new_bytes_start`.

#### `span_start(&self) -> u64`

**Purpose**: Returns the start of the full match span (the actual matched content).

**Usage**: The span may differ from the root hint:
- Root hint: The region used for deduplication
- Span: The actual matched content (may be wider for context)

#### `span_end(&self) -> u64`

**Purpose**: Returns the end (exclusive) of the full match span.

**Contract**: Typically `span_end >= root_hint_end` to capture the full matched region.

### Deduplication Semantics

Findings use a two-level deduplication strategy:

1. **Cross-Chunk Deduplication** (`root_hint` fields):
   - Findings with `root_hint_end < new_bytes_start` are dropped
   - Prevents reporting the same finding multiple times across overlapping chunks

2. **Within-Chunk Uniqueness** (`span` fields):
   - Two findings with the same `root_hint` but different spans are distinct
   - Allows multiple matches or transformed variants of the same secret

---

## Why Traits? Benefits of Abstraction

### 1. **Testability**

The trait abstraction enables **mock implementations** for testing:
- Mock engine and scratch provide deterministic, controllable behavior
- Scheduler logic can be tested without real scanning engines
- No need for expensive file I/O or secret detection in unit tests

**Example**: `engine_stub::MockEngine` and `engine_stub::ScanScratch` provide test implementations with minimal overhead.

### 2. **Implementation Flexibility**

Different engines can provide their own optimizations:
- Mock engine: Simple in-memory finding accumulation
- Real engine: Optimized SIMD scanning, specialized memory layouts
- Both work seamlessly with the same scheduler code

### 3. **Type Compatibility**

The traits bridge type differences between implementations:

| Aspect | Mock Engine | Real Engine |
|--------|-------------|-------------|
| Rule ID | `RuleId(u16)` | `u32` |
| Offsets | `u64` | `u32` |
| Finding Type | `FindingRec` | `api::FindingRec` |
| File ID | (N/A in mock) | `FileId` |

The traits normalize these via their method signatures (all return `u32` for rule IDs, `u64` for offsets).

### 4. **Thread Safety Without Locks**

The design separates concerns:
- `ScanEngine` is `Sync`: Can be safely shared across threads
- `EngineScratch` is thread-local: No synchronization needed
- No mutex/atomic operations in the hot path

### 5. **Separation of Concerns**

The scheduler doesn't need to know:
- How the engine represents findings internally
- What data structures the engine uses
- Engine-specific optimization details

The scheduler only cares about the trait contract.

---

## Key Methods: Purpose and Contracts

### Overlap-Based Chunking Contract

The scheduler and engine collaborate to ensure no findings are missed:

```
Chunk 1: [0 ────────── 1000)
Chunk 2:         [900 ────────── 1800)
            └─ overlap ─┘

Findings with root_hint_end < 900 → dropped (dedup)
Findings with root_hint_end >= 900 → kept (new in chunk 2)
```

### Scratch Reuse Pattern

```rust
for file in files {
    scratch.clear();  // Reset for new file

    for chunk in file.chunks() {
        engine.scan_chunk_into(&chunk, file_id, offset, &mut scratch);
        scratch.drop_prefix_findings(new_bytes_start);  // Dedup
        scratch.drain_findings_into(&mut output);  // Extract findings
    }
}
```

This pattern achieves:
- Single allocation per worker (scratch reused)
- O(1) drain operations (no copying)
- Automatic deduplication at chunk boundaries

---

## Implementation Notes: How Traits Enable Flexibility

### 1. **Mock Implementation for Testing**

```rust
// tests use MockEngine which:
// - Predefines findings
// - Requires no real scanning
// - Enables deterministic testing

let engine = MockEngine::new(vec![/* presets */]);
let finding = engine.scan_chunk_into(...);
// Findings are controlled and predictable
```

### 2. **Real Engine Implementation**

```rust
// Production uses engine_impl::RealEngine which:
// - Wraps the actual scanning library
// - Maps native types to trait types
// - Provides optimized scanning

let engine = RealEngine::wrap(crate::engine::Engine::new(...));
// Same scheduler code, different backend
```

### 3. **Custom Finding Deduplication**

Different engines can customize deduplication by varying `root_hint` fields:

- **Strict dedup**: Make `root_hint == span` to deduplicate similar matches
- **Lenient dedup**: Use wider `root_hint` to allow overlapping matches
- **Context-aware**: Adjust dedup based on transformed content

### 4. **Testability Features**

Trait methods enable targeted testing:

```rust
#[test]
fn test_overlap_deduplication() {
    let scratch = MockScratch::new();
    // Add findings spanning overlap boundary
    scratch.drop_prefix_findings(900);
    // Verify deduplication
    assert_eq!(scratch.findings_count(), expected);
}
```

### 5. **Performance Optimization**

The trait design allows engines to optimize:

- **Memory layout**: Engine chooses finding struct layout
- **Copying strategy**: `drain_findings_into` can swap buffers
- **Dedup performance**: Engine optimizes `drop_prefix_findings` logic

### 6. **Future Extensibility**

New engines can be added without modifying:
- Scheduler logic
- Worker thread code
- Deduplication logic
- Output formatting

Only a new trait implementation is needed.

---

## Thread Safety Model Visualization

```
┌──────────────────────────────────────────────────────┐
│               ScanEngine (Sync, Shared)              │
│        (created once, used by all workers)           │
└──────────────────────────────────────────────────────┘
                    │         │         │
         ┌──────────┴─────────┼─────────┴──────────┐
         │                    │                    │
         ▼                    ▼                    ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │  Worker 0   │   │  Worker 1   │   │  Worker N   │
    │             │   │             │   │             │
    │ Scratch 0   │   │ Scratch 1   │   │ Scratch N   │
    │(thread-loc) │   │(thread-loc) │   │(thread-loc) │
    └─────────────┘   └─────────────┘   └─────────────┘
```

**Key Properties**:
- Engine is immutable and safely shared (no synchronization)
- Each worker has isolated scratch (no contention)
- Findings are accumulated locally, extracted after each chunk
- No data is shared between workers during scanning

---

## Summary

The engine trait abstraction provides:

1. **Decoupling**: Scheduler is independent of engine type
2. **Testability**: Mock implementations enable unit testing
3. **Flexibility**: Different engines with different optimizations
4. **Type Normalization**: Bridges implementation-specific types
5. **Thread Safety**: Lock-free design with per-worker state
6. **Performance**: Efficient finding accumulation and deduplication
7. **Extensibility**: New engines without modifying core logic
