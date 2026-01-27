# Data Type Relationships

Class diagram showing the key types in scanner-rs and their relationships.

```mermaid
classDiagram
    direction TB

    class Engine {
        -Vec~RuleCompiled~ rules
        -Vec~TransformConfig~ transforms
        -Tuning tuning
        -AhoCorasick ac_anchors
        -Option~Base64YaraGate~ b64_gate
        -Vec~Target~ pat_targets
        -Vec~u32~ pat_offsets
        -usize max_anchor_pat_len
        -usize max_window_diameter_bytes
        +new(rules, transforms, tuning) Engine
        +scan_chunk(hay: &[u8]) Vec~Finding~
        +scan_chunk_into(buf, file_id, offset, scratch)
        +required_overlap() usize
        +rule_name(rule_id) &str
        +new_scratch() ScanScratch
    }

    class RuleSpec {
        +&'static str name
        +&'static [&'static [u8]] anchors
        +usize radius
        +Option~TwoPhaseSpec~ two_phase
        +Option~&'static [u8]~ must_contain
        +Regex re
    }

    class RuleCompiled {
        -&'static str name
        -usize radius
        -Option~&'static [u8]~ must_contain
        -Regex re
        -Option~TwoPhaseCompiled~ two_phase
    }

    class TwoPhaseCompiled {
        -usize seed_radius
        -usize full_radius
        -[PackedPatterns; 3] confirm
    }

    class PackedPatterns {
        -Vec~u8~ bytes
        -Vec~u32~ offsets
    }

    class Target {
        -u32 inner
        +rule_id() usize
        +variant() Variant
    }

    class SpanU32 {
        +u32 start
        +u32 end
    }

    class TwoPhaseSpec {
        +usize seed_radius
        +usize full_radius
        +&'static [&'static [u8]] confirm_any
    }

    class TransformConfig {
        +TransformId id
        +TransformMode mode
        +Gate gate
        +usize min_len
        +usize max_spans_per_buffer
        +usize max_encoded_len
        +usize max_decoded_bytes
        +bool plus_to_space
        +bool base64_allow_space_ws
    }

    class Tuning {
        +usize merge_gap
        +usize max_windows_per_rule_variant
        +usize pressure_gap_start
        +usize max_anchor_hits_per_rule_variant
        +usize max_utf16_decoded_bytes_per_window
        +usize max_transform_depth
        +usize max_total_decode_output_bytes
        +usize max_work_items
        +usize max_findings_per_chunk
    }

    class ScanScratch {
        -Vec~FindingRec~ out
        -Vec~WorkItem~ work_q
        -usize work_head
        -DecodeSlab slab
        -FixedSet128 seen
        -Vec~[HitAccumulator; 3]~ accs
        -ScratchVec~u32~ touched_pairs
        -DynamicBitSet touched
        -bool touched_any
        -ScratchVec~SpanU32~ windows
        -ScratchVec~SpanU32~ expanded
        -ScratchVec~SpanU32~ spans
        -StepArena step_arena
        +drain_findings() Vec~FindingRec~
        +drain_findings_into(out)
        +findings() &[FindingRec]
    }

    class Finding {
        +&'static str rule
        +Range~usize~ span
        +Range~usize~ root_span_hint
        +Vec~DecodeStep~ decode_steps
    }

    class FindingRec {
        +FileId file_id
        +u32 rule_id
        +u32 span_start
        +u32 span_end
        +u64 root_hint_start
        +u64 root_hint_end
        +StepId step_id
    }

    class FileId {
        +u32 inner
    }

    class StepId {
        +u32 inner
    }

    class DecodeStep {
        <<enumeration>>
        Transform
        Utf16Window
    }

    Engine --> RuleCompiled : contains
    Engine --> TransformConfig : contains
    Engine --> Tuning : contains
    Engine --> ScanScratch : creates

    RuleSpec --> TwoPhaseSpec : optional
    RuleCompiled --> TwoPhaseCompiled : compiled
    TwoPhaseCompiled --> PackedPatterns : uses

    ScanScratch --> FindingRec : produces
    ScanScratch --> StepId : tracks

    Finding --> DecodeStep : contains
    FindingRec --> FileId : references
    FindingRec --> StepId : references
```

## Pipeline Types

```mermaid
classDiagram
    direction TB

    class Pipeline {
        -Arc~Engine~ engine
        -PipelineConfig config
        -usize overlap
        -BufferPool pool
        +new(engine, config) Pipeline
        +scan_path(path) Result~PipelineStats~
    }

    class PipelineConfig {
        +usize chunk_size
        +usize max_files
    }

    class PipelineStats {
        +u64 files
        +u64 chunks
        +u64 findings
        +u64 errors
    }

    class FileTable {
        -Vec~PathBuf~ paths
        -Vec~u64~ sizes
        -Vec~(u64, u64)~ dev_inodes
        -Vec~u32~ flags
        +push(path, size, dev_inode, flags) FileId
        +path(id) &PathBuf
        +size(id) u64
        +flags(id) u32
    }

    class Chunk {
        +FileId file_id
        +u64 base_offset
        +u32 len
        +u32 prefix_len
        +BufferHandle buf
        +data() &[u8]
        +payload() &[u8]
    }

    class BufferPool {
        -Rc~BufferPoolInner~ inner
        +new(capacity) BufferPool
        +try_acquire() Option~BufferHandle~
        +acquire() BufferHandle
        +buf_len() usize
    }

    class BufferHandle {
        -Rc~BufferPoolInner~ pool
        -NonNull~u8~ ptr
        +as_slice() &[u8]
        +as_mut_slice() &mut [u8]
    }

    Pipeline --> PipelineConfig : uses
    Pipeline --> BufferPool : owns
    Pipeline --> FileTable : creates
    Pipeline --> Chunk : processes

    Chunk --> BufferHandle : owns
    BufferHandle --> BufferPool : returns to
    Chunk --> FileId : references
    FileTable --> FileId : produces
```

## Notes

- `Engine.b64_gate` is an optional encoded-space pre-gate for Base64 spans. It
  is built from the same anchor patterns as `ac_anchors` and is only used to
  skip wasteful decodes; the decoded-space gate still enforces correctness.

## Memory Pool Types

```mermaid
classDiagram
    direction TB

    class NodePoolType~NODE_SIZE, NODE_ALIGN~ {
        -NonNull~u8~ buffer
        -usize len
        -DynamicBitSet free
        +init(node_count) Self
        +acquire() NonNull~u8~
        +release(node)
        +reset()
        +deinit()
    }

    class DynamicBitSet {
        -Vec~u64~ words
        -usize bit_length
        +empty(bit_length) DynamicBitSet
        +is_set(idx) bool
        +set(idx)
        +unset(idx)
        +clear()
        +toggle_all()
        +count() usize
        +iter_set() Iterator
    }

    class BitSet~N, WORDS~ {
        -[u64; WORDS] words
        +empty() BitSet
        +full() BitSet
        +is_set(idx) bool
        +set(idx)
        +unset(idx)
        +first_set() Option~usize~
        +first_unset() Option~usize~
        +iter() Iterator
    }

    class ScratchVec~T~ {
        -NonNull~T~ ptr
        -usize len
        -usize cap
        +with_capacity(cap) ScratchVec
        +push(value)
        +clear()
        +len() usize
        +capacity() usize
    }

    class RingBuffer~T, N~ {
        -[MaybeUninit~T~; N] buf
        -u32 head
        -u32 len
        +new() RingBuffer
        +push_back(value) Result
        +pop_front() Option~T~
        +front() Option~&T~
        +is_full() bool
        +is_empty() bool
    }

    NodePoolType --> DynamicBitSet : uses
```

## Enumerations

```mermaid
classDiagram
    class TransformId {
        <<enumeration>>
        UrlPercent
        Base64
    }

    class TransformMode {
        <<enumeration>>
        Disabled
        Always
        IfNoFindingsInThisBuffer
    }

    class Gate {
        <<enumeration>>
        None
        AnchorsInDecoded
    }

    class Variant {
        <<enumeration>>
        Raw
        Utf16Le
        Utf16Be
    }

    class Utf16Endianness {
        <<enumeration>>
        Le
        Be
    }

    class BufRef {
        <<enumeration>>
        Root
        Slab(Range~usize~)
    }
```

## Key Relationships Summary

| Source | Relationship | Target | Description |
|--------|--------------|--------|-------------|
| `Engine` | contains | `RuleCompiled` | Compiled detection rules |
| `Engine` | contains | `TransformConfig` | Transform configurations |
| `Engine` | creates | `ScanScratch` | Per-scan scratch state |
| `Pipeline` | owns | `BufferPool` | Buffer memory pool |
| `Pipeline` | creates | `FileTable` | File metadata store |
| `Chunk` | owns | `BufferHandle` | Buffer with RAII release |
| `FindingRec` | references | `FileId` | Source file identifier |
| `FindingRec` | references | `StepId` | Decode provenance chain |
| `NodePoolType` | uses | `DynamicBitSet` | Free slot tracking |
