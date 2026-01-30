# Architecture Overview

High-level C4-style component diagram showing the scanner-rs secret scanning engine architecture.

```mermaid
graph TB
    subgraph CLI["CLI Layer"]
        Main["main.rs<br/>Entry Point"]
    end

    subgraph Core["Core Engine"]
        Engine["Engine<br/>Pattern Matching"]
        Rules["RuleSpec / RuleCompiled / RuleMeta<br/>Detection Rules"]
        AC["AhoCorasick<br/>Anchor Automaton"]
        Transforms["TransformConfig<br/>URL/Base64 Decoding"]
        Tuning["Tuning<br/>DoS Protection"]
    end

    subgraph Pipeline["Pipeline Layer"]
        Walker["Walker<br/>File Discovery"]
        Reader["ReaderStage<br/>Chunking"]
        Scanner["ScanStage<br/>Detection"]
        Output["OutputStage<br/>Reporting"]
    end

    subgraph Memory["Memory Management"]
        BufferPool["BufferPool<br/>2MB Buffer Pool"]
        NodePool["NodePoolType<br/>Pre-allocated Buffers"]
        DecodeSlab["DecodeSlab<br/>Decoded Output Storage"]
    end

    subgraph DataStructures["Data Structures"]
        RingBuffer["RingBuffer<br/>SPSC Queues"]
        BitSet["BitSet / DynamicBitSet<br/>Pool Tracking"]
        FileTable["FileTable<br/>Columnar Metadata"]
    end

    subgraph State["Per-Chunk State"]
        ScanScratch["ScanScratch<br/>Reusable Scratch Buffers"]
        StepArena["StepArena<br/>Decode Provenance"]
        FixedSet128["FixedSet128<br/>Deduplication"]
        TimingWheel["TimingWheel&lt;PendingWindow, 1&gt;<br/>Window Expiration Scheduler"]
    end

    Main --> |"Arc&lt;Engine&gt;"| Engine
    Main --> |"scan_path_default()"| Walker

    Engine --> Rules
    Engine --> AC
    Engine --> Transforms
    Engine --> Tuning

    Walker --> |"FileId"| FileTable
    Walker --> |"file_ring"| Reader
    Reader --> |"chunk_ring"| Scanner
    Scanner --> |"out_ring"| Output

    Reader --> BufferPool
    BufferPool --> NodePool
    NodePool --> BitSet

    Scanner --> Engine
    Scanner --> ScanScratch
    ScanScratch --> DecodeSlab
    ScanScratch --> StepArena
    ScanScratch --> FixedSet128
    ScanScratch --> TimingWheel

    RingBuffer --> |"Inter-stage<br/>Communication"| Pipeline

    style CLI fill:#e1f5fe
    style Core fill:#fff3e0
    style Pipeline fill:#e8f5e9
    style Memory fill:#fce4ec
    style DataStructures fill:#f3e5f5
    style State fill:#fff8e1
```

## Component Descriptions

| Component | Location | Purpose |
|-----------|----------|---------|
| **CLI Layer** | `src/main.rs` | Entry point that parses args and invokes the pipeline |
| **Engine** | `src/lib.rs:992` | Compiled scanning engine with anchor patterns, rules, and transforms |
| **RuleSpec/RuleCompiled/RuleMeta** | `src/lib.rs:189-633` | Rule definitions, hot compiled data, and cold metadata |
| **AhoCorasick** | External crate | Multi-pattern anchor scanning (raw + UTF-16 variants) |
| **TransformConfig** | `src/lib.rs:96-121` | Transform stage configuration (URL percent, Base64) |
| **Pipeline** | `src/pipeline.rs:419` | 4-stage cooperative pipeline coordinator |
| **Walker** | `src/pipeline.rs:84` | Recursive file system traversal |
| **ReaderStage** | `src/pipeline.rs:232` | File chunking with overlap preservation |
| **ScanStage** | `src/pipeline.rs:303` | Detection engine invocation |
| **OutputStage** | `src/pipeline.rs:376` | Finding output to stdout |
| **BufferPool** | `src/lib.rs:367` | Fixed-capacity aligned buffer pool |
| **NodePoolType** | `src/lsm/node_pool.rs:32` | Generic pre-allocated node pool |
| **RingBuffer** | `src/stdx/ring_buffer.rs:22` | Fixed-capacity SPSC queue |
| **BitSet** | `src/stdx/bitset.rs:30` | Compile-time fixed bitset |
| **ScanScratch** | `src/lib.rs:859` | Per-scan reusable scratch state |
| **TimingWheel** | `src/stdx/timing_wheel.rs` | Hashed timing wheel for window expiration scheduling |

## Data Flow

1. **Input**: File path from CLI
2. **Walker**: Discovers files, populates FileTable, enqueues FileIds
3. **Reader**: Opens files, reads chunks with overlap, acquires buffers
4. **Scanner**: Runs Engine on each chunk, produces FindingRecs
5. **Output**: Formats and writes findings to stdout
6. **Memory**: Buffers flow through pool acquire/release lifecycle

## Design Principles

- **Anchor-first**: anchors keep regex work bounded to likely windows.
- **Deterministic memory**: fixed-capacity pools and rings make memory usage
  explicit and predictable.
- **Streaming decode**: transforms decode incrementally with budgets, so a
  single file cannot blow up CPU or memory.
- **Correctness over cleverness**: gates may allow false positives, but they
  never skip possible true matches; correctness is preserved by design.
