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
| **Engine** | `src/engine/core.rs:154` | Compiled scanning engine with anchor patterns, rules, and transforms |
| **RuleSpec** | `src/api.rs:519` | Rule definitions and specification for rule-based scanning |
| **RuleCompiled** | `src/engine/rule_repr.rs:268` | Compiled rule representation with hot data and validation gates |
| **AhoCorasick** | External crate | Multi-pattern anchor scanning (raw + UTF-16 variants) |
| **TransformConfig** | `src/api.rs:132` | Transform stage configuration (URL percent, Base64) |
| **Pipeline** | `src/pipeline.rs:831` | 4-stage cooperative pipeline coordinator |
| **Archive Core** | `src/archive/mod.rs` | Archive scanning config, budgets, outcomes, path canonicalization, and format helpers |
| **Walker** | `src/pipeline.rs:331` | Recursive file system traversal (Unix primary; fallback at line 196) |
| **ReaderStage** | `src/pipeline.rs:579` | File chunking with overlap preservation |
| **ScanStage** | `src/pipeline.rs:680` | Detection engine invocation |
| **OutputStage** | `src/pipeline.rs:785` | Finding output to stdout |
| **BufferPool** | `src/runtime.rs:468` | Fixed-capacity aligned buffer pool |
| **NodePoolType** | `src/pool/node_pool.rs:49` | Generic pre-allocated node pool |
| **RingBuffer** | `src/stdx/ring_buffer.rs:45` | Fixed-capacity SPSC queue |
| **DynamicBitSet** | `src/stdx/bitset.rs:51` | Runtime-sized bitset for pool tracking |
| **ScanScratch** | `src/engine/scratch.rs:83` | Per-scan reusable scratch state |
| **TimingWheel** | `src/stdx/timing_wheel.rs:479` | Hashed timing wheel for window expiration scheduling |

## Archive Scanning Notes

- Nested archive expansion is streaming-only and bounded by `ArchiveConfig::max_archive_depth`.
- Policy enforcement is deterministic: `FailArchive` stops the current container, `FailRun` aborts the scan.
- Archive entries use virtual `FileId` values (high-bit namespace) to isolate per-file engine state.

## Testing Harnesses

The optional simulation harnesses provide deterministic simulation primitives and replayable traces
for both scanner and scheduler testing. See `docs/scanner_test_harness_guide.md` and
`docs/scheduler_test_harness_guide.md` for the full design and workflow.

### Scanner Simulation Harness (`sim-harness` feature)

Scanner harness code lives in `src/sim_scanner/` with shared primitives in `src/sim/`.

| Component | Location | Purpose |
|-----------|----------|---------|
| **SimExecutor** | `src/sim/executor.rs` | Deterministic single-thread work-stealing model for simulation |
| **SimFs** | `src/sim/fs.rs` | Deterministic in-memory filesystem used by scenarios |
| **ScenarioGenerator** | `src/sim_scanner/generator.rs` | Synthetic scenario builder with expected-secret ground truth |
| **Scanner Oracles** | `src/sim_scanner/runner.rs` | Ground-truth and differential checks for scanner simulations |
| **SimRng / SimClock** | `src/sim/rng.rs`, `src/sim/clock.rs` | Stable RNG and simulated time source |
| **TraceRing** | `src/sim/trace.rs` | Bounded trace buffer for replay and debugging |
| **Minimizer** | `src/sim/minimize.rs` | Deterministic shrink passes for failing scanner artifacts |

### Scheduler Simulation Harness (`scheduler-sim` feature)

Scheduler harness code lives in `src/scheduler/sim_executor_harness.rs`.

| Component | Location | Purpose |
|-----------|----------|---------|
| **Scheduler Sim Harness** | `src/scheduler/sim_executor_harness.rs` | Deterministic executor model for scheduler interleaving tests |
| **Scheduler Sim Task VM** | `src/scheduler/sim_executor_harness.rs` | Bytecode VM driving scheduler-only task effects in simulation |
| **Scheduler Sim Resources** | `src/scheduler/sim_executor_harness.rs` | Deterministic resource accounting for permits/budgets in simulation |

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
