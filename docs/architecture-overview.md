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

| Component           | Location                       | Purpose                                                              |
| ------------------- | ------------------------------ | -------------------------------------------------------------------- |
| **CLI Layer**       | `src/main.rs`                  | Entry point that parses args and invokes the pipeline                |
| **Engine**          | `src/engine/core.rs:154`       | Compiled scanning engine with anchor patterns, rules, and transforms |
| **RuleSpec**        | `src/api.rs:519`               | Rule definitions and specification for rule-based scanning           |
| **RuleCompiled**    | `src/engine/rule_repr.rs:268`  | Compiled rule representation with hot data and validation gates      |
| **AhoCorasick**     | External crate                 | Multi-pattern anchor scanning (raw + UTF-16 variants)                |
| **TransformConfig** | `src/api.rs:132`               | Transform stage configuration (URL percent, Base64)                  |
| **Pipeline**        | `src/pipeline.rs:831`          | 4-stage cooperative pipeline coordinator                             |
| **Walker**          | `src/pipeline.rs:331`          | Recursive file system traversal (Unix primary; fallback at line 196) |
| **ReaderStage**     | `src/pipeline.rs:579`          | File chunking with overlap preservation                              |
| **ScanStage**       | `src/pipeline.rs:680`          | Detection engine invocation                                          |
| **OutputStage**     | `src/pipeline.rs:785`          | Finding output to stdout                                             |
| **BufferPool**      | `src/runtime.rs:468`           | Fixed-capacity aligned buffer pool                                   |
| **NodePoolType**    | `src/pool/node_pool.rs:49`     | Generic pre-allocated node pool                                      |
| **RingBuffer**      | `src/stdx/ring_buffer.rs:45`   | Fixed-capacity SPSC queue                                            |
| **DynamicBitSet**   | `src/stdx/bitset.rs:51`        | Runtime-sized bitset for pool tracking                               |
| **ScanScratch**     | `src/engine/scratch.rs:83`     | Per-scan reusable scratch state                                      |
| **TimingWheel**     | `src/stdx/timing_wheel.rs:479` | Hashed timing wheel for window expiration scheduling                 |
| **Git Preflight**   | `src/git_scan/preflight.rs`    | Maintenance readiness check for commit-graph, MIDX, and pack count   |
| **ArtifactStatus**  | `src/git_scan/preflight.rs`    | `Ready` vs `NeedsMaintenance` flag produced by Git preflight         |
| **Repo Open**       | `src/git_scan/repo_open.rs`    | Repo discovery, artifact mmaps, start set resolution, watermark load |
| **RepoJobState**    | `src/git_scan/repo_open.rs`    | Bundled repo metadata for downstream Git scan phases                 |
| **StartSetId**      | `src/git_scan/start_set.rs`    | Deterministic identity for start set configuration                   |
| **Watermark Keys**  | `src/git_scan/watermark_keys.rs` | Stable ref watermark key/value encoding                            |
| **Commit Graph View** | `src/git_scan/commit_walk.rs` | Commit-graph adapter with deterministic position lookup              |
| **Commit Walk**     | `src/git_scan/commit_walk.rs`  | `(watermark, tip]` traversal for introduced-by commit selection      |
| **Commit Walk Limits** | `src/git_scan/commit_walk_limits.rs` | Hard caps for commit traversal and ordering                   |
| **Snapshot Plan**   | `src/git_scan/snapshot_plan.rs` | Snapshot-mode commit selection (tips only)                          |
| **Tree Object Store** | `src/git_scan/object_store.rs` | Pack/loose tree loading for OID-only tree diffs                    |
| **Tree Diff Walker** | `src/git_scan/tree_diff.rs` | OID-only tree diffs that emit candidate blobs with context          |
| **Path Policy**     | `src/git_scan/path_policy.rs` | Fast path classification for candidate flags                         |
| **Spill Limits**    | `src/git_scan/spill_limits.rs` | Hard caps for spill chunk sizing and on-disk run growth             |
| **CandidateChunk**  | `src/git_scan/spill_chunk.rs` | Bounded candidate buffer + path arena with in-chunk dedupe          |
| **Spill Runs**      | `src/git_scan/run_writer.rs`, `src/git_scan/run_reader.rs` | Stable on-disk encoding for sorted candidate runs     |
| **Run Merger**      | `src/git_scan/spill_merge.rs` | K-way merge of spill runs with canonical dedupe                     |
| **Spiller**         | `src/git_scan/spiller.rs`     | Orchestrates chunking, spilling, and global merge                   |
| **Seen Blob Store** | `src/git_scan/seen_store.rs`  | Batched seen-blob checks for filtering already scanned blobs         |
| **WorkItems**       | `src/git_scan/work_items.rs`  | SoA candidate metadata tables for sorting without moving structs    |
| **Policy Hash**     | `src/git_scan/policy_hash.rs`  | Canonical BLAKE3 identity over rules, transforms, and tuning         |

## Git Scanning Preflight

The preflight module runs before any Git blob scanning and determines whether
maintenance artifacts are ready. The `ArtifactStatus` output gates later Git
scanning stages and surfaces missing commit-graph/MIDX or excessive pack counts.

## Git Repo Open

Repo open resolves the repository layout, detects object format, checks for
commit-graph and MIDX presence, and memory-maps those artifacts when ready.
It also resolves the start set refs (via `StartSetResolver`) and loads per-ref
watermarks from `RefWatermarkStore` using the `StartSetId` and policy hash.
The resulting `RepoJobState` is the metadata contract for later Git phases.

## Git Commit Selection

Commit selection uses the commit-graph for deterministic `(watermark, tip]`
traversal in introduced-by mode and emits snapshot tips directly in snapshot
mode. Introduced-by plans are reordered topologically so ancestors appear
before descendants, ensuring first-introduction semantics across merges.

## Git Tree Diff

Tree diffing loads tree objects from the object store and walks them in Git tree
order to emit blob candidates with commit/parent context and path classification.
The walker skips unchanged subtrees, never reads blobs during diffing, and
preserves deterministic candidate ordering for downstream spill/dedupe.

## Git Spill + Dedupe

Spill + dedupe buffers candidates in `CandidateChunk` until limits are reached,
then sorts and dedupes within the chunk before writing a spill run (`RunWriter`).
`Spiller` tracks spill run counts and bytes, and `RunMerger` performs a k-way
merge across runs to emit globally sorted, unique candidates. `WorkItems` stores
candidate metadata in SoA form so downstream sorting can shuffle indices without
moving large structs.

After global dedupe, sorted OID batches are sent to the seen-blob store so
previously scanned blobs can be filtered before decoding.

## Git Policy Hash

The policy hash is a canonical BLAKE3 identity over:
- Rule specs (canonicalized and order-invariant)
- Transform configs (order-preserving)
- Tuning parameters
- Merge diff mode
- Path policy version

## Testing Harnesses

The optional simulation harnesses provide deterministic simulation primitives and replayable traces
for both scanner and scheduler testing. See `docs/scanner_test_harness_guide.md` and
`docs/scheduler_test_harness_guide.md` for the full design and workflow.

### Scanner Simulation Harness (`sim-harness` feature)

Scanner harness code lives in `src/sim_scanner/` with shared primitives in `src/sim/`.

| Component             | Location                             | Purpose                                                        |
| --------------------- | ------------------------------------ | -------------------------------------------------------------- |
| **SimExecutor**       | `src/sim/executor.rs`                | Deterministic single-thread work-stealing model for simulation |
| **SimFs**             | `src/sim/fs.rs`                      | Deterministic in-memory filesystem used by scenarios           |
| **ScenarioGenerator** | `src/sim_scanner/generator.rs`       | Synthetic scenario builder with expected-secret ground truth   |
| **Scanner Oracles**   | `src/sim_scanner/runner.rs`          | Ground-truth and differential checks for scanner simulations   |
| **SimRng / SimClock** | `src/sim/rng.rs`, `src/sim/clock.rs` | Stable RNG and simulated time source                           |
| **TraceRing**         | `src/sim/trace.rs`                   | Bounded trace buffer for replay and debugging                  |
| **Minimizer**         | `src/sim/minimize.rs`                | Deterministic shrink passes for failing scanner artifacts      |

### Scheduler Simulation Harness (`scheduler-sim` feature)

Scheduler harness code lives in `src/scheduler/sim_executor_harness.rs`.

| Component                   | Location                                | Purpose                                                             |
| --------------------------- | --------------------------------------- | ------------------------------------------------------------------- |
| **Scheduler Sim Harness**   | `src/scheduler/sim_executor_harness.rs` | Deterministic executor model for scheduler interleaving tests       |
| **Scheduler Sim Task VM**   | `src/scheduler/sim_executor_harness.rs` | Bytecode VM driving scheduler-only task effects in simulation       |
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
