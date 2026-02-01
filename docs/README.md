# scanner-rs Documentation Index

Comprehensive documentation for the scanner-rs secret scanning engine.

## 📊 Documentation Status

### Summary Statistics
- **Total Documentation Files**: 32 (16 original + 16 new)
- **Source Files Documented**: 80 Rust files
- **Coverage Level**: Tiers 1-3 100% complete (all high-priority and supporting modules)
- **Last Updated**: February 2026

### What's Covered
- ✅ Architecture & System Design (complete)
- ✅ Detection Rules & Engine (complete - including supporting modules)
- ✅ Optimization & Performance (complete)
- ✅ Scheduler Subsystem (complete - including infrastructure)
- ✅ Memory Management (complete)
- ✅ Testing & Verification (complete)
- ⚠️  Utilities & Helpers (partial - Tier 4)

---

## 📖 Documentation by Category

### 1. Getting Started

| Document | Description | Audience |
|----------|-------------|----------|
| [architecture-overview.md](architecture-overview.md) | C4-style component diagram of the entire system | **START HERE** - All developers |
| [architecture.md](architecture.md) | High-level pipeline flow and engine processing | New contributors |
| [data-types.md](data-types.md) | Class diagrams showing key type relationships | API users |

**Quick Start Path**: `architecture-overview.md` → `detection-engine.md` → `pipeline-flow.md`

---

### 2. Core Architecture

#### System Design
| Document | Focus | Key Concepts |
|----------|-------|--------------|
| [architecture-overview.md](architecture-overview.md) | Component structure | CLI, Engine, Pipeline, Memory, Data Structures |
| [architecture.md](architecture.md) | Data flow | Walker→Reader→Scanner→Output, transform worklist |
| [pipeline-flow.md](pipeline-flow.md) | 4-stage cooperative pipeline | Ring buffers, backpressure, RAII |
| [pipeline-state-machine.md](pipeline-state-machine.md) | State transitions & termination | Reverse pump order, stall detection |

#### Detection Engine
| Document | Focus | Key Concepts |
|----------|-------|--------------|
| [detection-engine.md](detection-engine.md) | Multi-phase pattern matching | Anchor scan, window building, two-phase, regex confirmation |
| [detection-rules.md](detection-rules.md) | Rule coverage & anatomy | 223 rules across 12 categories, anchors, two-phase |
| [transform-chain.md](transform-chain.md) | Recursive decoding flow | URL/Base64 transforms, TimingWheel scheduling |

---

### 3. Engine Internals (NEW)

#### Core Engine (Tier 2)
| Document | Module | Description |
|----------|--------|-------------|
| [engine-vectorscan-prefilter.md](engine-vectorscan-prefilter.md) | `src/engine/vectorscan_prefilter.rs` | Database compilation, pattern types, callback mechanism, gate semantics |
| [engine-rule-compilation.md](engine-rule-compilation.md) | `src/engine/rule_repr.rs` | RuleSpec→RuleCompiled pipeline, variant handling, gate compilation |
| [engine-transforms.md](engine-transforms.md) | `src/engine/transform.rs` | URL/Base64 span detection, streaming decode, budget enforcement |
| [engine-window-validation.md](engine-window-validation.md) | `src/engine/window_validate.rs` | Gate checks, regex execution, entropy checking, finding extraction |

#### Supporting Modules (Tier 3 - NEW)
| Document | Module | Description |
|----------|--------|-------------|
| [engine-stream-decode.md](engine-stream-decode.md) | `src/engine/stream_decode.rs` | Streaming decode for transforms, ring buffer, timing wheel integration |
| [engine-decode-state.md](engine-decode-state.md) | `src/engine/decode_state.rs` | Decode step arena, provenance tracking, parent-linked chains |

**Purpose**: Deep dives into the detection engine's hot path (scan loop, validation, transforms).

---

### 4. Scheduler Subsystem (NEW)

#### Core Scheduler
| Document | Module | Description |
|----------|--------|-------------|
| [scheduler-local.md](scheduler-local.md) | `src/scheduler/local.rs` | FileSource trait, blocking reads, overlap carry, backpressure |
| [scheduler-task-graph.md](scheduler-task-graph.md) | `src/scheduler/task_graph.rs` | Object lifecycle FSM (enumerate→fetch→scan→done), work-conserving semantics |
| [scheduler-output-sinks.md](scheduler-output-sinks.md) | `src/scheduler/output_sink.rs` | Pluggable finding destinations (stdout, file, vec), batching |

#### Scheduler Integration
| Document | Module | Description |
|----------|--------|-------------|
| [scheduler-engine-abstraction.md](scheduler-engine-abstraction.md) | `src/scheduler/engine_trait.rs` | ScanEngine/EngineScratch/FindingRecord traits, why abstracted |
| [scheduler-engine-impl.md](scheduler-engine-impl.md) | `src/scheduler/engine_impl.rs` | Real engine adapter, lazy reset pattern, zero-copy extraction |

#### Scheduler Infrastructure (Tier 3 - NEW)
| Document | Module | Description |
|----------|--------|-------------|
| [scheduler-remote-backend.md](scheduler-remote-backend.md) | `src/scheduler/remote.rs` | HTTP/object-store backend, retry policies, transport abstraction |
| [scheduler-local-fs-uring.md](scheduler-local-fs-uring.md) | `src/scheduler/local_fs_uring.rs` | Linux io_uring async I/O, SQE/CQE queue management, 2-50× throughput |
| [scheduler-ts-buffer-pool.md](scheduler-ts-buffer-pool.md) | `src/scheduler/ts_buffer_pool.rs` | Thread-safe buffer recycling, per-worker caching, work-conserving stealing |
| [scheduler-device-slots.md](scheduler-device-slots.md) | `src/scheduler/device_slots.rs` | Per-device I/O concurrency limits, slot allocation, backpressure |
| [scheduler-global-resource-pool.md](scheduler-global-resource-pool.md) | `src/scheduler/global_resource_pool.rs` | Centralized permits for "fat" jobs, SLAs, memory management |

**Purpose**: Understand how the scheduler orchestrates file scanning, task management, output handling, and resource management.

---

### 5. Performance & Optimization

#### Analysis & Investigations
| Document | Focus | Key Findings |
|----------|-------|--------------|
| [throughput_analysis.md](throughput_analysis.md) | Layer-by-layer metrics | 489 MiB/s ASCII, 170 MiB/s random, gaps analysis |
| [throughput_bottleneck_analysis.md](throughput_bottleneck_analysis.md) | Two primary bottlenecks | Vectorscan automaton complexity vs validation cost |
| [throughput_investigation.md](throughput_investigation.md) | 10× performance gap | ⚠️ **CORRECTED** - generic-api-key has 20 anchors (not 270) |

#### Optimization Work
| Document | Focus | Status |
|----------|-------|--------|
| [rule_optimization_analysis.md](rule_optimization_analysis.md) | 222 gitleaks rules analyzed | 4 optimization categories, 2.4-6.4× speedups |
| [anchor_optimization_spec.md](anchor_optimization_spec.md) | Exact changes for anchor optimization | JWT `ey`→`eyJ`, Vault token split |

**Key Metrics**:
- Current throughput: 445 MiB/s (clean), 293 MiB/s (realistic)
- Target: 1-2 GiB/s
- Implemented optimizations: JWT 2.4×, Vault split

---

### 6. Memory Management & Correctness

| Document | Focus | Key Concepts |
|----------|-------|--------------|
| [memory-management.md](memory-management.md) | Buffer lifecycle & pools | BufferPool, RAII, 136×2MB buffers, DecodeSlab, ScanScratch |
| [kani-verification.md](kani-verification.md) | Formal verification | Kani model checking for TimingWheel (8 proofs), Bitset2 (5 proofs) |
| [tiger_harness_plan.md](tiger_harness_plan.md) | Deterministic testing | Simulation-style harness for chunking semantics validation |

**Coverage**:
- Memory: Pool management, acquire/release, overlap preservation
- Correctness: Bounded model checking, property-based testing

---

## 🔍 Finding Documentation

### By Task
| I want to... | Read this |
|--------------|-----------|
| Understand the overall architecture | [architecture-overview.md](architecture-overview.md) |
| Learn how detection works | [detection-engine.md](detection-engine.md) |
| Add a new detection rule | [detection-rules.md](detection-rules.md) |
| Optimize performance | [throughput_analysis.md](throughput_analysis.md) → [rule_optimization_analysis.md](rule_optimization_analysis.md) |
| Understand the pipeline | [pipeline-flow.md](pipeline-flow.md) → [pipeline-state-machine.md](pipeline-state-machine.md) |
| Work on the scheduler | [scheduler-local.md](scheduler-local.md) → [scheduler-task-graph.md](scheduler-task-graph.md) |
| Debug memory issues | [memory-management.md](memory-management.md) |
| Add transform support | [engine-transforms.md](engine-transforms.md) → [transform-chain.md](transform-chain.md) |
| Understand window validation | [engine-window-validation.md](engine-window-validation.md) |

### By Source File
| Source File | Documentation |
|-------------|---------------|
| `src/engine/core.rs` | [detection-engine.md](detection-engine.md) |
| `src/engine/vectorscan_prefilter.rs` | [engine-vectorscan-prefilter.md](engine-vectorscan-prefilter.md) |
| `src/engine/rule_repr.rs` | [engine-rule-compilation.md](engine-rule-compilation.md) |
| `src/engine/transform.rs` | [engine-transforms.md](engine-transforms.md) |
| `src/engine/window_validate.rs` | [engine-window-validation.md](engine-window-validation.md) |
| `src/engine/stream_decode.rs` | [engine-stream-decode.md](engine-stream-decode.md) |
| `src/engine/decode_state.rs` | [engine-decode-state.md](engine-decode-state.md) |
| `src/scheduler/local.rs` | [scheduler-local.md](scheduler-local.md) |
| `src/scheduler/task_graph.rs` | [scheduler-task-graph.md](scheduler-task-graph.md) |
| `src/scheduler/output_sink.rs` | [scheduler-output-sinks.md](scheduler-output-sinks.md) |
| `src/scheduler/engine_trait.rs` | [scheduler-engine-abstraction.md](scheduler-engine-abstraction.md) |
| `src/scheduler/engine_impl.rs` | [scheduler-engine-impl.md](scheduler-engine-impl.md) |
| `src/scheduler/remote.rs` | [scheduler-remote-backend.md](scheduler-remote-backend.md) |
| `src/scheduler/local_fs_uring.rs` | [scheduler-local-fs-uring.md](scheduler-local-fs-uring.md) |
| `src/scheduler/ts_buffer_pool.rs` | [scheduler-ts-buffer-pool.md](scheduler-ts-buffer-pool.md) |
| `src/scheduler/device_slots.rs` | [scheduler-device-slots.md](scheduler-device-slots.md) |
| `src/scheduler/global_resource_pool.rs` | [scheduler-global-resource-pool.md](scheduler-global-resource-pool.md) |
| `src/pipeline.rs` | [pipeline-flow.md](pipeline-flow.md), [pipeline-state-machine.md](pipeline-state-machine.md) |
| `src/gitleaks_rules.rs` | [detection-rules.md](detection-rules.md), [anchor_optimization_spec.md](anchor_optimization_spec.md) |

---

## ⚠️ Recent Documentation Fixes

### Critical Corrections (Feb 2026)
1. **throughput_investigation.md** - Fixed incorrect claims:
   - ✅ generic-api-key: 20 anchors (was incorrectly documented as 270)
   - ✅ Line numbers: 1258-1316 (was 1231-1246)
   - ✅ Rule has keywords_any gate (was documented as None)
   - ✅ sourcegraph-access-token: 2 anchors (was documented as 4)
   - ✅ Line numbers: 3416-3432 (was 3218-3233)

2. **architecture-overview.md** - Updated all component locations:
   - ✅ 16/16 component references corrected
   - ✅ File paths updated (e.g., Engine: `src/lib.rs:992` → `src/engine/core.rs:154`)
   - ✅ Line numbers synchronized with current codebase

**Impact**: Documentation now accurately reflects the current codebase structure.

---

## 📈 Coverage Analysis

### Documented Modules (Tiers 1, 2 & 3)
#### Engine Subsystem
- ✅ `src/engine/core.rs` - detection-engine.md
- ✅ `src/engine/vectorscan_prefilter.rs` - engine-vectorscan-prefilter.md
- ✅ `src/engine/rule_repr.rs` - engine-rule-compilation.md
- ✅ `src/engine/transform.rs` - engine-transforms.md
- ✅ `src/engine/window_validate.rs` - engine-window-validation.md
- ✅ `src/engine/stream_decode.rs` - engine-stream-decode.md (NEW)
- ✅ `src/engine/decode_state.rs` - engine-decode-state.md (NEW)
- ✅ `src/engine/scratch.rs` - memory-management.md

#### Scheduler Subsystem
- ✅ `src/scheduler/mod.rs` - Inline module docs (120 lines)
- ✅ `src/scheduler/local.rs` - scheduler-local.md
- ✅ `src/scheduler/task_graph.rs` - scheduler-task-graph.md
- ✅ `src/scheduler/output_sink.rs` - scheduler-output-sinks.md
- ✅ `src/scheduler/engine_trait.rs` - scheduler-engine-abstraction.md
- ✅ `src/scheduler/engine_impl.rs` - scheduler-engine-impl.md
- ✅ `src/scheduler/remote.rs` - scheduler-remote-backend.md (NEW)
- ✅ `src/scheduler/local_fs_uring.rs` - scheduler-local-fs-uring.md (NEW)
- ✅ `src/scheduler/ts_buffer_pool.rs` - scheduler-ts-buffer-pool.md (NEW)
- ✅ `src/scheduler/device_slots.rs` - scheduler-device-slots.md (NEW)
- ✅ `src/scheduler/global_resource_pool.rs` - scheduler-global-resource-pool.md (NEW)
- ✅ `src/scheduler/executor.rs` - Inline module docs (excellent)
- ✅ `src/scheduler/budget.rs` - Inline module docs
- ✅ `src/scheduler/metrics.rs` - Inline module docs

#### Core Modules
- ✅ `src/api.rs` - Inline type docs (750 lines)
- ✅ `src/lib.rs` - architecture-overview.md
- ✅ `src/pipeline.rs` - pipeline-flow.md, pipeline-state-machine.md
- ✅ `src/runtime.rs` - memory-management.md
- ✅ `src/async_io/mod.rs` - Inline module docs
- ✅ `src/regex2anchor.rs` - Inline module docs

### Undocumented Modules (Tier 3 & 4)
See [Gap Analysis](#gap-analysis) below for details on remaining work.

---

## 🎯 Gap Analysis

### Tier 3 Priority (Supporting Modules) - ✅ 100% COMPLETE

All Tier 3 modules are now fully documented:

| Module | Documentation | Status |
|--------|---------------|--------|
| `src/engine/stream_decode.rs` | [engine-stream-decode.md](engine-stream-decode.md) | ✅ Complete |
| `src/engine/decode_state.rs` | [engine-decode-state.md](engine-decode-state.md) | ✅ Complete |
| `src/scheduler/remote.rs` | [scheduler-remote-backend.md](scheduler-remote-backend.md) | ✅ Complete |
| `src/scheduler/local_fs_uring.rs` | [scheduler-local-fs-uring.md](scheduler-local-fs-uring.md) | ✅ Complete |
| `src/scheduler/ts_buffer_pool.rs` | [scheduler-ts-buffer-pool.md](scheduler-ts-buffer-pool.md) | ✅ Complete |
| `src/scheduler/device_slots.rs` | [scheduler-device-slots.md](scheduler-device-slots.md) | ✅ Complete |
| `src/scheduler/global_resource_pool.rs` | [scheduler-global-resource-pool.md](scheduler-global-resource-pool.md) | ✅ Complete |

### Tier 4 Priority (Low-Impact Utilities)
Estimated effort: 8 hours

**stdx utilities**: byte_ring, fixed_set, released_set, ring_buffer, fastrange

**scheduler utilities**: rng, ts_chunk, worker_id, count_budget, affinity, alloc, failure, yield_policy, findings, sim

**engine utilities**: helpers, hit_pool, work_items, buffer_scan

**Note**: Many of these have good inline documentation. Module-level docs would still be beneficial for discoverability.

---

## 📝 Documentation Guidelines

### For Contributors
When adding new features:
1. **Module-level docs** (//!) covering:
   - Purpose (1-2 sentences)
   - High-level algorithm (if applicable)
   - Key invariants
   - Use cases
   - Performance notes (O(n), cache locality)

2. **Type-level docs** for public types:
   - Invariants
   - Safety preconditions (if unsafe)
   - Examples (if non-obvious)

3. **Function-level docs** for public functions:
   - Preconditions
   - Panics clause
   - Performance O(n) bounds

### Style Guide
- Use moderate detail (match existing docs)
- Include code examples for complex concepts
- Add Mermaid diagrams for flows/state machines
- Cross-reference related documentation
- Update this README when adding new docs

---

## 🔗 External Resources

### Tools & Dependencies
- [Vectorscan](https://github.com/VectorCamp/vectorscan) - Pattern matching library (Hyperscan fork)
- [Kani](https://model-checking.github.io/kani/) - Rust verification tool
- [Criterion](https://github.com/bheisler/criterion.rs) - Benchmarking framework

### Related Projects
- [gitleaks](https://github.com/gitleaks/gitleaks) - Source of rule definitions
- [TigerBeetle](https://github.com/tigerbeetle/tigerbeetle) - Inspiration for defensive programming style

---

## 📊 Metrics

### Documentation Coverage
- **Fully Documented**: 36 modules (45%)
- **Partial Inline Docs**: 32 modules (40%)
- **Undocumented**: 12 modules (15%)
- **Total Modules**: 80

### Documentation Quality
- **High-Level Overview**: ✅ Excellent (architecture-overview.md)
- **API Documentation**: ✅ Excellent (api.rs, lib.rs)
- **Implementation Details**: ✅ Excellent (engine, scheduler - all major modules)
- **Performance Analysis**: ✅ Excellent (throughput_*.md)
- **Testing Strategy**: ✅ Good (kani-verification.md)

### Recent Additions (Feb 2026)
- 16 new module documentation files (9 Tier 2 + 7 Tier 3)
- 2 corrected existing files
- ~8,000 lines of new documentation
- All Tier 1-3 modules now 100% documented

---

## 🚀 Maintenance

### Keeping Docs Updated
1. **Code changes**: Update docs when refactoring changes semantics
2. **Performance work**: Update throughput_*.md with new benchmarks
3. **New rules**: Update detection-rules.md
4. **Architecture changes**: Update architecture-overview.md

### Automated Checks
Consider adding:
- Doc tests for code examples
- Link checker for cross-references
- Line number validator (flag outdated references)

---

## 📧 Questions?

For questions about:
- **Architecture**: See architecture-overview.md
- **Performance**: See throughput_analysis.md
- **Rules**: See detection-rules.md
- **Scheduler**: See scheduler-local.md
- **Engine**: See detection-engine.md

If documentation is unclear or missing, please open an issue or PR!

---

**Last Updated**: February 1, 2026
**Maintainers**: scanner-rs contributors
**License**: See LICENSE file in project root
