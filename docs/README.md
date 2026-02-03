# scanner-rs Documentation

Documentation index for the scanner-rs secret scanning engine. This guide helps you navigate the codebase and understand the system architecture, detection engine, scheduler, and performance characteristics.

## Documentation by Category

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
| [detection-engine.md](detection-engine.md) | Multi-stage pattern matching | Anchor scan, window building, two-phase, regex confirmation |
| [detection-rules.md](detection-rules.md) | Rule coverage & anatomy | 223 rules across 12 categories, anchors, two-phase |
| [transform-chain.md](transform-chain.md) | Recursive decoding flow | URL/Base64 transforms, TimingWheel scheduling |

---

### 3. Engine Internals

#### Core Engine
| Document | Module | Description |
|----------|--------|-------------|
| [engine-vectorscan-prefilter.md](engine-vectorscan-prefilter.md) | `src/engine/vectorscan_prefilter.rs` | Database compilation, pattern types, callback mechanism, gate semantics |
| [engine-rule-compilation.md](engine-rule-compilation.md) | `src/engine/rule_repr.rs` | RuleSpec→RuleCompiled pipeline, variant handling, gate compilation |
| [engine-transforms.md](engine-transforms.md) | `src/engine/transform.rs` | URL/Base64 span detection, streaming decode, budget enforcement |
| [engine-window-validation.md](engine-window-validation.md) | `src/engine/window_validate.rs` | Gate checks, regex execution, entropy checking, finding extraction |

#### Supporting Modules
| Document | Module | Description |
|----------|--------|-------------|
| [engine-stream-decode.md](engine-stream-decode.md) | `src/engine/stream_decode.rs` | Streaming decode for transforms, ring buffer, timing wheel integration |
| [engine-decode-state.md](engine-decode-state.md) | `src/engine/decode_state.rs` | Decode step arena, provenance tracking, parent-linked chains |

---

### 4. Scheduler Subsystem

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

#### Scheduler Infrastructure
| Document | Module | Description |
|----------|--------|-------------|
| [scheduler-remote-backend.md](scheduler-remote-backend.md) | `src/scheduler/remote.rs` | HTTP/object-store backend, retry policies, transport abstraction |
| [scheduler-local-fs-uring.md](scheduler-local-fs-uring.md) | `src/scheduler/local_fs_uring.rs` | Linux io_uring async I/O, SQE/CQE queue management, 2-50× throughput |
| [scheduler-ts-buffer-pool.md](scheduler-ts-buffer-pool.md) | `src/scheduler/ts_buffer_pool.rs` | Thread-safe buffer recycling, per-worker caching, work-conserving stealing |
| [scheduler-device-slots.md](scheduler-device-slots.md) | `src/scheduler/device_slots.rs` | Per-device I/O concurrency limits, slot allocation, backpressure |
| [scheduler-global-resource-pool.md](scheduler-global-resource-pool.md) | `src/scheduler/global_resource_pool.rs` | Centralized permits for "fat" jobs, SLAs, memory management |

---

### 5. Memory Management & Correctness

| Document | Focus | Key Concepts |
|----------|-------|--------------|
| [memory-management.md](memory-management.md) | Buffer lifecycle & pools | BufferPool, RAII, 136×2MB buffers, DecodeSlab, ScanScratch |
| [kani-verification.md](kani-verification.md) | Formal verification | Kani model checking for TimingWheel (8 proofs), Bitset2 (5 proofs) |

---

## Finding Documentation

### By Task
| I want to... | Read this |
|--------------|-----------|
| Understand the overall architecture | [architecture-overview.md](architecture-overview.md) |
| Learn how detection works | [detection-engine.md](detection-engine.md) |
| Add a new detection rule | [detection-rules.md](detection-rules.md) |
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
| `src/gitleaks_rules.rs` | [detection-rules.md](detection-rules.md) |

---

## Code Organization

The codebase is organized into several subsystems:

### Engine Subsystem
Core pattern matching and detection logic:
- `src/engine/core.rs` - detection-engine.md
- `src/engine/vectorscan_prefilter.rs` - engine-vectorscan-prefilter.md
- `src/engine/rule_repr.rs` - engine-rule-compilation.md
- `src/engine/transform.rs` - engine-transforms.md
- `src/engine/window_validate.rs` - engine-window-validation.md
- `src/engine/stream_decode.rs` - engine-stream-decode.md
- `src/engine/decode_state.rs` - engine-decode-state.md
- `src/engine/scratch.rs` - memory-management.md

### Scheduler Subsystem
Task orchestration, I/O, and resource management:
- `src/scheduler/local.rs` - scheduler-local.md
- `src/scheduler/task_graph.rs` - scheduler-task-graph.md
- `src/scheduler/output_sink.rs` - scheduler-output-sinks.md
- `src/scheduler/engine_trait.rs` - scheduler-engine-abstraction.md
- `src/scheduler/engine_impl.rs` - scheduler-engine-impl.md
- `src/scheduler/remote.rs` - scheduler-remote-backend.md
- `src/scheduler/local_fs_uring.rs` - scheduler-local-fs-uring.md
- `src/scheduler/ts_buffer_pool.rs` - scheduler-ts-buffer-pool.md
- `src/scheduler/device_slots.rs` - scheduler-device-slots.md
- `src/scheduler/global_resource_pool.rs` - scheduler-global-resource-pool.md

### Core Modules
- `src/api.rs` - Public API types and configuration
- `src/lib.rs` - Top-level orchestration (see architecture-overview.md)
- `src/pipeline.rs` - 4-stage processing pipeline (see pipeline-flow.md, pipeline-state-machine.md)
- `src/runtime.rs` - Buffer pools and memory management (see memory-management.md)

### Utilities
- `src/stdx/` - Custom data structures (timing_wheel, bitset, ring_buffer, byte_ring)
- `src/async_io/` - Async I/O abstractions

---

## Documentation Guidelines

When adding new features or modifying existing code:
1. Add or update module-level documentation (//!) explaining purpose, algorithms, and key invariants
2. Document public types and functions with preconditions, panics clauses, and performance characteristics
3. Include code examples and Mermaid diagrams for complex concepts
4. Cross-reference related documentation files
5. Update this index when adding new documentation files

---

## External Resources

### Tools & Dependencies
- [Vectorscan](https://github.com/VectorCamp/vectorscan) - Pattern matching library (Hyperscan fork)
- [Kani](https://model-checking.github.io/kani/) - Rust verification tool
- [Criterion](https://github.com/bheisler/criterion.rs) - Benchmarking framework

### Related Projects
- [gitleaks](https://github.com/gitleaks/gitleaks) - Source of rule definitions
- [TigerBeetle](https://github.com/tigerbeetle/tigerbeetle) - Inspiration for defensive programming style
