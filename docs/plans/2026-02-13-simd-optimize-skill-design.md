# SIMD Optimize Skill — Design Document

**Date**: 2026-02-13
**Status**: Approved
**Approach**: Flat Orchestrator (single skill with parallel agents and rich reference library)

---

## Overview

A general-purpose SIMD vectorization skill for Claude Code that:

- Detects the host machine's ISA features (ARM NEON/SVE, x86 SSE/AVX/AVX-512)
- Identifies vectorizable patterns in Rust code
- Generates platform-specific intrinsics with correct fallback chains
- Validates correctness and performance
- Uses tiered research: baked-in references first, `/deep-research` on demand

Assumes an **intermediate** user who understands vectorization concepts but needs help picking intrinsics, handling edge cases, and writing portable code.

## File Layout

```
.claude/skills/simd-optimize/
├── SKILL.md                       # Orchestrator
├── scripts/
│   ├── detect_simd.sh             # CPU feature detection → JSON
│   └── check_autovec.sh           # Did rustc auto-vectorize? → analysis
└── references/
    ├── x86-sse-avx.md             # SSE2 through AVX2
    ├── x86-avx512.md              # AVX-512 families (F, BW, VL, VBMI)
    ├── arm-neon.md                # AArch64 NEON intrinsics + patterns
    ├── arm-sve.md                 # SVE/SVE2 scalable vector patterns
    ├── simd-patterns.md           # ~15 ISA-agnostic patterns (both x86 + ARM)
    ├── portability-guide.md       # cfg dispatch, runtime detection, fallback chains
    └── pitfalls.md                # Alignment, denorms, autovec barriers, UB
```

## Workflow Phases

### Phase 0 — ISA Detection

Runs `detect_simd.sh` (no agents needed). Outputs structured JSON:

```json
{
  "arch": "aarch64",
  "os": "darwin",
  "rust_target": "aarch64-apple-darwin",
  "features": { "neon": true, "sve": false, "sve2": false },
  "max_vector_width_bits": 128,
  "recommended_baseline": "neon",
  "recommended_fast_path": null,
  "frequency_throttle_risk": false
}
```

Key fields:
- `recommended_baseline` — the ISA level all SIMD code should target
- `recommended_fast_path` — optional higher ISA for runtime dispatch (e.g., AVX-512 when AVX2 is baseline)
- `frequency_throttle_risk` — true on Intel CPUs where AVX-512 may downclock

Detection sources: `uname -m`, `rustc --print cfg`, platform-specific CPU info (sysctl on macOS, /proc/cpuinfo on Linux).

### Phase 1 — Analysis (3 parallel agents)

All three launched in a single message via Task tool:

| Agent | Role | Inputs | Output |
|-------|------|--------|--------|
| **Loop Analyzer** | Identify vectorizable patterns | Target code + ISA report | Candidate list with pattern classification (reduction, map, scan, search, LUT) |
| **Autovec Auditor** | Check what rustc already vectorized | `check_autovec.sh` output + assembly | Report of hit/miss autovectorization + missed opportunities |
| **Constraint Mapper** | Check data layout, alignment, types, memory access | Target code + struct definitions | Constraint report (AoS/SoA, alignment, stride, aliasing) |

### Phase 2 — Research & Strategy (tiered)

1. **Reference lookup**: Load relevant `references/*.md` based on Phase 0 ISA + Phase 1 patterns
2. **Gap check**: If pattern isn't in references → invoke `/deep-research` for that specific gap
3. **Strategy selection**: Choose one of:
   - Direct intrinsics (`std::arch`) — most control, best performance
   - Help auto-vectorizer — restructure code so rustc handles it (simplest)
   - Portable SIMD (`std::simd` nightly) — if portability > performance
   - Crate-based (`wide`, `pulp`, `multiversion`) — good middle ground

### Phase 3 — Implementation

Sequential, guided code generation:

1. Ensure scalar reference implementation exists (for correctness testing)
2. Write SIMD implementation(s) gated by `cfg(target_arch)` + `#[target_feature(enable = "...")]`
3. Wire runtime dispatch if needed (`is_x86_feature_detected!`)
4. Handle remainder elements (tail loop or masked final vector)
5. Add `unsafe` blocks with safety comments documenting invariants
6. Follow the project's existing patterns (match `set_associative_cache.rs` and `transform.rs` style)

### Phase 4 — Validation (2 parallel agents)

| Agent | Role |
|-------|------|
| **Correctness Validator** | Property tests (proptest) comparing SIMD vs scalar: empty, single element, exact width, width ± 1, all-zeros, all-ones, max values |
| **Performance Validator** | Invoke `/bench-compare` against scalar baseline, verify speedup, report throughput delta |

## Reference Documents — Content Outline

### `x86-sse-avx.md`
- SSE2 (baseline): 128-bit integer/float, movemask byte-search pattern
- SSE4.1: variable blend, extract/insert, `_mm_cmpistrm` string ops
- SSE4.2: CRC32, string comparison
- AVX: 256-bit float only (no integer)
- AVX2: 256-bit integer, gather, lane-crossing permutes
- Intrinsic naming: `_mm` (128), `_mm256` (256), type suffixes
- Patterns: byte search, horizontal sum/min/max, pack/unpack, shuffle LUT

### `x86-avx512.md`
- AVX-512F: 512-bit foundation, mask registers, ternary logic, compress/expand
- AVX-512BW: byte/word ops (text processing)
- AVX-512VL: 128/256-bit with AVX-512 features
- AVX-512VBMI/VBMI2: byte permute, compress bytes
- Frequency throttling: when 512-bit hurts, Intel vs AMD behavior
- Runtime detection pattern

### `arm-neon.md`
- Registers: 32 x 128-bit, Q/D views
- Naming: `v*q_*` (q = 128-bit), type suffixes
- Key ops: load/store, compare, narrow/widen, table lookup (vtbl)
- AArch64 advantages: 32 regs, no throttling, standard FMA
- Patterns: byte search, bitfield, zip/unzip for AoS↔SoA

### `arm-sve.md`
- Scalable vectors: width-agnostic (128–2048 bit)
- Predicates: `svbool_t`, `svwhilelt` loop control
- Availability: Graviton 3+, Neoverse V-series
- Patterns: predicated loops (no remainder), first-faulting loads

### `simd-patterns.md`
~15 patterns with side-by-side x86 + ARM implementations:
- Byte/character search
- Horizontal reduction (sum, min, max)
- Masked store/load
- Shuffle-based LUT
- Pack/unpack (widen/narrow)
- Scatter/gather
- Prefix sum (parallel scan)
- Popcount / leading zeros
- AoS ↔ SoA transpose
- Branchless select (blend)
- String/pattern matching
- Base64 encode/decode

### `portability-guide.md`
- `cfg(target_arch)` + `cfg(target_feature)` dispatch
- Runtime detection: `is_x86_feature_detected!`, aarch64 HWCAP
- Fallback chains: AVX-512 → AVX2 → SSE4.1 → scalar
- `#[target_feature(enable = "...")]` calling convention
- `std::simd` / `portable_simd` status
- `multiversion` crate
- Cross-compilation notes

### `pitfalls.md`
- Alignment (`loadu` vs `load`)
- Denormalized floats and flush-to-zero
- NaN handling differences
- Remainder loop off-by-one
- Autovectorization barriers
- AVX-512 frequency throttling
- Type punning UB
- `unsafe` contract documentation

## Detection Script (`detect_simd.sh`)

Works on macOS and Linux. Sources:
1. `uname -m` for architecture
2. `rustc --print cfg` for Rust-canonical features
3. Platform-specific: `sysctl` (macOS), `/proc/cpuinfo` (Linux)

Outputs JSON with: arch, os, rust_target, features map, max vector width, recommended baseline/fast-path, throttle risk flag.

## Skill Interactions

- **Invokes**: `/deep-research` (when references don't cover the pattern), `/bench-compare` (Phase 4 performance validation)
- **Complements**: `/asm-forge` (for post-SIMD assembly audit), `/rust-hotspot-finder` (to identify what to vectorize), `/performance-analyzer` (broader perf analysis)
- **No dependency on**: project-specific code or data structures

## Success Criteria

1. Given a scalar loop, the skill produces a working SIMD implementation that:
   - Compiles on the detected ISA without manual fixup
   - Passes property tests against the scalar reference
   - Shows measurable speedup on the detected hardware
2. The skill correctly avoids suggesting unavailable ISA features
3. The tiered research covers 80%+ of common patterns from references alone
4. The generated code follows Rust SIMD best practices (safety docs, proper gating, fallback chain)
