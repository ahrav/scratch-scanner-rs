# SIMD Optimize Skill — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a general-purpose SIMD vectorization skill orchestrator that detects ISA features, identifies vectorizable patterns, generates intrinsics code for ARM and x86, and validates correctness + performance.

**Architecture:** Flat orchestrator skill with parallel analysis agents, tiered research (baked-in references + /deep-research fallback), and rich reference library. Follows the same structure as `/asm-forge`.

**Tech Stack:** Bash scripts for detection, Markdown skill + references, Rust `std::arch` intrinsics, `cargo-show-asm`, Criterion benchmarks, proptest.

---

## Task 1: Create Directory Structure

**Files:**
- Create: `.claude/skills/simd-optimize/`
- Create: `.claude/skills/simd-optimize/scripts/`
- Create: `.claude/skills/simd-optimize/references/`

**Step 1: Create directories**

```bash
mkdir -p .claude/skills/simd-optimize/scripts
mkdir -p .claude/skills/simd-optimize/references
```

**Step 2: Verify**

```bash
find .claude/skills/simd-optimize -type d
```

Expected:
```
.claude/skills/simd-optimize
.claude/skills/simd-optimize/scripts
.claude/skills/simd-optimize/references
```

**Step 3: Commit**

```bash
# Nothing to commit yet (empty dirs aren't tracked by git).
# Files committed in subsequent tasks.
```

---

## Task 2: Write `detect_simd.sh`

**Files:**
- Create: `.claude/skills/simd-optimize/scripts/detect_simd.sh`

This script detects the host machine's SIMD capabilities and outputs structured JSON. It must work on macOS (Apple Silicon + Intel) and Linux (x86_64 + aarch64).

**Step 1: Write the script**

```bash
#!/usr/bin/env bash
# detect_simd.sh — Detect SIMD capabilities and output JSON
# Works on macOS (Apple Silicon, Intel) and Linux (x86_64, aarch64)
set -euo pipefail

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Normalize arch names
case "$ARCH" in
    arm64) ARCH="aarch64" ;;
    x86_64|amd64) ARCH="x86_64" ;;
esac

# --- Feature detection functions ---

detect_x86_features() {
    local features='{}'
    local flags=""

    if [[ "$OS" == "darwin" ]]; then
        flags=$(sysctl -a 2>/dev/null | grep -E 'cpu\.(features|extfeatures|leaf7_features)' | tr '[:upper:]' '[:lower:]' || true)
    elif [[ "$OS" == "linux" ]]; then
        flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
    fi

    # Also query rustc for canonical Rust feature names
    local rust_features=""
    if command -v rustc &>/dev/null; then
        rust_features=$(rustc --print cfg 2>/dev/null | grep 'target_feature' | sed 's/target_feature="\(.*\)"/\1/' || true)
    fi

    # Combine both sources for detection
    local all_info="$flags $rust_features"

    # SSE family
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'sse2|sse2' && echo true || echo false)" '. + {sse2: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'sse4[\._]1|sse4\.1' && echo true || echo false)" '. + {sse4_1: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'sse4[\._]2|sse4\.2' && echo true || echo false)" '. + {sse4_2: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'ssse3' && echo true || echo false)" '. + {ssse3: $v}')

    # AVX family
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qw 'avx' && echo true || echo false)" '. + {avx: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qw 'avx2' && echo true || echo false)" '. + {avx2: $v}')

    # AVX-512 families
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'avx512f' && echo true || echo false)" '. + {avx512f: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'avx512bw' && echo true || echo false)" '. + {avx512bw: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'avx512vl' && echo true || echo false)" '. + {avx512vl: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'avx512vbmi' && echo true || echo false)" '. + {avx512vbmi: $v}')

    # BMI / POPCNT / FMA
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qE 'bmi1|bmi' && echo true || echo false)" '. + {bmi1: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qw 'bmi2' && echo true || echo false)" '. + {bmi2: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qw 'popcnt' && echo true || echo false)" '. + {popcnt: $v}')
    features=$(echo "$features" | jq --argjson v "$(echo "$all_info" | grep -qw 'fma' && echo true || echo false)" '. + {fma: $v}')

    echo "$features"
}

detect_aarch64_features() {
    local features='{}'

    if [[ "$OS" == "darwin" ]]; then
        # macOS: All Apple Silicon has NEON, AES, SHA, CRC
        features='{"neon": true, "aes": true, "sha2": true, "crc": true, "sve": false, "sve2": false}'

        # Check for specific features via sysctl
        if sysctl -n hw.optional.arm.FEAT_SVE 2>/dev/null | grep -q 1; then
            features=$(echo "$features" | jq '. + {sve: true}')
        fi
        if sysctl -n hw.optional.arm.FEAT_SVE2 2>/dev/null | grep -q 1; then
            features=$(echo "$features" | jq '. + {sve2: true}')
        fi
    elif [[ "$OS" == "linux" ]]; then
        local cpu_features
        cpu_features=$(grep -m1 '^Features' /proc/cpuinfo 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)

        features=$(echo '{}' | jq --argjson v "$(echo "$cpu_features" | grep -qw 'neon\|asimd' && echo true || echo false)" '. + {neon: $v}')
        features=$(echo "$features" | jq --argjson v "$(echo "$cpu_features" | grep -qw 'aes' && echo true || echo false)" '. + {aes: $v}')
        features=$(echo "$features" | jq --argjson v "$(echo "$cpu_features" | grep -qw 'sha2' && echo true || echo false)" '. + {sha2: $v}')
        features=$(echo "$features" | jq --argjson v "$(echo "$cpu_features" | grep -qw 'crc32' && echo true || echo false)" '. + {crc: $v}')
        features=$(echo "$features" | jq --argjson v "$(echo "$cpu_features" | grep -qw 'sve' && echo true || echo false)" '. + {sve: $v}')
        features=$(echo "$features" | jq --argjson v "$(echo "$cpu_features" | grep -qw 'sve2' && echo true || echo false)" '. + {sve2: $v}')
    fi

    echo "$features"
}

# --- Recommendation logic ---

get_x86_recommendation() {
    local features="$1"
    local has_avx512f has_avx2 has_sse42
    has_avx512f=$(echo "$features" | jq -r '.avx512f')
    has_avx2=$(echo "$features" | jq -r '.avx2')
    has_sse42=$(echo "$features" | jq -r '.sse4_2')

    local baseline="sse2"
    local fast_path="null"
    local max_width=128
    local throttle_risk=false

    if [[ "$has_avx2" == "true" ]]; then
        baseline="avx2"
        max_width=256
    elif [[ "$has_sse42" == "true" ]]; then
        baseline="sse4.2"
        max_width=128
    fi

    if [[ "$has_avx512f" == "true" ]]; then
        fast_path="\"avx512\""
        max_width=512
        # Intel CPUs throttle on AVX-512; AMD Zen4+ does not
        local cpu_vendor=""
        if [[ "$OS" == "linux" ]]; then
            cpu_vendor=$(grep -m1 'vendor_id' /proc/cpuinfo 2>/dev/null | awk '{print $3}' || true)
        elif [[ "$OS" == "darwin" ]]; then
            cpu_vendor=$(sysctl -n machdep.cpu.vendor 2>/dev/null || true)
        fi
        if [[ "$cpu_vendor" == "GenuineIntel" ]]; then
            throttle_risk=true
        fi
    fi

    echo "$baseline" "$fast_path" "$max_width" "$throttle_risk"
}

get_aarch64_recommendation() {
    local features="$1"
    local has_sve has_sve2
    has_sve=$(echo "$features" | jq -r '.sve')
    has_sve2=$(echo "$features" | jq -r '.sve2')

    local baseline="neon"
    local fast_path="null"
    local max_width=128

    if [[ "$has_sve2" == "true" ]]; then
        fast_path="\"sve2\""
        max_width=2048  # scalable, up to implementation limit
    elif [[ "$has_sve" == "true" ]]; then
        fast_path="\"sve\""
        max_width=2048
    fi

    echo "$baseline" "$fast_path" "$max_width" "false"
}

# --- Rust target triple ---

get_rust_target() {
    if command -v rustc &>/dev/null; then
        rustc -vV 2>/dev/null | grep '^host:' | awk '{print $2}'
    else
        echo "unknown"
    fi
}

# --- CPU model ---

get_cpu_model() {
    if [[ "$OS" == "darwin" ]]; then
        sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown"
    elif [[ "$OS" == "linux" ]]; then
        grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || echo "unknown"
    else
        echo "unknown"
    fi
}

# --- Main ---

FEATURES=""
RECOMMENDATION=""

case "$ARCH" in
    x86_64)
        FEATURES=$(detect_x86_features)
        RECOMMENDATION=$(get_x86_recommendation "$FEATURES")
        ;;
    aarch64)
        FEATURES=$(detect_aarch64_features)
        RECOMMENDATION=$(get_aarch64_recommendation "$FEATURES")
        ;;
    *)
        echo '{"error": "Unsupported architecture: '"$ARCH"'"}' >&2
        exit 1
        ;;
esac

read -r BASELINE FAST_PATH MAX_WIDTH THROTTLE_RISK <<< "$RECOMMENDATION"

RUST_TARGET=$(get_rust_target)
CPU_MODEL=$(get_cpu_model)

# Build output JSON
jq -n \
    --arg arch "$ARCH" \
    --arg os "$OS" \
    --arg rust_target "$RUST_TARGET" \
    --arg cpu_model "$CPU_MODEL" \
    --argjson features "$FEATURES" \
    --arg baseline "$BASELINE" \
    --argjson fast_path "$FAST_PATH" \
    --argjson max_width "$MAX_WIDTH" \
    --argjson throttle_risk "$THROTTLE_RISK" \
    '{
        arch: $arch,
        os: $os,
        rust_target: $rust_target,
        cpu_model: $cpu_model,
        features: $features,
        max_vector_width_bits: $max_width,
        recommended_baseline: $baseline,
        recommended_fast_path: $fast_path,
        frequency_throttle_risk: $throttle_risk
    }'
```

**Step 2: Make executable and test**

```bash
chmod +x .claude/skills/simd-optimize/scripts/detect_simd.sh
bash .claude/skills/simd-optimize/scripts/detect_simd.sh
```

Expected: Valid JSON output with correct arch, features, and recommendations for the current machine.

**Step 3: Verify JSON is parseable**

```bash
bash .claude/skills/simd-optimize/scripts/detect_simd.sh | jq .
```

Expected: Pretty-printed JSON, no errors.

**Step 4: Commit**

```bash
git add .claude/skills/simd-optimize/scripts/detect_simd.sh
git commit -m "feat(simd-optimize): add ISA detection script"
```

---

## Task 3: Write `check_autovec.sh`

**Files:**
- Create: `.claude/skills/simd-optimize/scripts/check_autovec.sh`

This script checks whether rustc auto-vectorized a function by looking for SIMD instructions in the assembly output.

**Step 1: Write the script**

```bash
#!/usr/bin/env bash
# check_autovec.sh — Check if rustc auto-vectorized a function
# Usage: check_autovec.sh <crate> <function_path>
# Example: check_autovec.sh scanner-rs 'scanner_rs::engine::core::Engine::scan_chunk'
set -euo pipefail

CRATE="${1:?Usage: check_autovec.sh <crate> <function_path>}"
FUNC="${2:?Usage: check_autovec.sh <crate> <function_path>}"

if ! command -v cargo-asm &>/dev/null && ! cargo asm --help &>/dev/null 2>&1; then
    echo '{"error": "cargo-show-asm not installed. Run: cargo install cargo-show-asm"}' >&2
    exit 1
fi

# Collect assembly
ASM_FILE=$(mktemp /tmp/autovec-check-XXXXXX.s)
trap 'rm -f "$ASM_FILE"' EXIT

if ! cargo asm --lib -p "$CRATE" "$FUNC" > "$ASM_FILE" 2>/dev/null; then
    echo '{"error": "Failed to collect ASM. Check function path with: cargo asm --lib -p '"$CRATE"' 2>&1 | grep '"'partial_name'"'"}' >&2
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    arm64|aarch64) ARCH="aarch64" ;;
    x86_64|amd64) ARCH="x86_64" ;;
esac

# Count SIMD instructions
simd_count=0
scalar_count=0
total_instructions=0

if [[ "$ARCH" == "x86_64" ]]; then
    # x86 SIMD instruction prefixes: v (AVX/AVX2/AVX-512), p (packed SSE int),
    # movdq, movap, movup, adds/subs/muls packed, etc.
    simd_count=$(grep -cE '^\s+(v[a-z]|movdq|movap|movup|padd|psub|pmul|pand|por|pxor|pcmp|pshuf|punpck|pack|pmov|pmin|pmax)' "$ASM_FILE" 2>/dev/null || echo 0)

    # Scalar arithmetic in loops
    scalar_count=$(grep -cE '^\s+(add|sub|imul|mov|cmp|test|lea)\s' "$ASM_FILE" 2>/dev/null || echo 0)

elif [[ "$ARCH" == "aarch64" ]]; then
    # AArch64 NEON: instructions operating on v/q registers
    simd_count=$(grep -cE '^\s+(ld[1-4]|st[1-4]|fmla|fmul|fadd|fsub|add[pv]|sub[pv]|mul\s+v|mla|and\s+v|orr\s+v|eor\s+v|cm(eq|ge|gt|hi|hs|le|lt)|cnt|bsl|tbl|tbx|ext|zip|uzp|trn|rev|dup|ins|mov\s+v|umov|smov|movi|mvni|shl|sshr|ushr|ssra|usra|smin|smax|umin|umax|addv|uminv|umaxv)' "$ASM_FILE" 2>/dev/null || echo 0)

    scalar_count=$(grep -cE '^\s+(add|sub|mul|mov|cmp|ldr|str|b\.|cbz|cbnz)\s' "$ASM_FILE" 2>/dev/null || echo 0)
fi

total_instructions=$(grep -cE '^\s+[a-z]' "$ASM_FILE" 2>/dev/null || echo 0)

# Determine vectorization status
vectorized="false"
if [[ "$simd_count" -gt 5 ]]; then
    vectorized="true"
fi

# Check for common vectorization widths
widths='[]'
if [[ "$ARCH" == "x86_64" ]]; then
    has_512=$(grep -cE '^\s+v\w+.*zmm' "$ASM_FILE" 2>/dev/null || echo 0)
    has_256=$(grep -cE '^\s+v\w+.*ymm' "$ASM_FILE" 2>/dev/null || echo 0)
    has_128=$(grep -cE '^\s+(v\w+.*xmm|movdq|movap|padd|psub)' "$ASM_FILE" 2>/dev/null || echo 0)

    widths='[]'
    [[ "$has_128" -gt 0 ]] && widths=$(echo "$widths" | jq '. + [128]')
    [[ "$has_256" -gt 0 ]] && widths=$(echo "$widths" | jq '. + [256]')
    [[ "$has_512" -gt 0 ]] && widths=$(echo "$widths" | jq '. + [512]')
elif [[ "$ARCH" == "aarch64" ]]; then
    has_neon=$(grep -cE '\s+v[0-9]+\.' "$ASM_FILE" 2>/dev/null || echo 0)
    has_sve=$(grep -cE '^\s+(ld1[bhdw]|st1[bhdw]|whilelt|ptrue|pfalse)' "$ASM_FILE" 2>/dev/null || echo 0)

    [[ "$has_neon" -gt 0 ]] && widths=$(echo "$widths" | jq '. + [128]')
    [[ "$has_sve" -gt 0 ]] && widths=$(echo "$widths" | jq '. + ["scalable"]')
fi

jq -n \
    --arg func "$FUNC" \
    --arg arch "$ARCH" \
    --argjson vectorized "$vectorized" \
    --argjson simd_count "$simd_count" \
    --argjson scalar_count "$scalar_count" \
    --argjson total "$total_instructions" \
    --argjson widths "$widths" \
    --arg asm_file "$ASM_FILE" \
    '{
        function: $func,
        arch: $arch,
        auto_vectorized: $vectorized,
        simd_instruction_count: $simd_count,
        scalar_instruction_count: $scalar_count,
        total_instructions: $total,
        vector_widths_used: $widths,
        asm_file: $asm_file,
        simd_ratio: (if $total > 0 then (($simd_count * 100) / $total) else 0 end)
    }'
```

**Step 2: Make executable**

```bash
chmod +x .claude/skills/simd-optimize/scripts/check_autovec.sh
```

**Step 3: Test on a known SIMD function**

```bash
bash .claude/skills/simd-optimize/scripts/check_autovec.sh scanner-rs \
  'scanner_rs::lsm::set_associative_cache::search_tags_neon'
```

Expected: JSON with `auto_vectorized: true`, `simd_instruction_count > 0`.

**Step 4: Test on a scalar function**

```bash
bash .claude/skills/simd-optimize/scripts/check_autovec.sh scanner-rs \
  'scanner_rs::stdx::fastrange::fastrange_u64'
```

Expected: JSON with `auto_vectorized: false`, `simd_instruction_count: 0` or very low.

**Step 5: Commit**

```bash
git add .claude/skills/simd-optimize/scripts/check_autovec.sh
git commit -m "feat(simd-optimize): add auto-vectorization check script"
```

---

## Task 4: Research — x86 SIMD Intrinsics

**Purpose:** Gather accurate, comprehensive x86 SIMD reference material for the reference docs.

**Step 1: Run /deep-research for x86 SSE through AVX2**

Invoke `/deep-research` with this query:

> Comprehensive reference for Rust `std::arch::x86_64` SIMD intrinsics covering SSE2, SSSE3, SSE4.1, SSE4.2, AVX, and AVX2. For each ISA level, provide:
> 1. Available vector widths and element types
> 2. Key intrinsic functions with Rust signatures (from `core::arch::x86_64`)
> 3. Common usage patterns in Rust with code examples
> 4. The `_mm`/`_mm256` naming conventions and type suffixes
> 5. Performance characteristics (latency/throughput on modern Intel/AMD)
> 6. Common patterns: byte search with movemask, horizontal sum/min/max, pack/unpack, shuffle-based lookup table, blend/select
>
> Focus on Rust-specific usage (not C intrinsics). Include `#[target_feature(enable = "...")]` annotations.

Save output to `/tmp/research-x86-sse-avx.md`.

**Step 2: Run /deep-research for AVX-512**

Invoke `/deep-research` with this query:

> Comprehensive reference for Rust `std::arch::x86_64` AVX-512 intrinsics. Cover:
> 1. AVX-512 sub-families: F, BW, VL, DQ, VBMI, VBMI2, BITALG, VNNI, IFMA, VP2INTERSECT
> 2. Mask registers (`__mmask8/16/32/64`) and masked operations in Rust
> 3. Key intrinsics: ternary logic, compress/expand, conflict detection, permute
> 4. `_mm512_*` naming and the VL variants (`_mm256_mask_*`, `_mm_mask_*`)
> 5. Frequency throttling on Intel CPUs (which instructions trigger it, Sapphire Rapids vs older)
> 6. AMD Zen4/5 AVX-512 behavior (no throttling, 256-bit internal execution)
> 7. When 512-bit width helps vs hurts (data size thresholds, cache effects)
> 8. Rust-specific: runtime detection pattern with `is_x86_feature_detected!`
> 9. Code example: masked byte comparison and compress for text processing

Save output to `/tmp/research-x86-avx512.md`.

---

## Task 5: Research — ARM SIMD Intrinsics

**Step 1: Run /deep-research for NEON**

> Comprehensive reference for Rust `std::arch::aarch64` NEON intrinsics. Cover:
> 1. Register model: 32 × 128-bit V registers, Q (128-bit) and D (64-bit) views
> 2. Intrinsic naming: `v*q_*` (q = 128-bit), type suffixes (`u8`, `s16`, `f32`, etc.)
> 3. Key intrinsic categories with Rust signatures:
>    - Load/store: `vld1q_*`, `vst1q_*`, `vld2q_*` (interleaved)
>    - Arithmetic: `vaddq_*`, `vsubq_*`, `vmulq_*`, `vmlaq_*` (multiply-accumulate)
>    - Compare: `vceqq_*`, `vcgtq_*`, `vcltq_*`, `vcgeq_*`
>    - Bitwise: `vandq_*`, `vorrq_*`, `veorq_*`, `vbslq_*` (bitwise select)
>    - Shuffle/permute: `vtbl1_*`, `vtbl2_*`, `vextq_*`, `vzip*`, `vuzp*`, `vtrn*`
>    - Narrow/widen: `vmovn_*`, `vmovl_*`, `vqmovn_*`
>    - Reduce: `vaddvq_*`, `vmaxvq_*`, `vminvq_*`
> 4. AArch64 advantages over x86: 32 registers, no frequency throttling, FMA standard
> 5. Common patterns with Rust code: byte search, bitfield extraction, AoS↔SoA with zip/unzip
> 6. Differences from ARM32 NEON (AArch64-only intrinsics)

Save output to `/tmp/research-arm-neon.md`.

**Step 2: Run /deep-research for SVE/SVE2**

> Comprehensive reference for ARM SVE and SVE2 in Rust. Cover:
> 1. Scalable vector model: VL-agnostic programming, `svbool_t` predicates
> 2. Rust support status: `std::arch::aarch64` SVE intrinsics (stabilized? nightly?)
> 3. Key concepts: `svwhilelt`, `svptrue_b*`, predicated operations, first-faulting loads
> 4. Loop control without remainder: predicated tail handling
> 5. SVE2 additions: crypto, complex arithmetic, gather/scatter improvements
> 6. Hardware availability: AWS Graviton 3/4, Neoverse V1/V2/V3, Fujitsu A64FX
> 7. Performance characteristics vs NEON (when SVE is faster)
> 8. Code examples in Rust (or C with Rust translation notes)

Save output to `/tmp/research-arm-sve.md`.

---

## Task 6: Research — Cross-Platform Patterns & Pitfalls

**Step 1: Run /deep-research for SIMD patterns**

> Side-by-side x86 and ARM NEON implementations of common SIMD patterns in Rust. For each pattern provide both the `std::arch::x86_64` and `std::arch::aarch64` versions:
> 1. Byte/character search in buffer (find first occurrence of a byte)
> 2. Horizontal sum (reduce vector to scalar sum)
> 3. Horizontal min/max
> 4. Masked load and store
> 5. Shuffle-based lookup table (4-bit → byte mapping)
> 6. Pack (narrow) and unpack (widen) between element sizes
> 7. Scatter and gather operations
> 8. Prefix sum (inclusive scan)
> 9. Population count and leading/trailing zeros
> 10. AoS ↔ SoA transpose
> 11. Branchless select / conditional blend
> 12. Base64 encode/decode chunk processing

Save output to `/tmp/research-simd-patterns.md`.

**Step 2: Run /deep-research for portability**

> Cross-platform SIMD portability in Rust. Cover:
> 1. `cfg(target_arch)` and `cfg(target_feature)` conditional compilation
> 2. `#[target_feature(enable = "avx2")]` attribute and `unsafe` calling convention
> 3. Runtime feature detection: `is_x86_feature_detected!("avx2")` and aarch64 HWCAP via libc
> 4. Fallback chain pattern: AVX-512 → AVX2 → SSE4.1 → SSE2 → scalar
> 5. Function pointer dispatch vs `#[cfg]` static dispatch — tradeoffs
> 6. `std::simd` (portable_simd) nightly feature: current status, API, limitations
> 7. `multiversion` crate: automatic multi-versioned dispatch
> 8. `wide` crate: portable SIMD types
> 9. `pulp` crate: typed SIMD dispatch
> 10. Cross-compilation: targeting different arch than host
> 11. Complete Rust example of a function with x86 AVX2 + ARM NEON + scalar fallback

Save output to `/tmp/research-portability.md`.

**Step 3: Run /deep-research for pitfalls**

> Common SIMD pitfalls and bugs in Rust. Cover:
> 1. Alignment: `_mm_loadu_si128` vs `_mm_load_si128`, `vld1q_u8` (always unaligned on AArch64)
> 2. Denormalized float performance: DAZ/FTZ modes, `_MM_SET_FLUSH_ZERO_MODE`
> 3. NaN handling differences between x86 and ARM
> 4. Remainder loop bugs: off-by-one when input length isn't a multiple of vector width
> 5. Auto-vectorization barriers: function calls in loops, pointer aliasing, complex control flow, iterator adaptors that inhibit vectorization
> 6. AVX-512 frequency throttling: which instruction classes trigger it, mitigation strategies
> 7. AVX/SSE transition penalties (vzeroupper)
> 8. Type punning and transmute safety in Rust SIMD
> 9. `unsafe` contract documentation: what invariants must hold for SIMD unsafe blocks
> 10. Testing SIMD code: edge cases that break (zero-length, single element, max values, NaN)

Save output to `/tmp/research-pitfalls.md`.

---

## Task 7: Write `x86-sse-avx.md`

**Files:**
- Create: `.claude/skills/simd-optimize/references/x86-sse-avx.md`

**Step 1: Write the reference doc**

Using the research output from Task 4 Step 1, write a comprehensive reference document following the format and depth of the existing `asm-forge/references/aarch64-codegen.md` (~275 lines). Must include:

1. **Header**: Title, one-line description, scope (SSE2 through AVX2)
2. **ISA Progression Table**: SSE2 → SSSE3 → SSE4.1 → SSE4.2 → AVX → AVX2 with vector width, key additions
3. **Intrinsic Naming Conventions**: `_mm_` (128-bit), `_mm256_` (256-bit), type suffixes (`_epi8`, `_epi32`, `_ps`, `_pd`)
4. **Key Intrinsics by Category**: Load/store, arithmetic, compare, bitwise, shuffle/permute, pack/unpack, blend — with Rust signatures
5. **Common Patterns** (with complete Rust code examples):
   - Byte search using movemask
   - Horizontal sum/min/max
   - Shuffle-based 4-bit lookup table
   - Pack/unpack for narrowing/widening
6. **SSE4.2 String Operations**: `_mm_cmpistrm`, `_mm_cmpestrm` for text scanning
7. **AVX2 Lane-Crossing**: `_mm256_permutevar8x32_epi32`, gather instructions
8. **Performance Notes**: Latency/throughput for key operations on modern microarchitectures

Target: ~300-400 lines. Every intrinsic must use the correct Rust `core::arch::x86_64` name.

**Step 2: Verify accuracy**

Cross-check a sample of intrinsic names against the Rust documentation or Intel Intrinsics Guide.

**Step 3: Commit**

```bash
git add .claude/skills/simd-optimize/references/x86-sse-avx.md
git commit -m "feat(simd-optimize): add x86 SSE/AVX2 reference"
```

---

## Task 8: Write `x86-avx512.md`

**Files:**
- Create: `.claude/skills/simd-optimize/references/x86-avx512.md`

**Step 1: Write the reference doc**

Using research from Task 4 Step 2. Must include:

1. **AVX-512 Family Overview**: Table of sub-extensions (F, BW, VL, DQ, VBMI, VBMI2, etc.) with what each adds
2. **Mask Registers**: `__mmask8/16/32/64`, masked operations, write-masking, zero-masking
3. **Key Intrinsics**: Ternary logic (`_mm512_ternarylogic_epi64`), compress/expand, permute, conflict detection
4. **VL (Vector Length) Variants**: Using AVX-512 features at 128/256-bit widths
5. **Frequency Throttling**:
   - Intel: which instruction classes cause downclocking (heavy vs light)
   - Sapphire Rapids vs Ice Lake vs older behavior
   - AMD Zen4/5: no throttling, 256-bit internal execution
   - Decision matrix: when to use 512-bit vs stick with 256-bit
6. **Runtime Detection Pattern**: Complete Rust example with `is_x86_feature_detected!`
7. **Code Example**: Masked byte comparison + compress for filtering

Target: ~250-350 lines.

**Step 2: Commit**

```bash
git add .claude/skills/simd-optimize/references/x86-avx512.md
git commit -m "feat(simd-optimize): add AVX-512 reference"
```

---

## Task 9: Write `arm-neon.md`

**Files:**
- Create: `.claude/skills/simd-optimize/references/arm-neon.md`

**Step 1: Write the reference doc**

Using research from Task 5 Step 1. Must include:

1. **Register Model**: 32 × 128-bit V registers, Q (128-bit) and D (64-bit) views, type suffixes
2. **Intrinsic Naming Convention**: `v` prefix, `q` suffix for 128-bit, type suffixes (`_u8`, `_s16`, `_f32`)
3. **Key Intrinsics by Category**: Load/store, arithmetic, compare, bitwise, shuffle (vtbl/vext/vzip/vuzp/vtrn), narrow/widen, reduce
4. **AArch64 vs ARM32 NEON**: AArch64-only features (scalar FP in NEON regs, full IEEE compliance, `vaddv` horizontal)
5. **Common Patterns** (with Rust code):
   - Byte search in buffer
   - Bitfield extraction and packing
   - AoS ↔ SoA conversion with zip/unzip
   - Table lookup with vtbl
6. **AArch64 Advantages**: 32 SIMD regs, no frequency throttling, deterministic latency, FMA standard
7. **Apple Silicon Notes**: Always available, high-performance implementation

Target: ~300-400 lines.

**Step 2: Commit**

```bash
git add .claude/skills/simd-optimize/references/arm-neon.md
git commit -m "feat(simd-optimize): add ARM NEON reference"
```

---

## Task 10: Write `arm-sve.md`

**Files:**
- Create: `.claude/skills/simd-optimize/references/arm-sve.md`

**Step 1: Write the reference doc**

Using research from Task 5 Step 2. Must include:

1. **Scalable Vector Model**: Width-agnostic programming, VL (vector length) concept
2. **Predicate Registers**: `svbool_t`, `svwhilelt`, `svptrue_b8/16/32/64`
3. **Key Intrinsics**: Load/store (predicated), arithmetic, compare, compact/expand
4. **Loop Control**: Predicated loops that eliminate remainder handling
5. **First-Faulting Loads**: Speculative safe memory access
6. **SVE2 Additions**: What SVE2 adds over SVE1
7. **Hardware Availability**: Which processors support SVE/SVE2
8. **Rust Support Status**: Current `std::arch::aarch64` SVE support, nightly features
9. **When to Use SVE vs NEON**: Decision criteria

Target: ~200-300 lines (SVE is more specialized, less commonly used).

**Step 2: Commit**

```bash
git add .claude/skills/simd-optimize/references/arm-sve.md
git commit -m "feat(simd-optimize): add ARM SVE reference"
```

---

## Task 11: Write `simd-patterns.md`

**Files:**
- Create: `.claude/skills/simd-optimize/references/simd-patterns.md`

**Step 1: Write the reference doc**

Using research from Task 6 Step 1. This is the most important reference doc — it provides side-by-side implementations. Must include ~12-15 patterns, each with:

- **Pattern name and description**
- **When to use**: What loop shape triggers this pattern
- **x86 implementation** (SSE2/AVX2): Complete Rust code with `#[target_feature]`
- **ARM implementation** (NEON): Complete Rust code with `#[target_feature]`
- **Performance notes**: Expected speedup, input size thresholds

Patterns to cover:
1. Byte search (find byte in buffer)
2. Horizontal sum
3. Horizontal min/max
4. Masked load/store
5. Shuffle-based LUT (4-bit index → byte)
6. Pack/unpack (narrow/widen)
7. Scatter/gather
8. Prefix sum (parallel scan)
9. Popcount / CLZ / CTZ
10. AoS ↔ SoA transpose
11. Branchless select (blend/bsl)
12. Base64 decode chunk

Target: ~400-500 lines (this is the largest reference doc).

**Step 2: Commit**

```bash
git add .claude/skills/simd-optimize/references/simd-patterns.md
git commit -m "feat(simd-optimize): add cross-platform SIMD patterns reference"
```

---

## Task 12: Write `portability-guide.md`

**Files:**
- Create: `.claude/skills/simd-optimize/references/portability-guide.md`

**Step 1: Write the reference doc**

Using research from Task 6 Step 2. Must include:

1. **Static Dispatch** (`cfg`): `cfg(target_arch)`, `cfg(target_feature)` patterns
2. **`#[target_feature]` Attribute**: Calling convention, `unsafe` requirement, how it works
3. **Runtime Dispatch**: `is_x86_feature_detected!`, aarch64 HWCAP detection
4. **Fallback Chain Template**: Complete Rust example showing AVX-512 → AVX2 → SSE → scalar
5. **Function Pointer Dispatch vs Static Dispatch**: Tradeoffs (binary size, call overhead, maintainability)
6. **Portable SIMD Crates**:
   - `std::simd` (portable_simd): Status, API, when to use
   - `multiversion` crate: Automatic multi-versioning
   - `wide` crate: Portable SIMD types
   - `pulp` crate: Typed dispatch
7. **Complete Example**: A function implemented for x86 AVX2 + ARM NEON + scalar fallback with proper `cfg` gating

Target: ~300-350 lines.

**Step 2: Commit**

```bash
git add .claude/skills/simd-optimize/references/portability-guide.md
git commit -m "feat(simd-optimize): add portability guide reference"
```

---

## Task 13: Write `pitfalls.md`

**Files:**
- Create: `.claude/skills/simd-optimize/references/pitfalls.md`

**Step 1: Write the reference doc**

Using research from Task 6 Step 3. Must include:

1. **Alignment**: `loadu` vs `load` (x86), NEON always-unaligned, performance impact
2. **Denormalized Floats**: DAZ/FTZ, `_MM_SET_FLUSH_ZERO_MODE`, performance cliff
3. **NaN Handling**: x86 vs ARM comparison semantics differences
4. **Remainder Loops**: Off-by-one patterns, overlap technique, masked tail
5. **Auto-Vectorization Barriers**: Function calls, aliasing, iterator chains that block LLVM
6. **AVX-512 Throttling**: Intel downclocking rules, mitigation
7. **AVX/SSE Transitions**: `vzeroupper`, when it's needed, what happens without it
8. **Type Punning & Transmute**: Safe vs unsafe transmute for SIMD types in Rust
9. **`unsafe` Contract Documentation**: What safety comments must cover for SIMD blocks
10. **Testing Edge Cases**: Zero-length, single element, exact vector width, width ± 1, all-zeros, all-ones, NaN, max values, alignment boundaries

Target: ~250-350 lines.

**Step 2: Commit**

```bash
git add .claude/skills/simd-optimize/references/pitfalls.md
git commit -m "feat(simd-optimize): add SIMD pitfalls reference"
```

---

## Task 14: Write `SKILL.md` Orchestrator

**Files:**
- Create: `.claude/skills/simd-optimize/SKILL.md`

**Step 1: Write the skill**

The orchestrator SKILL.md must include:

1. **Frontmatter**: name, description, user-invocable
2. **Philosophy statement**
3. **When to Use / When NOT to Use**
4. **Prerequisites**: cargo-show-asm, Criterion benchmarks, proptest
5. **Invocation**: `/simd-optimize @file.rs "function or description"`
6. **Workflow Overview**: ASCII diagram of phases
7. **Phase 0: ISA Detection**: Run `detect_simd.sh`, present capability report
8. **Phase 1: Analysis**: 3 parallel agents (Loop Analyzer, Autovec Auditor, Constraint Mapper) — exact prompt templates for each
9. **Phase 2: Research & Strategy**: Tiered lookup — load references, gap-check, strategy selection matrix
10. **Phase 3: Implementation**: Step-by-step code generation guide with template
11. **Phase 4: Validation**: 2 parallel agents (Correctness Validator, Performance Validator) — exact prompt templates
12. **Output Format**: Summary report template
13. **Tips**: ISA-specific notes, when to escalate to `/deep-research`
14. **Related Skills**: Links to `/asm-forge`, `/rust-hotspot-finder`, `/bench-compare`, etc.

The agent prompt templates in Phases 1 and 4 should follow the pattern from `asm-forge`'s Phase 0 (common preamble + agent-specific focus).

Key orchestrator logic for Phase 2 (tiered research):
```
IF ISA is x86_64:
    Load references/x86-sse-avx.md
    IF features.avx512f: also load references/x86-avx512.md
ELIF ISA is aarch64:
    Load references/arm-neon.md
    IF features.sve or features.sve2: also load references/arm-sve.md

ALWAYS load: references/simd-patterns.md, references/portability-guide.md, references/pitfalls.md

IF pattern not found in loaded references:
    Invoke /deep-research with specific query about the pattern + ISA
```

Target: ~400-500 lines (similar to asm-forge's 450 lines).

**Step 2: Verify skill loads**

Test that Claude Code recognizes the skill:
```
# In Claude Code, run:
/simd-optimize --help
# Should show the skill description
```

**Step 3: Commit**

```bash
git add .claude/skills/simd-optimize/SKILL.md
git commit -m "feat(simd-optimize): add main orchestrator skill"
```

---

## Task 15: Smoke Test the Skill

**Step 1: Run ISA detection**

```bash
bash .claude/skills/simd-optimize/scripts/detect_simd.sh | jq .
```

Verify output matches the current machine.

**Step 2: Run autovec check on a known function**

```bash
bash .claude/skills/simd-optimize/scripts/check_autovec.sh scanner-rs \
  'scanner_rs::lsm::set_associative_cache::SetAssociativeCache<WAYS,SETS,TAG_BITS,BUCKET_BITS>::search'
```

Verify JSON output is reasonable.

**Step 3: Invoke the skill on a sample function**

In Claude Code, invoke:
```
/simd-optimize @src/stdx/fastrange.rs "vectorize fastrange_u64 for batch processing"
```

Verify that:
- Phase 0 produces an ISA capability report
- Phase 1 agents analyze the code
- Phase 2 loads appropriate references for the detected ISA
- The skill provides actionable SIMD implementation guidance

**Step 4: Final commit**

```bash
git add -A .claude/skills/simd-optimize/
git commit -m "feat: complete simd-optimize skill with references and scripts"
```

---

## Task 16: Copy to `.codex/skills/` (mirror)

The project maintains parallel skill directories in both `.claude/skills/` and `.codex/skills/`.

**Step 1: Mirror the skill**

```bash
cp -r .claude/skills/simd-optimize .codex/skills/simd-optimize
```

**Step 2: Verify**

```bash
diff -r .claude/skills/simd-optimize .codex/skills/simd-optimize
```

Expected: No differences.

**Step 3: Commit**

```bash
git add .codex/skills/simd-optimize/
git commit -m "chore: mirror simd-optimize skill to .codex/skills/"
```

---

## Execution Notes

### Research tasks (4-6) can run in parallel

Tasks 4, 5, and 6 are independent research tasks. Launch all `/deep-research` invocations simultaneously using parallel Task tool calls for maximum efficiency. There are 6 research queries total — all can run concurrently.

### Reference doc tasks (7-13) depend on research

Tasks 7-13 each depend on their corresponding research task. However, reference doc writing can be parallelized: once all research is complete, launch multiple subagents to write docs simultaneously.

### Suggested parallel execution groups

| Group | Tasks | Dependencies |
|-------|-------|-------------|
| A (infra) | 1, 2, 3 | None |
| B (research) | 4, 5, 6 | None (run all 6 queries in parallel) |
| C (docs) | 7, 8, 9, 10, 11, 12, 13 | Depends on B |
| D (orchestrator) | 14 | Depends on A (for script paths) |
| E (validation) | 15, 16 | Depends on C and D |
