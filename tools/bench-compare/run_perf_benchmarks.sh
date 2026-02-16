#!/usr/bin/env bash
# ==========================================================================
# Perf-Stat Benchmark Harness
#
# Collects hardware performance counters (perf stat) for scanner-rs,
# Kingfisher, TruffleHog, and Gitleaks on the vscode repo (git mode,
# warm cache). Four event groups × four scanners = 16 measured runs
# plus 16 warmup runs.
#
# Requirements:
#   - Linux with perf installed
#   - perf_event_paranoid <= 2 (user-space events with :u suffix)
#   - All scanner binaries built in release mode
#   - vscode repo cloned under REPO_BASE
#
# Usage: ./run_perf_benchmarks.sh
# ==========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
PERF_RAW_DIR="$RESULTS_DIR/perf_raw"
CONFIGS_DIR="$SCRIPT_DIR/configs"
CSV="$RESULTS_DIR/perf_metrics.csv"

# ── Scanner binaries ─────────────────────────────────────────────────
SCANNER_RS="${SCANNER_RS_BIN:-$SCRIPT_DIR/../../target/release/scanner-rs}"
KINGFISHER="${KINGFISHER_BIN:-/local/home/ahrav/scratch/kingfisher/target/release/kingfisher}"
TRUFFLEHOG_BIN="${TRUFFLEHOG_BIN:-/local/home/ahrav/scratch/trufflehog/trufflehog}"
GITLEAKS_BIN="${GITLEAKS_BIN:-/local/home/ahrav/scratch/gitleaks/gitleaks}"

# ── Repo ─────────────────────────────────────────────────────────────
REPO_BASE="${BENCHMARK_REPO_BASE:-/local/home/ahrav/scratch}"
REPO="vscode"
REPO_PATH="$REPO_BASE/$REPO"

# ── Scanners ─────────────────────────────────────────────────────────
SCANNERS=(scanner-rs kingfisher trufflehog gitleaks)

# ── Perf event groups ────────────────────────────────────────────────
# ARM Graviton3 PMU supports ~6 hardware counters per group.
# With time-multiplexing on 13+ second workloads, all events get
# sufficient sampling time (~2s each).

declare -A EVENT_GROUPS
EVENT_GROUPS[group1]="cycles:u,instructions:u,stalled-cycles-frontend:u,stalled-cycles-backend:u,branch-misses:u,bus-cycles:u"
EVENT_GROUPS[group2]="L1-dcache-loads:u,L1-dcache-load-misses:u,L1-icache-loads:u,L1-icache-load-misses:u,cache-references:u,cache-misses:u"
EVENT_GROUPS[group3]="l2d_cache:u,l2d_cache_refill:u,l2d_cache_lmiss_rd:u,mem_access:u,l2d_cache_wb:u,l2d_cache_allocate:u"
EVENT_GROUPS[group4]="dTLB-loads:u,dTLB-load-misses:u,dtlb_walk:u,iTLB-loads:u,iTLB-load-misses:u,br_pred:u"

GROUP_NAMES=(group1 group2 group3 group4)

TOTAL_RUNS=$(( ${#SCANNERS[@]} * ${#GROUP_NAMES[@]} ))
RUN_NUM=0

# ── Directories ──────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR" "$PERF_RAW_DIR"

# ── Verify prerequisites ─────────────────────────────────────────────
for bin in "$SCANNER_RS" "$KINGFISHER" "$TRUFFLEHOG_BIN" "$GITLEAKS_BIN"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: Binary not found or not executable: $bin" >&2
        exit 1
    fi
done

if [[ ! -d "$REPO_PATH" ]]; then
    echo "ERROR: Repo directory not found: $REPO_PATH" >&2
    exit 1
fi

if ! command -v perf &>/dev/null; then
    echo "ERROR: perf not found. Install linux-tools-$(uname -r)" >&2
    exit 1
fi

PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 4)
if [[ "$PARANOID" -gt 2 ]]; then
    echo "ERROR: perf_event_paranoid=$PARANOID (need <=2 for user-space events)" >&2
    echo "  Fix: sudo sysctl kernel.perf_event_paranoid=2" >&2
    exit 1
fi

# ── Scanner command wrappers ─────────────────────────────────────────
# Each function runs the scanner on vscode in git mode and writes
# stdout/stderr to the provided file paths.

run_scanner_rs() {
    local stdout_file="$1" stderr_file="$2"
    "$SCANNER_RS" scan git "--repo=$REPO_PATH" \
        --event-format=json --transforms=all --decode-depth=2 \
        > "$stdout_file" 2> "$stderr_file" || true
}

run_kingfisher() {
    local stdout_file="$1" stderr_file="$2"
    "$KINGFISHER" scan "$REPO_PATH" \
        --no-validate --git-history=full --format json \
        > "$stdout_file" 2> "$stderr_file" || true
}

run_trufflehog() {
    local stdout_file="$1" stderr_file="$2"
    local detectors_file="$CONFIGS_DIR/trufflehog-detectors.txt"
    local include_flag=""
    if [[ -f "$detectors_file" ]]; then
        include_flag="--include-detectors=$(cat "$detectors_file" | tr -d '\n')"
    fi
    "$TRUFFLEHOG_BIN" git --no-verification --json \
        $include_flag \
        "file://$REPO_PATH" \
        > "$stdout_file" 2> "$stderr_file" || true
}

run_gitleaks() {
    local stdout_file="$1" stderr_file="$2"
    local gl_config="$CONFIGS_DIR/gitleaks-config.toml"
    local config_flag=""
    if [[ -f "$gl_config" ]]; then
        config_flag="--config $gl_config"
    fi
    "$GITLEAKS_BIN" git $config_flag \
        --report-format json --report-path /dev/null \
        --max-decode-depth 2 --max-archive-depth 3 \
        --exit-code 0 "$REPO_PATH" \
        > "$stdout_file" 2> "$stderr_file" || true
}

# ── Parse perf stat output ───────────────────────────────────────────
# Extracts event name → count pairs from perf stat -o output.
# Outputs CSV-compatible values via Python for robustness.

parse_perf_output() {
    local perf_file="$1"
    python3 -c "
import re, sys

with open('$perf_file') as f:
    text = f.read()

# Extract wall time from 'seconds time elapsed' line
time_match = re.search(r'([\d.]+)\s+seconds time elapsed', text)
wall_time = float(time_match.group(1)) if time_match else 0.0

# Extract event lines: <count> <event_name> [optional comment]
# Handles commas in numbers and <not counted> / <not supported>
events = {}
for line in text.split('\n'):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('Performance'):
        continue

    # Match lines like: '1,234,567  cycles:u  # ...'
    m = re.match(r'^([\d,]+)\s+(\S+)', line)
    if m:
        count_str = m.group(1).replace(',', '')
        event_name = m.group(2)
        events[event_name] = int(count_str)
    # Match <not counted> / <not supported>
    elif '<not counted>' in line or '<not supported>' in line:
        m2 = re.search(r'<not (?:counted|supported)>\s+(\S+)', line)
        if m2:
            events[m2.group(1)] = 0

# Print as key=value pairs, one per line.
# Some generic events (L1-dcache-loads, dTLB-loads, etc.) drop the :u suffix
# in perf output even when specified with :u. Emit both variants so the CSV
# lookup by the :u column name always finds the value.
print(f'wall_time_s={wall_time:.6f}')
for name, count in sorted(events.items()):
    print(f'{name}={count}')
    if not name.endswith(':u'):
        print(f'{name}:u={count}')
"
}

# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

echo "=========================================="
echo " Perf-Stat Benchmark"
echo " $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo " Repo: $REPO (git mode, warm cache)"
echo " Scanners: ${SCANNERS[*]}"
echo " Groups: ${GROUP_NAMES[*]}"
echo " Total measured runs: $TOTAL_RUNS"
echo " (plus $TOTAL_RUNS warmup runs)"
echo "=========================================="
echo ""

# ── CSV header ───────────────────────────────────────────────────────
# Collect all unique event names across groups for column headers.
# We write a wide-format CSV: scanner, group, wall_time_s, event1, event2, ...

# Build ordered list of all events
ALL_EVENTS=()
for group in "${GROUP_NAMES[@]}"; do
    IFS=',' read -ra evts <<< "${EVENT_GROUPS[$group]}"
    for evt in "${evts[@]}"; do
        ALL_EVENTS+=("$evt")
    done
done

# Write CSV header
{
    printf "scanner,group,wall_time_s"
    for evt in "${ALL_EVENTS[@]}"; do
        printf ",%s" "$evt"
    done
    printf "\n"
} > "$CSV"

# ── Run benchmarks ───────────────────────────────────────────────────
for scanner in "${SCANNERS[@]}"; do
    for group in "${GROUP_NAMES[@]}"; do
        RUN_NUM=$((RUN_NUM + 1))
        events="${EVENT_GROUPS[$group]}"

        echo "[$RUN_NUM/$TOTAL_RUNS] $scanner / $group"

        warmup_stdout="$PERF_RAW_DIR/${scanner}_${group}_warmup.json"
        warmup_stderr="$PERF_RAW_DIR/${scanner}_${group}_warmup.stderr"
        perf_output="$PERF_RAW_DIR/${scanner}_${group}.perf"
        measured_stdout="$PERF_RAW_DIR/${scanner}_${group}.json"
        measured_stderr="$PERF_RAW_DIR/${scanner}_${group}.stderr"

        # ── Warmup run (populate page cache) ─────────────────────
        echo "  warmup..."
        case "$scanner" in
            scanner-rs) run_scanner_rs "$warmup_stdout" "$warmup_stderr" ;;
            kingfisher)  run_kingfisher "$warmup_stdout" "$warmup_stderr" ;;
            trufflehog)  run_trufflehog "$warmup_stdout" "$warmup_stderr" ;;
            gitleaks)    run_gitleaks "$warmup_stdout" "$warmup_stderr" ;;
        esac
        rm -f "$warmup_stdout" "$warmup_stderr"

        # ── Measured run with perf stat ──────────────────────────
        echo "  measuring ($group: $events)..."
        case "$scanner" in
            scanner-rs)
                perf stat -e "$events" -o "$perf_output" -- \
                    "$SCANNER_RS" scan git "--repo=$REPO_PATH" \
                        --event-format=json --transforms=all --decode-depth=2 \
                    > "$measured_stdout" 2> "$measured_stderr" || true
                ;;
            kingfisher)
                perf stat -e "$events" -o "$perf_output" -- \
                    "$KINGFISHER" scan "$REPO_PATH" \
                        --no-validate --git-history=full --format json \
                    > "$measured_stdout" 2> "$measured_stderr" || true
                ;;
            trufflehog)
                local_detectors="$CONFIGS_DIR/trufflehog-detectors.txt"
                local_include=""
                if [[ -f "$local_detectors" ]]; then
                    local_include="--include-detectors=$(cat "$local_detectors" | tr -d '\n')"
                fi
                perf stat -e "$events" -o "$perf_output" -- \
                    "$TRUFFLEHOG_BIN" git --no-verification --json \
                        $local_include \
                        "file://$REPO_PATH" \
                    > "$measured_stdout" 2> "$measured_stderr" || true
                ;;
            gitleaks)
                local_config="$CONFIGS_DIR/gitleaks-config.toml"
                local_cflag=""
                if [[ -f "$local_config" ]]; then
                    local_cflag="--config $local_config"
                fi
                perf stat -e "$events" -o "$perf_output" -- \
                    "$GITLEAKS_BIN" git $local_cflag \
                        --report-format json --report-path /dev/null \
                        --max-decode-depth 2 --max-archive-depth 3 \
                        --exit-code 0 "$REPO_PATH" \
                    > "$measured_stdout" 2> "$measured_stderr" || true
                ;;
        esac

        # ── Parse and append to CSV ──────────────────────────────
        if [[ ! -f "$perf_output" ]]; then
            echo "  WARN: perf output missing for $scanner/$group" >&2
            continue
        fi

        # Parse perf output into associative array
        declare -A PARSED=()
        while IFS='=' read -r key val; do
            PARSED["$key"]="$val"
        done < <(parse_perf_output "$perf_output")

        # Write CSV row
        {
            printf "%s,%s,%s" "$scanner" "$group" "${PARSED[wall_time_s]:-0}"
            for evt in "${ALL_EVENTS[@]}"; do
                printf ",%s" "${PARSED[$evt]:-0}"
            done
            printf "\n"
        } >> "$CSV"

        wall_done="${PARSED[wall_time_s]:-?}"
        unset PARSED

        echo "  done (wall: ${wall_done}s)"
    done
done

echo ""
echo "=========================================="
echo " Perf benchmark complete: $RUN_NUM runs"
echo " Raw perf data: $PERF_RAW_DIR/"
echo " CSV: $CSV"
echo "=========================================="
