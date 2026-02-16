#!/usr/bin/env bash
# ==========================================================================
# Scanner Comparison Benchmark Harness
#
# Runs scanner-rs, Kingfisher, TruffleHog, and Gitleaks across 8 repos
# in git + fs modes with cold + warm cache. 128 sequential runs total.
#
# Usage: sudo ./run_benchmarks.sh          # full run (needs sudo for cache drop)
#        ./run_benchmarks.sh --smoke       # smoke test on rocksdb only
#        ./run_benchmarks.sh --no-cold     # skip cold runs (no sudo needed)
# ==========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
RAW_DIR="$RESULTS_DIR/raw"
CONFIGS_DIR="$SCRIPT_DIR/configs"
CSV="$RESULTS_DIR/metrics.csv"

# ── Scanner binaries ─────────────────────────────────────────────────
SCANNER_RS="${SCANNER_RS_BIN:-$SCRIPT_DIR/../../target/release/scanner-rs}"
KINGFISHER="${KINGFISHER_BIN:-/local/home/ahrav/scratch/kingfisher/target/release/kingfisher}"
TRUFFLEHOG_BIN="${TRUFFLEHOG_BIN:-/local/home/ahrav/scratch/trufflehog/trufflehog}"
GITLEAKS_BIN="${GITLEAKS_BIN:-/local/home/ahrav/scratch/gitleaks/gitleaks}"

# ── Repos ────────────────────────────────────────────────────────────
REPO_BASE="${BENCHMARK_REPO_BASE:-/local/home/ahrav/scratch}"
ALL_REPOS=(node vscode linux rocksdb tensorflow Babylon.js gcc jdk)
SMOKE_REPOS=(rocksdb)

# ── Config ───────────────────────────────────────────────────────────
SCANNERS=(scanner-rs kingfisher trufflehog gitleaks)
MODES=(git fs)
ALL_CACHES=(cold warm)
NO_COLD_CACHES=(warm)

# ── Parse flags ──────────────────────────────────────────────────────
REPOS=("${ALL_REPOS[@]}")
CACHES=("${ALL_CACHES[@]}")
for arg in "$@"; do
    case "$arg" in
        --smoke)   REPOS=("${SMOKE_REPOS[@]}") ;;
        --no-cold) CACHES=("${NO_COLD_CACHES[@]}") ;;
    esac
done

TOTAL_RUNS=$(( ${#SCANNERS[@]} * ${#REPOS[@]} * ${#MODES[@]} * ${#CACHES[@]} ))
RUN_NUM=0

# ── Directories ──────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR" "$RAW_DIR"
for s in "${SCANNERS[@]}"; do
    mkdir -p "$RAW_DIR/$s"
done

# ── Environment capture ──────────────────────────────────────────────
capture_environment() {
    local env_file="$RESULTS_DIR/environment.txt"
    {
        echo "=== Benchmark Environment ==="
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Hostname: $(hostname)"
        echo ""
        echo "--- CPU ---"
        lscpu 2>/dev/null | grep -E "^(Architecture|CPU\(s\)|Model name|Thread|Socket|CPU MHz|L1|L2|L3|Flags)" || true
        echo ""
        echo "--- Memory ---"
        free -h 2>/dev/null || true
        echo ""
        echo "--- Kernel ---"
        uname -a
        echo ""
        echo "--- Storage ---"
        df -h / 2>/dev/null || true
        echo ""
        lsblk -d 2>/dev/null | head -5 || true
        echo ""
        cat /sys/block/nvme*/queue/scheduler 2>/dev/null || true
        echo ""
        echo "--- Compilers ---"
        rustc --version 2>/dev/null || echo "rustc: not found"
        go version 2>/dev/null || echo "go: not found"
        echo ""
        echo "--- Scanner versions ---"
        echo "scanner-rs: $(cd "$(dirname "$SCANNER_RS")/../.." && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
        echo "kingfisher: $(cd "$(dirname "$KINGFISHER")/../.." && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
        echo "trufflehog: $(cd "$(dirname "$TRUFFLEHOG_BIN")/.." && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
        echo "gitleaks:   $(cd "$(dirname "$GITLEAKS_BIN")/.." && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    } > "$env_file"
    echo "Environment captured → $env_file"
}

# ── Cache management ─────────────────────────────────────────────────
drop_caches() {
    sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    sleep 2  # settle time for EBS
}

# ── Bytes scanned estimation ─────────────────────────────────────────
repo_bytes_fs() {
    du -sb "$1" 2>/dev/null | cut -f1
}

repo_bytes_git() {
    local size_pack
    size_pack=$(git -C "$1" count-objects -v 2>/dev/null | grep 'size-pack' | sed 's/.*: //')
    python3 -c "print(int(${size_pack:-0}) * 1024)"
}

# ── Finding count extraction ─────────────────────────────────────────
count_findings() {
    local scanner="$1" output_file="$2" report_file="$3"
    case "$scanner" in
        scanner-rs)
            # Count lines with "type":"finding" or "type": "finding"
            # Use a variable to avoid grep -c (exit 1 on zero matches) + || echo 0
            # producing "0\n0" and corrupting the CSV.
            local n
            n=$(grep -c '"type"[[:space:]]*:[[:space:]]*"finding"' "$output_file" 2>/dev/null) || true
            echo "${n:-0}"
            ;;
        kingfisher)
            # JSON objects, one per line
            wc -l < "$output_file" 2>/dev/null | tr -d ' '
            ;;
        trufflehog)
            # JSON lines output
            wc -l < "$output_file" 2>/dev/null | tr -d ' '
            ;;
        gitleaks)
            # JSON array in report file
            if [[ -f "$report_file" ]]; then
                python3 -c "import json; print(len(json.load(open('$report_file'))))" 2>/dev/null || echo 0
            else
                echo 0
            fi
            ;;
    esac
}

# ── Parse /usr/bin/time -v output ────────────────────────────────────
parse_time_output() {
    local time_file="$1"
    python3 -c "
import re, sys
with open('$time_file') as f:
    text = f.read()
# Match the time value after the last colon on the Elapsed line
m = re.search(r'Elapsed \(wall clock\) time.*?:\s*([\d:.]+)\s*$', text, re.MULTILINE)
if not m:
    print('0.00')
    sys.exit()
raw = m.group(1)
parts = raw.split(':')
if len(parts) == 3:
    s = float(parts[0])*3600 + float(parts[1])*60 + float(parts[2])
elif len(parts) == 2:
    s = float(parts[0])*60 + float(parts[1])
else:
    s = float(parts[0])
print(f'{s:.2f}')
"
}

parse_user_time() {
    python3 -c "
import re
with open('$1') as f:
    text = f.read()
m = re.search(r'User time.*?:\s*(\S+)', text)
print(m.group(1) if m else '0.00')
"
}

parse_sys_time() {
    python3 -c "
import re
with open('$1') as f:
    text = f.read()
m = re.search(r'System time.*?:\s*(\S+)', text)
print(m.group(1) if m else '0.00')
"
}

parse_max_rss() {
    python3 -c "
import re
with open('$1') as f:
    text = f.read()
m = re.search(r'Maximum resident.*?:\s*(\S+)', text)
print(m.group(1) if m else '0')
"
}

# ── Run a single scanner ─────────────────────────────────────────────
run_scanner() {
    local scanner="$1" repo_path="$2" mode="$3"
    local repo_name
    repo_name=$(basename "$repo_path")
    local output_file="$RAW_DIR/$scanner/${repo_name}_${mode}_${CURRENT_CACHE}.json"
    local report_file="$RAW_DIR/$scanner/${repo_name}_${mode}_${CURRENT_CACHE}_report.json"
    local time_file="$RAW_DIR/$scanner/${repo_name}_${mode}_${CURRENT_CACHE}.time"
    local stderr_file="$RAW_DIR/$scanner/${repo_name}_${mode}_${CURRENT_CACHE}.stderr"

    case "$scanner" in
        scanner-rs)
            if [[ "$mode" == "git" ]]; then
                /usr/bin/time -v -o "$time_file" \
                    "$SCANNER_RS" scan git "--repo=$repo_path" \
                        --event-format=json --transforms=all --decode-depth=2 \
                    > "$output_file" 2> "$stderr_file" || true
            else
                /usr/bin/time -v -o "$time_file" \
                    "$SCANNER_RS" scan fs "--path=$repo_path" \
                        --event-format=json --transforms=all --decode-depth=2 --scan-archives \
                    > "$output_file" 2> "$stderr_file" || true
            fi
            ;;
        kingfisher)
            if [[ "$mode" == "git" ]]; then
                /usr/bin/time -v -o "$time_file" \
                    "$KINGFISHER" scan "$repo_path" \
                        --no-validate --git-history=full --format json \
                    > "$output_file" 2> "$stderr_file" || true
            else
                /usr/bin/time -v -o "$time_file" \
                    "$KINGFISHER" scan "$repo_path" \
                        --no-validate --git-history=none --format json \
                    > "$output_file" 2> "$stderr_file" || true
            fi
            ;;
        trufflehog)
            local detectors_file="$CONFIGS_DIR/trufflehog-detectors.txt"
            local include_flag=""
            if [[ -f "$detectors_file" ]]; then
                include_flag="--include-detectors=$(cat "$detectors_file" | tr -d '\n')"
            fi
            if [[ "$mode" == "git" ]]; then
                /usr/bin/time -v -o "$time_file" \
                    "$TRUFFLEHOG_BIN" git --no-verification --json \
                        $include_flag \
                        "file://$repo_path" \
                    > "$output_file" 2> "$stderr_file" || true
            else
                /usr/bin/time -v -o "$time_file" \
                    "$TRUFFLEHOG_BIN" filesystem --no-verification --json \
                        $include_flag \
                        "$repo_path" \
                    > "$output_file" 2> "$stderr_file" || true
            fi
            ;;
        gitleaks)
            local gl_config="$CONFIGS_DIR/gitleaks-config.toml"
            local config_flag=""
            if [[ -f "$gl_config" ]]; then
                config_flag="--config $gl_config"
            fi
            if [[ "$mode" == "git" ]]; then
                /usr/bin/time -v -o "$time_file" \
                    "$GITLEAKS_BIN" git $config_flag \
                        --report-format json --report-path "$report_file" \
                        --max-decode-depth 2 --max-archive-depth 3 \
                        --exit-code 0 "$repo_path" \
                    > "$output_file" 2> "$stderr_file" || true
            else
                /usr/bin/time -v -o "$time_file" \
                    "$GITLEAKS_BIN" directory $config_flag \
                        --report-format json --report-path "$report_file" \
                        --max-decode-depth 2 --max-archive-depth 3 \
                        --exit-code 0 "$repo_path" \
                    > "$output_file" 2> "$stderr_file" || true
            fi
            ;;
    esac

    # ── Extract metrics ──────────────────────────────────────────────
    if [[ ! -f "$time_file" ]]; then
        echo "WARN: time output missing for $scanner/$repo_name/$mode/$CURRENT_CACHE" >&2
        return
    fi

    local wall_s user_s sys_s max_rss bytes_scanned findings throughput
    wall_s=$(parse_time_output "$time_file")
    user_s=$(parse_user_time "$time_file")
    sys_s=$(parse_sys_time "$time_file")
    max_rss=$(parse_max_rss "$time_file")

    if [[ "$mode" == "fs" ]]; then
        bytes_scanned=$(repo_bytes_fs "$repo_path")
    else
        bytes_scanned=$(repo_bytes_git "$repo_path")
    fi

    findings=$(count_findings "$scanner" "$output_file" "$report_file")

    # Throughput in MiB/s (use python3 since bc may not be installed)
    throughput=$(python3 -c "
w = float('$wall_s')
b = float('$bytes_scanned')
print(f'{b / 1048576 / w:.2f}' if w > 0 else '0')
" 2>/dev/null || echo "0")

    # Append to CSV
    echo "$scanner,$repo_name,$mode,$CURRENT_CACHE,$wall_s,$user_s,$sys_s,$max_rss,$bytes_scanned,$findings,$throughput" >> "$CSV"
}

# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

echo "=========================================="
echo " Scanner Comparison Benchmark"
echo " $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo " Repos: ${REPOS[*]}"
echo " Modes: ${MODES[*]}"
echo " Caches: ${CACHES[*]}"
echo " Total runs: $TOTAL_RUNS"
echo "=========================================="

# Verify binaries exist
for bin in "$SCANNER_RS" "$KINGFISHER" "$TRUFFLEHOG_BIN" "$GITLEAKS_BIN"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: Binary not found or not executable: $bin" >&2
        exit 1
    fi
done

# Verify repos exist
for repo in "${REPOS[@]}"; do
    if [[ ! -d "$REPO_BASE/$repo" ]]; then
        echo "ERROR: Repo directory not found: $REPO_BASE/$repo" >&2
        exit 1
    fi
done

capture_environment

# CSV header
echo "scanner,repo,mode,cache,wall_time_s,user_time_s,sys_time_s,max_rss_kb,bytes_scanned,findings_count,throughput_mib_s" > "$CSV"

for repo in "${REPOS[@]}"; do
    REPO_PATH="$REPO_BASE/$repo"
    echo ""
    echo "──────────────────────────────────────────"
    echo " Repo: $repo"
    echo "──────────────────────────────────────────"

    for mode in "${MODES[@]}"; do
        for cache in "${CACHES[@]}"; do
            CURRENT_CACHE="$cache"

            for scanner in "${SCANNERS[@]}"; do
                RUN_NUM=$((RUN_NUM + 1))
                echo "[$RUN_NUM/$TOTAL_RUNS] $scanner | $repo | $mode | $cache"

                if [[ "$cache" == "cold" ]]; then
                    drop_caches
                elif [[ "$cache" == "warm" ]]; then
                    # Warm: do a throwaway run to populate page cache.
                    # Use a temp CURRENT_CACHE to avoid overwriting real output.
                    echo "  (warming cache...)"
                    CURRENT_CACHE="__warmup__"
                    run_scanner "$scanner" "$REPO_PATH" "$mode" || true
                    # Remove warmup artifacts + the CSV row it appended
                    rm -f "$RAW_DIR/$scanner/"*__warmup__* 2>/dev/null
                    sed -i.bak '/__warmup__/d' "$CSV" 2>/dev/null && rm -f "$CSV.bak"
                    CURRENT_CACHE="$cache"
                fi

                run_scanner "$scanner" "$REPO_PATH" "$mode"
                echo "  ✓ done"
            done
        done
    done
done

echo ""
echo "=========================================="
echo " Benchmark complete: $RUN_NUM runs"
echo " Results: $CSV"
echo "=========================================="
