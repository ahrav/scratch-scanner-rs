# Performance baseline (2026-01-27)

This document records baseline measurements on **this machine** and the exact commands used.
All results below were collected on **2026-01-27**.

## Machine + toolchain

- OS: Amazon Linux 2 (kernel 5.10.247-246.989.amzn2int.aarch64)
- Arch: aarch64
- CPU: ARM implementer 0x41, part 0xd40, variant 0x1, revision 1
- Cores/threads: 16 cores, 1 thread per core
- Caches: L1d 64K, L1i 64K, L2 1024K, L3 32768K (from `lscpu`)
- Rust: `rustc 1.90.0 (1159e78c4 2025-09-14)`
- Cargo: `cargo 1.90.0 (840b83a10 2025-07-30)`
- Build flags: `RUSTFLAGS="-C target-cpu=native"`
- Cargo profiles: `release opt-level=3` (from `Cargo.toml`)

## Dataset for end-to-end scan

Generated a deterministic 256 MiB file at `bench-data/data.bin`:

- Size: 268,435,456 bytes (256 MiB)
- Content: xorshift64 bytes with injected token strings
- Injected every chunk:
  - Raw tokens (AWS + GitHub) at fixed strides
  - One Base64 run containing the AWS token near the end of each 1 MiB chunk

Generation command (already executed in this repo):

```
python3 - <<'PY'
import base64
from pathlib import Path

root = Path("bench-data")
root.mkdir(exist_ok=True)
path = root / "data.bin"

size = 256 * 1024 * 1024  # 256 MiB
chunk = 1024 * 1024  # 1 MiB

seed = 0x1234_5678_9ABC_DEF0

def xorshift64(x):
    x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 7) & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
    return x & 0xFFFFFFFFFFFFFFFF

token = b"AKIAIOSFODNN7EXAMPLE"
ghp = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
b64 = base64.b64encode(token) + b"\n"

with path.open("wb") as f:
    offset = 0
    x = seed
    while offset < size:
        n = min(chunk, size - offset)
        buf = bytearray(n)
        i = 0
        while i < n:
            x = xorshift64(x)
            v = x
            take = min(8, n - i)
            for j in range(take):
                buf[i + j] = v & 0xFF
                v >>= 8
            i += take

        for pos in range(0, max(0, n - len(token)), 64 * 1024):
            buf[pos : pos + len(token)] = token
        for pos in range(32 * 1024, max(32 * 1024, n - len(ghp)), 128 * 1024):
            if pos + len(ghp) <= n:
                buf[pos : pos + len(ghp)] = ghp

        if len(b64) <= n:
            buf[-len(b64) :] = b64

        f.write(buf)
        offset += n

print(f"wrote {path} ({path.stat().st_size} bytes)")
PY
```

## Additional datasets (multi-dataset end-to-end)

Generated five deterministic 256 MiB datasets under `bench-data/e2e`:

- `random_hits`: xorshift64 bytes + injected AWS/GitHub tokens + one Base64 token per chunk
- `random_nohits`: xorshift64 bytes only
- `ascii_hits`: ASCII alphabet bytes + injected AWS/GitHub tokens
- `base64_noise`: Base64 alphabet + whitespace + one Base64 token per chunk
- `urlish_noise`: URL-ish alphabet + one percent-encoded AWS token per chunk

Generation command (executed in this repo):

```
python3 - <<'PY'
import base64
import random
from pathlib import Path

root = Path("bench-data/e2e")
root.mkdir(parents=True, exist_ok=True)

SIZE = 256 * 1024 * 1024
CHUNK = 1024 * 1024

TOKEN = b"AKIAIOSFODNN7EXAMPLE"
GHP = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
B64 = base64.b64encode(TOKEN) + b"\n"
URL_ENC_TOKEN = b"".join(b"%" + f"{b:02X}".encode() for b in TOKEN)

URLISH = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"abcdefghijklmnopqrstuvwxyz"
    b"0123456789"
    b"-_.~:/?#[]@!$&'()*+,;=%"
)
B64_ALPHA = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"abcdefghijklmnopqrstuvwxyz"
    b"0123456789"
    b"+/=_-\n\r\t "
)
ASCII_ALPHA = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"abcdefghijklmnopqrstuvwxyz"
    b"0123456789 "
)

TRANSLATE = {
    "urlish": bytes(URLISH[i % len(URLISH)] for i in range(256)),
    "b64": bytes(B64_ALPHA[i % len(B64_ALPHA)] for i in range(256)),
    "ascii": bytes(ASCII_ALPHA[i % len(ASCII_ALPHA)] for i in range(256)),
}

def randbytes(rng: random.Random, n: int) -> bytes:
    return rng.getrandbits(n * 8).to_bytes(n, "little")

def xorshift64(x: int) -> int:
    x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 7) & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
    return x & 0xFFFFFFFFFFFFFFFF

def write_file(path: Path, gen):
    if path.exists() and path.stat().st_size == SIZE:
        print(f"skip {path} (exists)")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        gen(f)
    print(f"wrote {path} ({path.stat().st_size} bytes)")

def gen_mapped(f, seed: int, table: bytes, inject_tokens=False, inject_b64=False, inject_url=False):
    rng = random.Random(seed)
    offset = 0
    while offset < SIZE:
        n = min(CHUNK, SIZE - offset)
        data = randbytes(rng, n).translate(table)
        buf = bytearray(data)
        if inject_tokens:
            for pos in range(0, max(0, n - len(TOKEN)), 64 * 1024):
                buf[pos : pos + len(TOKEN)] = TOKEN
            for pos in range(32 * 1024, max(32 * 1024, n - len(GHP)), 128 * 1024):
                if pos + len(GHP) <= n:
                    buf[pos : pos + len(GHP)] = GHP
        if inject_b64 and len(B64) <= n:
            buf[-len(B64) :] = B64
        if inject_url and len(URL_ENC_TOKEN) <= n:
            start = n - len(URL_ENC_TOKEN)
            buf[start:n] = URL_ENC_TOKEN
        f.write(buf)
        offset += n

def gen_ascii_hits(f):
    gen_mapped(f, 0xA11CE, TRANSLATE["ascii"], inject_tokens=True)

def gen_b64_noise(f):
    gen_mapped(f, 0xB64B64, TRANSLATE["b64"], inject_b64=True)

def gen_urlish_noise(f):
    gen_mapped(f, 0xBADDCAFE, TRANSLATE["urlish"], inject_url=True)

def gen_random_hits(f):
    seed = 0x1234_5678_9ABC_DEF0
    x = seed
    offset = 0
    while offset < SIZE:
        n = min(CHUNK, SIZE - offset)
        buf = bytearray(n)
        i = 0
        while i < n:
            x = xorshift64(x)
            v = x
            take = min(8, n - i)
            for j in range(take):
                buf[i + j] = v & 0xFF
                v >>= 8
            i += take
        for pos in range(0, max(0, n - len(TOKEN)), 64 * 1024):
            buf[pos : pos + len(TOKEN)] = TOKEN
        for pos in range(32 * 1024, max(32 * 1024, n - len(GHP)), 128 * 1024):
            if pos + len(GHP) <= n:
                buf[pos : pos + len(GHP)] = GHP
        if len(B64) <= n:
            buf[-len(B64) :] = B64
        f.write(buf)
        offset += n

def gen_random_nohits(f):
    seed = 0x0FED_CBA9_8765_4321
    x = seed
    offset = 0
    while offset < SIZE:
        n = min(CHUNK, SIZE - offset)
        buf = bytearray(n)
        i = 0
        while i < n:
            x = xorshift64(x)
            v = x
            take = min(8, n - i)
            for j in range(take):
                buf[i + j] = v & 0xFF
                v >>= 8
            i += take
        f.write(buf)
        offset += n

write_file(root / "random_hits" / "data.bin", gen_random_hits)
write_file(root / "random_nohits" / "data.bin", gen_random_nohits)
write_file(root / "ascii_hits" / "data.bin", gen_ascii_hits)
write_file(root / "base64_noise" / "data.bin", gen_b64_noise)
write_file(root / "urlish_noise" / "data.bin", gen_urlish_noise)
PY
```

## Benchmark suite

Added Criterion benchmarks:

- `benches/scan.rs`: engine scan, baseline linear scan, base64 gate
- `benches/structures.rs`: FixedSet128, ReleasedSet, DynamicBitSet

Commands:

```
RUSTFLAGS="-C target-cpu=native" cargo bench --bench scan
RUSTFLAGS="-C target-cpu=native" cargo bench --bench structures
RUSTFLAGS="-C target-cpu=native" cargo bench --bench hotspots --features bench
```

### Engine scan (4 MiB buffers)

| Bench | Time (median) | Throughput (median) |
|---|---:|---:|
| engine_scan/manual/random | 59.264 ms | 67.495 MiB/s |
| engine_scan/manual/ascii_hits | 45.612 ms | 87.697 MiB/s |
| engine_scan/manual/base64_hits | 14.749 ms | 271.21 MiB/s |
| engine_scan/derived/random | 58.538 ms | 68.332 MiB/s |
| engine_scan/derived/ascii_hits | 40.759 ms | 98.138 MiB/s |
| engine_scan/derived/base64_hits | 16.851 ms | 237.37 MiB/s |

Notes:
- Buffers are 4 MiB, generated in-memory (no I/O).
- `ascii_hits` contains injected AWS + GitHub tokens.
- `base64_hits` is a stream of base64-encoded AWS tokens.

### Baseline linear scan (4 MiB buffers)

| Bench | Time (median) | Throughput (median) |
|---|---:|---:|
| baseline/linear_sum | 403.90 µs | 9.6714 GiB/s |
| baseline/memchr_Z (no match) | 85.606 µs | 45.630 GiB/s |

Notes:
- `memchr_Z` uses a buffer filled with `A` so it scans the full 4 MiB.
- These are in-cache baselines, not end-to-end file scan throughput.

### Base64 gate (1 MiB buffers)

| Bench | Time (median) | Throughput (median) |
|---|---:|---:|
| b64_gate/hits_at_end_one_shot | 2.0491 ms | 488.02 MiB/s |
| b64_gate/hits_at_end_stream | 2.0489 ms | 488.06 MiB/s |
| b64_gate/noise_one_shot | 2.0494 ms | 487.96 MiB/s |

Notes:
- `hits_at_end_*` forces a full scan before a hit is found.
- `noise_one_shot` is a full negative scan on base64 noise.

### Hotspot microbenches (4 MiB buffers)

Transform span finding (`find_spans_into`):

| Bench | Time (median) | Throughput (median) |
|---|---:|---:|
| transform_spans_url/limited/random | 16.297 ms | 245.45 MiB/s |
| transform_spans_url/unbounded/random | 16.507 ms | 242.32 MiB/s |
| transform_spans_url/limited/urlish | 581.10 µs | 6.7221 GiB/s |
| transform_spans_url/unbounded/urlish | 4.8858 ms | 818.70 MiB/s |
| transform_spans_b64/limited/random | 15.661 ms | 255.41 MiB/s |
| transform_spans_b64/unbounded/random | 15.649 ms | 255.61 MiB/s |
| transform_spans_b64/limited/base64_noise | 732.43 µs | 5.3333 GiB/s |
| transform_spans_b64/unbounded/base64_noise | 5.7853 ms | 691.40 MiB/s |

Aho-Corasick anchor scan (manual anchors):

| Bench | Time (median) | Throughput (median) |
|---|---:|---:|
| ac_anchors/find_overlapping/random | 16.952 ms | 235.97 MiB/s |
| ac_anchors/find_overlapping/anchors_hits | 18.055 ms | 221.55 MiB/s |

Notes:
- `limited` uses `max_spans_per_buffer = 8` (demo config); `unbounded` uses 1024.
- `urlish` is URL-safe ASCII with `%2F` escapes injected every 64 bytes.
- `base64_noise` is full base64-alphabet data.

### Size sweep (full scan; max_spans_per_buffer = 4096)

Configuration for size sweep:
- sample_size = 10, measurement_time = 3s
- `max_spans_per_buffer = 4096` to avoid early exit on dense inputs

URL span finder throughput (MiB/s):

| Size | random | urlish |
|---:|---:|---:|
| 64 KiB | 278.11 | 860.48 |
| 256 KiB | 251.67 | 855.89 |
| 1 MiB | 243.78 | 857.66 |
| 4 MiB | 242.13 | 857.79 |
| 16 MiB | 242.73 | 855.99 |
| 64 MiB | 242.96 | 855.62 |

Base64 span finder throughput (MiB/s):

| Size | random | base64_noise |
|---:|---:|---:|
| 64 KiB | 274.88 | 665.55 |
| 256 KiB | 260.36 | 682.67 |
| 1 MiB | 256.38 | 680.75 |
| 4 MiB | 255.60 | 682.93 |
| 16 MiB | 255.60 | 679.95 |
| 64 MiB | 255.12 | 688.73 |

Aho-Corasick anchor scan throughput (MiB/s):

| Size | random | anchors_hits |
|---:|---:|---:|
| 64 KiB | 237.30 | 216.78 |
| 256 KiB | 233.99 | 218.16 |
| 1 MiB | 234.37 | 217.46 |
| 4 MiB | 234.28 | 220.89 |
| 16 MiB | 233.76 | 217.01 |
| 64 MiB | 233.98 | 221.61 |

Observations:
- Throughput is effectively flat from 64 KiB → 64 MiB; no obvious cache cliff on this CPU.
- Random inputs are ~243–275 MiB/s; dense URL/base64 inputs are ~680–860 MiB/s when fully scanned.

### perf microbench harness (perf_hotspots)

Built a small harness to feed perf with stable, single-function loops (4 MiB buffers):

```
RUSTFLAGS="-C target-cpu=native" cargo build --release --features bench --bin perf_hotspots
```

Commands and key results:

```
perf stat -d -- target/release/perf_hotspots url_random 3
perf stat -d -- target/release/perf_hotspots b64_random 3
perf stat -d -- target/release/perf_hotspots ac_random 3
```

- `url_random`: cycles=7.918e9, instructions=1.183e10, IPC=1.49, L1D miss rate=0.03%
- `b64_random`: cycles=7.916e9, instructions=1.720e10, IPC=2.17, L1D miss rate=0.03%
- `ac_random`: cycles=7.897e9, instructions=2.531e10, IPC=3.21, L1D miss rate=0.11%

Call graph confirmation:

```
perf record -F 199 -g -o /tmp/perf_url.data -- target/release/perf_hotspots url_random 3
perf report --stdio --no-children --percent-limit 1 -i /tmp/perf_url.data
```

Top symbol:
- `scanner_rs::engine::transform::find_spans_into` ~98.43%

```
perf record -F 199 -g -o /tmp/perf_ac.data -- target/release/perf_hotspots ac_random 3
perf report --stdio --no-children --percent-limit 1 -i /tmp/perf_ac.data
```

Top symbol:
- `aho_corasick::automaton::try_find_overlapping_fwd` ~98.46%

## Optimization focus (evidence-based)

1) **Transform span finding dominates end-to-end scans.** perf on the full scan shows `find_spans_into` ~58% of cycles; perf microbench isolates it at ~98% of samples. Improving this path yields the largest single-core win.

2) **Anchor scan is the second-largest contributor.** Aho-Corasick shows ~36% of cycles in the full scan, and microbench isolates it at ~98% of samples. Any gains here stack with span-finder improvements.

3) **Size sweep is flat across 64 KiB → 64 MiB.** Throughput is stable and L1D miss rates are ~0.1–0.5%. This points to **compute/branch cost**, not memory-latency, as the main limiter. Focus on instruction count, branchiness, and SIMD-friendly classification.

4) **Random inputs are ~3x slower than dense URL/base64 runs when fully scanned.** This suggests the per-byte classification and branch structure on “mostly non-matching” bytes is the primary cost center. Optimizations that make “no match” cheaper should have the highest leverage.

5) **LUT + fast-reject materially reduce work.** After switching to LUT classification and adding a trigger prefilter + NEON b64ish skip, random-span throughput improved ~20–25% and perf shows substantially fewer instructions in the span finder. The next gains likely require reducing per-byte work inside the run scan itself (e.g., vectorized run-length detection or fewer per-byte checks).

6) **End-to-end regression not reproduced in multi-dataset runs (warm-cache, default IO).** On `bench-data/e2e/random_hits`, median throughput is **85.9 MiB/s** across 5 runs using the default IO backend (io_uring on this machine). Random/no-hit input is still slower (~74.5 MiB/s), and base64/urlish-heavy datasets are significantly faster. A cold-cache confirmation would require root access to drop caches.

### Core data structures

| Bench | Time (median) | Throughput (median) |
|---|---:|---:|
| fixed_set128/insert_reset | 119.99 µs | 102.41 Melem/s |
| released_set/insert_pop | 169.12 µs | 48.440 Melem/s |
| dynamic_bitset/set_count_clear | 4.2383 µs | 966.43 Melem/s |

## End-to-end scan throughput (default IO, multi-dataset)

Command (stdout suppressed to avoid output costs, 5 runs per dataset):

```
python3 - <<'PY'
import statistics
import subprocess
import time
from pathlib import Path

BIN = Path("target/release/scanner-rs")
root = Path("bench-data/e2e")
datasets = [
    "random_hits",
    "random_nohits",
    "ascii_hits",
    "base64_noise",
    "urlish_noise",
]
runs = 5

for name in datasets:
    path = root / name
    total = sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
    mib = total / (1024 * 1024)
    thr = []
    for _ in range(runs):
        t0 = time.perf_counter()
        subprocess.run([str(BIN), str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        dt = time.perf_counter() - t0
        thr.append(mib / dt)
    print(name, thr, statistics.median(thr))
PY
```

Results (warm-cache; datasets generated immediately before runs; default IO backend):

| Dataset | Median MiB/s | Mean | Stdev | Min | Max |
|---|---:|---:|---:|---:|---:|
| random_hits | 85.91 | 85.91 | 0.10 | 85.75 | 86.02 |
| random_nohits | 74.50 | 74.40 | 0.26 | 73.92 | 74.70 |
| ascii_hits | 158.49 | 158.70 | 1.26 | 156.80 | 160.71 |
| base64_noise | 242.10 | 241.68 | 3.66 | 236.21 | 247.36 |
| urlish_noise | 151.85 | 152.08 | 0.97 | 151.11 | 153.67 |

Targets (locked, median MiB/s):
- random_hits: 85.91
- random_nohits: 74.50
- ascii_hits: 158.49
- base64_noise: 242.10
- urlish_noise: 151.85

## perf stat (single run, sync IO)

Command:

```
perf stat -d target/release/scanner-rs --io=sync bench-data > /dev/null
```

Key counters:

- cycles: 9,149,187,852
- instructions: 24,621,065,028
- IPC: 2.69
- L1D load misses: 0.12% of L1D loads
- elapsed: 3.702 s (user 3.531 s, sys 0.170 s)

Derived (bytes=268,435,456):

- cycles/byte: 34.08
- instructions/byte: 91.72

## perf record (hot paths)

Commands:

```
perf record -F 299 -g -- target/release/scanner-rs --io=sync bench-data > /dev/null
perf report --stdio --no-children --percent-limit 1
```

Top symbols (cycles):

- `aho_corasick::automaton::try_find_overlapping_fwd` ~43.92%
- `scanner_rs::engine::transform::find_spans_into` ~42.49%
- `aho_corasick::util::prefilter::RareBytesOne::find_in` ~7.07%
- `memchr::memmem::searcher::searcher_kind_neon` ~1.76%

## North-star upper bound (single-core)

Measured in-cache upper bounds on this machine (4 MiB buffers):

- Linear sum: **~9.67 GiB/s**
- `memchr` no-match: **~45.63 GiB/s**

The current end-to-end sync scan throughput is **~77.9 MiB/s**, which is:

- ~0.72% of the linear-sum baseline
- ~0.15% of the memchr baseline

These baselines are *not* achievable end-to-end because the scanner does far more work than a
single-pass byte sweep, but they provide a hard upper bound for single-core scan throughput on
this machine.
