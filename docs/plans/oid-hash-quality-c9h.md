# OID Hash Quality Validation (`scratch-scanner-rs-c9h`)

Date: 2026-02-15

## Scope

Validate OID hash quality/performance for open-addressed OID tables after the
FNV-1a -> SplitMix-style transition.

Compared strategies:

1. `fnv1a64` (historical baseline)
2. `splitmix_head_tail` (current: head/tail fold + Stafford mix)
3. `first8_le` (fallback candidate: direct first 8 bytes)

## Commands

```bash
cargo bench --bench oid_hash_quality -- \
  --repo ../gitleaks \
  --repo ../tigerbeetle \
  --repo ../trufflehog \
  --iters=5
```

## Raw Results

### `../gitleaks`

`unique_oids=11382 table_size=16384 load_factor=0.6947`

| strategy | build_ns_per_key | hit_ns | miss_ns | insert_avg_probe | insert_max_probe | miss_avg_probe | miss_max_probe | insert_collisions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| fnv1a64 | 22.776 | 21.090 | 33.098 | 2.1227 | 70 | 5.7822 | 77 | 3963 |
| splitmix_head_tail | 7.663 | 9.367 | 14.836 | 2.1099 | 43 | 5.6863 | 62 | 3973 |
| first8_le | 6.417 | 7.119 | 17.622 | 2.0742 | 34 | 7.7432 | 79 | 6266 |

### `../tigerbeetle`

`unique_oids=83548 table_size=131072 load_factor=0.6374`

| strategy | build_ns_per_key | hit_ns | miss_ns | insert_avg_probe | insert_max_probe | miss_avg_probe | miss_max_probe | insert_collisions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| fnv1a64 | 22.397 | 23.374 | 36.473 | 1.8839 | 60 | 4.3312 | 68 | 26672 |
| splitmix_head_tail | 10.258 | 11.732 | 19.693 | 1.8876 | 66 | 4.3104 | 75 | 26766 |
| first8_le | 7.731 | 8.824 | 20.265 | 1.8827 | 57 | 5.9735 | 64 | 41010 |

### `../trufflehog`

`unique_oids=68178 table_size=131072 load_factor=0.5202`

| strategy | build_ns_per_key | hit_ns | miss_ns | insert_avg_probe | insert_max_probe | miss_avg_probe | miss_max_probe | insert_collisions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| fnv1a64 | 18.108 | 20.374 | 32.375 | 1.5416 | 27 | 2.6872 | 45 | 17710 |
| splitmix_head_tail | 8.554 | 10.050 | 16.305 | 1.5459 | 44 | 2.7110 | 50 | 17761 |
| first8_le | 6.051 | 7.083 | 16.497 | 1.5503 | 29 | 3.9497 | 40 | 25440 |

## Outcome

`splitmix_head_tail` is validated as a good tradeoff on real pack OID
distributions:

- Probe/collision quality is near-parity with FNV-1a (collision deltas are
  ~0.3%-0.4% across the measured repos).
- Throughput is materially better than FNV-1a:
  - build: ~2.0x-2.5x faster
  - hit lookups: ~2.0x-3.0x faster
  - miss lookups: ~1.6x-2.6x faster

`first8_le` is fast but consistently increases collision pressure and miss probe
lengths (notably +43%-54% insert collisions in the larger repos), so it is not
preferred as the default.

Decision: keep current SplitMix-style OID hash; no production hash change
required from this validation.
