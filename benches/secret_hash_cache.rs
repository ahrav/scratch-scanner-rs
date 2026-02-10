//! Benchmarks for `SecretHashCache` on the finding-frame encoding hot path.
//!
//! Exercises `get_or_compute` under three access patterns:
//! - **All-same**: 100% L1 hit (consecutive identical secrets)
//! - **Interleaved-N**: N distinct secrets cycled, measuring L2 hit rate
//! - **All-unique**: 100% miss, baseline BLAKE3 cost per finding

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_rs::store::StoreKeys;
use scanner_rs::SecretHashCache;

const OPS: u64 = 1_000;

/// Deterministic PRNG for reproducible benchmarks.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_bytes(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_exact_mut(8) {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        out
    }
}

/// 100% L1 hit — same secret every call.
fn bench_all_same(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_hash_cache/all_same");
    group.throughput(Throughput::Elements(OPS));

    let keys = StoreKeys::bootstrap_from_env();
    let norm_hash = [0xAB_u8; 32];

    group.bench_function("l1_hit", |b| {
        b.iter_batched(
            || {
                let mut cache = SecretHashCache::new();
                // Prime the cache with one entry.
                cache.get_or_compute(&norm_hash, &keys);
                cache
            },
            |mut cache| {
                for _ in 0..OPS {
                    black_box(cache.get_or_compute(&norm_hash, &keys));
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// N distinct secrets cycled, exercising L2 set-associative lookups.
fn bench_interleaved(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_hash_cache/interleaved");
    group.throughput(Throughput::Elements(OPS));

    let keys = StoreKeys::bootstrap_from_env();

    for n_distinct in [2, 4, 8, 16, 32] {
        let mut rng = Xorshift64::new(0xDEAD_BEEF_CAFE_0000 + n_distinct as u64);
        let hashes: Vec<[u8; 32]> = (0..n_distinct).map(|_| rng.next_bytes()).collect();

        group.bench_function(BenchmarkId::new("distinct", n_distinct), |b| {
            b.iter_batched(
                || {
                    let mut cache = SecretHashCache::new();
                    // Prime all entries.
                    for h in &hashes {
                        cache.get_or_compute(h, &keys);
                    }
                    cache
                },
                |mut cache| {
                    for i in 0..OPS as usize {
                        let h = &hashes[i % hashes.len()];
                        black_box(cache.get_or_compute(h, &keys));
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// 100% miss — every call computes a fresh BLAKE3 hash (baseline cost).
fn bench_all_unique(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_hash_cache/all_unique");
    group.throughput(Throughput::Elements(OPS));

    let keys = StoreKeys::bootstrap_from_env();

    let mut rng = Xorshift64::new(0xCAFE_BABE_1234_5678);
    let hashes: Vec<[u8; 32]> = (0..OPS as usize).map(|_| rng.next_bytes()).collect();

    group.bench_function("miss", |b| {
        b.iter_batched(
            SecretHashCache::new,
            |mut cache| {
                for h in &hashes {
                    black_box(cache.get_or_compute(h, &keys));
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Zipf-distributed access over K=8 distinct secrets (realistic workload).
fn bench_zipf_mix(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_hash_cache/zipf_mix");

    let keys = StoreKeys::bootstrap_from_env();
    let k = 8usize;
    let mut rng = Xorshift64::new(0xF00D_FACE_0000_0008);
    let hashes: Vec<[u8; 32]> = (0..k).map(|_| rng.next_bytes()).collect();

    // Build Zipf-ish CDF: P(i) ~ 1/(i+1).
    let weights: Vec<f64> = (0..k).map(|i| 1.0 / (i as f64 + 1.0)).collect();
    let total: f64 = weights.iter().sum();
    let cdf: Vec<f64> = weights
        .iter()
        .scan(0.0, |acc, w| {
            *acc += w / total;
            Some(*acc)
        })
        .collect();

    for &batch_size in &[100u64, 1_000] {
        // Pre-compute the access sequence deterministically.
        let mut seq_rng = Xorshift64::new(0xBEEF_0000 + batch_size);
        let indices: Vec<usize> = (0..batch_size as usize)
            .map(|_| {
                let raw = seq_rng.next_bytes();
                let val = u64::from_le_bytes(raw[..8].try_into().unwrap());
                let u = (val >> 1) as f64 / (1u64 << 63) as f64;
                cdf.iter().position(|&c| u < c).unwrap_or(k - 1)
            })
            .collect();

        group.throughput(Throughput::Elements(batch_size));
        group.bench_function(BenchmarkId::new("k8", batch_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = SecretHashCache::new();
                    for h in &hashes {
                        cache.get_or_compute(h, &keys);
                    }
                    cache
                },
                |mut cache| {
                    for &idx in &indices {
                        let h = &hashes[idx];
                        black_box(cache.get_or_compute(h, &keys));
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_all_same,
    bench_interleaved,
    bench_all_unique,
    bench_zipf_mix,
);
criterion_main!(benches);
