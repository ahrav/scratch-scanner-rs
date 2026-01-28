use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_rs::stdx::ReleasedSet;
use std::collections::HashSet;

const OPS_PER_ITER: u64 = 10_000;

// Simple xorshift for reproducible random keys.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

fn make_keys(count: usize, seed: u64) -> Vec<u64> {
    let mut rng = XorShift64::new(seed);
    (0..count).map(|_| rng.next_u64()).collect()
}

fn make_keys_with_duplicates(unique_count: usize, total_count: usize, seed: u64) -> Vec<u64> {
    let unique_keys = make_keys(unique_count, seed);
    let mut rng = XorShift64::new(seed ^ 0x1234);
    (0..total_count)
        .map(|_| unique_keys[(rng.next_u64() as usize) % unique_count])
        .collect()
}

// ============================================================================
// 1. Basic Insert Performance
// ============================================================================

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/insert");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384; // ~60% load factor with 10K ops
    let keys = make_keys(OPS_PER_ITER as usize, 0xdead_beef);

    group.bench_function("basic_insert", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 2. Load Factor Analysis
// ============================================================================

fn bench_load_factor(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/load_factor");

    // Test at various load factors: 25%, 50%, 75%, 90%, 99%
    // ReleasedSet has internal 2x overhead, so actual table load is half these values
    let load_factors = [25, 50, 75, 90, 99];

    for &load_pct in &load_factors {
        // For N% load factor, we need cap = ops * 100 / N
        let ops = 10_000usize;
        let cap = ops * 100 / load_pct;
        let keys = make_keys(ops, 0xcafe_babe);
        group.throughput(Throughput::Elements(ops as u64));

        group.bench_with_input(
            BenchmarkId::new("insert", format!("{}%_load", load_pct)),
            &(cap, &keys),
            |b, (cap, keys)| {
                let mut set = ReleasedSet::with_capacity(*cap);
                b.iter(|| {
                    set.clear_retaining_capacity();
                    for &key in *keys {
                        black_box(set.insert(black_box(key)));
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 3. Duplicate Detection (Idempotent Tracking)
// ============================================================================

fn bench_duplicates(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/duplicates");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;

    // 0% duplicates (all unique)
    let unique_keys = make_keys(OPS_PER_ITER as usize, 0xaaaa_bbbb);
    group.bench_function("0%_duplicates", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &unique_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // 50% duplicates
    let half_dup_keys = make_keys_with_duplicates(5000, OPS_PER_ITER as usize, 0xbbbb_cccc);
    group.bench_function("50%_duplicates", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &half_dup_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // 90% duplicates
    let high_dup_keys = make_keys_with_duplicates(1000, OPS_PER_ITER as usize, 0xcccc_dddd);
    group.bench_function("90%_duplicates", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &high_dup_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // 100% duplicates (same key repeated)
    let same_key = 0xDEAD_BEEF_CAFE_BABEu64;
    group.bench_function("100%_duplicates", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            set.insert(same_key);
            for _ in 1..OPS_PER_ITER {
                black_box(set.insert(black_box(same_key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 4. Contains (Lookup) Performance
// ============================================================================

fn bench_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/contains");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;
    let keys = make_keys(OPS_PER_ITER as usize, 0x1234_5678);

    // Lookup existing keys
    group.bench_function("existing_keys", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        for &key in &keys {
            set.insert(key);
        }
        b.iter(|| {
            for &key in &keys {
                black_box(set.contains(black_box(key)));
            }
        })
    });

    // Lookup missing keys (probes to empty slot)
    let missing_keys = make_keys(OPS_PER_ITER as usize, 0x8765_4321);
    group.bench_function("missing_keys", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        for &key in &keys {
            set.insert(key);
        }
        b.iter(|| {
            for &key in &missing_keys {
                black_box(set.contains(black_box(key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 5. Pop Performance (Stack + Backshift Deletion)
// ============================================================================

fn bench_pop(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/pop");

    // Test pop at various set sizes
    let sizes = [100, 1_000, 10_000];

    for &size in &sizes {
        let keys = make_keys(size, 0xface_cafe);
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("drain", size), &keys, |b, keys| {
            let mut set = ReleasedSet::with_capacity(size + 100);
            b.iter(|| {
                for &key in keys {
                    set.insert(key);
                }
                while let Some(key) = set.pop() {
                    black_box(key);
                }
            })
        });
    }

    group.finish();
}

// ============================================================================
// 6. Pop with Clustered Keys (Backshift Worst Case)
// ============================================================================

fn bench_pop_clustered(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/pop_clustered");

    let size = 1000;
    group.throughput(Throughput::Elements(size as u64));

    // Sequential keys (may cluster based on hash distribution)
    let sequential_keys: Vec<u64> = (0..size).collect();
    group.bench_function("sequential_keys", |b| {
        let mut set = ReleasedSet::with_capacity(size as usize + 100);
        b.iter(|| {
            for &key in &sequential_keys {
                set.insert(key);
            }
            while let Some(key) = set.pop() {
                black_box(key);
            }
        })
    });

    // Adversarial keys: all map to nearby slots (SplitMix64 makes this hard)
    // Use keys that differ only in low bits to test hash quality
    let adversarial_keys: Vec<u64> = (0..size).map(|i| i << 48).collect();
    group.bench_function("adversarial_keys", |b| {
        let mut set = ReleasedSet::with_capacity(size as usize + 100);
        b.iter(|| {
            for &key in &adversarial_keys {
                set.insert(key);
            }
            while let Some(key) = set.pop() {
                black_box(key);
            }
        })
    });

    group.finish();
}

// ============================================================================
// 7. Clear Performance
// ============================================================================

fn bench_clear(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/clear");

    // Test clear at various capacities
    let capacities = [100, 1_000, 10_000, 100_000];

    for &cap in &capacities {
        // Fill to 50% capacity before clearing
        let keys = make_keys(cap / 2, 0x7777_8888);

        group.bench_with_input(BenchmarkId::new("filled_50%", cap), &(cap, &keys), |b, (cap, keys)| {
            let mut set = ReleasedSet::with_capacity(*cap);
            b.iter(|| {
                for &key in *keys {
                    set.insert(key);
                }
                set.clear_retaining_capacity();
                black_box(());
            })
        });
    }

    group.finish();
}

// ============================================================================
// 8. HashSet Comparison
// ============================================================================

fn bench_vs_hashset(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/vs_hashset");

    let keys = make_keys(1000, 0xfeed_face);
    let iterations = 100u64;

    group.throughput(Throughput::Elements(iterations * keys.len() as u64));

    // ReleasedSet with clear
    group.bench_function("released_set_clear_insert", |b| {
        let mut set = ReleasedSet::with_capacity(2048);
        b.iter(|| {
            for _ in 0..iterations {
                set.clear_retaining_capacity();
                for &key in &keys {
                    black_box(set.insert(black_box(key)));
                }
            }
        })
    });

    // HashSet<u64> with clear
    group.bench_function("hashset_u64_clear_insert", |b| {
        let mut set = HashSet::with_capacity(2048);
        b.iter(|| {
            for _ in 0..iterations {
                set.clear();
                for &key in &keys {
                    black_box(set.insert(black_box(key)));
                }
            }
        })
    });

    // Pop comparison: ReleasedSet vs HashSet drain
    group.bench_function("released_set_pop", |b| {
        let mut set = ReleasedSet::with_capacity(2048);
        b.iter(|| {
            for _ in 0..iterations {
                for &key in &keys {
                    set.insert(key);
                }
                while let Some(key) = set.pop() {
                    black_box(key);
                }
            }
        })
    });

    group.bench_function("hashset_drain", |b| {
        let mut set = HashSet::with_capacity(2048);
        b.iter(|| {
            for _ in 0..iterations {
                for &key in &keys {
                    set.insert(key);
                }
                for key in set.drain() {
                    black_box(key);
                }
            }
        })
    });

    group.finish();
}

// ============================================================================
// 9. Scaling Analysis (Cache Pressure)
// ============================================================================

fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/scaling");

    // Capacity sizes: 1K, 4K, 16K, 64K, 256K
    // Memory per slot: ReleasedEntry enum = 16 bytes (Empty/Occupied(u64) with tag + padding)
    // Plus stack: Vec<u64> = 8 bytes per element
    // L1: ~32KB, L2: ~256KB, L3: ~6-12MB typical
    let sizes = [1024, 4096, 16384, 65536, 262144];

    for &size in &sizes {
        // Insert 50% of capacity to get consistent load factor
        let ops = size / 2;
        let keys = make_keys(ops, 0x9999_8888);

        group.throughput(Throughput::Elements(ops as u64));

        group.bench_with_input(
            BenchmarkId::new("insert", format!("{}cap", size)),
            &(size, &keys),
            |b, (cap, keys)| {
                let mut set = ReleasedSet::with_capacity(*cap);
                b.iter(|| {
                    set.clear_retaining_capacity();
                    for &key in *keys {
                        black_box(set.insert(black_box(key)));
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 10. Hash Quality Tests
// ============================================================================

fn bench_hash_quality(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/hash_quality");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;

    // Sequential keys (tests SplitMix64 distribution)
    let sequential_keys: Vec<u64> = (0..OPS_PER_ITER).collect();
    group.bench_function("sequential_keys", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &sequential_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Strided keys (every 256th value)
    let strided_keys: Vec<u64> = (0..OPS_PER_ITER).map(|i| i * 256).collect();
    group.bench_function("strided_keys", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &strided_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Power-of-two keys (common in systems programming)
    let pot_keys: Vec<u64> = (0..OPS_PER_ITER).map(|i| 1u64 << (i % 64)).collect();
    group.bench_function("power_of_two_keys", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &pot_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Random keys (baseline)
    let random_keys = make_keys(OPS_PER_ITER as usize, 0xabcd_ef01);
    group.bench_function("random_keys", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &random_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 11. Mixed Workload (Insert → Contains → Pop)
// ============================================================================

fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/mixed");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;

    // Pattern: insert batch, check contains, then pop all
    let keys = make_keys(3333, 0x1111_2222);
    let check_keys = make_keys(3334, 0x3333_4444);

    group.bench_function("insert_contains_pop", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            // Insert phase
            for &key in &keys {
                set.insert(key);
            }
            // Contains phase (mix of hits and misses)
            for &key in &check_keys {
                black_box(set.contains(black_box(key)));
            }
            // Pop phase
            while let Some(key) = set.pop() {
                black_box(key);
            }
        })
    });

    // Real-world pattern: insert many, then check many duplicates
    let initial_keys = make_keys(5000, 0x5555_6666);
    let duplicate_keys = make_keys(5000, 0x5555_6666); // Same seed = same keys

    group.bench_function("insert_then_dup_check", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &initial_keys {
                set.insert(key);
            }
            for &key in &duplicate_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 12. Insert/Pop Cycle (Steady State and Alternating)
// ============================================================================

fn bench_insert_pop_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/insert_pop_cycle");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;
    let keys = make_keys(OPS_PER_ITER as usize, 0x7777_8888);

    // Steady state: fill to 50%, then insert/pop pairs
    group.bench_function("steady_state", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        // Pre-fill to 50%
        for &key in keys.iter().take(cap / 2) {
            set.insert(key);
        }
        let cycle_keys = make_keys(OPS_PER_ITER as usize, 0x9999_aaaa);
        b.iter(|| {
            for &key in &cycle_keys {
                set.insert(key);
                black_box(set.pop());
            }
        })
    });

    // Alternating: insert N, pop N
    group.bench_function("alternating_batch", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        let batch_size = 100;
        let batches = (OPS_PER_ITER as usize) / batch_size;
        b.iter(|| {
            for batch in 0..batches {
                // Insert batch
                for i in 0..batch_size {
                    let key = keys[batch * batch_size + i];
                    set.insert(key);
                }
                // Pop batch
                for _ in 0..batch_size {
                    black_box(set.pop());
                }
            }
        })
    });

    group.finish();
}

// ============================================================================
// 13. Worst Case Scenarios
// ============================================================================

fn bench_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/worst_case");

    // 99% full table with sparse keys
    let cap = 1000;
    let ops = 990; // 99% of capacity
    let keys = make_keys(ops, 0xbad_f00d);

    group.throughput(Throughput::Elements(ops as u64));
    group.bench_function("99%_full_insert", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            set.clear_retaining_capacity();
            for &key in &keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Lookup in 99% full table
    group.bench_function("99%_full_contains", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        for &key in &keys {
            set.insert(key);
        }
        b.iter(|| {
            for &key in &keys {
                black_box(set.contains(black_box(key)));
            }
        })
    });

    // Pop from 99% full table (many backshifts)
    group.bench_function("99%_full_pop", |b| {
        let mut set = ReleasedSet::with_capacity(cap);
        b.iter(|| {
            for &key in &keys {
                set.insert(key);
            }
            while let Some(key) = set.pop() {
                black_box(key);
            }
        })
    });

    group.finish();
}

// ============================================================================
// 14. Construction (with_capacity)
// ============================================================================

fn bench_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("released_set/construction");

    let capacities = [64, 256, 1024, 4096, 16384, 65536];

    for &cap in &capacities {
        group.bench_with_input(BenchmarkId::new("with_capacity", cap), &cap, |b, &cap| {
            b.iter(|| {
                let set = ReleasedSet::with_capacity(black_box(cap));
                black_box(set);
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_insert,
    bench_load_factor,
    bench_duplicates,
    bench_contains,
    bench_pop,
    bench_pop_clustered,
    bench_clear,
    bench_vs_hashset,
    bench_scaling,
    bench_hash_quality,
    bench_mixed_workload,
    bench_insert_pop_cycle,
    bench_worst_case,
    bench_construction,
);

criterion_main!(benches);
