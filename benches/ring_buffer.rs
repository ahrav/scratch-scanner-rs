use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_rs::stdx::RingBuffer;

const OPS_PER_ITER: u64 = 10_000;

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

fn make_u64_keys(count: usize, seed: u64) -> Vec<u64> {
    let mut rng = XorShift64::new(seed);
    (0..count).map(|_| rng.next_u64()).collect()
}

/// Benchmarks the hot path: push when full requires pop first.
fn bench_push_pop_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Power-of-2 capacity for mask optimization
    group.bench_function("push_pop_cycle_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if rb.is_full() {
                    black_box(rb.pop_front());
                }
                rb.push_back_assume_capacity(black_box(i));
            }
            rb.clear();
        })
    });

    group.bench_function("push_pop_cycle_cap16", |b| {
        let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if rb.is_full() {
                    black_box(rb.pop_front());
                }
                rb.push_back_assume_capacity(black_box(i));
            }
            rb.clear();
        })
    });

    group.bench_function("push_pop_cycle_cap64", |b| {
        let mut rb: RingBuffer<u64, 64> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if rb.is_full() {
                    black_box(rb.pop_front());
                }
                rb.push_back_assume_capacity(black_box(i));
            }
            rb.clear();
        })
    });

    group.finish();
}

/// Alternating push/pop - tests the tightest loop.
fn bench_alternating(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("alternating_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_assume_capacity(black_box(i));
                black_box(rb.pop_front());
            }
        })
    });

    group.bench_function("alternating_cap16", |b| {
        let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_assume_capacity(black_box(i));
                black_box(rb.pop_front());
            }
        })
    });

    group.finish();
}

/// Fill then drain - tests bulk operations.
fn bench_fill_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");

    for cap in [8usize, 16, 32, 64] {
        let iterations = OPS_PER_ITER / cap as u64;
        group.throughput(Throughput::Elements(iterations * cap as u64));

        match cap {
            8 => {
                group.bench_with_input(BenchmarkId::new("fill_drain", cap), &cap, |b, _| {
                    let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
                    b.iter(|| {
                        for _ in 0..iterations {
                            // Fill
                            for i in 0..8u64 {
                                rb.push_back_assume_capacity(black_box(i));
                            }
                            // Drain
                            while rb.pop_front().is_some() {}
                        }
                    })
                });
            }
            16 => {
                group.bench_with_input(BenchmarkId::new("fill_drain", cap), &cap, |b, _| {
                    let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
                    b.iter(|| {
                        for _ in 0..iterations {
                            for i in 0..16u64 {
                                rb.push_back_assume_capacity(black_box(i));
                            }
                            while rb.pop_front().is_some() {}
                        }
                    })
                });
            }
            32 => {
                group.bench_with_input(BenchmarkId::new("fill_drain", cap), &cap, |b, _| {
                    let mut rb: RingBuffer<u64, 32> = RingBuffer::new();
                    b.iter(|| {
                        for _ in 0..iterations {
                            for i in 0..32u64 {
                                rb.push_back_assume_capacity(black_box(i));
                            }
                            while rb.pop_front().is_some() {}
                        }
                    })
                });
            }
            64 => {
                group.bench_with_input(BenchmarkId::new("fill_drain", cap), &cap, |b, _| {
                    let mut rb: RingBuffer<u64, 64> = RingBuffer::new();
                    b.iter(|| {
                        for _ in 0..iterations {
                            for i in 0..64u64 {
                                rb.push_back_assume_capacity(black_box(i));
                            }
                            while rb.pop_front().is_some() {}
                        }
                    })
                });
            }
            _ => unreachable!(),
        }
    }

    group.finish();
}

/// Random access via get() - tests index calculation.
fn bench_random_access(c: &mut Criterion) {
    let indices = make_u64_keys(OPS_PER_ITER as usize, 0xdead_beef_cafe_babe);

    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("random_get_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        for i in 0..8u64 {
            rb.push_back_assume_capacity(i);
        }
        b.iter(|| {
            let mut sum = 0u64;
            for &idx in &indices {
                if let Some(&val) = rb.get((idx % 8) as u32) {
                    sum = sum.wrapping_add(val);
                }
            }
            black_box(sum)
        })
    });

    group.bench_function("random_get_cap64", |b| {
        let mut rb: RingBuffer<u64, 64> = RingBuffer::new();
        for i in 0..64u64 {
            rb.push_back_assume_capacity(i);
        }
        b.iter(|| {
            let mut sum = 0u64;
            for &idx in &indices {
                if let Some(&val) = rb.get((idx % 64) as u32) {
                    sum = sum.wrapping_add(val);
                }
            }
            black_box(sum)
        })
    });

    group.finish();
}

/// Test wraparound behavior - push/pop with offset head.
fn bench_wraparound(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("wraparound_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        // Pre-fill and pop to create head offset
        for i in 0..4u64 {
            rb.push_back_assume_capacity(i);
        }
        for _ in 0..4 {
            rb.pop_front();
        }
        // Now head is at offset 4

        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_assume_capacity(black_box(i));
                black_box(rb.pop_front());
            }
        })
    });

    group.finish();
}

/// Test front() access pattern.
fn bench_front_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("front_access_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        for i in 0..8u64 {
            rb.push_back_assume_capacity(i);
        }
        b.iter(|| {
            let mut sum = 0u64;
            for _ in 0..OPS_PER_ITER {
                if let Some(&val) = rb.front() {
                    sum = sum.wrapping_add(val);
                }
            }
            black_box(sum)
        })
    });

    group.finish();
}

/// Compare push_back (with capacity check) vs push_back_assume_capacity.
fn bench_push_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("push_back_checked", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if rb.is_full() {
                    rb.pop_front();
                }
                let _ = rb.push_back(black_box(i));
            }
            rb.clear();
        })
    });

    group.bench_function("push_back_unchecked", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if rb.is_full() {
                    rb.pop_front();
                }
                rb.push_back_assume_capacity(black_box(i));
            }
            rb.clear();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_push_pop_cycle,
    bench_alternating,
    bench_fill_drain,
    bench_random_access,
    bench_wraparound,
    bench_front_access,
    bench_push_variants,
);

criterion_main!(benches);
