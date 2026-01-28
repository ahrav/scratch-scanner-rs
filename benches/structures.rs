use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use scanner_rs::stdx::{DynamicBitSet, FixedSet128, ReleasedSet};

const SET_CAP_POW2: usize = 1 << 14; // 16384 slots
const FIXED_SET_LOAD: usize = (SET_CAP_POW2 * 3) / 4; // 75% load
const RELEASED_SET_CAP: usize = 8192;
const BITSET_BITS: usize = 1 << 16; // 65536 bits
const BITSET_TOGGLES: usize = 1 << 12; // 4096 toggles

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

    fn next_u128(&mut self) -> u128 {
        let hi = self.next_u64() as u128;
        let lo = self.next_u64() as u128;
        (hi << 64) | lo
    }
}

fn make_u128_keys(count: usize, seed: u64) -> Vec<u128> {
    let mut rng = XorShift64::new(seed);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(rng.next_u128());
    }
    out
}

fn make_u64_keys(count: usize, seed: u64) -> Vec<u64> {
    let mut rng = XorShift64::new(seed);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(rng.next_u64());
    }
    out
}

fn make_bit_indices(count: usize, bit_len: usize, seed: u64) -> Vec<usize> {
    let mut rng = XorShift64::new(seed);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push((rng.next_u64() as usize) % bit_len);
    }
    out
}

fn bench_fixed_set128(c: &mut Criterion) {
    let keys = make_u128_keys(FIXED_SET_LOAD, 0x1234_5678_9abc_def0);
    let mut set = FixedSet128::with_pow2(SET_CAP_POW2);

    let mut group = c.benchmark_group("fixed_set128");
    group.throughput(Throughput::Elements(keys.len() as u64));
    group.bench_function("insert_reset", |b| {
        b.iter(|| {
            set.reset();
            for &k in &keys {
                black_box(set.insert(k));
            }
        })
    });
    group.finish();
}

fn bench_released_set(c: &mut Criterion) {
    let keys = make_u64_keys(RELEASED_SET_CAP, 0x0f0e_0d0c_0b0a_0908);
    let mut set = ReleasedSet::with_capacity(RELEASED_SET_CAP);

    let mut group = c.benchmark_group("released_set");
    group.throughput(Throughput::Elements(keys.len() as u64));
    group.bench_function("insert_pop", |b| {
        b.iter(|| {
            set.clear_retaining_capacity();
            for &k in &keys {
                set.insert(k);
            }
            let mut acc = 0u64;
            while let Some(k) = set.pop() {
                acc ^= k;
            }
            black_box(acc);
        })
    });
    group.finish();
}

fn bench_dynamic_bitset(c: &mut Criterion) {
    let indices = make_bit_indices(BITSET_TOGGLES, BITSET_BITS, 0xfeed_face_cafe_beef);
    let mut bits = DynamicBitSet::empty(BITSET_BITS);

    let mut group = c.benchmark_group("dynamic_bitset");
    group.throughput(Throughput::Elements(indices.len() as u64));
    group.bench_function("set_count_clear", |b| {
        b.iter(|| {
            bits.clear();
            for &idx in &indices {
                bits.set(idx);
            }
            let count = bits.count();
            black_box(count);
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_fixed_set128,
    bench_released_set,
    bench_dynamic_bitset
);
criterion_main!(benches);
