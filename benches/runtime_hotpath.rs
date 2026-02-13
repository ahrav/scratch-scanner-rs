use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_rs::{
    demo_engine, read_file_chunks, BufferPool, FileId, ScannerConfig, ScannerRuntime,
};
use std::fs;
use std::ops::ControlFlow;
use std::sync::Arc;
use tempfile::TempDir;

const DATA_LEN: usize = 4 * 1024 * 1024;
const CHUNK_SIZE: usize = 256 * 1024;
const OVERLAP: usize = 256;

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

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0usize;
        while i < out.len() {
            let mut v = self.next_u64();
            let take = (out.len() - i).min(8);
            for j in 0..take {
                out[i + j] = (v & 0xff) as u8;
                v >>= 8;
            }
            i += take;
        }
    }
}

fn make_random(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut rng = XorShift64::new(seed);
    rng.fill_bytes(&mut out);
    out
}

fn make_ascii_with_hits(len: usize, seed: u64) -> Vec<u8> {
    let mut out = make_random(len, seed);
    let token = b"ghp_0123456789abcdef0123456789abcdef0123";
    let stride = 4096usize;
    let mut idx = 1024usize;
    while idx + token.len() <= out.len() {
        out[idx..idx + token.len()].copy_from_slice(token);
        idx = idx.saturating_add(stride);
    }
    out
}

fn write_dataset(root: &TempDir, name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = root.path().join(name);
    fs::write(&path, data).expect("write bench dataset");
    path
}

fn bench_scan_file_sync(c: &mut Criterion) {
    let root = TempDir::new().expect("tempdir");
    let random = write_dataset(
        &root,
        "random.bin",
        &make_random(DATA_LEN, 0xabc1_2345_ded0_beef),
    );
    let hits = write_dataset(
        &root,
        "ascii_hits.txt",
        &make_ascii_with_hits(DATA_LEN, 0xface_b00c_1234_5678),
    );
    let datasets = [("random", random), ("ascii_hits", hits)];

    let engine = Arc::new(demo_engine());
    let mut runtime = ScannerRuntime::new(
        engine,
        ScannerConfig {
            chunk_size: CHUNK_SIZE,
            io_queue: 2,
            reader_threads: 1,
            scan_threads: 1,
            max_findings_per_file: 16_384,
        },
    );

    let mut group = c.benchmark_group("runtime_scan_file_sync");
    for (name, path) in datasets {
        group.throughput(Throughput::Bytes(DATA_LEN as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &path, |b, path| {
            b.iter(|| {
                let findings = runtime
                    .scan_file_sync(FileId(0), path.as_path())
                    .expect("scan_file_sync");
                black_box(findings.len());
            })
        });
    }
    group.finish();
}

fn bench_read_file_chunks(c: &mut Criterion) {
    let root = TempDir::new().expect("tempdir");
    let path = write_dataset(
        &root,
        "chunk_reader.bin",
        &make_random(DATA_LEN, 0x0123_4567_89ab_cdef),
    );
    let pool = BufferPool::new(2);
    let mut tail = vec![0u8; OVERLAP];

    let mut group = c.benchmark_group("runtime_read_file_chunks");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));
    group.bench_function("random", |b| {
        b.iter(|| {
            let mut payload_total = 0usize;
            read_file_chunks(
                FileId(0),
                path.as_path(),
                &pool,
                CHUNK_SIZE,
                OVERLAP,
                &mut tail,
                |chunk| {
                    payload_total = payload_total.saturating_add(chunk.payload().len());
                    ControlFlow::Continue(())
                },
            )
            .expect("read_file_chunks");
            black_box(payload_total);
        })
    });
    group.finish();
}

criterion_group!(
    runtime_hotpath,
    bench_scan_file_sync,
    bench_read_file_chunks
);
criterion_main!(runtime_hotpath);
