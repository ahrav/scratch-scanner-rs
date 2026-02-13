//! Archive scanning throughput benchmark.
//!
//! Measures decompressed bytes/sec through the archive scan pipeline with a
//! no-op sink, isolating scan+budget overhead from engine/detection costs.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::io::{self, Cursor, Read, Write};

use scanner_rs::archive::{
    scan_targz_stream, ArchiveConfig, ArchiveEnd, ArchiveEntrySink, ArchiveScratch, ArchiveStats,
    EntryChunk, EntryMeta,
};

// ---------------------------------------------------------------------------
// No-op sink: discards all chunks (isolates scan+budget overhead)
// ---------------------------------------------------------------------------

struct NullSink {
    total_bytes: u64,
}

impl NullSink {
    fn new() -> Self {
        Self { total_bytes: 0 }
    }
}

impl ArchiveEntrySink for NullSink {
    type Error = io::Error;

    fn on_entry_start(&mut self, _meta: &EntryMeta<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error> {
        self.total_bytes += chunk.new_bytes_len as u64;
        Ok(())
    }

    fn on_entry_end(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG for reproducible test data
// ---------------------------------------------------------------------------

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

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let mut v = self.next_u64();
            let chunk = buf.len() - i;
            let take = if chunk < 8 { chunk } else { 8 };
            for j in 0..take {
                buf[i + j] = (v & 0xff) as u8;
                v >>= 8;
            }
            i += take;
        }
    }
}

// ---------------------------------------------------------------------------
// Tar.gz archive builder (deterministic, in-memory)
// ---------------------------------------------------------------------------

fn build_tar_header(name: &[u8], size: u64) -> [u8; 512] {
    let mut hdr = [0u8; 512];

    // name field (0..100)
    let name_len = name.len().min(100);
    hdr[..name_len].copy_from_slice(&name[..name_len]);

    // mode (100..108)
    hdr[100..108].copy_from_slice(b"0000644\0");
    // uid (108..116)
    hdr[108..116].copy_from_slice(b"0001000\0");
    // gid (116..124)
    hdr[116..124].copy_from_slice(b"0001000\0");

    // size in octal (124..136)
    let mut size_field = [b'0'; 11];
    let mut v = size;
    for i in (0..11).rev() {
        size_field[i] = b'0' + ((v & 7) as u8);
        v >>= 3;
    }
    hdr[124..135].copy_from_slice(&size_field);
    hdr[135] = 0;

    // mtime (136..148)
    hdr[136..148].copy_from_slice(b"00000000000\0");

    // checksum placeholder (148..156) - spaces
    for b in &mut hdr[148..156] {
        *b = b' ';
    }

    // typeflag: regular file
    hdr[156] = b'0';

    // ustar magic
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");

    // compute checksum
    let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    hdr[148..156].copy_from_slice(chk.as_bytes());

    hdr
}

fn tar_pad(size: u64) -> usize {
    let rem = size % 512;
    if rem == 0 {
        0
    } else {
        (512 - rem) as usize
    }
}

/// Build a deterministic tar archive in memory.
fn build_tar(entry_count: usize, entry_size: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut tar = Vec::with_capacity(entry_count * (512 + entry_size + 512));

    let mut payload = vec![0u8; entry_size];

    for i in 0..entry_count {
        // Generate deterministic filename
        let name = format!("entry_{:06}.bin", i);
        let hdr = build_tar_header(name.as_bytes(), entry_size as u64);
        tar.extend_from_slice(&hdr);

        // Generate deterministic payload
        rng.fill_bytes(&mut payload);
        tar.extend_from_slice(&payload);

        // Pad to 512-byte boundary
        let pad = tar_pad(entry_size as u64);
        if pad > 0 {
            tar.extend_from_slice(&vec![0u8; pad]);
        }
    }

    // Two zero blocks to signal end of archive
    tar.extend_from_slice(&[0u8; 1024]);
    tar
}

/// Gzip-compress a tar archive in memory.
fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Build a deterministic tar.gz archive.
fn build_targz(entry_count: usize, entry_size: usize, seed: u64) -> Vec<u8> {
    let tar = build_tar(entry_count, entry_size, seed);
    gzip_compress(&tar)
}

/// Compute total decompressed payload bytes for verification.
fn expected_decompressed(entry_count: usize, entry_size: usize) -> u64 {
    (entry_count as u64) * (entry_size as u64)
}

// ---------------------------------------------------------------------------
// ZipSource stub for ArchiveScratch (not used but required by generics)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct NullZipSource;

impl Read for NullZipSource {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl io::Seek for NullZipSource {
    fn seek(&mut self, _pos: io::SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}

impl scanner_rs::archive::formats::ZipSource for NullZipSource {
    fn len(&self) -> io::Result<u64> {
        Ok(0)
    }
    fn try_clone(&self) -> io::Result<Self> {
        Ok(NullZipSource)
    }
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_targz_throughput(c: &mut Criterion) {
    let configs: &[(usize, usize, &str)] = &[
        // (entry_count, entry_size, label)
        (100, 1024, "100x1KB"),
        (100, 64 * 1024, "100x64KB"),
        (10, 1024 * 1024, "10x1MB"),
        (1000, 1024, "1000x1KB"),
        (1000, 64 * 1024, "1000x64KB"),
    ];

    let archive_cfg = ArchiveConfig {
        enabled: true,
        max_archive_depth: 4,
        max_entries_per_archive: 100_000,
        max_uncompressed_bytes_per_entry: 256 * 1024 * 1024,
        max_total_uncompressed_bytes_per_archive: 1024 * 1024 * 1024,
        max_total_uncompressed_bytes_per_root: 2048 * 1024 * 1024,
        max_archive_metadata_bytes: 64 * 1024 * 1024,
        max_inflation_ratio: 1000,
        ..ArchiveConfig::default()
    };

    let chunk_size = 256 * 1024;
    let overlap = 0;

    let mut group = c.benchmark_group("targz_scan");

    for &(entry_count, entry_size, label) in configs {
        let targz = build_targz(entry_count, entry_size, 0xDEAD_BEEF_CAFE_1234);
        let decompressed_total = expected_decompressed(entry_count, entry_size);

        group.throughput(Throughput::Bytes(decompressed_total));
        group.bench_with_input(BenchmarkId::new("throughput", label), &targz, |b, targz| {
            let mut scratch: ArchiveScratch<NullZipSource> =
                ArchiveScratch::new(&archive_cfg, chunk_size, overlap);
            let mut sink = NullSink::new();
            let mut stats = ArchiveStats::default();

            b.iter(|| {
                sink.total_bytes = 0;
                stats = ArchiveStats::default();
                let reader = Cursor::new(black_box(targz.as_slice()));
                let result: Result<ArchiveEnd, io::Error> = scan_targz_stream(
                    reader,
                    b"/bench/test.tar.gz",
                    &archive_cfg,
                    &mut scratch,
                    &mut sink,
                    &mut stats,
                );
                black_box(result.unwrap());
                black_box(sink.total_bytes);
            });
        });
    }

    group.finish();
}

fn bench_budget_overhead(c: &mut Criterion) {
    // Isolate budget charging overhead with many small entries
    let archive_cfg = ArchiveConfig {
        enabled: true,
        max_archive_depth: 4,
        max_entries_per_archive: 100_000,
        max_uncompressed_bytes_per_entry: 256 * 1024 * 1024,
        max_total_uncompressed_bytes_per_archive: 1024 * 1024 * 1024,
        max_total_uncompressed_bytes_per_root: 2048 * 1024 * 1024,
        max_archive_metadata_bytes: 64 * 1024 * 1024,
        max_inflation_ratio: 1000,
        ..ArchiveConfig::default()
    };

    let chunk_size = 256 * 1024;
    let overlap = 0;

    // Many small entries: high per-entry overhead ratio
    let targz_small = build_targz(10_000, 64, 0x1234_5678_9ABC_DEF0);
    let decompressed_small = expected_decompressed(10_000, 64);

    let mut group = c.benchmark_group("budget_overhead");
    group.throughput(Throughput::Bytes(decompressed_small));
    group.bench_function("10000x64B", |b| {
        let mut scratch: ArchiveScratch<NullZipSource> =
            ArchiveScratch::new(&archive_cfg, chunk_size, overlap);
        let mut sink = NullSink::new();
        let mut stats = ArchiveStats::default();

        b.iter(|| {
            sink.total_bytes = 0;
            stats = ArchiveStats::default();
            let reader = Cursor::new(black_box(targz_small.as_slice()));
            let result: Result<ArchiveEnd, io::Error> = scan_targz_stream(
                reader,
                b"/bench/small.tar.gz",
                &archive_cfg,
                &mut scratch,
                &mut sink,
                &mut stats,
            );
            black_box(result.unwrap());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_targz_throughput, bench_budget_overhead);
criterion_main!(benches);
