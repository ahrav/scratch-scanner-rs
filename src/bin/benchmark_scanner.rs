//! Benchmark suite for scanner engine performance.
//!
//! # Usage
//!
//! ```bash
//! cargo run --release --bin benchmark_scanner              # Run all benchmarks
//! cargo run --release --bin benchmark_scanner -- --json    # JSON output
//! cargo run --release --bin benchmark_scanner -- --filter Size  # Filter by pattern
//! cargo run --release --bin benchmark_scanner -- --list-tests   # List available tests
//! ```
//!
//! Notes:
//! - Hardware counters are Linux-only and best-effort. Use --disable-hw-counters to skip them.

use scanner_rs::{demo_engine_with_anchor_mode, AnchorMode, Engine};
use std::env;
use std::fs::File;
use std::hint::black_box;
use std::io::{self, Write};
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::{fs, path::Path};

const DEFAULT_ITERATIONS: usize = 12;
const DEFAULT_WARMUPS: usize = 2;
const DEFAULT_BUF_MIB: usize = 4;
const SIZE_SWEEP: &[usize] = &[
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    4 * 1024 * 1024,
    8 * 1024 * 1024,
];

const AWS_TOKEN: &[u8] = b"AKIAIOSFODNN7EXAMPLE";
const GHP_TOKEN: &[u8] = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
const AWS_B64: &[u8] = b"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";

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
            let take = (buf.len() - i).min(8);
            for j in 0..take {
                buf[i + j] = (v & 0xff) as u8;
                v >>= 8;
            }
            i += take;
        }
    }

    fn fill_ascii(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            let v = (self.next_u64() & 0xff) as u8;
            let letter = b'a' + (v % 26);
            *b = letter;
        }
    }
}

#[derive(Clone, Copy)]
enum DatasetKind {
    Random,
    AsciiHits,
    Utf16LeHits,
    Utf16BeHits,
    Base64Hits,
}

impl DatasetKind {
    const ALL: [DatasetKind; 5] = [
        DatasetKind::Random,
        DatasetKind::AsciiHits,
        DatasetKind::Utf16LeHits,
        DatasetKind::Utf16BeHits,
        DatasetKind::Base64Hits,
    ];

    fn name(self) -> &'static str {
        match self {
            DatasetKind::Random => "random",
            DatasetKind::AsciiHits => "ascii_hits",
            DatasetKind::Utf16LeHits => "utf16le_hits",
            DatasetKind::Utf16BeHits => "utf16be_hits",
            DatasetKind::Base64Hits => "base64_hits",
        }
    }

    fn build(self, len: usize) -> Vec<u8> {
        match self {
            DatasetKind::Random => make_random(len, 0x1234_5678_9abc_def0),
            DatasetKind::AsciiHits => make_ascii_hits(len),
            DatasetKind::Utf16LeHits => make_utf16_hits(len, false),
            DatasetKind::Utf16BeHits => make_utf16_hits(len, true),
            DatasetKind::Base64Hits => make_base64_hits(len),
        }
    }
}

struct Dataset {
    name: &'static str,
    buf: Vec<u8>,
}

fn make_random(len: usize, seed: u64) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut rng = XorShift64::new(seed);
    rng.fill_bytes(&mut buf);
    buf
}

fn make_ascii_hits(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut rng = XorShift64::new(0x1111_2222_3333_4444);
    rng.fill_ascii(&mut buf);
    inject_token(&mut buf, AWS_TOKEN, 4 * 1024);
    inject_token(&mut buf, GHP_TOKEN, 16 * 1024);
    buf
}

fn make_utf16_hits(len: usize, be: bool) -> Vec<u8> {
    let mut buf = make_utf16_text(len, if be { 0x5555_6666_7777_8888 } else { 0x9999_aaaa_bbbb_cccc }, be);
    inject_token_utf16(&mut buf, AWS_TOKEN, 4 * 1024, be);
    inject_token_utf16(&mut buf, GHP_TOKEN, 16 * 1024, be);
    buf
}

fn make_base64_hits(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() + AWS_B64.len() < len {
        out.extend_from_slice(AWS_B64);
        out.push(b'\n');
    }
    if out.len() < len {
        let remaining = len - out.len();
        out.resize(out.len() + remaining, b'A');
    }
    out
}

fn inject_token(buf: &mut [u8], token: &[u8], stride: usize) {
    if token.is_empty() || stride == 0 || buf.len() < token.len() {
        return;
    }
    let mut i = 1usize;
    while i + token.len() <= buf.len() {
        buf[i..i + token.len()].copy_from_slice(token);
        i = i.saturating_add(stride);
    }
}

fn encode_utf16_bytes(input: &[u8], be: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        if be {
            out.push(0);
            out.push(b);
        } else {
            out.push(b);
            out.push(0);
        }
    }
    out
}

fn make_utf16_text(len: usize, seed: u64, be: bool) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut rng = XorShift64::new(seed);
    let code_units = len / 2;
    for i in 0..code_units {
        let v = (rng.next_u64() & 0xff) as u8;
        let letter = b'a' + (v % 26);
        let idx = i * 2;
        if be {
            out[idx] = 0;
            out[idx + 1] = letter;
        } else {
            out[idx] = letter;
            out[idx + 1] = 0;
        }
    }

    if out.len() >= 2 {
        if be {
            out[0] = 0xFE;
            out[1] = 0xFF;
        } else {
            out[0] = 0xFF;
            out[1] = 0xFE;
        }
    }

    out
}

fn inject_token_utf16(buf: &mut [u8], token: &[u8], stride_bytes: usize, be: bool) {
    let stride_units = (stride_bytes / 2).max(1);
    let encoded = encode_utf16_bytes(token, be);
    if encoded.is_empty() || buf.len() < encoded.len() {
        return;
    }

    let mut i = 0usize;
    let max_units = buf.len() / 2;
    while i + token.len() <= max_units {
        let byte_idx = i * 2;
        if byte_idx + encoded.len() > buf.len() {
            break;
        }
        buf[byte_idx..byte_idx + encoded.len()].copy_from_slice(&encoded);
        i = i.saturating_add(stride_units);
    }
}

struct EngineVariant {
    name: &'static str,
    engine: Engine,
}

struct BenchmarkResult {
    test_name: String,
    dataset_name: String,
    engine_name: String,
    bytes_scanned: usize,
    iterations: usize,

    mean_time_ms: f64,
    median_time_ms: f64,
    standard_deviation: f64,
    min_time_ms: f64,
    max_time_ms: f64,
    p95_time_ms: f64,
    p99_time_ms: f64,

    throughput_mib_s: f64,
    findings_per_scan: usize,

    l1_cache_misses: usize,
    l2_cache_misses: usize,
    l3_cache_misses: usize,
    tlb_misses: usize,
    branch_misses: usize,
    cpu_cycles: usize,
    instructions: usize,
    stalled_cycles_frontend: usize,
    stalled_cycles_backend: usize,
    stalled_cycles_backend_mem: usize,
    instructions_per_cycle: f64,
}

impl BenchmarkResult {
    fn new(test_name: &str, iterations: usize) -> Self {
        Self {
            test_name: test_name.to_string(),
            dataset_name: String::new(),
            engine_name: String::new(),
            bytes_scanned: 0,
            iterations,
            mean_time_ms: 0.0,
            median_time_ms: 0.0,
            standard_deviation: 0.0,
            min_time_ms: 0.0,
            max_time_ms: 0.0,
            p95_time_ms: 0.0,
            p99_time_ms: 0.0,
            throughput_mib_s: 0.0,
            findings_per_scan: 0,
            l1_cache_misses: 0,
            l2_cache_misses: 0,
            l3_cache_misses: 0,
            tlb_misses: 0,
            branch_misses: 0,
            cpu_cycles: 0,
            instructions: 0,
            stalled_cycles_frontend: 0,
            stalled_cycles_backend: 0,
            stalled_cycles_backend_mem: 0,
            instructions_per_cycle: 0.0,
        }
    }
}

struct StatisticalAnalysis;

impl StatisticalAnalysis {
    fn mean(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<f64>() / values.len() as f64
    }

    fn standard_deviation(values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        let mean = Self::mean(values);
        let mut variance = 0.0;
        for v in values {
            variance += (v - mean) * (v - mean);
        }
        variance /= (values.len() - 1) as f64;
        variance.sqrt()
    }

    fn median(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let n = sorted.len();
        if n.is_multiple_of(2) {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        } else {
            sorted[n / 2]
        }
    }

    fn percentile(values: &[f64], p: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        if p <= 0.0 {
            return sorted[0];
        }
        if p >= 1.0 {
            return sorted[sorted.len() - 1];
        }
        let pos = p * (sorted.len() as f64 - 1.0);
        let i = pos.floor() as usize;
        let frac = pos - i as f64;
        if i + 1 >= sorted.len() {
            return sorted[i];
        }
        sorted[i] * (1.0 - frac) + sorted[i + 1] * frac
    }
}

/// Point-in-time snapshot of hardware performance counters.
#[derive(Clone, Copy, Default)]
struct HardwareCounterSnapshot {
    l1_cache_misses: usize,
    l2_cache_misses: usize,
    l3_cache_misses: usize,
    tlb_misses: usize,
    branch_misses: usize,
    cpu_cycles: usize,
    instructions: usize,
    stalled_cycles_frontend: usize,
    stalled_cycles_backend: usize,
    stalled_cycles_backend_mem: usize,
}

/// Linux perf_event file descriptors for hardware performance monitoring.
///
/// Opens counters for cache misses (L1/L2/L3), TLB misses, branch mispredictions,
/// CPU cycles, instructions, and stall cycles. Falls back gracefully when
/// specific counters are unavailable (varies by CPU architecture).
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct HardwareCounters {
    l1_cache_misses: RawFd,
    l2_cache_misses: RawFd,
    l3_cache_misses: RawFd,
    tlb_misses: RawFd,
    branch_misses: RawFd,
    cpu_cycles: RawFd,
    instructions: RawFd,
    stalled_cycles_frontend: RawFd,
    stalled_cycles_backend: RawFd,
    stalled_backend_raw: RawFd,
    stalled_backend_mem: RawFd,
    enabled: bool,
}

#[cfg(target_os = "linux")]
impl HardwareCounters {
    /// Opens available hardware counters. Returns disabled instance if `enable` is false
    /// or no counters can be opened (permission denied, unsupported CPU).
    fn new(enable: bool) -> Self {
        if !enable {
            return Self::disabled();
        }

        let base_attr = PerfEventAttr::new();
        let mut counters = Self::disabled();
        let mut any_open = false;

        let mut cache_attr = base_attr;
        cache_attr.type_ = PERF_TYPE_HW_CACHE;
        cache_attr.config = PERF_COUNT_HW_CACHE_L1D
            | (PERF_COUNT_HW_CACHE_OP_READ << 8)
            | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
        counters.l1_cache_misses = perf_event_open(&cache_attr);
        any_open |= counters.l1_cache_misses >= 0;

        let l2_events = [
            "l2d_cache_refill",
            "l2d_cache_lmiss_rd",
            "l2_cache_refill",
            "l2_rqsts.miss",
        ];
        counters.l2_cache_misses = open_pmu_event_by_name_list(&l2_events, &base_attr);
        if counters.l2_cache_misses < 0 {
            cache_attr.config = PERF_COUNT_HW_CACHE_LL
                | (PERF_COUNT_HW_CACHE_OP_READ << 8)
                | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
            counters.l2_cache_misses = perf_event_open(&cache_attr);
        }
        any_open |= counters.l2_cache_misses >= 0;

        let l3_events = [
            "l3d_cache_refill",
            "l3_cache_refill",
            "llc_misses",
            "llc-load-misses",
        ];
        counters.l3_cache_misses = open_pmu_event_by_name_list(&l3_events, &base_attr);
        if counters.l3_cache_misses < 0 {
            cache_attr.config = PERF_COUNT_HW_CACHE_NODE
                | (PERF_COUNT_HW_CACHE_OP_READ << 8)
                | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
            counters.l3_cache_misses = perf_event_open(&cache_attr);
        }
        any_open |= counters.l3_cache_misses >= 0;

        cache_attr.config = PERF_COUNT_HW_CACHE_DTLB
            | (PERF_COUNT_HW_CACHE_OP_READ << 8)
            | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
        counters.tlb_misses = perf_event_open(&cache_attr);
        any_open |= counters.tlb_misses >= 0;

        let mut hw_attr = base_attr;
        hw_attr.type_ = PERF_TYPE_HARDWARE;
        hw_attr.config = PERF_COUNT_HW_BRANCH_MISSES;
        counters.branch_misses = perf_event_open(&hw_attr);
        any_open |= counters.branch_misses >= 0;

        hw_attr.config = PERF_COUNT_HW_CPU_CYCLES;
        counters.cpu_cycles = perf_event_open(&hw_attr);
        any_open |= counters.cpu_cycles >= 0;

        hw_attr.config = PERF_COUNT_HW_INSTRUCTIONS;
        counters.instructions = perf_event_open(&hw_attr);
        any_open |= counters.instructions >= 0;

        hw_attr.config = PERF_COUNT_HW_STALLED_CYCLES_FRONTEND;
        counters.stalled_cycles_frontend = perf_event_open(&hw_attr);
        any_open |= counters.stalled_cycles_frontend >= 0;

        hw_attr.config = PERF_COUNT_HW_STALLED_CYCLES_BACKEND;
        counters.stalled_cycles_backend = perf_event_open(&hw_attr);
        any_open |= counters.stalled_cycles_backend >= 0;

        counters.stalled_backend_raw = open_pmu_event_by_name("stall_backend", &base_attr);
        counters.stalled_backend_mem = open_pmu_event_by_name("stall_backend_mem", &base_attr);
        any_open |= counters.stalled_backend_raw >= 0 || counters.stalled_backend_mem >= 0;

        counters.enabled = any_open;
        counters
    }

    fn available(&self) -> bool {
        self.enabled
    }

    /// Resets all counters to zero and starts counting.
    fn reset_and_enable(&self) {
        if !self.enabled {
            return;
        }
        reset_and_enable_fd(self.l1_cache_misses);
        reset_and_enable_fd(self.l2_cache_misses);
        reset_and_enable_fd(self.l3_cache_misses);
        reset_and_enable_fd(self.tlb_misses);
        reset_and_enable_fd(self.branch_misses);
        reset_and_enable_fd(self.cpu_cycles);
        reset_and_enable_fd(self.instructions);
        reset_and_enable_fd(self.stalled_cycles_frontend);
        reset_and_enable_fd(self.stalled_cycles_backend);
        reset_and_enable_fd(self.stalled_backend_raw);
        reset_and_enable_fd(self.stalled_backend_mem);
    }

    /// Stops all counters. Values are preserved until next reset.
    fn disable(&self) {
        if !self.enabled {
            return;
        }
        disable_fd(self.l1_cache_misses);
        disable_fd(self.l2_cache_misses);
        disable_fd(self.l3_cache_misses);
        disable_fd(self.tlb_misses);
        disable_fd(self.branch_misses);
        disable_fd(self.cpu_cycles);
        disable_fd(self.instructions);
        disable_fd(self.stalled_cycles_frontend);
        disable_fd(self.stalled_cycles_backend);
        disable_fd(self.stalled_backend_raw);
        disable_fd(self.stalled_backend_mem);
    }

    /// Reads current counter values, applying time-based scaling for multiplexed counters.
    fn read(&self) -> HardwareCounterSnapshot {
        if !self.enabled {
            return HardwareCounterSnapshot::default();
        }

        let mut stalled_backend = read_scaled_counter(self.stalled_cycles_backend);
        if stalled_backend == 0 {
            let raw = read_scaled_counter(self.stalled_backend_raw);
            if raw > 0 {
                stalled_backend = raw;
            }
        }

        HardwareCounterSnapshot {
            l1_cache_misses: read_scaled_counter(self.l1_cache_misses) as usize,
            l2_cache_misses: read_scaled_counter(self.l2_cache_misses) as usize,
            l3_cache_misses: read_scaled_counter(self.l3_cache_misses) as usize,
            tlb_misses: read_scaled_counter(self.tlb_misses) as usize,
            branch_misses: read_scaled_counter(self.branch_misses) as usize,
            cpu_cycles: read_scaled_counter(self.cpu_cycles) as usize,
            instructions: read_scaled_counter(self.instructions) as usize,
            stalled_cycles_frontend: read_scaled_counter(self.stalled_cycles_frontend) as usize,
            stalled_cycles_backend: stalled_backend as usize,
            stalled_cycles_backend_mem: read_scaled_counter(self.stalled_backend_mem) as usize,
        }
    }

    fn disabled() -> Self {
        Self {
            l1_cache_misses: -1,
            l2_cache_misses: -1,
            l3_cache_misses: -1,
            tlb_misses: -1,
            branch_misses: -1,
            cpu_cycles: -1,
            instructions: -1,
            stalled_cycles_frontend: -1,
            stalled_cycles_backend: -1,
            stalled_backend_raw: -1,
            stalled_backend_mem: -1,
            enabled: false,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for HardwareCounters {
    fn drop(&mut self) {
        close_fd(&mut self.l1_cache_misses);
        close_fd(&mut self.l2_cache_misses);
        close_fd(&mut self.l3_cache_misses);
        close_fd(&mut self.tlb_misses);
        close_fd(&mut self.branch_misses);
        close_fd(&mut self.cpu_cycles);
        close_fd(&mut self.instructions);
        close_fd(&mut self.stalled_cycles_frontend);
        close_fd(&mut self.stalled_cycles_backend);
        close_fd(&mut self.stalled_backend_raw);
        close_fd(&mut self.stalled_backend_mem);
        self.enabled = false;
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
struct HardwareCounters;

#[cfg(not(target_os = "linux"))]
impl HardwareCounters {
    fn new(_enable: bool) -> Self {
        Self
    }

    fn available(&self) -> bool {
        false
    }

    fn reset_and_enable(&self) {}

    fn disable(&self) {}

    fn read(&self) -> HardwareCounterSnapshot {
        HardwareCounterSnapshot::default()
    }
}

/// Specification for a PMU (Performance Monitoring Unit) event.
///
/// Loaded from /sys/bus/event_source/devices/*/events/* on Linux.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct PmuEventSpec {
    type_: i32,
    config: u64,
    config1: u64,
    config2: u64,
}

/// Attribute structure for perf_event_open syscall.
///
/// Matches the kernel's `struct perf_event_attr` layout.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
}

#[cfg(target_os = "linux")]
impl PerfEventAttr {
    fn new() -> Self {
        let mut attr = Self {
            type_: 0,
            size: std::mem::size_of::<Self>() as u32,
            config: 0,
            sample_period_or_freq: 0,
            sample_type: 0,
            read_format: PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
            flags: 0,
            wakeup_events: 0,
            bp_type: 0,
            config1: 0,
            config2: 0,
        };

        attr.flags |= PERF_ATTR_FLAG_DISABLED;
        attr.flags |= PERF_ATTR_FLAG_EXCLUDE_KERNEL;
        attr.flags |= PERF_ATTR_FLAG_EXCLUDE_HV;

        attr
    }
}

// =============================================================================
// Linux perf_event constants
// See: https://man7.org/linux/man-pages/man2/perf_event_open.2.html
// =============================================================================

#[cfg(target_os = "linux")]
const PERF_TYPE_HARDWARE: u32 = 0;
#[cfg(target_os = "linux")]
const PERF_TYPE_HW_CACHE: u32 = 3;

#[cfg(target_os = "linux")]
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;

#[cfg(target_os = "linux")]
const PERF_COUNT_HW_CACHE_L1D: u64 = 0;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_CACHE_LL: u64 = 2;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_CACHE_DTLB: u64 = 3;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_CACHE_NODE: u64 = 6;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_CACHE_OP_READ: u64 = 0;
#[cfg(target_os = "linux")]
const PERF_COUNT_HW_CACHE_RESULT_MISS: u64 = 1;

#[cfg(target_os = "linux")]
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 1;
#[cfg(target_os = "linux")]
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 2;

#[cfg(target_os = "linux")]
const PERF_ATTR_FLAG_DISABLED: u64 = 1 << 0;
#[cfg(target_os = "linux")]
const PERF_ATTR_FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const PERF_ATTR_FLAG_EXCLUDE_HV: u64 = 1 << 6;

#[cfg(target_os = "linux")]
const IOC_NRBITS: u64 = 8;
#[cfg(target_os = "linux")]
const IOC_TYPEBITS: u64 = 8;
#[cfg(target_os = "linux")]
const IOC_SIZEBITS: u64 = 14;

#[cfg(target_os = "linux")]
const IOC_NRSHIFT: u64 = 0;
#[cfg(target_os = "linux")]
const IOC_TYPESHIFT: u64 = IOC_NRSHIFT + IOC_NRBITS;
#[cfg(target_os = "linux")]
const IOC_SIZESHIFT: u64 = IOC_TYPESHIFT + IOC_TYPEBITS;
#[cfg(target_os = "linux")]
const IOC_DIRSHIFT: u64 = IOC_SIZESHIFT + IOC_SIZEBITS;
#[cfg(target_os = "linux")]
const IOC_NONE: u64 = 0;

#[cfg(target_os = "linux")]
const fn ioc(dir: u64, type_: u64, nr: u64, size: u64) -> u64 {
    (dir << IOC_DIRSHIFT) | (type_ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

#[cfg(target_os = "linux")]
const fn io(type_: u64, nr: u64) -> u64 {
    ioc(IOC_NONE, type_, nr, 0)
}

#[cfg(target_os = "linux")]
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = io(b'$' as u64, 0) as libc::c_ulong;
#[cfg(target_os = "linux")]
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = io(b'$' as u64, 1) as libc::c_ulong;
#[cfg(target_os = "linux")]
const PERF_EVENT_IOC_RESET: libc::c_ulong = io(b'$' as u64, 3) as libc::c_ulong;

/// Opens a perf event counter. Returns fd on success, -1 on failure.
#[cfg(target_os = "linux")]
fn perf_event_open(attr: &PerfEventAttr) -> RawFd {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr as *const PerfEventAttr,
            0 as libc::c_int,
            -1 as libc::c_int,
            -1 as libc::c_int,
            0 as libc::c_ulong,
        )
    };
    if ret < 0 { -1 } else { ret as RawFd }
}

#[cfg(target_os = "linux")]
fn close_fd(fd: &mut RawFd) {
    if *fd >= 0 {
        unsafe {
            libc::close(*fd);
        }
        *fd = -1;
    }
}

#[cfg(target_os = "linux")]
fn reset_and_enable_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::ioctl(fd, PERF_EVENT_IOC_RESET, 0);
            libc::ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        }
    }
}

#[cfg(target_os = "linux")]
fn disable_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct PerfRead {
    value: u64,
    time_enabled: u64,
    time_running: u64,
}

/// Reads a counter value, scaling for time-based multiplexing.
#[cfg(target_os = "linux")]
fn read_scaled_counter(fd: RawFd) -> u64 {
    if fd < 0 {
        return 0;
    }
    let mut data = PerfRead {
        value: 0,
        time_enabled: 0,
        time_running: 0,
    };
    let bytes = unsafe {
        libc::read(
            fd,
            &mut data as *mut PerfRead as *mut libc::c_void,
            std::mem::size_of::<PerfRead>(),
        )
    };
    if bytes < 0 {
        return 0;
    }
    if bytes == std::mem::size_of::<u64>() as isize {
        return data.value;
    }
    if bytes != std::mem::size_of::<PerfRead>() as isize {
        return 0;
    }

    let mut scaled = data.value as f64;
    if data.time_running > 0 && data.time_enabled > data.time_running {
        scaled = (data.value as f64) * (data.time_enabled as f64) / (data.time_running as f64);
    }
    scaled as u64
}

#[cfg(target_os = "linux")]
fn parse_u64_base0(input: &str) -> Option<u64> {
    let value = input.trim();
    if value.is_empty() {
        return None;
    }
    let (radix, digits) = if let Some(rest) = value.strip_prefix("0x").or(value.strip_prefix("0X"))
    {
        (16, rest)
    } else if value.len() > 1 && value.starts_with('0') {
        (8, &value[1..])
    } else {
        (10, value)
    };
    u64::from_str_radix(digits, radix).ok()
}

#[cfg(target_os = "linux")]
fn parse_pmu_event_spec(spec: &str, out: &mut PmuEventSpec) -> bool {
    let mut has_config = false;
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let mut iter = token.splitn(2, '=');
        let key = iter.next().unwrap_or("").trim();
        let value = iter.next().unwrap_or("").trim();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        let parsed = match parse_u64_base0(value) {
            Some(parsed) => parsed,
            None => continue,
        };
        match key {
            "event" | "config" => {
                out.config = parsed;
                has_config = true;
            }
            "config1" => out.config1 = parsed,
            "config2" => out.config2 = parsed,
            _ => {}
        }
    }
    has_config
}

/// Loads a PMU event specification by name from sysfs.
///
/// Searches /sys/bus/event_source/devices/*/events/{event_name} for
/// architecture-specific event definitions (e.g., "l2d_cache_refill" on ARM).
#[cfg(target_os = "linux")]
fn load_pmu_event_spec(event_name: &str) -> Option<PmuEventSpec> {
    let devices_path = Path::new("/sys/bus/event_source/devices");
    let entries = fs::read_dir(devices_path).ok()?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let base_path = entry.path();
        let event_path = base_path.join("events").join(event_name);
        let event_spec = match fs::read_to_string(&event_path) {
            Ok(spec) => spec,
            Err(_) => continue,
        };
        let event_spec = event_spec.lines().next().unwrap_or("").trim();
        if event_spec.is_empty() {
            continue;
        }

        let type_path = base_path.join("type");
        let type_str = match fs::read_to_string(&type_path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let type_id = match type_str.trim().parse::<i32>() {
            Ok(value) => value,
            Err(_) => continue,
        };
        if type_id < 0 {
            continue;
        }

        let mut spec = PmuEventSpec {
            type_: type_id,
            config: 0,
            config1: 0,
            config2: 0,
        };
        if !parse_pmu_event_spec(event_spec, &mut spec) {
            continue;
        }
        return Some(spec);
    }
    None
}

#[cfg(target_os = "linux")]
fn open_pmu_event_by_name(event_name: &str, base_attr: &PerfEventAttr) -> RawFd {
    let spec = match load_pmu_event_spec(event_name) {
        Some(spec) => spec,
        None => return -1,
    };
    let mut attr = *base_attr;
    attr.type_ = spec.type_ as u32;
    attr.config = spec.config;
    attr.config1 = spec.config1;
    attr.config2 = spec.config2;
    perf_event_open(&attr)
}

#[cfg(target_os = "linux")]
fn open_pmu_event_by_name_list(names: &[&str], base_attr: &PerfEventAttr) -> RawFd {
    for name in names {
        let fd = open_pmu_event_by_name(name, base_attr);
        if fd >= 0 {
            return fd;
        }
    }
    -1
}

struct BenchmarkRunner {
    enable_hardware_counters: bool,
}

impl BenchmarkRunner {
    fn new() -> Self {
        Self {
            enable_hardware_counters: cfg!(target_os = "linux"),
        }
    }

    fn set_enable_hardware_counters(&mut self, enable: bool) {
        self.enable_hardware_counters = if cfg!(target_os = "linux") {
            enable
        } else {
            false
        };
    }

    fn run_benchmark<S, B>(
        &self,
        test_name: &str,
        mut setup_fn: S,
        mut bench_fn: B,
        iterations: usize,
        warmups: usize,
    ) -> BenchmarkResult
    where
        S: FnMut(),
        B: FnMut(),
    {
        let mut result = BenchmarkResult::new(test_name, iterations);
        let mut times = Vec::with_capacity(iterations);

        setup_fn();

        for _ in 0..warmups {
            bench_fn();
        }

        let counters = HardwareCounters::new(self.enable_hardware_counters);
        let snapshot = if counters.available() {
            counters.reset_and_enable();
            bench_fn();
            counters.disable();
            counters.read()
        } else {
            bench_fn();
            HardwareCounterSnapshot::default()
        };

        result.l1_cache_misses = snapshot.l1_cache_misses;
        result.l2_cache_misses = snapshot.l2_cache_misses;
        result.l3_cache_misses = snapshot.l3_cache_misses;
        result.tlb_misses = snapshot.tlb_misses;
        result.branch_misses = snapshot.branch_misses;
        result.cpu_cycles = snapshot.cpu_cycles;
        result.instructions = snapshot.instructions;
        result.stalled_cycles_frontend = snapshot.stalled_cycles_frontend;
        result.stalled_cycles_backend = snapshot.stalled_cycles_backend;
        result.stalled_cycles_backend_mem = snapshot.stalled_cycles_backend_mem;
        result.instructions_per_cycle = if snapshot.cpu_cycles > 0 {
            snapshot.instructions as f64 / snapshot.cpu_cycles as f64
        } else {
            0.0
        };

        for _ in 0..2 {
            bench_fn();
        }

        for _ in 0..iterations {
            let start = Instant::now();
            bench_fn();
            let duration = start.elapsed();
            times.push(duration_to_ms(duration));
        }

        result.mean_time_ms = StatisticalAnalysis::mean(&times);
        result.median_time_ms = StatisticalAnalysis::median(&times);
        result.standard_deviation = StatisticalAnalysis::standard_deviation(&times);
        result.min_time_ms = times.iter().cloned().fold(f64::INFINITY, f64::min);
        result.max_time_ms = times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        result.p95_time_ms = StatisticalAnalysis::percentile(&times, 0.95);
        result.p99_time_ms = StatisticalAnalysis::percentile(&times, 0.99);

        result
    }
}

struct BenchmarkSuite {
    runner: BenchmarkRunner,
    results: Vec<BenchmarkResult>,
    filter: String,
    iterations: usize,
    warmups: usize,
    buf_len: usize,
    hardware_counters_enabled: bool,
}

impl BenchmarkSuite {
    fn new() -> Self {
        Self {
            runner: BenchmarkRunner::new(),
            results: Vec::new(),
            filter: String::new(),
            iterations: DEFAULT_ITERATIONS,
            warmups: DEFAULT_WARMUPS,
            buf_len: DEFAULT_BUF_MIB * 1024 * 1024,
            hardware_counters_enabled: cfg!(target_os = "linux"),
        }
    }

    fn set_filter(&mut self, filter: String) {
        self.filter = filter;
    }

    fn set_iterations(&mut self, iterations: usize) {
        self.iterations = iterations.max(1);
    }

    fn set_warmups(&mut self, warmups: usize) {
        self.warmups = warmups;
    }

    fn set_buf_len(&mut self, buf_len: usize) {
        self.buf_len = buf_len.max(1);
    }

    fn set_hardware_counters(&mut self, enable: bool) {
        let effective = if cfg!(target_os = "linux") {
            enable
        } else {
            false
        };
        self.hardware_counters_enabled = effective;
        self.runner.set_enable_hardware_counters(effective);
    }

    fn should_run_test(&self, test_name: &str) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        test_name == self.filter || test_name.contains(&self.filter)
    }

    fn run_all(&mut self, json_output: bool, output_file: Option<String>) -> io::Result<()> {
        if !json_output {
            println!("=== Scanner Benchmark Suite ===\n");
        }

        let engines = vec![
            EngineVariant {
                name: "manual",
                engine: demo_engine_with_anchor_mode(AnchorMode::Manual),
            },
            EngineVariant {
                name: "derived",
                engine: demo_engine_with_anchor_mode(AnchorMode::Derived),
            },
        ];

        self.benchmark_size_scaling(&engines, json_output);
        self.benchmark_dataset_mix(&engines, json_output);

        if json_output {
            let json = self.to_json();
            if let Some(path) = output_file {
                let mut file = File::create(path)?;
                file.write_all(json.as_bytes())?;
            } else {
                println!("{json}");
            }
        }

        Ok(())
    }

    fn list_tests(&self) {
        let mut names = Vec::new();
        for &size in SIZE_SWEEP {
            for engine in ["manual", "derived"] {
                names.push(test_name_size(DatasetKind::Random.name(), size, engine));
            }
        }
        for kind in DatasetKind::ALL {
            for engine in ["manual", "derived"] {
                names.push(test_name_dataset(kind.name(), engine));
            }
        }
        names.sort();
        for name in names {
            println!("{name}");
        }
    }

    fn benchmark_size_scaling(&mut self, engines: &[EngineVariant], silent: bool) {
        if !silent {
            println!("--- Benchmark: Size Scaling (random data) ---");
        }

        for &size in SIZE_SWEEP {
            let dataset = Dataset {
                name: DatasetKind::Random.name(),
                buf: DatasetKind::Random.build(size),
            };
            for variant in engines {
                let test_name = test_name_size(dataset.name, size, variant.name);
                if !self.should_run_test(&test_name) {
                    continue;
                }
                let result = self.run_scan_benchmark(&test_name, variant, &dataset);
                self.record_result(result, silent);
            }
        }

        if !silent {
            println!();
        }
    }

    fn benchmark_dataset_mix(&mut self, engines: &[EngineVariant], silent: bool) {
        if !silent {
            println!(
                "--- Benchmark: Dataset Mix ({} buffer, demo rules) ---",
                format_size(self.buf_len)
            );
        }

        let datasets: Vec<Dataset> = DatasetKind::ALL
            .iter()
            .map(|kind| Dataset {
                name: kind.name(),
                buf: kind.build(self.buf_len),
            })
            .collect();

        for variant in engines {
            for dataset in &datasets {
                let test_name = test_name_dataset(dataset.name, variant.name);
                if !self.should_run_test(&test_name) {
                    continue;
                }
                let result = self.run_scan_benchmark(&test_name, variant, dataset);
                self.record_result(result, silent);
            }
        }

        if !silent {
            println!();
        }
    }

    fn run_scan_benchmark(
        &self,
        test_name: &str,
        variant: &EngineVariant,
        dataset: &Dataset,
    ) -> BenchmarkResult {
        let mut scratch = variant.engine.new_scratch();
        let mut last_hits = 0usize;

        let setup = || {};
        let bench = || {
            let hits = variant.engine.scan_chunk(black_box(&dataset.buf), &mut scratch);
            last_hits = hits.len();
            black_box(last_hits);
        };

        let mut result = self.runner.run_benchmark(
            test_name,
            setup,
            bench,
            self.iterations,
            self.warmups,
        );

        result.dataset_name = dataset.name.to_string();
        result.engine_name = variant.name.to_string();
        result.bytes_scanned = dataset.buf.len();
        result.findings_per_scan = last_hits;

        let bytes = dataset.buf.len() as f64;
        let mean_ms = result.mean_time_ms.max(0.000001);
        result.throughput_mib_s = (bytes / (mean_ms / 1000.0)) / (1024.0 * 1024.0);

        result
    }

    fn record_result(&mut self, result: BenchmarkResult, silent: bool) {
        if !silent {
            self.print_result_line(&result);
        }
        self.results.push(result);
    }

    fn print_result_line(&self, result: &BenchmarkResult) {
        println!(
            "{:<42} mean {:>8.3} ms  p95 {:>8.3} ms  p99 {:>8.3} ms  {:>8.2} MiB/s  hits {:>5}",
            result.test_name,
            result.mean_time_ms,
            result.p95_time_ms,
            result.p99_time_ms,
            result.throughput_mib_s,
            result.findings_per_scan
        );
        if self.hardware_counters_enabled && result.cpu_cycles > 0 {
            println!(
                "    ipc {:>4.2}  l1m {}  l2m {}  l3m {}  tlbm {}  brm {}",
                result.instructions_per_cycle,
                result.l1_cache_misses,
                result.l2_cache_misses,
                result.l3_cache_misses,
                result.tlb_misses,
                result.branch_misses
            );
        }
    }

    fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str("  \"results\": [\n");
        for (idx, r) in self.results.iter().enumerate() {
            out.push_str("    {\n");
            out.push_str(&format!("      \"testName\": \"{}\",\n", r.test_name));
            out.push_str(&format!("      \"dataset\": \"{}\",\n", r.dataset_name));
            out.push_str(&format!("      \"engine\": \"{}\",\n", r.engine_name));
            out.push_str(&format!("      \"bytesScanned\": {},\n", r.bytes_scanned));
            out.push_str(&format!("      \"iterations\": {},\n", r.iterations));
            out.push_str(&format!("      \"meanTimeMs\": {:.3},\n", r.mean_time_ms));
            out.push_str(&format!(
                "      \"medianTimeMs\": {:.3},\n",
                r.median_time_ms
            ));
            out.push_str(&format!(
                "      \"standardDeviation\": {:.3},\n",
                r.standard_deviation
            ));
            out.push_str(&format!("      \"minTimeMs\": {:.3},\n", r.min_time_ms));
            out.push_str(&format!("      \"maxTimeMs\": {:.3},\n", r.max_time_ms));
            out.push_str(&format!("      \"p95TimeMs\": {:.3},\n", r.p95_time_ms));
            out.push_str(&format!("      \"p99TimeMs\": {:.3},\n", r.p99_time_ms));
            out.push_str(&format!(
                "      \"l1CacheMisses\": {},\n",
                r.l1_cache_misses
            ));
            out.push_str(&format!(
                "      \"l2CacheMisses\": {},\n",
                r.l2_cache_misses
            ));
            out.push_str(&format!(
                "      \"l3CacheMisses\": {},\n",
                r.l3_cache_misses
            ));
            out.push_str(&format!("      \"tlbMisses\": {},\n", r.tlb_misses));
            out.push_str(&format!(
                "      \"branchMisses\": {},\n",
                r.branch_misses
            ));
            out.push_str(&format!("      \"cpuCycles\": {},\n", r.cpu_cycles));
            out.push_str(&format!(
                "      \"instructions\": {},\n",
                r.instructions
            ));
            out.push_str(&format!(
                "      \"stalledCyclesFrontend\": {},\n",
                r.stalled_cycles_frontend
            ));
            out.push_str(&format!(
                "      \"stalledCyclesBackend\": {},\n",
                r.stalled_cycles_backend
            ));
            out.push_str(&format!(
                "      \"stalledCyclesBackendMem\": {},\n",
                r.stalled_cycles_backend_mem
            ));
            out.push_str(&format!(
                "      \"instructionsPerCycle\": {:.3},\n",
                r.instructions_per_cycle
            ));
            out.push_str(&format!(
                "      \"throughputMiBPerSec\": {:.3},\n",
                r.throughput_mib_s
            ));
            out.push_str(&format!(
                "      \"findingsPerScan\": {}\n",
                r.findings_per_scan
            ));
            out.push_str("    }");
            if idx + 1 < self.results.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n}");
        out
    }
}

fn duration_to_ms(dur: Duration) -> f64 {
    dur.as_secs_f64() * 1000.0
}

fn format_size(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * 1024;
    if bytes.is_multiple_of(MIB) {
        format!("{}MiB", bytes / MIB)
    } else if bytes.is_multiple_of(KIB) {
        format!("{}KiB", bytes / KIB)
    } else {
        format!("{}B", bytes)
    }
}

fn test_name_size(dataset: &str, size: usize, engine: &str) -> String {
    format!("Size_{}_{}_{}", dataset, format_size(size), engine)
}

fn test_name_dataset(dataset: &str, engine: &str) -> String {
    format!("Dataset_{}_{}", dataset, engine)
}

fn print_usage(program: &str) {
    eprintln!("Usage: {program} [options]");
    eprintln!("Options:");
    eprintln!("  --json                 Output results in JSON format");
    eprintln!("  --output <file>        Write results to file (default: stdout)");
    eprintln!("  --filter <pattern>     Run only tests matching pattern");
    eprintln!("  --list-tests           List all available tests");
    eprintln!("  --iterations <count>   Timed iterations per test (default: {DEFAULT_ITERATIONS})");
    eprintln!("  --warmups <count>      Warmup iterations per test (default: {DEFAULT_WARMUPS})");
    eprintln!("  --buf-mib <mib>         Buffer size for dataset mix (default: {DEFAULT_BUF_MIB} MiB)");
    eprintln!("  --disable-hw-counters  Disable hardware counters (Linux only)");
    eprintln!("  --help, -h             Show this help");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut json_output = false;
    let mut output_file: Option<String> = None;
    let mut filter_pattern: Option<String> = None;
    let mut list_tests = false;
    let mut iterations = DEFAULT_ITERATIONS;
    let mut warmups = DEFAULT_WARMUPS;
    let mut buf_mib = DEFAULT_BUF_MIB;
    let mut disable_hw = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json_output = true;
                i += 1;
            }
            "--output" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --output requires a filename argument");
                    print_usage(&args[0]);
                    std::process::exit(1);
                }
                output_file = Some(args[i + 1].clone());
                i += 2;
            }
            "--filter" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --filter requires a pattern argument");
                    print_usage(&args[0]);
                    std::process::exit(1);
                }
                filter_pattern = Some(args[i + 1].clone());
                i += 2;
            }
            "--list-tests" => {
                list_tests = true;
                i += 1;
            }
            "--iterations" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --iterations requires a count argument");
                    print_usage(&args[0]);
                    std::process::exit(1);
                }
                iterations = match args[i + 1].parse::<usize>() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("Error: --iterations requires a number");
                        std::process::exit(1);
                    }
                };
                i += 2;
            }
            "--warmups" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --warmups requires a count argument");
                    print_usage(&args[0]);
                    std::process::exit(1);
                }
                warmups = match args[i + 1].parse::<usize>() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("Error: --warmups requires a number");
                        std::process::exit(1);
                    }
                };
                i += 2;
            }
            "--buf-mib" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --buf-mib requires a MiB argument");
                    print_usage(&args[0]);
                    std::process::exit(1);
                }
                buf_mib = match args[i + 1].parse::<usize>() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("Error: --buf-mib requires a number");
                        std::process::exit(1);
                    }
                };
                i += 2;
            }
            "--disable-hw-counters" => {
                disable_hw = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                return Ok(());
            }
            other => {
                eprintln!("Unknown option: {other}");
                print_usage(&args[0]);
                std::process::exit(1);
            }
        }
    }

    let mut suite = BenchmarkSuite::new();
    suite.set_iterations(iterations);
    suite.set_warmups(warmups);
    suite.set_buf_len(buf_mib * 1024 * 1024);
    if disable_hw {
        suite.set_hardware_counters(false);
    }

    if list_tests {
        suite.list_tests();
        return Ok(());
    }

    if let Some(filter) = filter_pattern {
        suite.set_filter(filter);
    }

    suite.run_all(json_output, output_file)
}
