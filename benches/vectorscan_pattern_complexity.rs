//! Vectorscan Pattern Complexity Benchmark
//!
//! This benchmark isolates Vectorscan itself to determine if pattern complexity
//! affects its throughput, or if the bottleneck is entirely downstream.
//!
//! # Key Question
//! Does compiling complex gitleaks-style patterns into Vectorscan make the
//! automaton traversal slower, or is Vectorscan throughput roughly constant
//! regardless of pattern complexity?
//!
//! # Test Groups
//!
//! 1. **literal_anchors**: Simple literal patterns (e.g., "AKIA", "ghp_")
//! 2. **simple_regex**: Basic regex patterns (e.g., `AKIA[A-Z0-9]{16}`)
//! 3. **complex_regex**: Full gitleaks-style patterns with HS_FLAG_PREFILTER
//!
//! # Interpretation
//!
//! - If all three groups have similar throughput → Vectorscan is NOT the bottleneck
//! - If complex_regex is significantly slower → Vectorscan automaton is the issue
//!
//! Run with: cargo bench --bench vectorscan_pattern_complexity

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use scanner_rs::RuleSpec;
use std::ffi::CString;
use vectorscan_rs_sys as vs;

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Generate clean ASCII that won't match any patterns.
fn gen_clean_ascii(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = b'a' + ((state & 0xFF) % 26) as u8;
    }
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }
    buf
}

/// Generate data with anchor hits that won't fully match patterns.
/// This tests the scenario where Vectorscan finds potential matches
/// but they fail full validation.
fn gen_data_with_anchors(size: usize) -> Vec<u8> {
    let mut data = gen_clean_ascii(size, 0x1234);

    // Inject anchors every ~100KB
    let anchors: &[&[u8]] = &[
        b"AKIA",
        b"ghp_",
        b"xoxb",
        b"sk_live_",
        b"eyJh",
        b"AIza",
        b"npm_",
        b"SG.",
    ];

    for (i, anchor) in anchors.iter().cycle().enumerate() {
        let pos = i * 100_000;
        if pos + anchor.len() >= size {
            break;
        }
        data[pos..pos + anchor.len()].copy_from_slice(anchor);
    }

    data
}

/// Minimal callback that just counts matches.
extern "C" fn count_callback(
    _id: std::ffi::c_uint,
    _from: u64,
    _to: u64,
    _flags: std::ffi::c_uint,
    ctx: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    unsafe {
        let count = ctx as *mut u64;
        *count += 1;
    }
    0 // Continue scanning
}

/// Helper to compile patterns and run benchmark.
struct VsDb {
    db: *mut vs::hs_database_t,
    scratch: *mut vs::hs_scratch_t,
}

impl VsDb {
    fn compile(patterns: &[&str], flags: &[u32]) -> Result<Self, String> {
        let c_patterns: Vec<CString> = patterns.iter().map(|p| CString::new(*p).unwrap()).collect();
        let pattern_ptrs: Vec<*const i8> = c_patterns.iter().map(|p| p.as_ptr()).collect();
        let ids: Vec<u32> = (0..patterns.len() as u32).collect();

        let mut db: *mut vs::hs_database_t = std::ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = std::ptr::null_mut();

        let rc = unsafe {
            vs::hs_compile_multi(
                pattern_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                patterns.len() as u32,
                vs::HS_MODE_BLOCK,
                std::ptr::null(),
                &mut db,
                &mut compile_err,
            )
        };

        if rc != vs::HS_SUCCESS as i32 {
            let msg = if !compile_err.is_null() {
                unsafe {
                    let msg = std::ffi::CStr::from_ptr((*compile_err).message)
                        .to_string_lossy()
                        .to_string();
                    vs::hs_free_compile_error(compile_err);
                    msg
                }
            } else {
                format!("compile failed: rc={}", rc)
            };
            return Err(msg);
        }

        let mut scratch: *mut vs::hs_scratch_t = std::ptr::null_mut();
        let rc = unsafe { vs::hs_alloc_scratch(db, &mut scratch) };
        if rc != vs::HS_SUCCESS as i32 {
            unsafe { vs::hs_free_database(db) };
            return Err(format!("hs_alloc_scratch failed: rc={}", rc));
        }

        Ok(Self { db, scratch })
    }

    fn scan(&self, data: &[u8]) -> u64 {
        let mut count: u64 = 0;
        let rc = unsafe {
            vs::hs_scan(
                self.db,
                data.as_ptr() as *const i8,
                data.len() as u32,
                0,
                self.scratch,
                Some(count_callback),
                (&mut count as *mut u64) as *mut std::ffi::c_void,
            )
        };
        assert!(rc == vs::HS_SUCCESS as i32 || rc == vs::HS_SCAN_TERMINATED);
        count
    }
}

impl Drop for VsDb {
    fn drop(&mut self) {
        unsafe {
            vs::hs_free_scratch(self.scratch);
            vs::hs_free_database(self.db);
        }
    }
}

fn build_full_rule_patterns(include_generic: bool) -> Vec<String> {
    let mut rules: Vec<RuleSpec> = scanner_rs::gitleaks_rules();
    if !include_generic {
        rules.retain(|r| r.name != "generic-api-key");
    }
    rules.iter().map(|r| r.re.as_str().to_owned()).collect()
}

fn build_prefilter_flags(count: usize) -> Vec<u32> {
    vec![vs::HS_FLAG_PREFILTER; count]
}

/// Benchmark 4b: Full rule set as used by the engine prefilter DB.
fn bench_full_rules_prefilter(c: &mut Criterion) {
    let mut group = c.benchmark_group("vs_full_rules_prefilter");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let anchor_data = gen_data_with_anchors(BUFFER_SIZE);

    let full_patterns = build_full_rule_patterns(true);
    let full_flags = build_prefilter_flags(full_patterns.len());
    let full_refs: Vec<&str> = full_patterns.iter().map(|p| p.as_str()).collect();
    let full_db = VsDb::compile(&full_refs, &full_flags).expect("compile full rules failed");

    let no_generic_patterns = build_full_rule_patterns(false);
    let no_generic_flags = build_prefilter_flags(no_generic_patterns.len());
    let no_generic_refs: Vec<&str> = no_generic_patterns.iter().map(|p| p.as_str()).collect();
    let no_generic_db =
        VsDb::compile(&no_generic_refs, &no_generic_flags).expect("compile no-generic failed");

    group.bench_function("full_rules_clean", |b| {
        b.iter(|| black_box(full_db.scan(black_box(&clean_data))))
    });

    group.bench_function("full_rules_with_anchors", |b| {
        b.iter(|| black_box(full_db.scan(black_box(&anchor_data))))
    });

    group.bench_function("no_generic_clean", |b| {
        b.iter(|| black_box(no_generic_db.scan(black_box(&clean_data))))
    });

    group.bench_function("no_generic_with_anchors", |b| {
        b.iter(|| black_box(no_generic_db.scan(black_box(&anchor_data))))
    });

    group.finish();
}

/// Benchmark 1: Pure literal patterns (no regex)
fn bench_literal_anchors(c: &mut Criterion) {
    let mut group = c.benchmark_group("vs_literal_anchors");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let anchor_data = gen_data_with_anchors(BUFFER_SIZE);

    // 10 literal patterns (no regex features)
    let patterns: &[&str] = &[
        "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "ghp_", "gho_",
    ];
    let flags: Vec<u32> = vec![vs::HS_FLAG_SINGLEMATCH; patterns.len()];

    let db = VsDb::compile(patterns, &flags).expect("compile failed");

    group.bench_function("10_literals_clean", |b| {
        b.iter(|| black_box(db.scan(black_box(&clean_data))))
    });

    group.bench_function("10_literals_with_anchors", |b| {
        b.iter(|| black_box(db.scan(black_box(&anchor_data))))
    });

    group.finish();
}

/// Benchmark 2: Simple regex patterns
fn bench_simple_regex(c: &mut Criterion) {
    let mut group = c.benchmark_group("vs_simple_regex");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let anchor_data = gen_data_with_anchors(BUFFER_SIZE);

    // 10 simple regex patterns (literal prefix + char class)
    let patterns: &[&str] = &[
        r"AKIA[A-Z0-9]{16}",
        r"AGPA[A-Z0-9]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"gho_[A-Za-z0-9]{36}",
        r"xoxb-[0-9]{10,13}",
        r"sk_live_[a-zA-Z0-9]{24}",
        r"pk_live_[a-zA-Z0-9]{24}",
        r"AIza[A-Za-z0-9_-]{35}",
        r"npm_[A-Za-z0-9]{36}",
        r"SG\.[A-Za-z0-9_-]{22}",
    ];
    let flags: Vec<u32> = vec![vs::HS_FLAG_SINGLEMATCH; patterns.len()];

    let db = VsDb::compile(patterns, &flags).expect("compile failed");

    group.bench_function("10_simple_regex_clean", |b| {
        b.iter(|| black_box(db.scan(black_box(&clean_data))))
    });

    group.bench_function("10_simple_regex_with_anchors", |b| {
        b.iter(|| black_box(db.scan(black_box(&anchor_data))))
    });

    group.finish();
}

/// Benchmark 3: Complex gitleaks-style patterns with HS_FLAG_PREFILTER
fn bench_complex_regex_prefilter(c: &mut Criterion) {
    let mut group = c.benchmark_group("vs_complex_regex_prefilter");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let anchor_data = gen_data_with_anchors(BUFFER_SIZE);

    // 10 complex gitleaks-style patterns
    // These are the actual patterns from gitleaks rules
    let patterns: &[&str] = &[
        // AWS access key (simplified for Vectorscan compatibility)
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        // GitHub token
        r"ghp_[A-Za-z0-9]{36}",
        // Slack token
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        // Stripe key
        r"(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,99}",
        // JWT (simplified)
        r"eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,}",
        // Google API key
        r"AIza[A-Za-z0-9_-]{35}",
        // NPM token
        r"npm_[A-Za-z0-9]{36}",
        // SendGrid
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        // PyPI token
        r"pypi-[A-Za-z0-9_-]{50,}",
        // Private key header
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
    ];
    // Use PREFILTER flag like the real scanner does
    let flags: Vec<u32> = vec![vs::HS_FLAG_PREFILTER | vs::HS_FLAG_SINGLEMATCH; patterns.len()];

    let db = VsDb::compile(patterns, &flags).expect("compile failed");

    group.bench_function("10_complex_prefilter_clean", |b| {
        b.iter(|| black_box(db.scan(black_box(&clean_data))))
    });

    group.bench_function("10_complex_prefilter_with_anchors", |b| {
        b.iter(|| black_box(db.scan(black_box(&anchor_data))))
    });

    group.finish();
}

/// Benchmark 4: Full gitleaks complexity (case-insensitive, lazy quantifiers)
fn bench_full_gitleaks_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("vs_full_gitleaks");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let anchor_data = gen_data_with_anchors(BUFFER_SIZE);

    // Full gitleaks patterns with case-insensitive and context matching
    // Note: Some patterns may need simplification for Vectorscan compatibility
    let patterns: &[&str] = &[
        // AWS with context (simplified - removed unsupported features)
        r"(?i)(?:aws|amazon).{0,50}(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        // GitHub with context
        r"(?i)(?:github|gh).{0,30}ghp_[A-Za-z0-9]{36}",
        // Slack with context
        r"(?i)slack.{0,30}xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        // Stripe with context
        r"(?i)stripe.{0,30}(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,99}",
        // JWT (no context needed)
        r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_/-]{10,}\.[a-zA-Z0-9_/-]{10,}",
        // Google with context
        r"(?i)(?:google|gcp|firebase).{0,30}AIza[A-Za-z0-9_-]{35}",
        // NPM with context
        r"(?i)npm.{0,30}npm_[A-Za-z0-9]{36}",
        // SendGrid with context
        r"(?i)sendgrid.{0,30}SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        // Generic API key pattern
        r#"(?i)api[_-]?key.{0,20}['"][A-Za-z0-9_-]{20,}['"]"#,
        // Private key
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
    ];
    let flags: Vec<u32> = vec![vs::HS_FLAG_PREFILTER | vs::HS_FLAG_SINGLEMATCH; patterns.len()];

    let db = match VsDb::compile(patterns, &flags) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Warning: full gitleaks patterns failed to compile: {}", e);
            eprintln!("Skipping this benchmark group");
            return;
        }
    };

    group.bench_function("10_full_gitleaks_clean", |b| {
        b.iter(|| black_box(db.scan(black_box(&clean_data))))
    });

    group.bench_function("10_full_gitleaks_with_anchors", |b| {
        b.iter(|| black_box(db.scan(black_box(&anchor_data))))
    });

    group.finish();
}

/// Benchmark 5: Scale test - 50 vs 100 vs 200 patterns
fn bench_pattern_count_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("vs_pattern_scaling");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    // Generate N simple patterns
    fn make_patterns(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!(r"PAT{:03}[A-Z0-9]{{16}}", i))
            .collect()
    }

    for count in [10, 50, 100, 200] {
        let patterns = make_patterns(count);
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
        let flags: Vec<u32> = vec![vs::HS_FLAG_SINGLEMATCH; count];

        let db = VsDb::compile(&pattern_refs, &flags).expect("compile failed");

        group.bench_function(format!("{}_patterns", count), |b| {
            b.iter(|| black_box(db.scan(black_box(&clean_data))))
        });
    }

    group.finish();
}

/// Benchmark 6: Callback overhead - measure impact of match frequency
fn bench_callback_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("vs_callback_overhead");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    // Create data with varying anchor densities
    fn gen_data_with_density(size: usize, hits_per_mb: usize) -> Vec<u8> {
        let mut data = gen_clean_ascii(size, 0x5678);
        let anchor = b"TESTANCHOR";
        let interval = (1024 * 1024) / hits_per_mb.max(1);

        for i in 0..(size / interval) {
            let pos = i * interval;
            if pos + anchor.len() < size {
                data[pos..pos + anchor.len()].copy_from_slice(anchor);
            }
        }
        data
    }

    let patterns: &[&str] = &[r"TESTANCHOR"];
    let flags: Vec<u32> = vec![0]; // No SINGLEMATCH - count all hits

    let db = VsDb::compile(patterns, &flags).expect("compile failed");

    // 0 hits per MB (clean data)
    let data_0 = gen_clean_ascii(BUFFER_SIZE, 0x9999);
    group.bench_function("0_hits_per_mb", |b| {
        b.iter(|| black_box(db.scan(black_box(&data_0))))
    });

    // 10 hits per MB
    let data_10 = gen_data_with_density(BUFFER_SIZE, 10);
    group.bench_function("10_hits_per_mb", |b| {
        b.iter(|| black_box(db.scan(black_box(&data_10))))
    });

    // 100 hits per MB
    let data_100 = gen_data_with_density(BUFFER_SIZE, 100);
    group.bench_function("100_hits_per_mb", |b| {
        b.iter(|| black_box(db.scan(black_box(&data_100))))
    });

    // 1000 hits per MB
    let data_1000 = gen_data_with_density(BUFFER_SIZE, 1000);
    group.bench_function("1000_hits_per_mb", |b| {
        b.iter(|| black_box(db.scan(black_box(&data_1000))))
    });

    group.finish();
}

criterion_group!(
    vectorscan_complexity,
    bench_literal_anchors,
    bench_simple_regex,
    bench_complex_regex_prefilter,
    bench_full_gitleaks_patterns,
    bench_full_rules_prefilter,
    bench_pattern_count_scaling,
    bench_callback_overhead,
);

criterion_main!(vectorscan_complexity);
