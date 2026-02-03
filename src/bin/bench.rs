//! Benchmark CLI Binary
//!
//! Place this file at: src/bin/bench.rs
//!
//! Build and run:
//! ```bash
//! cargo build --release --bin bench
//! ./target/release/bench --help
//! ./target/release/bench --bench local --preset ci
//! ./target/release/bench --bench executor --tasks 100000
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// Import from the library crate
use scanner_rs::scheduler::bench::{run_benchmark, BenchConfig, BenchReport};
use scanner_rs::scheduler::bench_compare::{BenchBaseline, BenchComparison};
use scanner_rs::scheduler::bench_executor::{ExecutorMicrobench, ExecutorMicrobenchConfig};
use scanner_rs::scheduler::bench_local::LocalScanBenchmark;
use scanner_rs::scheduler::bench_synthetic::{FileSizeDistribution, SyntheticConfig};
use scanner_rs::scheduler::engine_stub::{MockEngine, MockRule};
use scanner_rs::scheduler::local::LocalConfig;
use scanner_rs::scheduler::output_sink::{FileSink, NullSink, OutputSink, StdoutSink};

// ============================================================================
// Argument Parsing
// ============================================================================

#[derive(Debug)]
struct Args {
    bench: BenchType,
    preset: Preset,
    workers: Option<usize>,
    files: Option<usize>,
    file_size: Option<usize>,
    secret_density: Option<f64>,
    sink: SinkKind,
    sink_path: Option<PathBuf>,
    tasks: Option<usize>,
    work_ns: Option<u64>,
    warmup: Option<usize>,
    iters: Option<usize>,
    pin_harness: Option<usize>,
    seed: Option<u64>,
    ci: bool,
    save_baseline: Option<PathBuf>,
    baseline: Option<PathBuf>,
    threshold: f64,
    help: bool,
    verbose: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BenchType {
    Local,
    Executor,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Preset {
    Default,
    Ci,
    Detailed,
    Stress,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SinkKind {
    Null,
    Stdout,
    File,
}

impl std::fmt::Display for SinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SinkKind::Null => "null",
            SinkKind::Stdout => "stdout",
            SinkKind::File => "file",
        };
        f.write_str(s)
    }
}

impl Default for Args {
    fn default() -> Self {
        Self {
            bench: BenchType::Local,
            preset: Preset::Default,
            workers: None,
            files: None,
            file_size: None,
            secret_density: None,
            sink: SinkKind::Null,
            sink_path: None,
            tasks: None,
            work_ns: None,
            warmup: None,
            iters: None,
            pin_harness: None,
            seed: None,
            ci: false,
            save_baseline: None,
            baseline: None,
            threshold: 5.0,
            help: false,
            verbose: false,
        }
    }
}

/// Exit with error message.
fn die(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    eprintln!("Run with --help for usage");
    std::process::exit(2);
}

/// Get next argument value or die.
fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> String {
    it.next()
        .unwrap_or_else(|| die(&format!("{} requires a value", flag)))
}

/// Parse a numeric argument or die.
fn parse_num<T: std::str::FromStr>(val: &str, flag: &str) -> T {
    val.parse()
        .unwrap_or_else(|_| die(&format!("Invalid {}: '{}'", flag, val)))
}

/// Parse size with suffix (k/m/g) with overflow checking.
fn parse_size_strict(s: &str, flag: &str) -> usize {
    let s = s.trim();
    let (num_str, mult): (&str, u64) = match s.as_bytes().last().copied() {
        Some(b'k') | Some(b'K') => (&s[..s.len() - 1], 1024),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'g') | Some(b'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };

    let n: u64 = num_str
        .parse()
        .unwrap_or_else(|_| die(&format!("Invalid {}: '{}'", flag, s)));

    let bytes = n
        .checked_mul(mult)
        .unwrap_or_else(|| die(&format!("{} overflow: '{}'", flag, s)));

    usize::try_from(bytes)
        .unwrap_or_else(|_| die(&format!("{} too large for this platform: '{}'", flag, s)))
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1).peekable();

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => args.help = true,
            "--verbose" | "-v" => args.verbose = true,
            "--ci" => args.ci = true,

            "--bench" | "-b" => {
                let val = next_value(&mut it, "--bench");
                args.bench = match val.as_str() {
                    "local" => BenchType::Local,
                    "executor" => BenchType::Executor,
                    _ => die(&format!(
                        "Unknown bench type: '{}' (expected 'local' or 'executor')",
                        val
                    )),
                };
            }

            "--preset" | "-p" => {
                let val = next_value(&mut it, "--preset");
                args.preset = match val.as_str() {
                    "default" => Preset::Default,
                    "ci" => Preset::Ci,
                    "detailed" => Preset::Detailed,
                    "stress" => Preset::Stress,
                    _ => die(&format!(
                        "Unknown preset: '{}' (expected default/ci/detailed/stress)",
                        val
                    )),
                };
            }

            "--workers" | "-w" => {
                let val = next_value(&mut it, "--workers");
                let n: usize = parse_num(&val, "--workers");
                if n == 0 {
                    die("--workers must be >= 1");
                }
                if n > 256 {
                    die("--workers must be <= 256");
                }
                args.workers = Some(n);
            }

            "--files" | "-f" => {
                let val = next_value(&mut it, "--files");
                let n: usize = parse_num(&val, "--files");
                if n == 0 {
                    die("--files must be >= 1");
                }
                args.files = Some(n);
            }

            "--file-size" => {
                let val = next_value(&mut it, "--file-size");
                let n = parse_size_strict(&val, "--file-size");
                if n == 0 {
                    die("--file-size must be >= 1");
                }
                args.file_size = Some(n);
            }

            "--secret-density" => {
                let val = next_value(&mut it, "--secret-density");
                args.secret_density = Some(parse_num(&val, "--secret-density"));
            }

            "--sink" => {
                let val = next_value(&mut it, "--sink");
                args.sink = match val.as_str() {
                    "null" => SinkKind::Null,
                    "stdout" => SinkKind::Stdout,
                    "file" => SinkKind::File,
                    _ => die(&format!(
                        "Unknown sink: '{}' (expected 'null', 'stdout', or 'file')",
                        val
                    )),
                };
            }

            "--sink-path" => {
                let val = next_value(&mut it, "--sink-path");
                args.sink_path = Some(PathBuf::from(val));
            }

            "--tasks" | "-t" => {
                let val = next_value(&mut it, "--tasks");
                let n: usize = parse_num(&val, "--tasks");
                if n == 0 {
                    die("--tasks must be >= 1");
                }
                args.tasks = Some(n);
            }

            "--work-ns" => {
                let val = next_value(&mut it, "--work-ns");
                args.work_ns = Some(parse_num(&val, "--work-ns"));
            }

            "--warmup" => {
                let val = next_value(&mut it, "--warmup");
                args.warmup = Some(parse_num(&val, "--warmup"));
            }

            "--iters" | "-i" => {
                let val = next_value(&mut it, "--iters");
                let n: usize = parse_num(&val, "--iters");
                if n == 0 {
                    die("--iters must be >= 1");
                }
                args.iters = Some(n);
            }

            "--pin-harness" => {
                let val = next_value(&mut it, "--pin-harness");
                args.pin_harness = Some(parse_num(&val, "--pin-harness"));
            }

            "--seed" | "-s" => {
                let val = next_value(&mut it, "--seed");
                args.seed = Some(parse_num(&val, "--seed"));
            }

            "--save-baseline" => {
                let val = next_value(&mut it, "--save-baseline");
                args.save_baseline = Some(PathBuf::from(val));
            }

            "--baseline" => {
                let val = next_value(&mut it, "--baseline");
                args.baseline = Some(PathBuf::from(val));
            }

            "--threshold" => {
                let val = next_value(&mut it, "--threshold");
                args.threshold = parse_num(&val, "--threshold");
            }

            other => die(&format!("Unknown argument: '{}'", other)),
        }
    }

    // Validate flag combinations
    validate_arg_combinations(&args);

    args
}

/// Validate that flags are appropriate for the selected benchmark type.
fn validate_arg_combinations(args: &Args) {
    match args.bench {
        BenchType::Local => {
            if args.tasks.is_some() {
                die("--tasks is only valid with --bench executor");
            }
            if args.work_ns.is_some() {
                die("--work-ns is only valid with --bench executor");
            }
            if args.sink_path.is_some() && args.sink != SinkKind::File {
                die("--sink-path is only valid with --sink file");
            }
        }
        BenchType::Executor => {
            if args.files.is_some() {
                die("--files is only valid with --bench local");
            }
            if args.file_size.is_some() {
                die("--file-size is only valid with --bench local");
            }
            if args.secret_density.is_some() {
                die("--secret-density is only valid with --bench local");
            }
            if args.sink != SinkKind::Null || args.sink_path.is_some() {
                die("--sink/--sink-path are only valid with --bench local");
            }
        }
    }
}

fn print_help() {
    println!(
        r#"Scheduler Benchmark CLI

USAGE:
    bench [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Verbose output
    --ci                    Output machine-parseable one-line summary
                            (separate from --preset ci which sets config)

BENCHMARK SELECTION:
    -b, --bench TYPE        Benchmark type: "local" (default) or "executor"
    -p, --preset PRESET     Configuration preset:
                            - default: Balanced settings (100 files, 64KiB)
                            - ci: Quick check (50 files, 4KiB, 3 iters)
                            - detailed: Thorough (1000 files, mixed sizes, 20 iters)
                            - stress: High load (10000 files)

LOCAL SCAN OPTIONS (--bench local only):
    -w, --workers N         Number of worker threads (1-256)
    -f, --files N           Number of synthetic files
    --file-size SIZE        File size (e.g., 64k, 1m, 2g)
    --secret-density N      Secrets per KB (e.g., 0.01 = ~10 secrets/MB)
    --sink TYPE             Output sink: null (default), stdout, file
    --sink-path PATH        Output file path (only with --sink file)

EXECUTOR OPTIONS (--bench executor only):
    -t, --tasks N           Number of tasks
    --work-ns N             Simulated work per task in nanoseconds

COMMON OPTIONS:
    --warmup N              Warmup iterations (not measured)
    -i, --iters N           Measured iterations (>= 1)
    --pin-harness N         Pin benchmark HARNESS thread to CPU core N
                            (Note: does NOT pin worker threads)
    -s, --seed N            Random seed for reproducibility

REGRESSION DETECTION:
    --baseline FILE         Compare against baseline (error if regression)
    --save-baseline FILE    Save results as baseline
    --threshold PCT         Regression threshold percentage (default: 5.0)

EXAMPLES:
    # Quick CI check
    bench --preset ci

    # Detailed local scan profiling with 4 workers
    bench --bench local --preset detailed --workers 4

    # Output-heavy scan to stress sink contention
    bench --bench local --files 1000 --file-size 64k --secret-density 0.05 --sink file

    # Executor microbenchmark
    bench --bench executor --tasks 1000000 --work-ns 100

    # Save baseline for regression detection
    bench --save-baseline baseline.txt

    # CI regression check (exits 1 on regression)
    bench --baseline baseline.txt --threshold 5 --ci

NOTE:
    --ci controls OUTPUT FORMAT (one-line summary)
    --preset ci controls CONFIG (fewer files, quick iterations)
    For CI pipelines, typically use BOTH: bench --preset ci --ci
"#
    );
}

// ============================================================================
// Output Sink Helpers
// ============================================================================

fn default_sink_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("scanner-bench-{}-{}.out", pid, nanos));
    path
}

fn build_output_sink(args: &Args) -> Arc<dyn OutputSink> {
    match args.sink {
        SinkKind::Null => Arc::new(NullSink::new()),
        SinkKind::Stdout => Arc::new(StdoutSink::new()),
        SinkKind::File => {
            let path = args.sink_path.clone().unwrap_or_else(default_sink_path);
            if args.verbose {
                eprintln!("Benchmark output sink: file {}", path.display());
            }
            let sink = FileSink::create(&path).unwrap_or_else(|e| {
                die(&format!(
                    "Failed to create sink file {}: {}",
                    path.display(),
                    e
                ))
            });
            Arc::new(sink)
        }
    }
}

// ============================================================================
// Default Engine
// ============================================================================

fn default_engine() -> MockEngine {
    MockEngine::new(
        vec![
            MockRule {
                name: "secret".into(),
                pattern: b"SECRET".to_vec(),
            },
            MockRule {
                name: "password".into(),
                pattern: b"PASSWORD".to_vec(),
            },
            MockRule {
                name: "api_key".into(),
                pattern: b"API_KEY".to_vec(),
            },
        ],
        32, // 32 byte overlap
    )
}

// ============================================================================
// Baseline Handling (shared between benchmarks)
// ============================================================================

/// Handle baseline comparison and saving for any benchmark.
///
/// # Exit Codes
///
/// - Exits with code 1 if a regression is detected (beyond threshold).
/// - Exits with code 1 if baseline file cannot be read or parsed.
/// - Does NOT exit on successful comparison or save.
///
/// # Side Effects
///
/// - Prints comparison summary to stdout (unless `--ci` mode).
/// - Writes baseline file if `--save-baseline` is specified.
fn handle_baseline(args: &Args, report: &BenchReport, bench_name: &str, config_fingerprint: &str) {
    // Compare against existing baseline
    if let Some(baseline_path) = &args.baseline {
        match std::fs::read_to_string(baseline_path) {
            Ok(content) => {
                match parse_simple_baseline(&content) {
                    Some(baseline) => {
                        // Warn if config fingerprint doesn't match
                        if let Some(stored_fp) = &baseline.config_fingerprint {
                            if stored_fp != config_fingerprint {
                                eprintln!(
                                    "WARNING: Baseline config differs from current run\n  Baseline: {}\n  Current:  {}",
                                    stored_fp, config_fingerprint
                                );
                            }
                        }

                        let baseline_report = baseline.to_synthetic_report();
                        let comparison = BenchComparison::new(&baseline_report, report);

                        if !args.ci {
                            println!("\n{}", comparison.summary(5.0));
                        }

                        if comparison.has_regression(args.threshold) {
                            if args.ci {
                                println!("{}", comparison.ci_summary());
                            }
                            eprintln!(
                                "\nâš ï¸  REGRESSION DETECTED (threshold: {}%)",
                                args.threshold
                            );
                            std::process::exit(1);
                        } else if !args.ci {
                            println!(
                                "âœ… No regression detected (threshold: {}%)",
                                args.threshold
                            );
                        }
                    }
                    None => {
                        eprintln!("Failed to parse baseline file: {}", baseline_path.display());
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to read baseline {}: {}", baseline_path.display(), e);
                std::process::exit(1);
            }
        }
    }

    // Save new baseline
    if let Some(save_path) = &args.save_baseline {
        let baseline =
            BenchBaselineExt::from_report_with_config(bench_name, report, config_fingerprint);
        let content = format_simple_baseline_ext(&baseline);
        if let Err(e) = std::fs::write(save_path, &content) {
            eprintln!("Failed to save baseline: {}", e);
            std::process::exit(1);
        }
        if !args.ci {
            println!("\nBaseline saved to: {}", save_path.display());
        }
    }
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args = parse_args();

    if args.help {
        print_help();
        return;
    }

    if !args.ci {
        println!("=== Scheduler Benchmark ===\n");
    }

    if args.verbose {
        eprintln!("Args: {:?}\n", args);
    }

    match args.bench {
        BenchType::Local => run_local_bench(&args),
        BenchType::Executor => run_executor_bench(&args),
    }
}

fn run_local_bench(args: &Args) {
    // Build synthetic config from preset
    let mut synthetic_config = match args.preset {
        Preset::Ci => SyntheticConfig::quick(),
        Preset::Detailed => SyntheticConfig::realistic(),
        Preset::Stress => SyntheticConfig::stress(),
        Preset::Default => SyntheticConfig::default(),
    };

    // Apply overrides
    if let Some(files) = args.files {
        synthetic_config.file_count = files;
    }
    if let Some(size) = args.file_size {
        synthetic_config.file_size = FileSizeDistribution::Fixed(size);
    }
    if let Some(seed) = args.seed {
        synthetic_config.seed = seed;
    }
    if let Some(density) = args.secret_density {
        synthetic_config.secret_density = density;
    }

    // Build local config
    let mut local_config = LocalConfig::default();
    if let Some(workers) = args.workers {
        local_config.workers = workers;
    }
    if let Some(seed) = args.seed {
        local_config.seed = seed;
    }

    // Build bench config
    let mut bench_config = match args.preset {
        Preset::Ci => BenchConfig::ci_quick(),
        Preset::Detailed => BenchConfig::detailed(),
        _ => BenchConfig::default(),
    };

    if let Some(warmup) = args.warmup {
        bench_config.warmup_iters = warmup;
    }
    if let Some(iters) = args.iters {
        bench_config.iters = iters;
    }
    bench_config.pin_core = args.pin_harness;

    // Create engine and benchmark
    let engine = Arc::new(default_engine());
    let output_sink = build_output_sink(args);

    if args.verbose {
        eprintln!(
            "Generating {} synthetic files...",
            synthetic_config.file_count
        );
    }

    let mut bench = match LocalScanBenchmark::new_with_output_sink(
        Arc::clone(&engine),
        synthetic_config.clone(),
        local_config.clone(),
        output_sink,
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to create benchmark: {}", e);
            std::process::exit(1);
        }
    };

    if !args.ci {
        println!("{}", bench.description());
        println!(
            "Generated {} files ({} bytes) in {}ms\n",
            bench.synthetic_stats().files_generated,
            bench.synthetic_stats().bytes_written,
            bench.synthetic_stats().generation_ms,
        );
    }

    // Run benchmark
    let report = run_benchmark(&mut bench, bench_config.clone());

    // Output results
    if args.ci {
        println!("{}", report.summary());
    } else {
        println!("{}", report.detailed());
    }

    // Config fingerprint for baseline comparison
    let config_fingerprint = format!(
        "local:workers={},files={},file_size={:?},chunk={},seed={},density={},sink={}",
        local_config.workers,
        synthetic_config.file_count,
        synthetic_config.file_size,
        local_config.chunk_size,
        local_config.seed,
        synthetic_config.secret_density,
        args.sink,
    );

    handle_baseline(args, &report, "local_scan", &config_fingerprint);
}

fn run_executor_bench(args: &Args) {
    // Build executor config from preset
    let mut config = match args.preset {
        Preset::Ci => ExecutorMicrobenchConfig {
            task_count: 10_000,
            work_ns: 0,
            workers: 2,
            ..Default::default()
        },
        Preset::Detailed => ExecutorMicrobenchConfig::typical(),
        Preset::Stress => ExecutorMicrobenchConfig::steal_stress(),
        Preset::Default => ExecutorMicrobenchConfig::default(),
    };

    // Apply overrides
    if let Some(tasks) = args.tasks {
        config.task_count = tasks;
    }
    if let Some(work) = args.work_ns {
        config.work_ns = work;
    }
    if let Some(workers) = args.workers {
        config.workers = workers;
    }
    if let Some(seed) = args.seed {
        config.seed = seed;
    }

    // Build bench config
    let mut bench_config = match args.preset {
        Preset::Ci => BenchConfig::ci_quick(),
        Preset::Detailed => BenchConfig::detailed(),
        _ => BenchConfig::default(),
    };

    if let Some(warmup) = args.warmup {
        bench_config.warmup_iters = warmup;
    }
    if let Some(iters) = args.iters {
        bench_config.iters = iters;
    }
    bench_config.pin_core = args.pin_harness;

    // Create and run benchmark
    let mut bench = ExecutorMicrobench::new(config.clone());

    if !args.ci {
        println!("{}\n", bench.description());
    }

    let report = run_benchmark(&mut bench, bench_config.clone());

    // Output results
    if args.ci {
        println!("{}", report.summary());
    } else {
        println!("{}", report.detailed());

        // Executor-specific metrics from first iteration
        if !report.iterations.is_empty() {
            let total_tasks: u64 = report.iterations.iter().map(|i| i.files).sum();
            let total_wall_secs: f64 = report
                .iterations
                .iter()
                .map(|i| i.wall_time.as_secs_f64())
                .sum();

            println!(
                "\nExecutor Metrics (across {} iterations):",
                report.iterations.len()
            );
            println!("  Total tasks: {}", total_tasks);
            if total_wall_secs > 0.0 {
                println!(
                    "  Avg tasks/sec: {:.0}",
                    total_tasks as f64 / total_wall_secs
                );
            }
        }
    }

    // Config fingerprint for baseline comparison
    let config_fingerprint = format!(
        "executor:workers={},tasks={},work_ns={},seed={}",
        config.workers, config.task_count, config.work_ns, config.seed,
    );

    handle_baseline(args, &report, "executor_microbench", &config_fingerprint);
}

// ============================================================================
// Extended Baseline Format (with config fingerprint)
// ============================================================================

/// Extended baseline with config fingerprint.
#[derive(Clone, Debug)]
struct BenchBaselineExt {
    inner: BenchBaseline,
    config_fingerprint: Option<String>,
}

impl BenchBaselineExt {
    fn from_report_with_config(name: &str, report: &BenchReport, config: &str) -> Self {
        Self {
            inner: BenchBaseline::from_report(name, report),
            config_fingerprint: Some(config.to_string()),
        }
    }
}

fn format_simple_baseline_ext(b: &BenchBaselineExt) -> String {
    let mut s = format!(
        "name={}\n\
         throughput_mibs={:.4}\n\
         p50_ns={}\n\
         p95_ns={}\n\
         p99_ns={}\n\
         peak_rss_bytes={}\n\
         cpu_utilization={:.6}\n\
         iters={}\n\
         timestamp={}\n\
         git_commit={}\n",
        b.inner.name,
        b.inner.throughput_mibs,
        b.inner.p50_ns,
        b.inner.p95_ns,
        b.inner.p99_ns,
        b.inner.peak_rss_bytes,
        b.inner.cpu_utilization,
        b.inner.iters,
        b.inner.timestamp,
        b.inner.git_commit.as_deref().unwrap_or("unknown"),
    );

    if let Some(fp) = &b.config_fingerprint {
        s.push_str(&format!("config={}\n", fp));
    }

    s
}

/// Extended baseline parsed from file.
///
/// Contains all metrics needed to reconstruct a synthetic `BenchReport`
/// for comparison against a current run.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ParsedBaseline {
    name: String,
    throughput_mibs: f64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    peak_rss_bytes: u64,
    cpu_utilization: f64,
    iters: usize,
    timestamp: String,
    git_commit: Option<String>,
    config_fingerprint: Option<String>,
}

impl ParsedBaseline {
    fn to_synthetic_report(&self) -> BenchReport {
        use scanner_rs::scheduler::bench::BenchIter;
        use scanner_rs::scheduler::rusage::ProcUsageDelta;
        use std::time::Duration;

        let cpu_time_ns = (self.p50_ns as f64 * self.cpu_utilization) as u64;
        let iter = BenchIter {
            wall_time: Duration::from_nanos(self.p50_ns),
            cpu_usage: ProcUsageDelta {
                user_time: Duration::from_nanos(cpu_time_ns),
                sys_time: Duration::ZERO,
                ending_max_rss_bytes: self.peak_rss_bytes,
            },
            files: 0,
            bytes: (self.throughput_mibs * 1024.0 * 1024.0 * (self.p50_ns as f64 / 1_000_000_000.0))
                as u64,
            findings: 0,
            errors: 0,
        };

        BenchReport::from_iterations(vec![iter], BenchConfig::default())
    }
}

/// Parse a baseline file in simple key=value format.
///
/// # Expected Format
///
/// ```text
/// name=benchmark_name
/// throughput_mibs=123.4567
/// p50_ns=1234567
/// p95_ns=2345678
/// p99_ns=3456789
/// peak_rss_bytes=104857600
/// cpu_utilization=3.870000
/// iters=5
/// timestamp=1234567890
/// git_commit=abc123... (or "unknown")
/// config=local:workers=4,files=100 (optional)
/// ```
///
/// # Validation
///
/// Returns `None` if:
/// - `name` is empty
/// - `throughput_mibs` is negative or NaN
/// - `iters` is 0
/// - Percentiles are not monotonic (p50 > p95 or p95 > p99)
fn parse_simple_baseline(content: &str) -> Option<ParsedBaseline> {
    let mut name = String::new();
    let mut throughput_mibs: f64 = 0.0;
    let mut p50_ns = 0u64;
    let mut p95_ns = 0u64;
    let mut p99_ns = 0u64;
    let mut peak_rss_bytes = 0u64;
    let mut cpu_utilization = 0.0;
    let mut iters = 0usize;
    let mut timestamp = String::new();
    let mut git_commit = None;
    let mut config_fingerprint = None;

    for line in content.lines() {
        if let Some((key, val)) = line.split_once('=') {
            match key.trim() {
                "name" => name = val.trim().to_string(),
                "throughput_mibs" => throughput_mibs = val.trim().parse().unwrap_or(0.0),
                "p50_ns" => p50_ns = val.trim().parse().unwrap_or(0),
                "p95_ns" => p95_ns = val.trim().parse().unwrap_or(0),
                "p99_ns" => p99_ns = val.trim().parse().unwrap_or(0),
                "peak_rss_bytes" => peak_rss_bytes = val.trim().parse().unwrap_or(0),
                "cpu_utilization" => cpu_utilization = val.trim().parse().unwrap_or(0.0),
                "iters" => iters = val.trim().parse().unwrap_or(0),
                "timestamp" => timestamp = val.trim().to_string(),
                "git_commit" => {
                    let v = val.trim();
                    if v != "unknown" {
                        git_commit = Some(v.to_string());
                    }
                }
                "config" => {
                    config_fingerprint = Some(val.trim().to_string());
                }
                _ => {}
            }
        }
    }

    // Validate required fields
    if name.is_empty() {
        return None;
    }
    if throughput_mibs < 0.0 || throughput_mibs.is_nan() {
        return None;
    }
    if iters == 0 {
        return None;
    }
    // Percentiles should be monotonic (allow equal for edge cases)
    if p50_ns > p95_ns || p95_ns > p99_ns {
        return None;
    }

    Some(ParsedBaseline {
        name,
        throughput_mibs,
        p50_ns,
        p95_ns,
        p99_ns,
        peak_rss_bytes,
        cpu_utilization,
        iters,
        timestamp,
        git_commit,
        config_fingerprint,
    })
}
