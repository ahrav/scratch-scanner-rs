//! Top-level scan orchestration.
//!
//! Dispatches to the appropriate source driver based on the parsed
//! CLI configuration:
//!
//! - **FS** → [`parallel_scan_dir`] (work-stealing executor, streaming directory walk)
//! - **Git** → [`run_git_scan`] (pack execution, tree diffs, loose scan)
//!
//! Both paths share a common [`EventSink`](super::events::EventSink) for
//! structured JSONL output to stdout, and emit a summary event at completion.
//! Human-readable stats go to stderr.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use crate::git_scan::{
    self, run_git_scan, GitScanConfig, GitScanResult, InMemoryPersistenceStore, NeverSeenStore,
    StartSetConfig,
};
use crate::scheduler::{parallel_scan_dir, ParallelScanConfig};
use crate::{
    demo_engine_with_anchor_mode, demo_engine_with_anchor_mode_and_max_transform_depth, demo_rules,
    demo_transforms, demo_tuning, AnchorMode, AnchorPolicy, Engine,
};

use super::source::git::{EmptyWatermarkStore, GitCliResolver};
use super::{EventFormat, FsScanConfig, GitSourceConfig, ScanConfig, SourceConfig};

/// Run a scan using the unified configuration.
///
/// This is the single entry point called by `main()`. It builds the
/// detection engine, selects the source driver, and runs the scan.
pub fn run(config: ScanConfig) -> io::Result<()> {
    let event_format = config.event_format;
    match config.source {
        SourceConfig::Fs(fs_cfg) => run_fs(fs_cfg, event_format),
        SourceConfig::Git(git_cfg) => run_git(git_cfg, event_format),
    }
}

/// Filesystem scan path — delegates to `parallel_scan_dir`.
///
/// Findings are emitted as structured JSONL events to stdout via the
/// [`EventSink`]. Summary stats are written to stderr.
fn run_fs(cfg: FsScanConfig, event_format: EventFormat) -> io::Result<()> {
    use super::events::{ScanEvent, SummaryEvent};
    use super::SourceKind;

    let t0 = Instant::now();
    let engine = Arc::new(build_engine(cfg.anchor_mode, cfg.decode_depth));
    let init_elapsed = t0.elapsed();

    let scan_start = Instant::now();

    // Structured event sink: JSONL findings to stdout, or null sink for diagnostics.
    let event_sink: Arc<dyn super::events::EventSink> = if cfg.null_sink {
        Arc::new(super::events::NullEventSink)
    } else {
        build_event_sink(event_format)
    };

    let mut ps_config = ParallelScanConfig {
        workers: cfg.workers,
        skip_hidden: false,
        respect_gitignore: false,
        event_sink: Arc::clone(&event_sink),
        ..Default::default()
    };
    if cfg.no_archives {
        ps_config.archive.enabled = false;
    }
    let report = parallel_scan_dir(&cfg.root, engine, ps_config)?;

    let scan_elapsed = scan_start.elapsed();
    let total_elapsed = t0.elapsed();
    let scan_secs = scan_elapsed.as_secs_f64();
    let throughput_mib = if scan_secs > 0.0 {
        (report.metrics.bytes_scanned as f64 / (1024.0 * 1024.0)) / scan_secs
    } else {
        0.0
    };

    // Emit structured summary event.
    event_sink.emit(ScanEvent::Summary(SummaryEvent {
        source: SourceKind::Fs,
        status: "complete",
        elapsed_ms: scan_elapsed.as_millis() as u64,
        bytes_scanned: report.metrics.bytes_scanned,
        findings_emitted: report.metrics.findings_emitted,
        errors: report.stats.io_errors,
        throughput_mib_s: throughput_mib,
    }));
    event_sink.flush();

    // Also write machine-readable stats to stderr for compatibility.
    eprintln!(
        "files={} chunks={} bytes={} findings={} errors={} init_ms={} scan_ms={} elapsed_ms={} throughput_mib_s={:.2} workers={}",
        report.stats.files_enqueued,
        report.metrics.chunks_scanned,
        report.metrics.bytes_scanned,
        report.metrics.findings_emitted,
        report.stats.io_errors,
        init_elapsed.as_millis(),
        scan_elapsed.as_millis(),
        total_elapsed.as_millis(),
        throughput_mib,
        cfg.workers,
    );

    Ok(())
}

/// Git scan path — delegates to `run_git_scan`.
///
/// Builds the engine, configures persistence stores (in-memory for CLI),
/// resolves the start set via `git` CLI commands, and runs the scan.
/// Findings stream through the [`EventSink`](super::events::EventSink);
/// summary + optional debug/perf output goes to stderr.
fn run_git(cfg: GitSourceConfig, event_format: EventFormat) -> io::Result<()> {
    let rules = demo_rules();
    let transforms = demo_transforms();
    let mut tuning = demo_tuning();
    if let Some(depth) = cfg.decode_depth {
        tuning.max_transform_depth = depth;
    }

    let base_config = GitScanConfig::default();
    let tree_delta_cache_bytes = cfg.tree_delta_cache_mb.map(|mb| {
        let bytes = mb as u64 * 1024 * 1024;
        if bytes > u64::from(u32::MAX) {
            eprintln!("--tree-delta-cache-mb exceeds max bytes for this build");
            std::process::exit(2);
        }
        bytes as u32
    });
    let engine_chunk_bytes = cfg.engine_chunk_mb.map(|mb| {
        let bytes = mb as u64 * 1024 * 1024;
        if bytes > u64::from(u32::MAX) {
            eprintln!("--engine-chunk-mb exceeds max chunk size");
            std::process::exit(2);
        }
        bytes as usize
    });

    let policy = git_scan::policy_hash(
        &rules,
        &transforms,
        &tuning,
        cfg.merge_mode,
        base_config.path_policy_version,
    );

    let engine = Arc::new(match cfg.anchor_mode {
        AnchorMode::Manual => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::ManualOnly)
        }
        AnchorMode::Derived => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::DerivedOnly)
        }
    });

    let event_sink = build_event_sink(event_format);

    let start_set = StartSetConfig::DefaultBranchOnly;
    let resolver = GitCliResolver::new(cfg.repo_root.clone(), start_set.clone());
    let seen_store = NeverSeenStore;
    let watermark_store = EmptyWatermarkStore;
    let persist_store = InMemoryPersistenceStore::default();

    let mut config = GitScanConfig {
        scan_mode: cfg.scan_mode,
        repo_id: cfg.repo_id,
        merge_diff_mode: cfg.merge_mode,
        start_set: start_set.clone(),
        policy_hash: policy,
        pack_exec_workers: cfg
            .pack_exec_workers
            .unwrap_or(base_config.pack_exec_workers),
        ..base_config
    };
    if let Some(bytes) = tree_delta_cache_bytes {
        config.tree_diff.max_tree_delta_cache_bytes = bytes;
    }
    if let Some(bytes) = engine_chunk_bytes {
        config.engine_adapter.chunk_bytes = bytes;
    }

    let scan_start = Instant::now();
    match run_git_scan(
        &cfg.repo_root,
        Arc::clone(&engine),
        &resolver,
        &seen_store,
        &watermark_store,
        Some(&persist_store),
        &config,
        Arc::clone(&event_sink),
    ) {
        Ok(GitScanResult(report)) => {
            emit_git_summary_event(&*event_sink, &report, scan_start.elapsed());
            event_sink.flush();
            print_git_report(&report, &config, cfg.debug, cfg.perf_breakdown);
            Ok(())
        }
        Err(err) => {
            eprintln!("git scan failed: {err}");
            std::process::exit(2);
        }
    }
}

/// Print git scan results to stderr (debug stats and/or perf breakdown).
fn print_git_report(
    report: &git_scan::GitScanReport,
    config: &GitScanConfig,
    debug: bool,
    perf_breakdown: bool,
) {
    if debug {
        print_git_debug(report);
    }
    if perf_breakdown {
        print_git_perf_breakdown(report, config);
    }
}

/// Construct the [`EventSink`] for the requested output format.
fn build_event_sink(event_format: EventFormat) -> Arc<dyn super::events::EventSink> {
    match event_format {
        EventFormat::Jsonl => Arc::new(super::events::JsonlEventSink::new(io::stdout())),
    }
}

/// Emit a structured `ScanEvent::Summary` for the completed git scan.
fn emit_git_summary_event(
    event_sink: &dyn super::events::EventSink,
    report: &git_scan::GitScanReport,
    elapsed: std::time::Duration,
) {
    use super::events::{ScanEvent, SummaryEvent};
    use super::SourceKind;

    let (status, errors) = match report.finalize.outcome {
        git_scan::FinalizeOutcome::Complete => ("complete", 0),
        git_scan::FinalizeOutcome::Partial { skipped_count } => ("partial", skipped_count),
    };
    let elapsed_secs = elapsed.as_secs_f64();
    let bytes_scanned = report.perf_stats.scan_bytes;
    let throughput_mib_s = if elapsed_secs > 0.0 {
        (bytes_scanned as f64 / (1024.0 * 1024.0)) / elapsed_secs
    } else {
        0.0
    };

    event_sink.emit(ScanEvent::Summary(SummaryEvent {
        source: SourceKind::Git,
        status,
        elapsed_ms: elapsed.as_millis() as u64,
        bytes_scanned,
        findings_emitted: report.finalize.stats.total_findings,
        errors: errors as u64,
        throughput_mib_s,
    }));
}

/// Dump verbose internal stats to stderr (commit counts, tree diff, pack plan, cache rejects).
fn print_git_debug(report: &git_scan::GitScanReport) {
    eprintln!("commits={}", report.commit_count);
    eprintln!("tree_diff_stats={:?}", report.tree_diff_stats);
    eprintln!("spill_stats={:?}", report.spill_stats);
    eprintln!("mapping_stats={:?}", report.mapping_stats);
    eprintln!("pack_plan_stats={:?}", report.pack_plan_stats);
    eprintln!("pack_plan_config={:?}", report.pack_plan_config);
    eprintln!(
        "pack_plan_delta_deps_total={}",
        report.pack_plan_delta_deps_total
    );
    eprintln!(
        "pack_plan_delta_deps_max={}",
        report.pack_plan_delta_deps_max
    );
    let pack_exec_stats: Vec<_> = report.pack_exec_reports.iter().map(|r| &r.stats).collect();
    let pack_exec_skips: usize = report.pack_exec_reports.iter().map(|r| r.skips.len()).sum();
    let cache_reject_hist = git_scan::aggregate_cache_reject_histogram(&report.pack_exec_reports);
    eprintln!("pack_exec_stats={:?}", pack_exec_stats);
    eprintln!("pack_exec_skips={}", pack_exec_skips);
    let mut skipped_by_reason: BTreeMap<&'static str, usize> = BTreeMap::new();
    for skip in &report.skipped_candidates {
        *skipped_by_reason.entry(skip.reason.as_str()).or_default() += 1;
    }
    eprintln!("skipped_by_reason={:?}", skipped_by_reason);
    if !report.skipped_candidates.is_empty() {
        let sample: Vec<_> = report.skipped_candidates.iter().take(5).collect();
        eprintln!("skipped_sample={:?}", sample);
    }
    eprintln!("cache_reject_bytes_total={}", cache_reject_hist.bytes_total);
    eprintln!("cache_reject_bytes_max={}", cache_reject_hist.bytes_max);
    eprintln!("cache_reject_histogram={:?}", cache_reject_hist.buckets);
    eprintln!(
        "cache_reject_histogram_top={}",
        cache_reject_hist.format_top(5)
    );
    eprintln!("{}", report.format_metrics());
}

/// Print a hierarchical timing breakdown of pack execution to stderr.
///
/// Shows decode, cache lookup, fallback resolve, and scan sub-stage
/// percentages relative to total pack_exec wall time.
fn print_git_perf_breakdown(report: &git_scan::GitScanReport, config: &GitScanConfig) {
    let mut total_cache_lookup_nanos = 0u64;
    let mut total_fallback_resolve_nanos = 0u64;
    let mut total_sink_emit_nanos = 0u64;
    let mut total_base_cache_hits = 0u64;
    let mut total_base_cache_misses = 0u64;
    let mut total_fallback_decodes = 0u64;
    let mut total_decoded_offsets = 0u64;

    for r in &report.pack_exec_reports {
        total_cache_lookup_nanos += r.stats.cache_lookup_nanos;
        total_fallback_resolve_nanos += r.stats.fallback_resolve_nanos;
        total_sink_emit_nanos += r.stats.sink_emit_nanos;
        total_base_cache_hits += r.stats.base_cache_hits as u64;
        total_base_cache_misses += r.stats.base_cache_misses as u64;
        total_fallback_decodes += r.stats.fallback_base_decodes as u64;
        total_decoded_offsets += r.stats.decoded_offsets as u64;
    }

    let perf = &report.perf_stats;
    let decode_nanos = perf.pack_inflate_nanos + perf.delta_apply_nanos;
    let total_nanos = report.stage_nanos.pack_exec;

    let pct = |n: u64| -> f64 {
        if total_nanos > 0 {
            (n as f64 / total_nanos as f64) * 100.0
        } else {
            0.0
        }
    };
    let secs = |n: u64| -> f64 { n as f64 / 1_000_000_000.0 };

    eprintln!("\npack_exec breakdown:");
    eprintln!(
        "  decode: {:.1}% ({:.3}s)",
        pct(decode_nanos),
        secs(decode_nanos)
    );
    eprintln!(
        "  cache_lookup: {:.1}% ({:.3}s)",
        pct(total_cache_lookup_nanos),
        secs(total_cache_lookup_nanos)
    );
    eprintln!(
        "  fallback_resolve: {:.1}% ({:.3}s)",
        pct(total_fallback_resolve_nanos),
        secs(total_fallback_resolve_nanos)
    );
    eprintln!(
        "  sink_emit: {:.1}% ({:.3}s)",
        pct(total_sink_emit_nanos),
        secs(total_sink_emit_nanos)
    );

    let total_base_lookups = total_base_cache_hits + total_base_cache_misses;
    let base_cache_hit_rate = if total_base_lookups > 0 {
        (total_base_cache_hits as f64 / total_base_lookups as f64) * 100.0
    } else {
        0.0
    };
    let fallback_rate = if total_decoded_offsets > 0 {
        (total_fallback_decodes as f64 / total_decoded_offsets as f64) * 100.0
    } else {
        0.0
    };

    eprintln!("\ncache efficiency:");
    eprintln!(
        "  base_cache_hit_rate: {:.1}% ({}/{})",
        base_cache_hit_rate, total_base_cache_hits, total_base_lookups
    );
    eprintln!("  fallback_rate: {:.1}%", fallback_rate);

    // Scan sub-stage breakdown.
    let vs_pre = perf.scan_vs_prefilter_nanos;
    let validate = perf.scan_validate_nanos;
    let transform = perf.scan_transform_nanos;
    let reset = perf.scan_reset_nanos;
    let sort_dedup = perf.scan_sort_dedup_nanos;
    let accounted = vs_pre + validate + transform + reset + sort_dedup;
    let scan_total = perf.scan_nanos;
    let other = scan_total.saturating_sub(accounted);

    let scan_pct = |n: u64| -> f64 {
        if scan_total > 0 {
            (n as f64 / scan_total as f64) * 100.0
        } else {
            0.0
        }
    };

    eprintln!("\nscan breakdown (within sink_emit):");
    eprintln!(
        "  vs_prefilter:  {:.1}% ({:.3}s)",
        scan_pct(vs_pre),
        secs(vs_pre)
    );
    eprintln!(
        "  validate:      {:.1}% ({:.3}s)",
        scan_pct(validate),
        secs(validate)
    );
    eprintln!(
        "  transform:     {:.1}% ({:.3}s)",
        scan_pct(transform),
        secs(transform)
    );
    eprintln!(
        "  reset:         {:.1}% ({:.3}s)",
        scan_pct(reset),
        secs(reset)
    );
    eprintln!(
        "  sort_dedup:    {:.1}% ({:.3}s)",
        scan_pct(sort_dedup),
        secs(sort_dedup)
    );
    eprintln!(
        "  other:         {:.1}% ({:.3}s)",
        scan_pct(other),
        secs(other)
    );

    let blobs = perf.scan_blob_count;
    let chunks = perf.scan_chunk_count;
    let zero_hit = perf.scan_zero_hit_chunks;
    let findings = perf.scan_findings_count;
    let zero_pct = if chunks > 0 {
        (zero_hit as f64 / chunks as f64) * 100.0
    } else {
        0.0
    };
    let bypass = perf.scan_chunker_bypass_count;
    let binary_skip = perf.scan_binary_skip_count;
    let bypass_pct = if blobs > 0 {
        (bypass as f64 / blobs as f64) * 100.0
    } else {
        0.0
    };
    eprintln!("scan stats:");
    eprintln!(
        "  blobs: {}  chunks: {}  zero_hit_chunks: {} ({:.1}%)  findings: {}",
        blobs, chunks, zero_hit, zero_pct, findings
    );
    let prefilter_bypass = perf.scan_prefilter_bypass_count;
    let prefilter_bypass_pct = if chunks > 0 {
        (prefilter_bypass as f64 / chunks as f64) * 100.0
    } else {
        0.0
    };
    eprintln!(
        "  chunker_bypass: {} ({:.1}%)  binary_skip: {}  prefilter_bypass: {} ({:.1}%)",
        bypass, bypass_pct, binary_skip, prefilter_bypass, prefilter_bypass_pct
    );

    // Cache configuration.
    let workers = config.pack_exec_workers;
    let budget = report.pack_cache_per_worker_bytes;
    let total_cache = budget.saturating_mul(workers);
    eprintln!("\ncache config:");
    eprintln!("  budget_per_worker: {} MiB", budget / (1024 * 1024));
    eprintln!("  workers: {}", workers);
    eprintln!("  total_cache_memory: {} MiB", total_cache / (1024 * 1024));
    eprintln!("  large_slot: 2 MiB");
    eprintln!("  small_slot: 64 KiB");

    // Cache reject histogram.
    let cache_reject_hist = git_scan::aggregate_cache_reject_histogram(&report.pack_exec_reports);
    eprintln!("\ncache rejects:");
    eprintln!("  total_rejects: {}", cache_reject_hist.rejects);
    eprintln!(
        "  reject_bytes_total: {} KiB",
        cache_reject_hist.bytes_total / 1024
    );
    eprintln!(
        "  reject_bytes_max: {} KiB",
        cache_reject_hist.bytes_max / 1024
    );
    eprintln!("  top_buckets: {}", cache_reject_hist.format_top(5));
}

/// Build the detection engine with the given anchor mode and optional decode depth.
///
/// Uses the built-in demo rules, transforms, and tuning defaults.
/// If `decode_depth` is `Some`, it overrides the default max transform
/// depth (number of Base64 / URL-decode passes the engine will attempt).
fn build_engine(anchor_mode: AnchorMode, decode_depth: Option<usize>) -> Engine {
    match decode_depth {
        Some(depth) => demo_engine_with_anchor_mode_and_max_transform_depth(anchor_mode, depth),
        None => demo_engine_with_anchor_mode(anchor_mode),
    }
}
