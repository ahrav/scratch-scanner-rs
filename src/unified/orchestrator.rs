//! Top-level scan orchestration.
//!
//! Dispatches to the appropriate source driver based on the parsed
//! CLI configuration:
//!
//! - **FS** → connector pipeline (`scan_connector`) when `connector-pipeline`
//!   feature is enabled, otherwise falls back to `parallel_scan_dir`
//! - **Git** → [`run_git_scan`] (pack execution, tree diffs, loose scan)
//!
//! Both paths share a common [`EventSink`](super::events::EventSink) for
//! structured output to stdout (format selected via `--event-format`),
//! and emit a `Summary` event at completion. Human-readable stats are
//! also written to stderr for backward-compatible machine parsing.
//!
//! # Lifecycle
//!
//! 1. Load rules (`--rules` override → executable-dir YAML → compiled-in fallback).
//! 2. Apply `--transforms` filter and build the detection [`Engine`].
//! 3. Construct the [`EventSink`] for the selected output format.
//! 4. Run the source driver (FS or Git), which emits `Finding` /
//!    `Progress` events through the sink.
//! 5. Emit a final `Summary` event and call `sink.flush()`.
//!
//! # Output Contract
//!
//! - Structured events are written to stdout via [`EventSink`].
//! - Human-readable and machine-parseable `key=value` summaries are written
//!   to stderr on successful FS/Git scans for backward-compatible tooling.
//! - Fatal configuration failures exit with status code `2`.
//!
//! # Rule Source Invariants
//!
//! - At most one rule source is chosen per run, using a strict precedence order.
//! - The executable-dir default candidate is selected only when a probe confirms
//!   that it exists on disk.
//! - Probe failures for the executable-dir default emit a warning and fall back
//!   to built-in rules.
//! - Built-in fallback remains available even when path discovery fails, so startup
//!   never depends on host filesystem layout.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::api::RuleSpec;
use crate::git_scan::{
    self, run_git_scan, GitScanConfig, GitScanResult, InMemoryPersistenceStore, NeverSeenStore,
    StartSetConfig,
};
use crate::scheduler::local_fs_owner::LocalReport;
#[cfg(feature = "connector-pipeline")]
use crate::scheduler::local_fs_owner::LocalStats;
use crate::store::StoreProducer as _;
use crate::{demo_rules, demo_transforms, demo_tuning, AnchorMode, AnchorPolicy, Engine};

use super::cli::TransformFilter;
use super::source::git::{EmptyWatermarkStore, GitCliResolver};
use super::{
    EventFormat, FsScanConfig, GitSourceConfig, OutputFormat, ScanConfig, SourceConfig,
    StoreCommand,
};

#[cfg(feature = "connector-pipeline")]
use gossip_contracts::connector::Cursor;
#[cfg(feature = "connector-pipeline")]
use gossip_contracts::coordination::ShardSpec;

/// Run a scan using the unified configuration.
///
/// This is the single entry point called by `main()`. It builds the
/// detection engine, selects the source driver, and runs the scan.
///
/// # Exit behavior
///
/// Sub-functions may call `std::process::exit(2)` on fatal configuration
/// errors (rule loading, overflow of CLI size params). This function itself
/// returns `io::Result` for normal I/O failures.
pub fn run(config: ScanConfig) -> io::Result<()> {
    let event_format = config.event_format;
    let verbose = config.verbose;
    let null_sink = config.null_sink;
    let rules_file = config.rules_file;
    let transform_filter = config.transform_filter;
    match config.source {
        SourceConfig::Fs(fs_cfg) => run_fs(
            fs_cfg,
            event_format,
            verbose,
            null_sink,
            rules_file,
            &transform_filter,
        ),
        SourceConfig::Git(git_cfg) => run_git(
            git_cfg,
            event_format,
            verbose,
            null_sink,
            rules_file,
            &transform_filter,
        ),
        SourceConfig::Store(cmd) => run_store_command(cmd),
    }
}

/// In-memory-only progress tracker for local filesystem scans.
///
/// Provides no crash-recovery: a failed scan restarts from scratch.
/// When persistence support is re-added to the connector pipeline,
/// this will be replaced by a backend-backed implementation.
#[cfg(feature = "connector-pipeline")]
#[derive(Debug)]
struct FsProgressState {
    shard: ShardSpec,
    cursor: Cursor,
}

#[cfg(feature = "connector-pipeline")]
impl FsProgressState {
    fn new() -> Self {
        Self {
            shard: ShardSpec::unbounded(),
            cursor: Cursor::initial(),
        }
    }
}

#[cfg(feature = "connector-pipeline")]
impl crate::scheduler::ProgressSink for FsProgressState {
    type Error = io::Error;

    fn shard_spec(&self) -> &ShardSpec {
        &self.shard
    }

    fn cursor(&self) -> Cursor {
        self.cursor.clone()
    }

    fn checkpoint(&mut self, cursor: &Cursor) -> Result<(), Self::Error> {
        self.cursor = cursor.clone();
        Ok(())
    }

    fn complete(&mut self, final_cursor: &Cursor) -> Result<(), Self::Error> {
        self.cursor = final_cursor.clone();
        Ok(())
    }

    /// No-op: local filesystem scans have no durable state to park.
    fn park(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// No-op: single-shard local scans do not use split hints.
    fn split_hint(
        &mut self,
        _key: &gossip_contracts::connector::ItemKey,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(feature = "connector-pipeline")]
fn run_fs_connector(
    engine: Arc<Engine>,
    cfg: &FsScanConfig,
    event_sink: Arc<dyn super::events::EventSink>,
) -> io::Result<LocalReport> {
    if cfg.persist_findings {
        return Err(io::Error::other(
            "filesystem persistence is not yet supported in connector pipeline mode",
        ));
    }

    let source_cfg = SourceConfig::Fs(cfg.clone());
    let mut connector = super::source::factory::build_connector(&source_cfg)?;

    let connector_cfg = crate::scheduler::ConnectorConfig {
        cpu_workers: cfg.workers.max(1),
        split_hint_budgets: None,
        ..Default::default()
    };

    let mut progress = FsProgressState::new();
    let (connector_report, metrics) = crate::scheduler::scan_connector(
        engine,
        connector.as_mut(),
        connector_cfg,
        &mut progress,
        event_sink,
    )
    .map_err(|err| {
        use crate::scheduler::ConnectorRunError;
        let category = match &err {
            ConnectorRunError::Config(_) => "configuration",
            ConnectorRunError::Enumerate(_) => "enumeration",
            ConnectorRunError::PageValidation(_) => "page validation",
            ConnectorRunError::Progress(_) => "progress",
            ConnectorRunError::Dispatch(_) => "dispatch",
            ConnectorRunError::PageIdOverflow => "runtime",
            ConnectorRunError::BudgetExceeded { .. } => "budget",
            ConnectorRunError::FileIdOverflow => "runtime",
        };
        io::Error::other(format!("filesystem connector {category} error: {err}"))
    })?;

    Ok(LocalReport {
        stats: LocalStats {
            files_enqueued: connector_report.enumerate.items_discovered,
            bytes_enqueued: metrics.bytes_scanned,
            io_errors: metrics.io_errors,
            dropped_findings: metrics.findings_dropped,
            persistence_emit_failures: metrics.persistence_emit_failures,
            persistence_incomplete: false,
        },
        metrics,
    })
}

/// Fallback when the connector-pipeline feature is not compiled in.
///
/// Delegates to [`parallel_scan_dir`](crate::scheduler::parallel_scan::parallel_scan_dir)
/// which provides the same scanning behaviour through the work-stealing
/// executor.  This keeps FS scans functional for default builds without
/// requiring the Gossip-rs path dependencies.
///
/// When `persist_findings` is enabled, wires a [`SqliteStoreProducer`] into
/// the scan config and finalizes the run after scanning completes.
#[cfg(not(feature = "connector-pipeline"))]
fn run_fs_connector(
    engine: Arc<Engine>,
    cfg: &FsScanConfig,
    event_sink: Arc<dyn super::events::EventSink>,
) -> io::Result<LocalReport> {
    use crate::scheduler::parallel_scan::{parallel_scan_dir, ParallelScanConfig};

    let producer = if cfg.persist_findings {
        Some(open_fs_store_producer(&cfg.root)?)
    } else {
        None
    };

    let mut scan_cfg = ParallelScanConfig {
        workers: cfg.workers.max(1),
        // Match the connector pipeline's discovery defaults:
        // scan hidden files and ignore .gitignore rules so the
        // fallback produces the same file set as the connector path.
        skip_hidden: false,
        respect_gitignore: false,
        skip_binary: !cfg.scan_binary,
        event_sink,
        store_producer: producer
            .clone()
            .map(|p| p as Arc<dyn crate::store::StoreProducer>),
        ..Default::default()
    };

    if cfg.skip_archives {
        scan_cfg.archive.enabled = false;
    }

    let report = parallel_scan_dir(&cfg.root, engine, scan_cfg)?;

    if let Some(ref p) = producer {
        let had_limits =
            report.stats.dropped_findings > 0 || report.stats.persistence_emit_failures > 0;
        if let Err(e) = p.end_run(had_limits) {
            eprintln!("warn: persistence finalization failed: {}", e.detail());
        }
    }

    Ok(report)
}

/// Create a [`SqliteStoreProducer`] rooted at `<scan_root>/.scanner-store/findings.db`.
///
/// Derives a deterministic root identity from the scan root's canonical path
/// so that repeat scans of the same directory share identity records.
fn open_fs_store_producer(
    scan_root: &Path,
) -> io::Result<Arc<crate::store::db::writer::SqliteStoreProducer>> {
    use crate::store::db::writer::{SqliteStoreConfig, SqliteStoreProducer};
    use crate::store::keys::StoreKeys;
    use crate::store::root_id::{self, RootIdInput, RootKind};

    let keys = StoreKeys::bootstrap_from_env();
    let canonical = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: canonical.as_os_str().as_encoded_bytes(),
        },
        &keys,
    );

    let db_path = scan_root.join(".scanner-store").join("findings.db");
    let config = SqliteStoreConfig {
        db_path,
        root_id,
        root_kind: RootKind::Fs,
        identity_scheme: "fs_path_v1".to_string(),
        canonical_identity: canonical.as_os_str().as_encoded_bytes().to_vec(),
        display_name: Some(canonical.display().to_string()),
        id_hash_mode: keys.id_hash_mode(),
        scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };

    SqliteStoreProducer::open(config)
        .map(Arc::new)
        .map_err(|e| io::Error::other(format!("cannot open persistence store: {}", e.detail())))
}

/// Filesystem scan path.
///
/// Delegates to [`run_fs_connector`] which uses the connector pipeline when
/// the `connector-pipeline` feature is enabled, or falls back to
/// [`parallel_scan_dir`](crate::scheduler::parallel_scan::parallel_scan_dir).
/// Findings are emitted as structured events to stdout via the
/// [`EventSink`](super::events::EventSink) (format per `--event-format`).
/// Summary stats are written to stderr.
fn run_fs(
    cfg: FsScanConfig,
    event_format: EventFormat,
    verbose: bool,
    null_sink: bool,
    rules_file: Option<PathBuf>,
    transform_filter: &TransformFilter,
) -> io::Result<()> {
    use super::events::{ScanEvent, SummaryEvent};
    use super::SourceKind;

    let t0 = Instant::now();
    let rules = load_rules_for_scan(rules_file.as_deref());
    let transforms = apply_transform_filter(demo_transforms(), transform_filter);
    let mut tuning = demo_tuning();
    if let Some(depth) = cfg.decode_depth {
        tuning.max_transform_depth = depth;
    }
    let policy = match cfg.anchor_mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    let engine = Arc::new(Engine::new_with_anchor_policy(
        rules, transforms, tuning, policy,
    ));
    let init_elapsed = t0.elapsed();

    let scan_start = Instant::now();

    // Structured event sink: findings to stdout (format per --event-format),
    // or null sink for overhead measurement.
    let event_sink: Arc<dyn super::events::EventSink> = if null_sink {
        eprintln!("info: --null-sink enabled; findings will not be written to stdout");
        Arc::new(super::events::NullEventSink)
    } else {
        build_event_sink(event_format, verbose)
    };

    let report = run_fs_connector(Arc::clone(&engine), &cfg, Arc::clone(&event_sink))?;

    let scan_elapsed = scan_start.elapsed();
    let total_elapsed = t0.elapsed();
    let scan_secs = scan_elapsed.as_secs_f64();
    let throughput_mib = if scan_secs > 0.0 {
        (report.metrics.bytes_scanned as f64 / (1024.0 * 1024.0)) / scan_secs
    } else {
        0.0
    };
    let status = if report.stats.persistence_incomplete {
        "partial"
    } else {
        "complete"
    };

    // Emit structured summary event.
    event_sink.emit(ScanEvent::Summary(SummaryEvent {
        source: SourceKind::Fs,
        status,
        elapsed_ms: scan_elapsed.as_millis() as u64,
        bytes_scanned: report.metrics.bytes_scanned,
        findings_emitted: report.metrics.findings_emitted,
        errors: report.stats.io_errors,
        throughput_mib_s: throughput_mib,
    }));
    event_sink.flush();

    // Also write machine-readable stats to stderr for compatibility.
    let scanned_human = format_human_bytes(report.metrics.bytes_scanned);
    eprintln!(
        "files={}\nchunks={}\nbytes={} ({})\nfindings={}\nerrors={}\ndropped_findings={}\npersist_emit_failures={}\npersist_incomplete={}\nbinary_skipped={}\next_skipped={}\nlock_skipped={}\nbinary_extracted={}\ninit_ms={}\nscan_ms={}\npersist_ms={}\nelapsed_ms={}\nthroughput_mib_s={:.2}\nworkers={}",
        report.stats.files_enqueued,
        report.metrics.chunks_scanned,
        report.metrics.bytes_scanned,
        scanned_human,
        report.metrics.findings_emitted,
        report.stats.io_errors,
        report.stats.dropped_findings,
        report.stats.persistence_emit_failures,
        report.stats.persistence_incomplete,
        report.metrics.binary_skipped,
        report.metrics.ext_skipped,
        report.metrics.lock_skipped,
        report.metrics.binary_extracted,
        init_elapsed.as_millis(),
        scan_elapsed.as_millis(),
        report.metrics.persist_ns / 1_000_000,
        total_elapsed.as_millis(),
        throughput_mib,
        cfg.workers,
    );

    Ok(())
}

/// Parse `in-pack` object count from `git count-objects -v` output.
///
/// Accepts surrounding whitespace and returns the first `in-pack:` entry.
/// Returns `None` when the field is missing or not a valid `u64`.
fn parse_in_pack_object_count(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("in-pack:")?;
        rest.trim().parse::<u64>().ok()
    })
}

/// Return `in-pack` object count for the repository.
///
/// This probe is advisory and used only for worker auto-sizing. Callers
/// should fall back to deterministic defaults when it fails.
///
/// # Errors
///
/// Returns an error when `git` invocation fails, exits non-zero, or the
/// expected `in-pack:` field is absent.
fn probe_in_pack_object_count(repo_root: &Path) -> io::Result<u64> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["count-objects", "-v"])
        .output()
        .map_err(|e| io::Error::other(format!("failed to run git count-objects: {e}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git count-objects failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_in_pack_object_count(&stdout)
        .ok_or_else(|| io::Error::other("missing in-pack entry in git count-objects output"))
}

/// Git scan path — delegates to [`run_git_scan`].
///
/// Builds the engine, configures persistence stores (in-memory for CLI),
/// resolves the start set via `git` CLI commands, and runs the scan.
/// Findings stream through the [`EventSink`](super::events::EventSink);
/// summary + optional debug/perf output goes to stderr.
///
/// `pack_exec_workers` is auto-sized from `git count-objects -v` when the
/// CLI does not provide an explicit value; probe failures fall back to the
/// static defaults from [`GitScanConfig::default`].
///
/// Calls `process::exit(2)` on fatal errors (rule loading, config overflow,
/// scan failure) rather than returning an error, matching the CLI exit-code
/// convention.
fn run_git(
    cfg: GitSourceConfig,
    event_format: EventFormat,
    verbose: bool,
    null_sink: bool,
    rules_file: Option<PathBuf>,
    transform_filter: &TransformFilter,
) -> io::Result<()> {
    let t0 = Instant::now();
    let rules = load_rules_for_scan(rules_file.as_deref());
    let transforms = apply_transform_filter(demo_transforms(), transform_filter);
    let mut tuning = demo_tuning();
    if let Some(depth) = cfg.decode_depth {
        tuning.max_transform_depth = depth;
    }

    let base_config = GitScanConfig::default();
    let tree_delta_cache_bytes = cfg.tree_delta_cache_mb.map(|mb| {
        let bytes = mb as u64 * 1024 * 1024;
        if bytes > u64::from(u32::MAX) {
            eprintln!("--x-tree-delta-cache-mb exceeds max bytes for this build");
            std::process::exit(2);
        }
        bytes as u32
    });
    let engine_chunk_bytes = cfg.engine_chunk_mb.map(|mb| {
        let bytes = mb as u64 * 1024 * 1024;
        if bytes > u64::from(u32::MAX) {
            eprintln!("--x-engine-chunk-mb exceeds max chunk size");
            std::process::exit(2);
        }
        bytes as usize
    });

    let policy = git_scan::policy_hash(&rules, &transforms, &tuning, cfg.merge_mode);

    let engine = Arc::new(match cfg.anchor_mode {
        AnchorMode::Manual => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::ManualOnly)
        }
        AnchorMode::Derived => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::DerivedOnly)
        }
    });

    let event_sink: Arc<dyn super::events::EventSink> = if null_sink {
        eprintln!("info: --null-sink enabled; findings will not be written to stdout");
        Arc::new(super::events::NullEventSink)
    } else {
        build_event_sink(event_format, verbose)
    };

    let start_set = StartSetConfig::DefaultBranchOnly;
    let resolver = GitCliResolver::new(cfg.repo_root.clone(), start_set.clone());
    let seen_store = NeverSeenStore;
    let watermark_store = EmptyWatermarkStore;
    let persist_store = InMemoryPersistenceStore::default();
    let pack_exec_workers = cfg.pack_exec_workers.unwrap_or_else(|| {
        probe_in_pack_object_count(&cfg.repo_root)
            .ok()
            .map(git_scan::auto_pack_exec_workers_for_in_pack)
            .unwrap_or(base_config.pack_exec_workers)
    });

    let mut config = GitScanConfig {
        scan_mode: cfg.scan_mode,
        repo_id: cfg.repo_id,
        merge_diff_mode: cfg.merge_mode,
        start_set: start_set.clone(),
        policy_hash: policy,
        pack_exec_workers,
        ..base_config
    };
    if let Some(bytes) = tree_delta_cache_bytes {
        config.tree_diff.max_tree_delta_cache_bytes = bytes;
    }
    if let Some(bytes) = engine_chunk_bytes {
        config.engine_adapter.chunk_bytes = bytes;
    }
    if cfg.scan_binary {
        config.engine_adapter.scan_binary = true;
    }
    config.enrich_identities = cfg.enrich_identities;

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
            let scan_elapsed = scan_start.elapsed();
            let total_elapsed = t0.elapsed();
            emit_git_summary_event(&*event_sink, &report, scan_elapsed);
            event_sink.flush();
            print_git_stderr_summary(&report, &config, scan_elapsed, total_elapsed);
            print_git_report(&report, &config, cfg.debug);
            Ok(())
        }
        Err(err) => {
            eprintln!("git scan failed: {err}");
            std::process::exit(2);
        }
    }
}

/// Execute a store query command (list-runs, list-findings, diff, list-secrets).
///
/// Opens the SQLite database in read-only mode and dispatches to the
/// appropriate query function from [`crate::store::db::query`].
fn run_store_command(cmd: StoreCommand) -> io::Result<()> {
    use crate::store::db::query;
    use crate::store::db::schema::configure_readonly_connection;
    use rusqlite::{Connection, OpenFlags};

    let open_db = |path: &std::path::Path| -> io::Result<Connection> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| io::Error::other(format!("failed to open store: {e}")))?;
        configure_readonly_connection(&conn)
            .map_err(|e| io::Error::other(format!("failed to configure connection: {e}")))?;
        Ok(conn)
    };

    match cmd {
        StoreCommand::ListRuns {
            store_dir,
            status,
            limit,
            format,
        } => {
            let conn = open_db(&store_dir.join("findings.db"))?;
            let runs = query::list_runs(&conn, status, limit)
                .map_err(|e| io::Error::other(format!("query failed: {e}")))?;

            match format {
                OutputFormat::Json => {
                    let rows: Vec<_> = runs
                        .iter()
                        .map(|run| {
                            serde_json::json!({
                                "run_id": run.run_id_hex,
                                "root": run.root_display,
                                "started_at": run.started_at,
                                "ended_at": run.ended_at,
                                "status": run.status,
                                "findings": run.findings_emitted,
                                "objects": run.objects_scanned,
                            })
                        })
                        .collect();
                    print_json(&rows)?;
                }
                OutputFormat::Text => {
                    if runs.is_empty() {
                        println!("No runs found.");
                    } else {
                        println!(
                            "{:<36} {:<8} {:<15} {:<10} ROOT",
                            "RUN ID", "STATUS", "STARTED", "FINDINGS"
                        );
                        for run in &runs {
                            let status_str = status_label(run.status);
                            let root = run.root_display.as_deref().unwrap_or("-");
                            println!(
                                "{:<36} {:<8} {:<15} {:<10} {}",
                                &run.run_id_hex[..run.run_id_hex.len().min(36)],
                                status_str,
                                run.started_at,
                                run.findings_emitted,
                                root,
                            );
                        }
                    }
                }
            }
        }

        StoreCommand::ListFindings {
            store_dir,
            run,
            rule,
            path,
            limit,
            format,
        } => {
            let conn = open_db(&store_dir.join("findings.db"))?;
            let run_pk = query::resolve_run_pk(&conn, &run)
                .map_err(|e| io::Error::other(format!("query failed: {e}")))?
                .ok_or_else(|| io::Error::other(format!("run not found: {run}")))?;

            let findings =
                query::list_findings(&conn, run_pk, rule.as_deref(), path.as_deref(), limit)
                    .map_err(|e| io::Error::other(format!("query failed: {e}")))?;

            match format {
                OutputFormat::Json => {
                    let rows: Vec<_> = findings
                        .iter()
                        .map(|f| {
                            serde_json::json!({
                                "occurrence_id": f.occurrence_id_hex,
                                "path": f.object_path,
                                "rule": f.rule_name,
                                "start": f.start_byte,
                                "end": f.end_byte,
                                "secret_hash": f.secret_hash_hex,
                            })
                        })
                        .collect();
                    print_json(&rows)?;
                }
                OutputFormat::Text => {
                    if findings.is_empty() {
                        println!("No findings for run {run}.");
                    } else {
                        println!("{} findings for run {}:", findings.len(), &run);
                        for f in &findings {
                            println!(
                                "  {} {}:{}-{} [{}]",
                                f.rule_name,
                                f.object_path,
                                f.start_byte,
                                f.end_byte,
                                &f.secret_hash_hex[..16],
                            );
                        }
                    }
                }
            }
        }

        StoreCommand::Diff {
            store_dir,
            run_a,
            run_b,
            format,
        } => {
            let conn = open_db(&store_dir.join("findings.db"))?;
            let pk_a = query::resolve_run_pk(&conn, &run_a)
                .map_err(|e| io::Error::other(format!("query failed: {e}")))?
                .ok_or_else(|| io::Error::other(format!("run A not found: {run_a}")))?;
            let pk_b = query::resolve_run_pk(&conn, &run_b)
                .map_err(|e| io::Error::other(format!("query failed: {e}")))?
                .ok_or_else(|| io::Error::other(format!("run B not found: {run_b}")))?;

            let diff = query::diff_runs(&conn, pk_a, pk_b, None)
                .map_err(|e| io::Error::other(format!("query failed: {e}")))?;

            match format {
                OutputFormat::Json => {
                    let payload = serde_json::json!({
                        "new_count": diff.new_findings.len(),
                        "resolved_count": diff.resolved_findings.len(),
                        "unchanged_count": diff.unchanged_count,
                    });
                    print_json(&payload)?;
                }
                OutputFormat::Text => {
                    println!(
                        "Diff: {} new, {} resolved, {} unchanged",
                        diff.new_findings.len(),
                        diff.resolved_findings.len(),
                        diff.unchanged_count,
                    );
                    if !diff.new_findings.is_empty() {
                        println!("\nNew findings:");
                        for f in &diff.new_findings {
                            println!(
                                "  + {} {}:{}-{}",
                                f.rule_name, f.object_path, f.start_byte, f.end_byte
                            );
                        }
                    }
                    if !diff.resolved_findings.is_empty() {
                        println!("\nResolved findings:");
                        for f in &diff.resolved_findings {
                            println!(
                                "  - {} {}:{}-{}",
                                f.rule_name, f.object_path, f.start_byte, f.end_byte
                            );
                        }
                    }
                }
            }
        }

        StoreCommand::ListSecrets {
            store_dir,
            status,
            limit,
            format,
        } => {
            let conn = open_db(&store_dir.join("findings.db"))?;
            let secrets = query::list_secrets(&conn, status, limit)
                .map_err(|e| io::Error::other(format!("query failed: {e}")))?;

            match format {
                OutputFormat::Json => {
                    let rows: Vec<_> = secrets
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "secret_hash": s.secret_hash_hex,
                                "occurrences": s.occurrence_count,
                                "first_seen": s.first_seen_run,
                                "last_seen": s.last_seen_run,
                                "status": s.status,
                            })
                        })
                        .collect();
                    print_json(&rows)?;
                }
                OutputFormat::Text => {
                    if secrets.is_empty() {
                        println!("No secrets found.");
                    } else {
                        println!(
                            "{:<36} {:<12} {:<8} FIRST SEEN",
                            "SECRET HASH", "OCCURRENCES", "STATUS"
                        );
                        for s in &secrets {
                            println!(
                                "{:<36} {:<12} {:<8} {}",
                                &s.secret_hash_hex[..s.secret_hash_hex.len().min(36)],
                                s.occurrence_count,
                                status_label(s.status),
                                s.first_seen_run,
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Map a persisted run/secret status code to a human-readable label.
///
/// Values mirror store schema query outputs. Unknown values map to
/// `"unknown"` for forward compatibility with newer schema versions.
fn status_label(status: i32) -> &'static str {
    match status {
        0 => "active",
        1 => "complete",
        2 => "limited",
        3 => "incomplete",
        4 => "failed",
        _ => "unknown",
    }
}

/// Serialize a value as a single-line JSON document to stdout.
///
/// # Errors
///
/// Returns an error if serialization fails.
fn print_json<T: serde::Serialize>(value: &T) -> io::Result<()> {
    let encoded = serde_json::to_string(value)
        .map_err(|e| io::Error::other(format!("json encode failed: {e}")))?;
    println!("{encoded}");
    Ok(())
}

/// Print git scan results to stderr based on the selected [`DebugLevel`].
///
/// Called only on successful scans. Output is gated by `debug_level` so the
/// default output is clean.
///
/// - [`DebugLevel::Off`]: no debug output.
/// - [`DebugLevel::Stats`]: verbose stage stats (`--debug`).
/// - [`DebugLevel::Perf`]: stage stats **and** pack execution timing
///   breakdown (`--debug=perf`).
#[cfg_attr(not(feature = "git-perf"), allow(unused_variables))]
fn print_git_report(
    report: &git_scan::GitScanReport,
    config: &GitScanConfig,
    debug_level: super::DebugLevel,
) {
    use super::DebugLevel;
    match debug_level {
        DebugLevel::Off => {}
        DebugLevel::Stats => {
            print_git_debug(report);
        }
        DebugLevel::Perf => {
            print_git_debug(report);
            #[cfg(feature = "git-perf")]
            print_git_perf_breakdown(report, config);
        }
    }
}

/// Construct the [`EventSink`] for the requested output format.
///
/// All sinks write to stdout. The `verbose` flag only affects the
/// [`TextEventSink`](super::text_sink::TextEventSink) (compact vs verbose).
fn build_event_sink(event_format: EventFormat, verbose: bool) -> Arc<dyn super::events::EventSink> {
    match event_format {
        EventFormat::Jsonl => Arc::new(super::events::JsonlEventSink::new(io::stdout())),
        EventFormat::Text => Arc::new(super::text_sink::TextEventSink::new(io::stdout(), verbose)),
        EventFormat::Json => Arc::new(super::json_sink::JsonEventSink::new(io::stdout())),
        EventFormat::Sarif => Arc::new(super::sarif_sink::SarifEventSink::new(io::stdout())),
    }
}

/// Emit a structured `ScanEvent::Summary` for the completed git scan.
///
/// Maps `FinalizeOutcome::Complete` to status `"complete"` (0 errors) and
/// `Partial` to `"partial"` (with the skipped-candidate count as errors).
/// Throughput is computed from always-on `common_metrics.bytes_scanned`.
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
    let bytes_scanned = report.common_metrics.bytes_scanned;
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
        findings_emitted: report.common_metrics.findings_emitted,
        errors: errors as u64,
        throughput_mib_s,
    }));
}

/// Print a machine-readable `key=value` summary block to stderr for git scans.
///
/// Always called on successful scans (not gated by `--debug`), matching the
/// FS scan path which always emits a comparable line. Field order is stable
/// for scripted parsing. Fields use git-specific names where the FS equivalent
/// doesn't apply (e.g. `objects` instead of `files`).
fn print_git_stderr_summary(
    report: &git_scan::GitScanReport,
    config: &GitScanConfig,
    scan_elapsed: std::time::Duration,
    total_elapsed: std::time::Duration,
) {
    let common = &report.common_metrics;
    let errors = match report.finalize.outcome {
        git_scan::FinalizeOutcome::Complete => 0u64,
        git_scan::FinalizeOutcome::Partial { skipped_count } => skipped_count as u64,
    };
    let scan_secs = scan_elapsed.as_secs_f64();
    let throughput_mib = if scan_secs > 0.0 {
        (common.bytes_scanned as f64 / (1024.0 * 1024.0)) / scan_secs
    } else {
        0.0
    };
    let init_ms = total_elapsed.saturating_sub(scan_elapsed).as_millis();
    let scanned_human = format_human_bytes(common.bytes_scanned);
    eprintln!(
        "objects={}\nchunks={}\nbytes={} ({})\nfindings={}\nerrors={}\nbinary_skipped={}\next_skipped={}\nlock_skipped={}\nbinary_extracted={}\ninit_ms={}\nscan_ms={}\nelapsed_ms={}\nthroughput_mib_s={:.2}\nworkers={}",
        common.objects_scanned,
        common.chunks_scanned,
        common.bytes_scanned,
        scanned_human,
        common.findings_emitted,
        errors,
        common.binary_skipped,
        common.ext_skipped,
        common.lock_skipped,
        common.binary_extracted,
        init_ms,
        scan_elapsed.as_millis(),
        total_elapsed.as_millis(),
        throughput_mib,
        config.pack_exec_workers,
    );
}

/// Format byte counts using binary IEC units (KiB, MiB, GiB, ...).
///
/// This keeps stderr summaries human-readable without losing the raw byte
/// count emitted in the adjacent `bytes=<raw>` field.
fn format_human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes}B");
    }

    let mut value = bytes as f64;
    let mut unit_idx = 0usize;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    format!("{value:.2}{}", UNITS[unit_idx])
}

/// Dump verbose internal stats to stderr (commit counts, tree diff, pack plan, cache rejects).
///
/// Emits one `key=value` or `key={:?}` line per stat. Includes a sample of
/// up to 5 skipped candidates for post-mortem diagnosis. Format is
/// intentionally unstructured — use `--event-format jsonl` for machine
/// consumption and reserve this output for human debugging.
///
/// `report.format_metrics()` always emits the same key set; in non-`git-perf`
/// builds perf-derived values are zero.
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
#[cfg(feature = "git-perf")]
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
    let binary_extract = perf.scan_binary_extract_count;
    eprintln!(
        "  chunker_bypass: {} ({:.1}%)  binary_skip: {}  binary_extract: {}  prefilter_bypass: {} ({:.1}%)",
        bypass, bypass_pct, binary_skip, binary_extract, prefilter_bypass, prefilter_bypass_pct
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

/// Retain only the transforms selected by the CLI `--transforms` flag.
///
/// Filtering happens *before* engine construction. In the git scan path
/// this is also before policy hashing, so disabling a transform correctly
/// invalidates the incremental-scan cache key.
fn apply_transform_filter(
    transforms: Vec<crate::api::TransformConfig>,
    filter: &TransformFilter,
) -> Vec<crate::api::TransformConfig> {
    match filter {
        TransformFilter::All => transforms,
        TransformFilter::None => Vec::new(),
        TransformFilter::Only(ref ids) => transforms
            .into_iter()
            .filter(|t| ids.contains(&t.id))
            .collect(),
    }
}

/// Load rules from a YAML file, falling back to the compiled-in set.
///
/// Fallback chain:
/// `--rules` override > `default_rules.yaml` next to binary > compiled-in fallback.
///
/// This helper exits the process with code `2` on read/parse failures because
/// rule configuration errors are treated as fatal startup misconfiguration.
/// Provenance and a deterministic fast content fingerprint are emitted for diagnostics.
///
/// Resolved provenance for the rule set selected for a scan.
///
/// # Invariants
/// - `Explicit` stores the CLI-provided path as-is; existence/readability are
///   validated by the loader.
/// - `DefaultCandidate` is selected only when probing confirms the exe-adjacent file exists.
/// - `BuiltInFallback` is used when no on-disk candidate was found.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RuleSource {
    Explicit(PathBuf),
    DefaultCandidate(PathBuf),
    BuiltInFallback,
}

impl RuleSource {
    #[inline]
    const fn source_label(&self) -> &'static str {
        match self {
            Self::Explicit(_) => "explicit",
            Self::DefaultCandidate(_) => "default",
            Self::BuiltInFallback => "built-in",
        }
    }
}

/// Resolve which rule source to use according to precedence.
///
/// Explicit `--rules` paths are accepted without existence checks so downstream
/// loader diagnostics can report precise read/parse failures. The exe-adjacent
/// default is accepted only if `try_exists()` confirms the file is present;
/// probe failures emit a warning before falling back to the built-in set.
fn resolve_rule_source(rules_file: Option<&Path>, default_path: Option<&Path>) -> RuleSource {
    if let Some(path) = rules_file {
        return RuleSource::Explicit(path.to_path_buf());
    }
    if let Some(path) = default_path {
        match path.try_exists() {
            Ok(true) => return RuleSource::DefaultCandidate(path.to_path_buf()),
            Ok(false) => {}
            Err(err) => {
                eprintln!("warning: failed to probe {}: {err}", path.display());
            }
        }
    }
    RuleSource::BuiltInFallback
}

/// Load and parse rules from `path`, returning `(rules, hash)`.
///
/// The file is read once up front to compute a provenance hash and parsed from
/// that same in-memory content to avoid hash/parse skew. Any failure exits the
/// process with code `2`.
fn load_rules_from_path(path: &Path, source: &RuleSource) -> (Vec<RuleSpec>, u64) {
    let content = match crate::rules::read_rules_text(path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("error: failed to read rules from {}: {e}", path.display());
            std::process::exit(2);
        }
    };
    let hash = crate::rules::rules_content_hash64(content.as_bytes());
    match crate::rules::load_rules_from_content(&content) {
        Ok(rules) => {
            eprintln!(
                "info: loaded {} rules from {} (source: {}, rule_hash: {hash:016x})",
                rules.len(),
                path.display(),
                source.source_label()
            );
            (rules, hash)
        }
        Err(e) => {
            eprintln!("error: failed to load rules from {}: {e}", path.display());
            std::process::exit(2);
        }
    }
}

/// Load the rule set for a scan run with deterministic fallback precedence.
///
/// # Selection order
/// 1. `--rules` explicit path
/// 2. `default_rules.yaml` next to the executable
/// 3. Compile-time embedded fallback (`default_rules.yaml`)
///
/// # Effects
/// - Emits provenance logs (source label and deterministic fast hash fingerprint).
/// - Exits with status `2` if a selected on-disk source (explicit or
///   default candidate) cannot be read/parsed.
fn load_rules_for_scan(rules_file: Option<&Path>) -> Vec<RuleSpec> {
    let default_path = crate::rules::default_rules_path();
    let source = resolve_rule_source(rules_file, default_path.as_deref());
    match &source {
        RuleSource::Explicit(path) | RuleSource::DefaultCandidate(path) => {
            let (rules, _) = load_rules_from_path(path, &source);
            rules
        }
        RuleSource::BuiltInFallback => {
            let rules = demo_rules();
            let built_in_hash = crate::rules::builtin_rules_hash64();
            eprintln!("info: no default_rules.yaml next to binary; using compiled-in rules");
            eprintln!(
                "info: using compiled-in rule set ({} rules, source: {}, rule_hash: {built_in_hash:016x})",
                rules.len(),
                source.source_label()
            );
            rules
        }
    }
}

#[cfg(test)]
#[path = "orchestrator_tests.rs"]
mod tests;
