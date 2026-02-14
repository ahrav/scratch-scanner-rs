//! Human-readable text event sink.
//!
//! Writes findings and summaries in a compact one-liner format (default)
//! or a multi-line verbose block. Progress events are suppressed in compact
//! mode and shown only in verbose mode. Diagnostic events always go to
//! **stderr** (not the main writer) regardless of mode.
//!
//! # Routing summary
//!
//! | Event | Compact mode | Verbose mode |
//! |------------|---------------------|-------------------------------|
//! | Finding | `{path}:{start}-{end}  {rule}  ({source})` | Multi-line block with all fields |
//! | Progress | suppressed | `[progress] …` |
//! | Summary | `[summary] …` | `[summary] …` |
//! | Diagnostic | stderr (always) | stderr (always) |
//! | CommitMeta | suppressed | `[commit_meta] id={} oid={} ts={}` |
//! | IdentityDictionary | suppressed | suppressed |

use std::io::{self, BufWriter, ErrorKind, Write};
use std::sync::Mutex;

use super::events::{
    CommitMetaEvent, DiagnosticEvent, EventSink, FindingEvent, ProgressEvent, ScanEvent,
    SummaryEvent,
};
use super::SourceKind;

/// Default buffer size (64 KiB) for buffered text emission.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// Human-readable text sink with compact and verbose modes.
///
/// Thread-safe: the internal `BufWriter` is guarded by a [`Mutex`], so
/// multiple worker threads may call [`EventSink::emit`] concurrently.
/// The mutex is held while formatting directly into the `BufWriter`, unlike
/// [`JsonlEventSink`](super::events::JsonlEventSink) which formats outside
/// the lock. This is acceptable because text output is a low-throughput
/// debug path — the JSONL sink is the production-grade choice.
///
/// # Error contract
///
/// `BrokenPipe` is silently swallowed (downstream consumer hung up).
/// Any other I/O error panics — a scan must not silently lose findings.
pub struct TextEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    verbose: bool,
}

impl<W: Write + Send> TextEventSink<W> {
    pub fn new(writer: W, verbose: bool) -> Self {
        Self {
            writer: Mutex::new(BufWriter::with_capacity(DEFAULT_BUF_CAPACITY, writer)),
            verbose,
        }
    }
}

impl<W: Write + Send + 'static> EventSink for TextEventSink<W> {
    fn emit(&self, event: ScanEvent<'_>) {
        match event {
            ScanEvent::Finding(ref f) => {
                let mut w = self.writer.lock().expect("text sink mutex poisoned");
                let res = if self.verbose {
                    write_finding_verbose(f, &mut *w)
                } else {
                    write_finding_compact(f, &mut *w)
                };
                handle_write_error(res);
            }
            ScanEvent::Progress(ref p) => {
                if self.verbose {
                    let mut w = self.writer.lock().expect("text sink mutex poisoned");
                    handle_write_error(write_progress(p, &mut *w));
                }
                // Compact mode: suppress progress events.
            }
            ScanEvent::Summary(ref s) => {
                let mut w = self.writer.lock().expect("text sink mutex poisoned");
                handle_write_error(write_summary(s, &mut *w));
            }
            ScanEvent::Diagnostic(ref d) => {
                // Diagnostics always go to stderr, not the main writer.
                write_diagnostic(d);
            }
            ScanEvent::CommitMeta(ref m) => {
                if self.verbose {
                    let mut w = self.writer.lock().expect("text sink mutex poisoned");
                    handle_write_error(write_commit_meta(m, &mut *w));
                }
                // Compact mode: suppress commit_meta events.
            }
            ScanEvent::IdentityDictionary(_) => {
                // Identity dictionary entries are consumed by JSONL sinks;
                // the human-readable text sink silently drops them.
            }
        }
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("text sink mutex poisoned");
        handle_write_error(writer.flush());
    }
}

/// Swallow `BrokenPipe`; panic on any other I/O error.
///
/// All text-sink write paths funnel through this so the error policy is
/// defined in exactly one place.
fn handle_write_error(result: io::Result<()>) {
    if let Err(e) = result {
        if e.kind() == ErrorKind::BrokenPipe {
            return;
        }
        panic!("text event sink write failed: {e}");
    }
}

/// Write `[{level}] {message}` to stderr. Best-effort: errors are ignored
/// because losing a diagnostic is acceptable, unlike losing a finding.
fn write_diagnostic(d: &DiagnosticEvent<'_>) {
    let _ = writeln!(std::io::stderr(), "[{}] {}", d.level, d.message);
}

fn lossy_path(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

fn source_label(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::Fs => "fs",
        SourceKind::Git => "git",
    }
}

/// Compact: `{path}:{start}-{end}  {rule_name}  ({source})`
fn write_finding_compact(f: &FindingEvent<'_>, w: &mut impl Write) -> io::Result<()> {
    writeln!(
        w,
        "{}:{}-{}  {}  ({})",
        lossy_path(f.object_path),
        f.start,
        f.end,
        f.rule_name,
        source_label(f.source),
    )
}

/// Verbose multi-line block with all available fields.
///
/// ```text
/// --- finding ---
///   rule:   {rule_name}
///   path:   {object_path}
///   range:  {start}-{end}
///   source: {fs|git}
///   commit: {commit_id}     // Git findings only
///   change: {change_kind}   // Git findings only
/// ```
fn write_finding_verbose(f: &FindingEvent<'_>, w: &mut impl Write) -> io::Result<()> {
    w.write_all(b"--- finding ---\n")?;
    writeln!(w, "  rule:   {}", f.rule_name)?;
    writeln!(w, "  path:   {}", lossy_path(f.object_path))?;
    writeln!(w, "  range:  {}-{}", f.start, f.end)?;
    writeln!(w, "  source: {}", source_label(f.source))?;
    if let Some(cid) = f.commit_id {
        writeln!(w, "  commit: {}", cid)?;
    }
    if let Some(ck) = f.change_kind {
        writeln!(w, "  change: {}", ck)?;
    }
    Ok(())
}

/// `[progress] {source} | {stage} | objects={n} bytes={n} findings={n}`
fn write_progress(p: &ProgressEvent, w: &mut impl Write) -> io::Result<()> {
    writeln!(
        w,
        "[progress] {} | {} | objects={} bytes={} findings={}",
        source_label(p.source),
        p.stage,
        p.objects_scanned,
        p.bytes_scanned,
        p.findings_emitted,
    )
}

/// `[summary] {source} | {status} | elapsed={ms}ms bytes={n} findings={n} errors={n} throughput={x.xx} MiB/s`
fn write_summary(s: &SummaryEvent, w: &mut impl Write) -> io::Result<()> {
    writeln!(
        w,
        "[summary] {} | {} | elapsed={}ms bytes={} findings={} errors={} throughput={:.2} MiB/s",
        source_label(s.source),
        s.status,
        s.elapsed_ms,
        s.bytes_scanned,
        s.findings_emitted,
        s.errors,
        s.throughput_mib_s,
    )
}

/// Verbose: `[commit_meta] id={commit_id} oid={hex} ts={timestamp}`
///
/// The OID is emitted as lowercase hex. `as_slice()` returns 20 bytes for
/// SHA-1 or 32 bytes for SHA-256, so the hex string is 40 or 64 chars
/// respectively — no branching required.
fn write_commit_meta(m: &CommitMetaEvent, w: &mut impl Write) -> io::Result<()> {
    write!(w, "[commit_meta] id={} oid=", m.commit_id)?;
    for &b in m.commit_oid.as_slice() {
        write!(w, "{b:02x}")?;
    }
    writeln!(w, " ts={}", m.timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified::events::ScanEvent;

    fn collect_text(event: ScanEvent<'_>, verbose: bool) -> String {
        let buf = Vec::new();
        let sink = TextEventSink::new(buf, verbose);
        sink.emit(event);
        sink.flush();
        let writer = sink.writer.lock().unwrap();
        String::from_utf8(writer.get_ref().clone()).unwrap()
    }

    #[test]
    fn compact_finding() {
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"src/main.rs",
                start: 42,
                end: 80,
                rule_id: 7,
                rule_name: "aws-access-key",
                commit_id: None,
                change_kind: None,
            }),
            false,
        );
        assert_eq!(out, "src/main.rs:42-80  aws-access-key  (fs)\n");
    }

    #[test]
    fn verbose_finding() {
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Git,
                object_path: b"config/.env",
                start: 0,
                end: 40,
                rule_id: 3,
                rule_name: "generic-secret",
                commit_id: Some(12),
                change_kind: Some("add"),
            }),
            true,
        );
        assert!(out.contains("--- finding ---"));
        assert!(out.contains("rule:   generic-secret"));
        assert!(out.contains("path:   config/.env"));
        assert!(out.contains("range:  0-40"));
        assert!(out.contains("source: git"));
        assert!(out.contains("commit: 12"));
        assert!(out.contains("change: add"));
    }

    #[test]
    fn compact_suppresses_progress() {
        let out = collect_text(
            ScanEvent::Progress(ProgressEvent {
                source: SourceKind::Fs,
                stage: "scanning",
                objects_scanned: 100,
                bytes_scanned: 1024,
                findings_emitted: 2,
            }),
            false,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn verbose_shows_progress() {
        let out = collect_text(
            ScanEvent::Progress(ProgressEvent {
                source: SourceKind::Fs,
                stage: "scanning",
                objects_scanned: 100,
                bytes_scanned: 1024,
                findings_emitted: 2,
            }),
            true,
        );
        assert!(out.contains("[progress]"));
        assert!(out.contains("objects=100"));
    }

    #[test]
    fn summary_output() {
        let out = collect_text(
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 1234,
                bytes_scanned: 104857600,
                findings_emitted: 3,
                errors: 0,
                throughput_mib_s: 81.23,
            }),
            false,
        );
        assert!(out.contains("[summary]"));
        assert!(out.contains("elapsed=1234ms"));
        assert!(out.contains("81.23 MiB/s"));
    }

    #[test]
    fn verbose_commit_meta() {
        use crate::git_scan::object_id::OidBytes;
        let oid = OidBytes::sha1([
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ]);
        let out = collect_text(
            ScanEvent::CommitMeta(CommitMetaEvent {
                commit_id: 42,
                commit_oid: oid,
                timestamp: 1_700_000_000,
                identity: None,
            }),
            true,
        );
        assert_eq!(
            out,
            "[commit_meta] id=42 oid=deadbeef0123456789abcdeffedcba9876543210 ts=1700000000\n"
        );
    }

    #[test]
    fn compact_suppresses_commit_meta() {
        use crate::git_scan::object_id::OidBytes;
        let out = collect_text(
            ScanEvent::CommitMeta(CommitMetaEvent {
                commit_id: 0,
                commit_oid: OidBytes::sha1([0u8; 20]),
                timestamp: 0,
                identity: None,
            }),
            false,
        );
        assert!(out.is_empty(), "compact mode must suppress commit_meta");
    }

    #[test]
    fn non_utf8_path_lossy() {
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"src/\xff/bad.rs",
                start: 0,
                end: 10,
                rule_id: 1,
                rule_name: "test",
                commit_id: None,
                change_kind: None,
            }),
            false,
        );
        // Invalid byte replaced with replacement character.
        assert!(out.contains('\u{FFFD}'));
    }

    // ── U1: SHA-256 OID in commit_meta ──────────────────────────────────

    #[test]
    fn verbose_commit_meta_sha256() {
        use crate::git_scan::object_id::OidBytes;
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (0xff - i) as u8;
        }
        let oid = OidBytes::sha256(bytes);
        let out = collect_text(
            ScanEvent::CommitMeta(CommitMetaEvent {
                commit_id: 1,
                commit_oid: oid,
                timestamp: 999,
                identity: None,
            }),
            true,
        );
        // 64-char hex for SHA-256.
        let expected_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(expected_hex.len(), 64);
        assert!(
            out.contains(&expected_hex),
            "SHA-256 hex not found in output: {out}"
        );
        assert_eq!(
            out,
            format!("[commit_meta] id=1 oid={expected_hex} ts=999\n")
        );
    }

    // ── U2: Float edge cases in summary ─────────────────────────────────

    #[test]
    fn summary_nan_throughput() {
        let out = collect_text(
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 0,
                bytes_scanned: 0,
                findings_emitted: 0,
                errors: 0,
                throughput_mib_s: f64::NAN,
            }),
            false,
        );
        // Rust's `{:.2}` formats NaN as "NaN" — document this pass-through
        // behavior. The JSONL sink clamps to 0.00, but the text sink is a
        // human-readable debug path, so displaying "NaN" is acceptable.
        assert!(out.contains("[summary]"));
        assert!(out.contains("NaN MiB/s"));
    }

    #[test]
    fn summary_infinity_throughput() {
        let out = collect_text(
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 1,
                bytes_scanned: 0,
                findings_emitted: 0,
                errors: 0,
                throughput_mib_s: f64::INFINITY,
            }),
            false,
        );
        assert!(out.contains("inf MiB/s"));
    }

    #[test]
    fn summary_neg_infinity_throughput() {
        let out = collect_text(
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 1,
                bytes_scanned: 0,
                findings_emitted: 0,
                errors: 0,
                throughput_mib_s: f64::NEG_INFINITY,
            }),
            false,
        );
        assert!(out.contains("-inf MiB/s"));
    }

    #[test]
    fn summary_zero_throughput() {
        let out = collect_text(
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 100,
                bytes_scanned: 0,
                findings_emitted: 0,
                errors: 0,
                throughput_mib_s: 0.0,
            }),
            false,
        );
        assert!(out.contains("0.00 MiB/s"));
    }

    #[test]
    fn summary_negative_throughput() {
        let out = collect_text(
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: 100,
                bytes_scanned: 0,
                findings_emitted: 0,
                errors: 0,
                throughput_mib_s: -42.5,
            }),
            false,
        );
        // Negative values pass through `{:.2}` unmodified.
        assert!(out.contains("-42.50 MiB/s"));
    }

    // ── U3: Empty path in finding ───────────────────────────────────────

    #[test]
    fn compact_finding_empty_path() {
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"",
                start: 42,
                end: 80,
                rule_id: 1,
                rule_name: "rule",
                commit_id: None,
                change_kind: None,
            }),
            false,
        );
        assert_eq!(out, ":42-80  rule  (fs)\n");
    }

    // ── U4: CommitMeta with identity present ────────────────────────────

    #[test]
    fn verbose_commit_meta_ignores_identity() {
        use crate::git_scan::identity_intern::CommitIdentityIds;
        use crate::git_scan::object_id::OidBytes;
        let oid = OidBytes::sha1([0xaa; 20]);
        let ids = CommitIdentityIds {
            author_name: 0,
            author_email: 1,
            committer_name: 2,
            committer_email: 3,
        };

        let with_identity = collect_text(
            ScanEvent::CommitMeta(CommitMetaEvent {
                commit_id: 7,
                commit_oid: oid,
                timestamp: 1_000,
                identity: Some(ids),
            }),
            true,
        );
        let without_identity = collect_text(
            ScanEvent::CommitMeta(CommitMetaEvent {
                commit_id: 7,
                commit_oid: oid,
                timestamp: 1_000,
                identity: None,
            }),
            true,
        );
        // The text sink silently ignores the identity field.
        assert_eq!(with_identity, without_identity);
    }

    // ── U5: Boundary numerics ───────────────────────────────────────────

    #[test]
    fn compact_finding_max_offsets() {
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Git,
                object_path: b"f",
                start: u64::MAX,
                end: u64::MAX,
                rule_id: u32::MAX,
                rule_name: "r",
                commit_id: Some(u32::MAX),
                change_kind: None,
            }),
            false,
        );
        assert!(out.contains(&u64::MAX.to_string()));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn summary_max_elapsed() {
        let out = collect_text(
            ScanEvent::Summary(SummaryEvent {
                source: SourceKind::Fs,
                status: "complete",
                elapsed_ms: u64::MAX,
                bytes_scanned: u64::MAX,
                findings_emitted: u64::MAX,
                errors: u64::MAX,
                throughput_mib_s: f64::MAX,
            }),
            false,
        );
        assert!(out.contains("[summary]"));
        assert!(out.contains(&format!("elapsed={}ms", u64::MAX)));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn verbose_progress_zero_counters() {
        let out = collect_text(
            ScanEvent::Progress(ProgressEvent {
                source: SourceKind::Git,
                stage: "scanning",
                objects_scanned: 0,
                bytes_scanned: 0,
                findings_emitted: 0,
            }),
            true,
        );
        assert!(out.contains("objects=0"));
        assert!(out.contains("bytes=0"));
        assert!(out.contains("findings=0"));
    }
}

// ============================================================================
// Property tests
// ============================================================================

/// Property-based tests that fuzz the text sink with arbitrary inputs.
///
/// Each property (P1–P5) targets a structural invariant of the output format
/// rather than a specific input value, complementing the exact-match unit
/// tests above.
#[cfg(all(test, feature = "stdx-proptest"))]
mod prop_tests {
    use super::*;
    use crate::git_scan::object_id::OidBytes;
    use crate::unified::events::ScanEvent;
    use proptest::prelude::*;

    fn collect_text(event: ScanEvent<'_>, verbose: bool) -> String {
        let buf = Vec::new();
        let sink = TextEventSink::new(buf, verbose);
        sink.emit(event);
        sink.flush();
        let writer = sink.writer.lock().unwrap();
        String::from_utf8(writer.get_ref().clone()).unwrap()
    }

    fn source_kind_strategy() -> impl Strategy<Value = SourceKind> {
        prop_oneof![Just(SourceKind::Fs), Just(SourceKind::Git),]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            .. ProptestConfig::default()
        })]

        // ── P1: Compact finding always produces exactly one line ────────
        //
        // Paths are filtered to exclude newline bytes (0x0a) because
        // `from_utf8_lossy` preserves them as literal '\n', breaking the
        // one-liner invariant. This is acceptable: Git paths with embedded
        // newlines are pathological and the text sink is a debug path.

        #[test]
        fn prop_compact_finding_single_line(
            path in proptest::collection::vec(
                any::<u8>().prop_filter("no newlines", |&b| b != b'\n'),
                0..256,
            ),
            start: u64,
            end: u64,
            rule_name in "[a-zA-Z0-9_-]{1,64}",
            source in source_kind_strategy(),
        ) {
            let out = collect_text(
                ScanEvent::Finding(FindingEvent {
                    source,
                    object_path: &path,
                    start,
                    end,
                    rule_id: 0,
                    rule_name: &rule_name,
                    commit_id: None,
                    change_kind: None,
                }),
                false,
            );
            // Exactly one newline, at the end.
            let newline_count = out.chars().filter(|&c| c == '\n').count();
            prop_assert_eq!(newline_count, 1, "expected exactly 1 newline, got {}: {:?}", newline_count, out);
            prop_assert!(out.ends_with('\n'));
            // Must contain the rule name and source label.
            prop_assert!(out.contains(&rule_name));
            let label = match source {
                SourceKind::Fs => "fs",
                SourceKind::Git => "git",
            };
            prop_assert!(out.contains(label));
        }

        // ── P2: Verbose finding always contains required field labels ───

        #[test]
        fn prop_verbose_finding_has_fields(
            path in proptest::collection::vec(any::<u8>(), 0..256),
            rule_name in "\\PC{1,64}",
            source in source_kind_strategy(),
        ) {
            let out = collect_text(
                ScanEvent::Finding(FindingEvent {
                    source,
                    object_path: &path,
                    start: 0,
                    end: 1,
                    rule_id: 0,
                    rule_name: &rule_name,
                    commit_id: None,
                    change_kind: None,
                }),
                true,
            );
            prop_assert!(out.contains("--- finding ---"));
            prop_assert!(out.contains("rule:"));
            prop_assert!(out.contains("path:"));
            prop_assert!(out.contains("range:"));
            prop_assert!(out.contains("source:"));
        }

        // ── P3: Compact mode suppresses progress and commit_meta ────────

        #[test]
        fn prop_compact_suppresses_progress(
            source in source_kind_strategy(),
            objects: u64,
            bytes: u64,
            findings: u64,
        ) {
            let out = collect_text(
                ScanEvent::Progress(ProgressEvent {
                    source,
                    stage: "scanning",
                    objects_scanned: objects,
                    bytes_scanned: bytes,
                    findings_emitted: findings,
                }),
                false,
            );
            prop_assert!(out.is_empty(), "compact mode must suppress progress, got: {out:?}");
        }

        #[test]
        fn prop_compact_suppresses_commit_meta(
            commit_id: u32,
            timestamp: u64,
            raw in proptest::collection::vec(any::<u8>(), 20..=20),
        ) {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&raw);
            let oid = OidBytes::sha1(arr);
            let out = collect_text(
                ScanEvent::CommitMeta(CommitMetaEvent {
                    commit_id,
                    commit_oid: oid,
                    timestamp,
                    identity: None,
                }),
                false,
            );
            prop_assert!(out.is_empty(), "compact mode must suppress commit_meta, got: {out:?}");
        }

        // ── P4: Summary always contains key markers ─────────────────────

        #[test]
        fn prop_summary_has_markers(
            source in source_kind_strategy(),
            elapsed_ms: u64,
            bytes: u64,
            findings: u64,
            errors: u64,
            throughput in any::<f64>(),
        ) {
            let out = collect_text(
                ScanEvent::Summary(SummaryEvent {
                    source,
                    status: "complete",
                    elapsed_ms,
                    bytes_scanned: bytes,
                    findings_emitted: findings,
                    errors,
                    throughput_mib_s: throughput,
                }),
                false,
            );
            prop_assert!(out.contains("[summary]"));
            prop_assert!(out.contains("elapsed="));
            prop_assert!(out.contains("MiB/s"));
            prop_assert!(out.ends_with('\n'));
        }

        // ── P5: OID hex formatting roundtrips ───────────────────────────

        #[test]
        fn prop_sha1_oid_hex_in_commit_meta(
            raw in proptest::collection::vec(any::<u8>(), 20..=20),
        ) {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&raw);
            let oid = OidBytes::sha1(arr);
            let out = collect_text(
                ScanEvent::CommitMeta(CommitMetaEvent {
                    commit_id: 0,
                    commit_oid: oid,
                    timestamp: 0,
                    identity: None,
                }),
                true,
            );
            let expected_hex: String = arr.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(
                out.contains(&expected_hex),
                "SHA-1 hex {expected_hex} not found in: {out:?}"
            );
        }

        #[test]
        fn prop_sha256_oid_hex_in_commit_meta(
            raw in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            let oid = OidBytes::sha256(arr);
            let out = collect_text(
                ScanEvent::CommitMeta(CommitMetaEvent {
                    commit_id: 0,
                    commit_oid: oid,
                    timestamp: 0,
                    identity: None,
                }),
                true,
            );
            let expected_hex: String = arr.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(
                out.contains(&expected_hex),
                "SHA-256 hex {expected_hex} not found in: {out:?}"
            );
        }
    }
}
