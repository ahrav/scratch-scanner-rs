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
//! | Finding | `{path}:{start}-{end}  {rule_name}  ({source})` | Multi-line block with all fields |
//! | Progress | suppressed | `[progress] …` |
//! | Summary | `[summary] …` | `[summary] …` |
//! | Diagnostic | stderr (always) | stderr (always) |
//! | CommitMeta | suppressed | `[commit_meta] id={} oid={} ts={}` (identity IDs omitted) |
//! | IdentityDictionary | suppressed | suppressed |

use std::io::{self, BufWriter, Write};
use std::sync::Mutex;

use super::events::{
    handle_sink_io, CommitMetaEvent, DiagnosticEvent, EventSink, FindingEvent, ProgressEvent,
    ScanEvent, SummaryEvent,
};
use super::json_write::write_oid_hex;
use super::SourceKind;

/// Default buffer size (64 KiB) for buffered text emission.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// Human-readable text sink with compact and verbose modes.
///
/// Thread-safe: the internal `BufWriter` is guarded by a [`Mutex`], so
/// multiple worker threads may call [`EventSink::emit`] concurrently.
/// Each event is formatted into a per-call scratch buffer first, then written
/// under the mutex with a single `write_all`. This keeps lock hold time short
/// under concurrent emitters while preserving atomic line writes.
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

    fn write_buffer(&self, buf: &[u8]) {
        let mut w = self.writer.lock().expect("text sink mutex poisoned");
        handle_sink_io(w.write_all(buf), "text event sink write");
    }
}

impl<W: Write + Send + 'static> EventSink for TextEventSink<W> {
    fn emit(&self, event: ScanEvent<'_>) {
        let mut line = Vec::with_capacity(256);
        match event {
            ScanEvent::Finding(ref f) => {
                if self.verbose {
                    write_finding_verbose(f, &mut line)
                } else {
                    write_finding_compact(f, &mut line)
                }
                .expect("formatting into Vec<u8> cannot fail");
            }
            ScanEvent::Progress(ref p) => {
                if self.verbose {
                    write_progress(p, &mut line).expect("formatting into Vec<u8> cannot fail");
                }
                // Compact mode: suppress progress events.
            }
            ScanEvent::Summary(ref s) => {
                write_summary(s, &mut line).expect("formatting into Vec<u8> cannot fail");
            }
            ScanEvent::Diagnostic(ref d) => {
                // Diagnostics always go to stderr, not the main writer.
                write_diagnostic(d);
            }
            ScanEvent::CommitMeta(ref m) => {
                if self.verbose {
                    write_commit_meta(m, &mut line).expect("formatting into Vec<u8> cannot fail");
                }
                // Compact mode: suppress commit_meta events.
            }
            ScanEvent::IdentityDictionary(_) => {
                // Identity dictionary entries are consumed by JSON-based sinks;
                // the human-readable text sink silently drops them.
            }
        }
        if !line.is_empty() {
            self.write_buffer(&line);
        }
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("text sink mutex poisoned");
        handle_sink_io(writer.flush(), "text event sink flush");
    }
}

/// Write `[{level}] {message}` to stderr. Best-effort: errors are ignored
/// because losing a diagnostic is acceptable, unlike losing a finding.
fn write_diagnostic(d: &DiagnosticEvent<'_>) {
    let _ = writeln!(std::io::stderr(), "[{}] {}", d.level, d.message);
}

/// Convert raw path bytes to a display-safe string.
///
/// 1. Decode as UTF-8 with lossy replacement (invalid bytes → U+FFFD).
/// 2. Replace control characters with escapes (`\xHH` or `\u{HHHH}`).
///    This prevents terminal/log injection and preserves the compact format's
///    one-line-per-finding invariant by escaping embedded newlines.
pub(crate) fn sanitize_path(bytes: &[u8]) -> String {
    use std::fmt::Write as FmtWrite;

    let lossy = String::from_utf8_lossy(bytes);
    if !lossy.chars().any(char::is_control) {
        return lossy.into_owned();
    }
    let mut out = String::with_capacity(lossy.len());
    for ch in lossy.chars() {
        if ch == '\u{FFFD}' {
            // Preserve the replacement character from lossy decoding as-is.
            out.push(ch);
        } else if ch.is_control() {
            // Escape control chars as \xHH (or \u{HHHH} when needed).
            let cp = ch as u32;
            if cp <= 0xff {
                let _ = write!(&mut out, "\\x{cp:02x}");
            } else {
                let _ = write!(&mut out, "\\u{{{cp:04x}}}");
            }
        } else {
            out.push(ch);
        }
    }
    out
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
        sanitize_path(f.object_path),
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
///   confidence: {score}     // omitted when 0
///   commit: {commit_id}     // Git findings only
///   change: {change_kind}   // Git findings only
/// ```
fn write_finding_verbose(f: &FindingEvent<'_>, w: &mut impl Write) -> io::Result<()> {
    w.write_all(b"--- finding ---\n")?;
    writeln!(w, "  rule:   {}", f.rule_name)?;
    writeln!(w, "  path:   {}", sanitize_path(f.object_path))?;
    writeln!(w, "  range:  {}-{}", f.start, f.end)?;
    writeln!(w, "  source: {}", source_label(f.source))?;
    if f.confidence_score != 0 {
        writeln!(w, "  confidence: {}", f.confidence_score)?;
    }
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
///
/// `throughput_mib_s` is formatted as-is with `{:.2}` — `NaN` and `Inf`
/// pass through unmodified. The JSONL encoder clamps these to `0.00`.
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
/// The OID is emitted as lowercase hex via [`write_oid_hex`] so all sinks
/// share one canonical OID encoding implementation.
///
/// `CommitMetaEvent::identity` is intentionally omitted here to keep text
/// output concise and human-readable. Use the JSONL sink when identity IDs
/// are needed downstream.
fn write_commit_meta(m: &CommitMetaEvent, buf: &mut Vec<u8>) -> io::Result<()> {
    write!(buf, "[commit_meta] id={} oid=", m.commit_id)?;
    write_oid_hex(&m.commit_oid, buf);
    writeln!(buf, " ts={}", m.timestamp)
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

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
                confidence_score: 0,
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
                confidence_score: 0,
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
                confidence_score: 0,
            }),
            false,
        );
        // Invalid byte replaced with replacement character.
        assert!(out.contains('\u{FFFD}'));
    }

    #[test]
    fn path_control_chars_sanitized() {
        // ANSI escape sequence in path (e.g. from a malicious Git tree entry).
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Git,
                object_path: b"src/\x1b[2Jevil.rs",
                start: 0,
                end: 5,
                rule_id: 1,
                rule_name: "rule",
                commit_id: None,
                change_kind: None,
                confidence_score: 0,
            }),
            false,
        );
        // The ESC byte (0x1b) must be escaped, not passed through raw.
        assert!(
            !out.contains('\x1b'),
            "raw ESC byte must not appear in output: {out:?}"
        );
        assert!(out.contains("\\x1b"));
    }

    #[test]
    fn path_newline_sanitized() {
        // Embedded newline must not break the one-line compact format.
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"a\nb",
                start: 0,
                end: 1,
                rule_id: 1,
                rule_name: "rule",
                commit_id: None,
                change_kind: None,
                confidence_score: 0,
            }),
            false,
        );
        // Exactly one newline (the line terminator), not two.
        let newline_count = out.chars().filter(|&c| c == '\n').count();
        assert_eq!(
            newline_count, 1,
            "embedded newline must be escaped: {out:?}"
        );
        assert!(out.contains("\\x0a"));
    }

    #[test]
    fn path_null_and_del_sanitized() {
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"a\x00b\x7fc",
                start: 0,
                end: 1,
                rule_id: 1,
                rule_name: "rule",
                commit_id: None,
                change_kind: None,
                confidence_score: 0,
            }),
            false,
        );
        assert!(out.contains("\\x00"), "NUL must be escaped: {out:?}");
        assert!(out.contains("\\x7f"), "DEL must be escaped: {out:?}");
    }

    // ── SHA-256 OID in commit_meta ──────────────────────────────────────

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

    // ── Float edge cases in summary ─────────────────────────────────────

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

    // ── Empty path in finding ───────────────────────────────────────────

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
                confidence_score: 0,
            }),
            false,
        );
        assert_eq!(out, ":42-80  rule  (fs)\n");
    }

    // ── CommitMeta with identity present ────────────────────────────────

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

    // ── Boundary numerics ───────────────────────────────────────────────

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
                confidence_score: 0,
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

    // ── Diagnostic event routing ────────────────────────────────────────

    #[test]
    fn diagnostic_does_not_write_to_main_writer() {
        let out = collect_text(
            ScanEvent::Diagnostic(DiagnosticEvent {
                level: "warn",
                message: "something happened",
            }),
            false,
        );
        assert!(
            out.is_empty(),
            "diagnostic must go to stderr, not main writer"
        );
    }

    // ── Verbose finding without optional fields ─────────────────────────

    #[test]
    fn verbose_finding_fs_no_optional_fields() {
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"lib.rs",
                start: 10,
                end: 20,
                rule_id: 1,
                rule_name: "test-rule",
                commit_id: None,
                change_kind: None,
                confidence_score: 0,
            }),
            true,
        );
        assert!(out.contains("--- finding ---"));
        assert!(out.contains("source: fs"));
        assert!(
            !out.contains("commit:"),
            "FS finding must not have commit line"
        );
        assert!(
            !out.contains("change:"),
            "FS finding must not have change line"
        );
    }

    // ── IdentityDictionary suppression ──────────────────────────────────

    #[test]
    fn identity_dictionary_suppressed_compact() {
        use crate::unified::events::IdentityDictionaryEvent;
        let out = collect_text(
            ScanEvent::IdentityDictionary(IdentityDictionaryEvent {
                id: 42,
                value: b"Alice <alice@example.com>",
            }),
            false,
        );
        assert!(
            out.is_empty(),
            "compact mode must suppress IdentityDictionary"
        );
    }

    #[test]
    fn identity_dictionary_suppressed_verbose() {
        use crate::unified::events::IdentityDictionaryEvent;
        let out = collect_text(
            ScanEvent::IdentityDictionary(IdentityDictionaryEvent {
                id: 42,
                value: b"Alice <alice@example.com>",
            }),
            true,
        );
        assert!(
            out.is_empty(),
            "verbose mode must suppress IdentityDictionary"
        );
    }

    // ── BrokenPipe error handling ───────────────────────────────────────

    /// A writer whose `flush()` always returns `BrokenPipe`.
    ///
    /// `write()` succeeds (bytes are absorbed by `BufWriter`'s internal
    /// buffer), so we test the BrokenPipe contract through `flush()` which
    /// bypasses buffering and hits the underlying writer directly.
    struct BrokenPipeWriter;

    impl std::io::Write for BrokenPipeWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // Accept writes so BufWriter doesn't fail during formatting.
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(ErrorKind::BrokenPipe, "pipe closed"))
        }
    }

    #[test]
    fn broken_pipe_swallowed_on_flush() {
        let sink = TextEventSink::new(BrokenPipeWriter, false);
        sink.emit(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"test",
            start: 0,
            end: 1,
            rule_id: 0,
            rule_name: "rule",
            commit_id: None,
            change_kind: None,
            confidence_score: 0,
        }));
        // flush() calls BrokenPipeWriter::flush() → BrokenPipe → must not panic.
        sink.flush();
    }

    /// A writer that always fails with `PermissionDenied`.
    struct FailWriter;

    impl std::io::Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(ErrorKind::PermissionDenied, "denied"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(ErrorKind::PermissionDenied, "denied"))
        }
    }

    #[test]
    #[should_panic(expected = "text event sink flush failed")]
    fn non_broken_pipe_error_panics() {
        let sink = TextEventSink::new(FailWriter, false);
        // flush() calls FailWriter::flush() → PermissionDenied → must panic.
        sink.flush();
    }

    // ── Realistic buffer-overflow write failure ──────────────────────────

    /// A writer that accepts up to `limit` bytes, then fails with
    /// [`ErrorKind::WriteZero`]. This simulates a realistic scenario like
    /// a full disk or a fixed-capacity output channel.
    ///
    /// Unlike [`FailWriter`] (which fails on every call), this writer
    /// succeeds for a while — long enough for `BufWriter`'s 64 KiB
    /// internal buffer to fill and trigger a flush to the underlying
    /// writer during a normal [`EventSink::emit`] call.
    struct LimitedWriter {
        remaining: usize,
    }

    impl LimitedWriter {
        fn new(limit: usize) -> Self {
            Self { remaining: limit }
        }
    }

    impl std::io::Write for LimitedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "writer capacity exhausted",
                ));
            }
            let n = buf.len().min(self.remaining);
            self.remaining -= n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn confidence_score_in_verbose_text() {
        // Score 7 → should appear.
        let out = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"src/secret.rs",
                start: 10,
                end: 50,
                rule_id: 1,
                rule_name: "api-key",
                commit_id: None,
                change_kind: None,
                confidence_score: 7,
            }),
            true,
        );
        assert!(
            out.contains("confidence: 7"),
            "verbose output must show confidence when non-zero: {out}"
        );

        // Score 0 → suppressed.
        let out_zero = collect_text(
            ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"src/other.rs",
                start: 0,
                end: 10,
                rule_id: 1,
                rule_name: "rule",
                commit_id: None,
                change_kind: None,
                confidence_score: 0,
            }),
            true,
        );
        assert!(
            !out_zero.contains("confidence:"),
            "verbose output must suppress confidence when 0: {out_zero}"
        );
    }

    /// Exercises the panic-on-write-failure contract with a realistic
    /// buffered-I/O failure scenario.
    ///
    /// The underlying [`LimitedWriter`] accepts 32 KiB then returns
    /// `WriteZero`. `TextEventSink::new` wraps it in a 64 KiB
    /// `BufWriter`, so the first ~64 KiB of findings are buffered
    /// in-memory without hitting the underlying writer. Once the buffer
    /// is full, `BufWriter` flushes to `LimitedWriter`. The first
    /// 32 KiB flush succeeds, but the remaining data triggers
    /// `WriteZero`, which propagates through [`handle_sink_io`] and
    /// panics.
    ///
    /// This is more realistic than [`non_broken_pipe_error_panics`]
    /// because it exercises the path where `BufWriter`'s internal flush
    /// during a `write_all` hits an error — the same codepath that fires
    /// when a real output file lives on a full disk.
    #[test]
    #[should_panic(expected = "text event sink write failed")]
    fn bufwriter_flush_to_failing_writer_panics() {
        let sink = TextEventSink::new(LimitedWriter::new(32 * 1024), false);

        // Each compact finding line is ~80 bytes. The 64 KiB BufWriter
        // buffer fills after ~800 findings, at which point it flushes to
        // LimitedWriter. The first flush writes 32 KiB successfully but
        // the remaining data hits WriteZero → panic via handle_sink_io.
        for _ in 0..2_000 {
            sink.emit(ScanEvent::Finding(FindingEvent {
                source: SourceKind::Fs,
                object_path: b"src/secrets/very-long-path-component/nested/deep/config.env",
                start: 0,
                end: 128,
                rule_id: 1,
                rule_name: "generic-api-key",
                commit_id: None,
                change_kind: None,
                confidence_score: 0,
            }));
        }
        // Belt-and-suspenders: flush in case the buffer hasn't spilled yet.
        sink.flush();
    }
}

// ============================================================================
// Property tests
// ============================================================================

/// Property-based tests that fuzz the text sink with arbitrary inputs.
///
/// Each property targets a structural invariant of the output format rather
/// than a specific input value, complementing the exact-match unit tests
/// above.
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
        // Respect the PROPTEST_CASES env var set by CI (4 on PRs, 32 nightly,
        // 64 full harness). Local runs without the env var get 512 cases.
        #![proptest_config(ProptestConfig::with_cases(
            std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512)
        ))]

        // ── Compact finding always produces exactly one line ────────────
        //
        // `sanitize_path` escapes all C0 control characters (including
        // newlines) as `\xHH`, so arbitrary byte paths cannot break the
        // one-line invariant. No input filtering is needed.

        #[test]
        fn prop_compact_finding_single_line(
            path in proptest::collection::vec(any::<u8>(), 0..256),
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
                    confidence_score: 0,
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

        // ── Verbose finding always contains required field labels ───────

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
                    confidence_score: 0,
                }),
                true,
            );
            prop_assert!(out.contains("--- finding ---"));
            prop_assert!(out.contains("rule:"));
            prop_assert!(out.contains("path:"));
            prop_assert!(out.contains("range:"));
            prop_assert!(out.contains("source:"));
        }

        // ── Summary always contains key markers ─────────────────────────
        //
        // Compact-mode suppression of progress and commit_meta events is
        // a simple `if self.verbose` branch — the unit tests
        // `compact_suppresses_progress` and `compact_suppresses_commit_meta`
        // cover it. Fuzzing random payloads through a no-op path adds no value.

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

        // ── OID hex formatting roundtrips ───────────────────────────────

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
