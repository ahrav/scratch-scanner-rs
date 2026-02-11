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

use std::io::{BufWriter, ErrorKind, Write};
use std::sync::Mutex;

use super::events::{
    CommitMetaEvent, DiagnosticEvent, EventSink, FindingEvent, ProgressEvent, ScanEvent,
    SummaryEvent,
};
use super::json_write::write_oid_hex;
use super::SourceKind;

/// Default buffer size (64 KiB) for buffered text emission.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// Human-readable text sink with compact and verbose modes.
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
                let line = if self.verbose {
                    format_finding_verbose(f)
                } else {
                    format_finding_compact(f)
                };
                write_line(&self.writer, &line);
            }
            ScanEvent::Progress(ref p) => {
                if self.verbose {
                    let line = format_progress(p);
                    write_line(&self.writer, &line);
                }
                // Compact mode: suppress progress events.
            }
            ScanEvent::Summary(ref s) => {
                let line = format_summary(s);
                write_line(&self.writer, &line);
            }
            ScanEvent::Diagnostic(ref d) => {
                // Diagnostics always go to stderr, not the main writer.
                write_diagnostic(d);
            }
            ScanEvent::CommitMeta(ref m) => {
                if self.verbose {
                    let line = format_commit_meta(m);
                    write_line(&self.writer, &line);
                }
                // Compact mode: suppress commit_meta events.
            }
        }
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("text sink mutex poisoned");
        if let Err(e) = writer.flush() {
            if e.kind() == ErrorKind::BrokenPipe {
                return;
            }
            panic!("text event sink flush failed: {}", e);
        }
    }
}

/// Acquire the writer mutex and write `line` atomically.
///
/// Panics on I/O errors other than broken pipe (same semantics as all sinks).
fn write_line<W: Write + Send>(writer: &Mutex<BufWriter<W>>, line: &str) {
    let mut w = writer.lock().expect("text sink mutex poisoned");
    if let Err(e) = w.write_all(line.as_bytes()) {
        if e.kind() == ErrorKind::BrokenPipe {
            return;
        }
        panic!("text event sink write failed: {}", e);
    }
}

fn write_diagnostic(d: &DiagnosticEvent<'_>) {
    // Best-effort stderr write; ignore errors.
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
fn format_finding_compact(f: &FindingEvent<'_>) -> String {
    format!(
        "{}:{}-{}  {}  ({})\n",
        lossy_path(f.object_path),
        f.start,
        f.end,
        f.rule_name,
        source_label(f.source),
    )
}

/// Verbose multi-line block.
fn format_finding_verbose(f: &FindingEvent<'_>) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("--- finding ---\n");
    out.push_str(&format!("  rule:   {}\n", f.rule_name));
    out.push_str(&format!("  path:   {}\n", lossy_path(f.object_path)));
    out.push_str(&format!("  range:  {}-{}\n", f.start, f.end));
    out.push_str(&format!("  source: {}\n", source_label(f.source)));
    if let Some(cid) = f.commit_id {
        out.push_str(&format!("  commit: {}\n", cid));
    }
    if let Some(ck) = f.change_kind {
        out.push_str(&format!("  change: {}\n", ck));
    }
    out
}

fn format_progress(p: &ProgressEvent) -> String {
    format!(
        "[progress] {} | {} | objects={} bytes={} findings={}\n",
        source_label(p.source),
        p.stage,
        p.objects_scanned,
        p.bytes_scanned,
        p.findings_emitted,
    )
}

fn format_summary(s: &SummaryEvent) -> String {
    format!(
        "[summary] {} | {} | elapsed={}ms bytes={} findings={} errors={} throughput={:.2} MiB/s\n",
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
fn format_commit_meta(m: &CommitMetaEvent) -> String {
    let mut hex_buf = Vec::with_capacity(m.commit_oid.len() as usize * 2);
    write_oid_hex(&m.commit_oid, &mut hex_buf);
    // SAFETY: write_oid_hex only pushes ASCII hex digits.
    let hex = unsafe { String::from_utf8_unchecked(hex_buf) };
    format!(
        "[commit_meta] id={} oid={} ts={}\n",
        m.commit_id, hex, m.timestamp,
    )
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
}
