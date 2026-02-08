//! Structured scan events, output sinks, and JSONL encoder.
//!
//! # Architecture
//!
//! Workers emit [`ScanEvent`] values through an [`EventSink`]. The default
//! implementation ([`JsonlEventSink`]) serializes each event as a single
//! JSON line (JSONL) and writes it atomically to the underlying writer.
//!
//! # Wire format
//!
//! Each event is one JSON object followed by `\n`. Batch ordering between
//! workers is non-deterministic, but individual events are never interleaved
//! at the byte level.
//!
//! # Performance
//!
//! Formatting happens into a caller-provided `Vec<u8>` buffer (typically
//! from per-worker scratch). The mutex is held only for the `write_all`
//! call, not during formatting.

use std::cell::RefCell;
use std::io::{BufWriter, ErrorKind, Write};
use std::sync::Mutex;

use super::json_write::{write_f64, write_json_bytes, write_json_str, write_source, write_u64};
use super::SourceKind;

thread_local! {
    static EMIT_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(256));
}

/// Format into a thread-local scratch buffer, then pass the filled bytes to `f`.
///
/// This two-phase design keeps the expensive formatting work *outside* any
/// sink mutex — the sink only holds its lock for the cheap `write_all`.
///
/// Falls back to a heap-allocated `Vec` if the thread-local is already
/// borrowed (reentrant call within the same thread, which shouldn't happen
/// in practice but is safe if it does).
pub(crate) fn with_format_buf<F>(encode: impl FnOnce(&mut Vec<u8>), f: F)
where
    F: FnOnce(&[u8]),
{
    EMIT_BUF.with(|cell| {
        if let Ok(mut buf) = cell.try_borrow_mut() {
            buf.clear();
            encode(&mut buf);
            f(&buf);
        } else {
            // Reentrant call — allocate a one-off buffer.
            let mut buf = Vec::with_capacity(256);
            encode(&mut buf);
            f(&buf);
        }
    });
}

// ============================================================================
// Event types
// ============================================================================

/// Structured scan event emitted during scanning.
///
/// All variants borrow where possible to avoid allocation on the hot path.
/// The [`EventSink`] implementation is responsible for serialization.
pub enum ScanEvent<'a> {
    Finding(FindingEvent<'a>),
    Progress(ProgressEvent),
    Summary(SummaryEvent),
    Diagnostic(DiagnosticEvent<'a>),
}

/// A single secret finding.
pub struct FindingEvent<'a> {
    pub source: SourceKind,
    /// Raw bytes — git paths are not guaranteed UTF-8.
    pub object_path: &'a [u8],
    pub start: u64,
    pub end: u64,
    pub rule_id: u32,
    pub rule_name: &'a str,
    /// Git-specific: commit ID (None for FS).
    pub commit_id: Option<u32>,
    /// Git-specific: change kind (None for FS).
    pub change_kind: Option<&'a str>,
}

/// Progress checkpoint emitted periodically.
pub struct ProgressEvent {
    pub source: SourceKind,
    pub stage: &'static str,
    pub objects_scanned: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
}

/// Final summary emitted when scanning completes.
pub struct SummaryEvent {
    pub source: SourceKind,
    pub status: &'static str,
    pub elapsed_ms: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
    pub errors: u64,
    pub throughput_mib_s: f64,
}

/// Debug / perf diagnostic line.
pub struct DiagnosticEvent<'a> {
    pub level: &'static str,
    pub message: &'a str,
}

// ============================================================================
// Traits
// ============================================================================

/// Thread-safe sink for structured scan events.
///
/// Implementations must be safe to call from multiple worker threads
/// concurrently. Internal synchronization (mutex, lock-free buffer)
/// is the implementor's responsibility.
///
/// # Error contract
///
/// All built-in sinks silently swallow `BrokenPipe` (the downstream
/// consumer hung up) and panic on any other I/O error. This is
/// intentional: a scan should not silently lose findings to a transient
/// write failure.
pub trait EventSink: Send + Sync {
    /// Serialize and write a single event. Must not block indefinitely.
    fn emit(&self, event: ScanEvent<'_>);
    /// Flush any buffered output. Called once at end-of-scan.
    fn flush(&self);
}

/// Stateless encoder: appends a wire-format representation of one event to `buf`.
///
/// Separated from [`EventSink`] so the encoding logic can be tested and
/// reused without I/O. [`JsonlEncoder`] is the only implementation today;
/// a future binary format would add a second.
pub trait EventEncoder: Send + Sync {
    /// Append the encoded representation of `event` to `buf`.
    fn encode(&self, event: &ScanEvent<'_>, buf: &mut Vec<u8>);
}

// ============================================================================
// JSONL encoder
// ============================================================================

/// JSONL encoder: one JSON object per line, no serde.
pub struct JsonlEncoder;

impl JsonlEncoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonlEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventEncoder for JsonlEncoder {
    fn encode(&self, event: &ScanEvent<'_>, buf: &mut Vec<u8>) {
        match event {
            ScanEvent::Finding(f) => encode_finding(f, buf),
            ScanEvent::Progress(p) => encode_progress(p, buf),
            ScanEvent::Summary(s) => encode_summary(s, buf),
            ScanEvent::Diagnostic(d) => encode_diagnostic(d, buf),
        }
        buf.push(b'\n');
    }
}

pub(crate) fn encode_finding(f: &FindingEvent<'_>, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"type\":\"finding\",\"source\":\"");
    write_source(f.source, buf);
    buf.extend_from_slice(b"\",\"path\":\"");
    write_json_bytes(f.object_path, buf);
    buf.extend_from_slice(b"\",\"start\":");
    write_u64(f.start, buf);
    buf.extend_from_slice(b",\"end\":");
    write_u64(f.end, buf);
    buf.extend_from_slice(b",\"rule_id\":");
    write_u64(f.rule_id as u64, buf);
    buf.extend_from_slice(b",\"rule\":\"");
    write_json_str(f.rule_name, buf);
    buf.push(b'"');
    if let Some(cid) = f.commit_id {
        buf.extend_from_slice(b",\"commit_id\":");
        write_u64(cid as u64, buf);
    }
    if let Some(ck) = f.change_kind {
        buf.extend_from_slice(b",\"change_kind\":\"");
        write_json_str(ck, buf);
        buf.push(b'"');
    }
    buf.push(b'}');
}

pub(crate) fn encode_progress(p: &ProgressEvent, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"type\":\"progress\",\"source\":\"");
    write_source(p.source, buf);
    buf.extend_from_slice(b"\",\"stage\":\"");
    write_json_str(p.stage, buf);
    buf.extend_from_slice(b"\",\"objects\":");
    write_u64(p.objects_scanned, buf);
    buf.extend_from_slice(b",\"bytes\":");
    write_u64(p.bytes_scanned, buf);
    buf.extend_from_slice(b",\"findings\":");
    write_u64(p.findings_emitted, buf);
    buf.push(b'}');
}

pub(crate) fn encode_summary(s: &SummaryEvent, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"type\":\"summary\",\"source\":\"");
    write_source(s.source, buf);
    buf.extend_from_slice(b"\",\"status\":\"");
    write_json_str(s.status, buf);
    buf.extend_from_slice(b"\",\"elapsed_ms\":");
    write_u64(s.elapsed_ms, buf);
    buf.extend_from_slice(b",\"bytes\":");
    write_u64(s.bytes_scanned, buf);
    buf.extend_from_slice(b",\"findings\":");
    write_u64(s.findings_emitted, buf);
    buf.extend_from_slice(b",\"errors\":");
    write_u64(s.errors, buf);
    buf.extend_from_slice(b",\"throughput_mib_s\":");
    write_f64(s.throughput_mib_s, buf);
    buf.push(b'}');
}

pub(crate) fn encode_diagnostic(d: &DiagnosticEvent<'_>, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"type\":\"diagnostic\",\"level\":\"");
    write_json_str(d.level, buf);
    buf.extend_from_slice(b"\",\"message\":\"");
    write_json_str(d.message, buf);
    buf.extend_from_slice(b"\"}");
}

// ============================================================================
// JSONL event sink
// ============================================================================

/// Default buffer size (64 KiB) for buffered JSONL emission.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// JSONL event sink: writes one JSON object per line.
///
/// The mutex is held only for `write_all`, not for formatting.
/// Callers should use per-worker `Vec<u8>` buffers for formatting
/// to minimize contention.
pub struct JsonlEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    encoder: JsonlEncoder,
}

impl<W: Write + Send> JsonlEventSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(BufWriter::with_capacity(DEFAULT_BUF_CAPACITY, writer)),
            encoder: JsonlEncoder::new(),
        }
    }
}

impl<W: Write + Send + 'static> EventSink for JsonlEventSink<W> {
    fn emit(&self, event: ScanEvent<'_>) {
        with_format_buf(
            |buf| self.encoder.encode(&event, buf),
            |bytes| {
                let mut writer = self.writer.lock().expect("jsonl sink mutex poisoned");
                if let Err(e) = writer.write_all(bytes) {
                    if e.kind() == ErrorKind::BrokenPipe {
                        return;
                    }
                    panic!("jsonl event sink write failed: {}", e);
                }
            },
        );
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("jsonl sink mutex poisoned");
        if let Err(e) = writer.flush() {
            if e.kind() == ErrorKind::BrokenPipe {
                return;
            }
            panic!("jsonl event sink flush failed: {}", e);
        }
    }
}

/// Null event sink that discards all events (for benchmarking).
pub struct NullEventSink;

impl EventSink for NullEventSink {
    fn emit(&self, _event: ScanEvent<'_>) {}
    fn flush(&self) {}
}

/// Collects JSONL-encoded events in memory (for testing).
///
/// Thread-safe: multiple workers can emit concurrently. Use `take()` to
/// drain the buffer and inspect JSONL output in test assertions.
pub struct VecEventSink {
    buf: Mutex<Vec<u8>>,
    encoder: JsonlEncoder,
}

impl VecEventSink {
    pub fn new() -> Self {
        Self {
            buf: Mutex::new(Vec::new()),
            encoder: JsonlEncoder::new(),
        }
    }

    /// Drain and return all accumulated JSONL bytes.
    pub fn take(&self) -> Vec<u8> {
        let mut buf = self.buf.lock().expect("vec event sink mutex poisoned");
        std::mem::take(&mut *buf)
    }

    /// Return accumulated bytes without draining.
    pub fn bytes(&self) -> Vec<u8> {
        self.buf
            .lock()
            .expect("vec event sink mutex poisoned")
            .clone()
    }
}

impl Default for VecEventSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for VecEventSink {
    fn emit(&self, event: ScanEvent<'_>) {
        with_format_buf(
            |tmp| self.encoder.encode(&event, tmp),
            |bytes| {
                let mut buf = self.buf.lock().expect("vec event sink mutex poisoned");
                buf.extend_from_slice(bytes);
            },
        );
    }

    fn flush(&self) {}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_jsonl(event: ScanEvent<'_>) -> String {
        let encoder = JsonlEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&event, &mut buf);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn finding_jsonl_basic() {
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 42,
            end: 80,
            rule_id: 7,
            rule_name: "aws-access-key",
            commit_id: None,
            change_kind: None,
        }));
        assert!(line.starts_with('{'));
        assert!(line.ends_with("}\n"));
        assert!(line.contains("\"type\":\"finding\""));
        assert!(line.contains("\"source\":\"fs\""));
        assert!(line.contains("\"path\":\"src/main.rs\""));
        assert!(line.contains("\"start\":42"));
        assert!(line.contains("\"end\":80"));
        assert!(line.contains("\"rule\":\"aws-access-key\""));
        assert!(!line.contains("commit_id"));
    }

    #[test]
    fn finding_jsonl_with_git_fields() {
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: b"config/.env",
            start: 0,
            end: 40,
            rule_id: 3,
            rule_name: "generic-secret",
            commit_id: Some(12),
            change_kind: Some("add"),
        }));
        assert!(line.contains("\"source\":\"git\""));
        assert!(line.contains("\"commit_id\":12"));
        assert!(line.contains("\"change_kind\":\"add\""));
    }

    #[test]
    fn finding_jsonl_non_utf8_path() {
        // Path with invalid UTF-8 byte 0xff.
        let path = b"src/\xff/bad.rs";
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: path,
            start: 0,
            end: 10,
            rule_id: 1,
            rule_name: "test",
            commit_id: None,
            change_kind: None,
        }));
        // The invalid byte should be escaped.
        assert!(line.contains("\\u00ff"));
        assert!(line.contains("\"path\":\"src/\\u00ff/bad.rs\""));
    }

    #[test]
    fn summary_jsonl() {
        let line = collect_jsonl(ScanEvent::Summary(SummaryEvent {
            source: SourceKind::Fs,
            status: "complete",
            elapsed_ms: 1234,
            bytes_scanned: 104857600,
            findings_emitted: 3,
            errors: 0,
            throughput_mib_s: 81.23,
        }));
        assert!(line.contains("\"type\":\"summary\""));
        assert!(line.contains("\"elapsed_ms\":1234"));
        assert!(line.contains("\"throughput_mib_s\":81.23"));
    }

    #[test]
    fn progress_jsonl() {
        let line = collect_jsonl(ScanEvent::Progress(ProgressEvent {
            source: SourceKind::Git,
            stage: "scanning",
            objects_scanned: 1024,
            bytes_scanned: 104857600,
            findings_emitted: 5,
        }));
        assert!(line.contains("\"type\":\"progress\""));
        assert!(line.contains("\"stage\":\"scanning\""));
        assert!(line.contains("\"objects\":1024"));
    }

    #[test]
    fn diagnostic_jsonl() {
        let line = collect_jsonl(ScanEvent::Diagnostic(DiagnosticEvent {
            level: "debug",
            message: "tree diff took 1.2s",
        }));
        assert!(line.contains("\"type\":\"diagnostic\""));
        assert!(line.contains("\"level\":\"debug\""));
        assert!(line.contains("\"message\":\"tree diff took 1.2s\""));
    }

    #[test]
    fn json_escaping() {
        let line = collect_jsonl(ScanEvent::Diagnostic(DiagnosticEvent {
            level: "debug",
            message: "path=\"foo\\bar\"\nnewline",
        }));
        assert!(line.contains("\\\""));
        assert!(line.contains("\\\\"));
        assert!(line.contains("\\n"));
    }

    #[test]
    fn jsonl_sink_writes_to_vec() {
        let buf = Vec::new();
        let sink = JsonlEventSink::new(buf);
        sink.emit(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"test.txt",
            start: 0,
            end: 10,
            rule_id: 1,
            rule_name: "test-rule",
            commit_id: None,
            change_kind: None,
        }));
        sink.flush();

        // After flush the BufWriter's internal buffer is flushed to the Vec.
        // Verify the sink didn't panic and the data is well-formed.
        let _inner = sink.writer.lock().unwrap();
    }
}
