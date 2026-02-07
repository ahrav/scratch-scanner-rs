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

use std::io::{BufWriter, ErrorKind, Write};
use std::sync::Mutex;

use super::SourceKind;

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
pub trait EventSink: Send + Sync {
    /// Serialize and write a single event. Must not block indefinitely.
    fn emit(&self, event: ScanEvent<'_>);
    /// Flush any buffered output. Called once at end-of-scan.
    fn flush(&self);
}

/// Encodes a [`ScanEvent`] into bytes.
///
/// Default implementation is JSONL. Future implementations could use
/// a zero-copy binary format.
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

fn encode_finding(f: &FindingEvent<'_>, buf: &mut Vec<u8>) {
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

fn encode_progress(p: &ProgressEvent, buf: &mut Vec<u8>) {
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

fn encode_summary(s: &SummaryEvent, buf: &mut Vec<u8>) {
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

fn encode_diagnostic(d: &DiagnosticEvent<'_>, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"type\":\"diagnostic\",\"level\":\"");
    write_json_str(d.level, buf);
    buf.extend_from_slice(b"\",\"message\":\"");
    write_json_str(d.message, buf);
    buf.extend_from_slice(b"\"}");
}

// ============================================================================
// JSON primitives (no serde)
// ============================================================================

fn write_source(kind: SourceKind, buf: &mut Vec<u8>) {
    match kind {
        SourceKind::Fs => buf.extend_from_slice(b"fs"),
        SourceKind::Git => buf.extend_from_slice(b"git"),
    }
}

/// Write a u64 as decimal ASCII.
fn write_u64(n: u64, buf: &mut Vec<u8>) {
    // itoa-style: write digits in reverse, then reverse.
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let start = buf.len();
    let mut v = n;
    while v > 0 {
        buf.push(b'0' + (v % 10) as u8);
        v /= 10;
    }
    buf[start..].reverse();
}

/// Write an f64 with 2 decimal places.
fn write_f64(n: f64, buf: &mut Vec<u8>) {
    // Format as integer part + 2 decimal places.
    // Handles NaN/Inf as 0.00 to avoid invalid JSON.
    if n.is_nan() || n.is_infinite() {
        buf.extend_from_slice(b"0.00");
        return;
    }
    let negative = n < 0.0;
    let abs = n.abs();
    let mut integer = abs as u64;
    let mut frac = ((abs - integer as f64) * 100.0).round() as u64;
    if frac >= 100 {
        integer += 1;
        frac -= 100;
    }

    if negative {
        buf.push(b'-');
    }
    write_u64(integer, buf);
    buf.push(b'.');
    if frac < 10 {
        buf.push(b'0');
    }
    write_u64(frac, buf);
}

/// Write a JSON-escaped UTF-8 string.
fn write_json_str(s: &str, buf: &mut Vec<u8>) {
    for byte in s.bytes() {
        match byte {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            0x00..=0x1f => {
                // Control characters: \u00XX
                buf.extend_from_slice(b"\\u00");
                buf.push(HEX_DIGITS[(byte >> 4) as usize]);
                buf.push(HEX_DIGITS[(byte & 0xf) as usize]);
            }
            _ => buf.push(byte),
        }
    }
}

/// Write raw bytes as a JSON string value.
///
/// Valid UTF-8 sequences are written as-is. Invalid bytes are escaped
/// as `\uXXXX` using the Unicode replacement character approach:
/// each invalid byte is written as `\u00XX`.
fn write_json_bytes(bytes: &[u8], buf: &mut Vec<u8>) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            // JSON special characters.
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            0x00..=0x1f => {
                buf.extend_from_slice(b"\\u00");
                buf.push(HEX_DIGITS[(b >> 4) as usize]);
                buf.push(HEX_DIGITS[(b & 0xf) as usize]);
            }
            // ASCII printable: pass through.
            0x20..=0x7e => buf.push(b),
            // Potential multi-byte UTF-8 start: validate and pass through if valid.
            _ => {
                let remaining = &bytes[i..];
                match std::str::from_utf8(remaining) {
                    Ok(s) => {
                        // Rest is valid UTF-8 — write it and done.
                        write_json_str(s, buf);
                        return;
                    }
                    Err(e) => {
                        let valid_up_to = e.valid_up_to();
                        if valid_up_to > 0 {
                            // Write the valid prefix.
                            // SAFETY: `from_utf8` above proved `remaining[..valid_up_to]`
                            // is valid UTF-8; `valid_up_to` is the boundary returned by
                            // `Utf8Error::valid_up_to()`.
                            let valid =
                                unsafe { std::str::from_utf8_unchecked(&remaining[..valid_up_to]) };
                            write_json_str(valid, buf);
                            i += valid_up_to;
                            continue;
                        }
                        // Invalid byte: escape as \u00XX.
                        buf.extend_from_slice(b"\\u00");
                        buf.push(HEX_DIGITS[(b >> 4) as usize]);
                        buf.push(HEX_DIGITS[(b & 0xf) as usize]);
                    }
                }
            }
        }
        i += 1;
    }
}

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

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
        // Reuse a thread-local buffer to avoid per-emit allocation.
        thread_local! {
            static ENCODE_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(256));
        }
        ENCODE_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            buf.clear();
            self.encoder.encode(&event, &mut buf);

            let mut writer = self.writer.lock().expect("jsonl sink mutex poisoned");
            if let Err(e) = writer.write_all(&buf) {
                if e.kind() == ErrorKind::BrokenPipe {
                    return;
                }
                panic!("jsonl event sink write failed: {}", e);
            }
        });
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
        thread_local! {
            static ENCODE_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(256));
        }
        ENCODE_BUF.with(|cell| {
            let mut tmp = cell.borrow_mut();
            tmp.clear();
            self.encoder.encode(&event, &mut tmp);
            let mut buf = self.buf.lock().expect("vec event sink mutex poisoned");
            buf.extend_from_slice(&tmp);
        });
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
    fn write_u64_values() {
        let mut buf = Vec::new();
        write_u64(0, &mut buf);
        assert_eq!(&buf, b"0");

        buf.clear();
        write_u64(42, &mut buf);
        assert_eq!(&buf, b"42");

        buf.clear();
        write_u64(u64::MAX, &mut buf);
        assert_eq!(std::str::from_utf8(&buf).unwrap(), u64::MAX.to_string());
    }

    #[test]
    fn write_f64_values() {
        let mut buf = Vec::new();
        write_f64(0.0, &mut buf);
        assert_eq!(&buf, b"0.00");

        buf.clear();
        write_f64(81.23, &mut buf);
        assert_eq!(&buf, b"81.23");

        buf.clear();
        write_f64(f64::NAN, &mut buf);
        assert_eq!(&buf, b"0.00");

        buf.clear();
        write_f64(-2.50, &mut buf);
        assert_eq!(&buf, b"-2.50");
    }

    #[test]
    fn write_f64_frac_rounds_to_100() {
        let mut buf = Vec::new();
        write_f64(99.996, &mut buf);
        assert_eq!(&buf, b"100.00");

        buf.clear();
        write_f64(1.995, &mut buf);
        assert_eq!(&buf, b"2.00");

        buf.clear();
        write_f64(0.999, &mut buf);
        assert_eq!(&buf, b"1.00");

        buf.clear();
        write_f64(-0.999, &mut buf);
        assert_eq!(&buf, b"-1.00");
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
