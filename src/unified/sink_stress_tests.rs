//! Thread-safety stress tests for all EventSink implementations.
//!
//! Spawns N threads, each emitting M events concurrently. Validates that
//! the output is well-formed and contains exactly N*M events with no
//! interleaving or corruption.

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use crate::unified::events::{EventSink, FindingEvent, ScanEvent};
    use crate::unified::json_sink::JsonEventSink;
    use crate::unified::sarif_sink::SarifEventSink;
    use crate::unified::text_sink::TextEventSink;
    use crate::unified::SourceKind;

    const NUM_THREADS: usize = 8;
    const EVENTS_PER_THREAD: usize = 100;
    const TOTAL_EVENTS: usize = NUM_THREADS * EVENTS_PER_THREAD;

    /// A `Write` wrapper around `Arc<Mutex<Vec<u8>>>`.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl SharedBuf {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }
        fn contents(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn make_finding(thread_id: usize, event_id: usize) -> ScanEvent<'static> {
        // Use leaked strings so the event can be 'static (test-only).
        let rule_name: &'static str =
            Box::leak(format!("rule-t{thread_id}-e{event_id}").into_boxed_str());
        ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"test.txt",
            start: event_id as u64,
            end: (event_id + 10) as u64,
            rule_id: thread_id as u32,
            rule_name,
            commit_id: None,
            change_kind: None,
            confidence_score: 0,
        })
    }

    fn stress_emit<S: EventSink>(sink: &S) {
        std::thread::scope(|scope| {
            for t in 0..NUM_THREADS {
                scope.spawn(move || {
                    for e in 0..EVENTS_PER_THREAD {
                        sink.emit(make_finding(t, e));
                    }
                });
            }
        });
        sink.flush();
    }

    // -- JSONL -----------------------------------------------------------------

    #[test]
    fn jsonl_stress_no_corruption() {
        let buf = SharedBuf::new();
        let sink = crate::unified::events::JsonlEventSink::new(buf.clone());
        stress_emit(&sink);

        let output = String::from_utf8(buf.contents()).expect("valid UTF-8");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(
            lines.len(),
            TOTAL_EVENTS,
            "expected {} JSONL lines, got {}",
            TOTAL_EVENTS,
            lines.len()
        );

        // Every line must be valid JSON.
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line {} invalid JSON: {}", i, e));
            assert_eq!(v["type"], "finding");
        }
    }

    // -- JSON array ------------------------------------------------------------

    #[test]
    fn json_stress_no_corruption() {
        let buf = SharedBuf::new();
        let sink = JsonEventSink::new(buf.clone());
        stress_emit(&sink);

        let output = String::from_utf8(buf.contents()).expect("valid UTF-8");
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(&output).expect("valid JSON array");
        assert_eq!(
            parsed.len(),
            TOTAL_EVENTS,
            "expected {} JSON elements, got {}",
            TOTAL_EVENTS,
            parsed.len()
        );
    }

    // -- SARIF -----------------------------------------------------------------

    #[test]
    fn sarif_stress_no_corruption() {
        let buf = SharedBuf::new();
        let sink = SarifEventSink::new(buf.clone());
        stress_emit(&sink);

        let output = String::from_utf8(buf.contents()).expect("valid UTF-8");
        let v: serde_json::Value = serde_json::from_str(&output).expect("valid SARIF JSON");
        let results = v["runs"][0]["results"]
            .as_array()
            .expect("results is array");
        assert_eq!(
            results.len(),
            TOTAL_EVENTS,
            "expected {} SARIF results, got {}",
            TOTAL_EVENTS,
            results.len()
        );
    }

    // -- Text ------------------------------------------------------------------

    #[test]
    fn text_compact_stress_no_corruption() {
        let buf = SharedBuf::new();
        let sink = TextEventSink::new(buf.clone(), false);
        stress_emit(&sink);

        let output = String::from_utf8(buf.contents()).expect("valid UTF-8");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(
            lines.len(),
            TOTAL_EVENTS,
            "expected {} text lines, got {}",
            TOTAL_EVENTS,
            lines.len()
        );

        // Every line should end with "(fs)" and contain no partial data.
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.ends_with("(fs)"),
                "line {} is malformed: {:?}",
                i,
                line
            );
        }
    }

    #[test]
    fn text_verbose_stress_no_corruption() {
        let buf = SharedBuf::new();
        let sink = TextEventSink::new(buf.clone(), true);
        stress_emit(&sink);

        let output = String::from_utf8(buf.contents()).expect("valid UTF-8");
        // Each verbose finding produces a block starting with "--- finding ---".
        let finding_count = output.matches("--- finding ---").count();
        assert_eq!(
            finding_count, TOTAL_EVENTS,
            "expected {} finding blocks, got {}",
            TOTAL_EVENTS, finding_count
        );
    }
}
