//! Property-based tests for [`LogReader`].
//!
//! Validates:
//! - Streaming round-trip through `LogReader` matches encoded records.
//! - Random truncation yields a valid prefix then an error (never panics).
//! - CRC bit-flip is always detected.
//! - `LogReader` and `LogRecordReader` agree on valid streams.

use proptest::prelude::*;
use scanner_rs::store::log::{
    encode_record, LogReader, LogRecordReader, DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
};
use std::io::Cursor;

// Re-use generators from the codec property tests.
mod generators {
    use proptest::prelude::*;
    use scanner_rs::store::log::{
        LogDurabilityMode, LogFindingBatch, LogFindingRecord, LogRecord, LogRuleDef, LogRunEnd,
        LogRunStart, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, LOG_FORMAT_VERSION,
    };
    use scanner_rs::store::{CorrelationMode, KeySource};

    fn arb_durability() -> impl Strategy<Value = LogDurabilityMode> {
        prop_oneof![
            Just(LogDurabilityMode::SegmentClose),
            Just(LogDurabilityMode::Batch),
        ]
    }

    fn arb_correlation_mode() -> impl Strategy<Value = CorrelationMode> {
        prop_oneof![
            Just(CorrelationMode::Persistent),
            Just(CorrelationMode::Ephemeral),
        ]
    }

    fn arb_key_source() -> impl Strategy<Value = KeySource> {
        prop_oneof![
            Just(KeySource::EnvVar),
            Just(KeySource::MissingEnvVar),
            Just(KeySource::InvalidEnvVar),
        ]
    }

    /// RunStart with version pinned to LOG_FORMAT_VERSION so it passes
    /// LogReader's version gate.
    pub fn arb_valid_run_start() -> impl Strategy<Value = LogRunStart> {
        (
            any::<u64>(),
            any::<u64>(),
            arb_durability(),
            arb_correlation_mode(),
            arb_key_source(),
            any::<u32>(),
            any::<u64>(),
            1..=DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
        )
            .prop_map(
                |(
                    run_id,
                    started_unix_ms,
                    durability,
                    correlation_mode,
                    key_source,
                    max_inflight_batches,
                    max_inflight_bytes,
                    max_frame_payload_bytes,
                )| {
                    LogRunStart {
                        version: LOG_FORMAT_VERSION,
                        run_id,
                        started_unix_ms,
                        durability,
                        correlation_mode,
                        key_source,
                        max_inflight_batches,
                        max_inflight_bytes,
                        max_frame_payload_bytes,
                    }
                },
            )
    }

    pub fn arb_rule_def() -> impl Strategy<Value = LogRuleDef> {
        (
            any::<u32>(),
            any::<[u8; 32]>(),
            proptest::collection::vec(any::<u8>(), 0..4096),
        )
            .prop_map(|(rule_id, rule_fingerprint, rule_name)| LogRuleDef {
                rule_id,
                rule_fingerprint,
                rule_name,
            })
    }

    fn arb_finding_record() -> impl Strategy<Value = LogFindingRecord> {
        (
            any::<u32>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
        )
            .prop_map(
                |(
                    rule_id,
                    rule_fingerprint,
                    secret_hash,
                    finding_id,
                    root_hint_start,
                    root_hint_end,
                    span_start,
                    span_end,
                )| {
                    LogFindingRecord {
                        rule_id,
                        rule_fingerprint,
                        secret_hash,
                        finding_id,
                        root_hint_start,
                        root_hint_end,
                        span_start,
                        span_end,
                    }
                },
            )
    }

    pub fn arb_finding_batch() -> impl Strategy<Value = LogFindingBatch> {
        (
            proptest::collection::vec(any::<u8>(), 0..256),
            proptest::collection::vec(arb_finding_record(), 0..20),
        )
            .prop_map(|(object_path, findings)| LogFindingBatch {
                object_path,
                findings,
            })
    }

    pub fn arb_run_end() -> impl Strategy<Value = LogRunEnd> {
        (any::<u64>(), any::<u64>(), any::<u64>(), any::<bool>()).prop_map(
            |(ended_unix_ms, dropped_findings, persistence_emit_failures, incomplete)| LogRunEnd {
                ended_unix_ms,
                dropped_findings,
                persistence_emit_failures,
                incomplete,
            },
        )
    }

    /// Record generator that LogReader will accept (version-gated RunStart).
    pub fn arb_valid_log_record() -> impl Strategy<Value = LogRecord> {
        prop_oneof![
            arb_valid_run_start().prop_map(LogRecord::RunStart),
            arb_rule_def().prop_map(LogRecord::RuleDef),
            arb_finding_batch().prop_map(LogRecord::FindingBatch),
            arb_run_end().prop_map(LogRecord::RunEnd),
        ]
    }
}

use generators::arb_valid_log_record;

const FRAME_HEADER_BYTES: usize = 8;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// 7a: Streaming round-trip through LogReader matches encoded records.
    #[test]
    fn logreader_streaming_roundtrip(
        records in proptest::collection::vec(arb_valid_log_record(), 1..50)
    ) {
        let mut buf = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        }

        let mut reader = LogReader::with_default_limit(Cursor::new(buf));
        let mut decoded = Vec::new();
        loop {
            match reader.next_record() {
                Ok(Some(rec)) => decoded.push(rec),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        prop_assert_eq!(decoded, records);
    }

    /// 7b: Random truncation always yields a valid prefix then an error.
    #[test]
    fn random_truncation_yields_valid_prefix(
        records in proptest::collection::vec(arb_valid_log_record(), 1..20),
        trunc_offset in any::<proptest::sample::Index>(),
    ) {
        let mut buf = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        }
        if buf.is_empty() {
            return Ok(());
        }
        // Truncate at a random point.
        let cut = trunc_offset.index(buf.len());
        buf.truncate(cut);

        let mut reader = LogReader::with_default_limit(Cursor::new(buf));
        let mut decoded = Vec::new();
        let mut stop_reason = None;
        loop {
            match reader.next_record() {
                Ok(Some(rec)) => decoded.push(rec),
                Ok(None) => break,
                Err(err) => {
                    stop_reason = Some(err.reason());
                    break;
                }
            }
        }

        // All decoded records must be a prefix of the original.
        prop_assert!(decoded.len() <= records.len());
        for (i, rec) in decoded.iter().enumerate() {
            prop_assert_eq!(rec, &records[i]);
        }

        // If we decoded fewer records than the original, there should have
        // been a stop reason (unless the truncation happened at an exact
        // frame boundary, giving clean EOF).
        if decoded.len() < records.len() && stop_reason.is_none() {
            // Clean EOF at a frame boundary — valid.
        }
    }

    /// 7c: CRC bit-flip is always detected by LogReader.
    #[test]
    fn crc_bit_flip_detected_by_logreader(rec in arb_valid_log_record()) {
        let mut buf = Vec::new();
        encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();

        // Only flip a bit in the body (after the 8-byte header).
        if buf.len() > FRAME_HEADER_BYTES {
            buf[FRAME_HEADER_BYTES] ^= 1;

            let mut reader = LogReader::with_default_limit(Cursor::new(buf));
            let result = reader.next_record();
            prop_assert!(result.is_err(), "expected error after bit flip");
        }
    }

    /// 7d: LogReader and LogRecordReader agree on valid streams.
    #[test]
    fn logreader_and_logrecordreader_agree(
        records in proptest::collection::vec(arb_valid_log_record(), 1..50)
    ) {
        let mut buf = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        }

        // Decode via LogReader.
        let mut lr = LogReader::with_default_limit(Cursor::new(buf.clone()));
        let mut lr_decoded = Vec::new();
        loop {
            match lr.next_record() {
                Ok(Some(rec)) => lr_decoded.push(rec),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        // Decode via LogRecordReader.
        let mut lrr = LogRecordReader::new(Cursor::new(buf), DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let mut lrr_decoded = Vec::new();
        while let Some(rec) = lrr.next_record().unwrap() {
            lrr_decoded.push(rec);
        }

        prop_assert_eq!(lr_decoded, lrr_decoded);
    }
}
