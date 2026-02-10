//! Property-based round-trip and invariant tests for the FS log codec.
//!
//! Validates:
//! - Encode→decode round-trips for all frame types with arbitrary valid data.
//! - CRC detects single-bit corruption.
//! - `frame_len` header matches the actual body size.
//! - Streaming decoder reconstructs multi-frame sequences.

use proptest::prelude::*;
use scanner_rs::store::log::{
    decode_record, encode_record, LogDurabilityMode, LogFindingBatch, LogFindingRecord, LogReader,
    LogRecord, LogRecordReader, LogRuleDef, LogRunEnd, LogRunStart,
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES, LOG_FORMAT_VERSION,
};
use scanner_rs::store::{CorrelationMode, KeySource};
use std::io::Cursor;

// ========================================================================
// Arbitrary generators
// ========================================================================

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

fn arb_run_start() -> impl Strategy<Value = LogRunStart> {
    (
        any::<u16>(),
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
                version,
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
                    version,
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

fn arb_rule_def() -> impl Strategy<Value = LogRuleDef> {
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

fn arb_finding_batch() -> impl Strategy<Value = LogFindingBatch> {
    (
        proptest::collection::vec(any::<u8>(), 0..256),
        proptest::collection::vec(arb_finding_record(), 0..20),
    )
        .prop_map(|(object_path, findings)| LogFindingBatch {
            object_path,
            findings,
        })
}

fn arb_run_end() -> impl Strategy<Value = LogRunEnd> {
    (any::<u64>(), any::<u64>(), any::<u64>(), any::<bool>()).prop_map(
        |(ended_unix_ms, dropped_findings, persistence_emit_failures, incomplete)| LogRunEnd {
            ended_unix_ms,
            dropped_findings,
            persistence_emit_failures,
            incomplete,
        },
    )
}

fn arb_log_record() -> impl Strategy<Value = LogRecord> {
    prop_oneof![
        arb_run_start().prop_map(LogRecord::RunStart),
        arb_rule_def().prop_map(LogRecord::RuleDef),
        arb_finding_batch().prop_map(LogRecord::FindingBatch),
        arb_run_end().prop_map(LogRecord::RunEnd),
    ]
}

/// RunStart with version pinned to LOG_FORMAT_VERSION — passes LogReader's
/// version gate so it can be used in recovery/boundary property tests.
fn arb_valid_run_start() -> impl Strategy<Value = LogRunStart> {
    arb_run_start().prop_map(|mut rs| {
        rs.version = LOG_FORMAT_VERSION;
        rs
    })
}

/// Record generator that LogReader will accept (version-gated RunStart).
fn arb_reader_valid_record() -> impl Strategy<Value = LogRecord> {
    prop_oneof![
        arb_valid_run_start().prop_map(LogRecord::RunStart),
        arb_rule_def().prop_map(LogRecord::RuleDef),
        arb_finding_batch().prop_map(LogRecord::FindingBatch),
        arb_run_end().prop_map(LogRecord::RunEnd),
    ]
}

// ========================================================================
// Property tests
// ========================================================================

const FRAME_HEADER_BYTES: usize = 8;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn roundtrip_arbitrary_run_start(rec in arb_run_start()) {
        let record = LogRecord::RunStart(rec);
        let mut buf = Vec::new();
        encode_record(&record, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        let decoded = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        prop_assert_eq!(decoded, record);
    }

    #[test]
    fn roundtrip_arbitrary_rule_def(rec in arb_rule_def()) {
        let record = LogRecord::RuleDef(rec);
        let mut buf = Vec::new();
        // rule_name up to 4KB fits within DEFAULT_MAX (16MB).
        encode_record(&record, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        let decoded = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        prop_assert_eq!(decoded, record);
    }

    #[test]
    fn roundtrip_arbitrary_finding_batch(rec in arb_finding_batch()) {
        let record = LogRecord::FindingBatch(rec);
        let mut buf = Vec::new();
        encode_record(&record, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        let decoded = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        prop_assert_eq!(decoded, record);
    }

    #[test]
    fn roundtrip_arbitrary_run_end(rec in arb_run_end()) {
        let record = LogRecord::RunEnd(rec);
        let mut buf = Vec::new();
        encode_record(&record, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        let decoded = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        prop_assert_eq!(decoded, record);
    }

    #[test]
    fn streaming_roundtrip_multi_frame_sequence(
        records in proptest::collection::vec(arb_log_record(), 1..50)
    ) {
        let mut buf = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        }

        let mut reader = LogRecordReader::new(Cursor::new(buf), DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let mut decoded = Vec::new();
        while let Some(rec) = reader.next_record().unwrap() {
            decoded.push(rec);
        }
        prop_assert_eq!(decoded, records);
    }

    #[test]
    fn crc_detects_single_bit_flip(rec in arb_log_record()) {
        let mut buf = Vec::new();
        encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();

        // Only flip a bit in the body (after the 8-byte header) if there is a body.
        if buf.len() > FRAME_HEADER_BYTES {
            // Flip the first bit of the first body byte.
            buf[FRAME_HEADER_BYTES] ^= 1;

            let result = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
            // Should be CrcMismatch, UnknownFrameType, or some decode error
            // (flipping the type byte might cause UnknownFrameType before CRC check
            // in decode_record, but decode_frame_body checks CRC first).
            prop_assert!(result.is_err(), "expected error after bit flip");
        }
    }

    #[test]
    fn frame_len_header_matches_body(rec in arb_log_record()) {
        let mut buf = Vec::new();
        encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();

        // Read the 4-byte frame_len from the header.
        let frame_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        // frame_len = type_byte(1) + payload_bytes
        // total frame = header(8) + frame_len
        let expected_total = FRAME_HEADER_BYTES + frame_len as usize;
        prop_assert_eq!(buf.len(), expected_total);
    }

    /// T1.8: Recovery boundary sits exactly at the end of valid frames when
    /// garbage bytes are appended. This is THE critical correctness property
    /// for crash recovery — off by 1 byte = data loss or retained corruption.
    #[test]
    fn recovery_boundary_after_garbage_tail(
        records in proptest::collection::vec(arb_reader_valid_record(), 1..20),
        garbage in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let mut buf = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        }
        let valid_len = buf.len() as u64;
        buf.extend_from_slice(&garbage);

        let mut reader = LogReader::with_default_limit(Cursor::new(buf));
        loop {
            match reader.next_record() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        // The boundary offset must equal the sum of all valid frame sizes.
        prop_assert_eq!(reader.next_frame_offset(), valid_len);
    }

    /// T2.8: Random single-byte corruption never causes a panic.
    /// Deterministic CI-friendly complement to the fuzz target.
    #[test]
    fn corruption_never_causes_panic(
        records in proptest::collection::vec(arb_reader_valid_record(), 1..20),
        flip_idx in any::<proptest::sample::Index>(),
    ) {
        let mut buf = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        }
        if buf.is_empty() {
            return Ok(());
        }
        let idx = flip_idx.index(buf.len());
        buf[idx] ^= 0xFF;

        let mut reader = LogReader::with_default_limit(Cursor::new(buf));
        // Drain until terminal — must not panic.
        loop {
            match reader.next_record() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }
}
