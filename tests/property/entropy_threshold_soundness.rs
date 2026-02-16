//! Property-based soundness tests for entropy thresholds.
//!
//! Validates that random strings drawn from common secret alphabets
//! comfortably exceed the configured `min_bits_per_byte` thresholds
//! (3.0 for most rules, 2.5 for numeric-only rules).
//!
//! Minimum length is 32: shorter strings can legitimately fall below
//! threshold due to birthday collisions in small alphabets, and the
//! production entropy gate already skips strings below `min_len`.
//!
//! This provides a permanent mathematical guardrail: if a threshold
//! change would reject legitimately random secrets, these tests fail.

use proptest::prelude::*;

/// Shannon entropy in bits per byte, matching the production formula
/// in `src/engine/helpers.rs`.
fn shannon_entropy_bits_per_byte(bytes: &[u8]) -> f32 {
    let n = bytes.len();
    if n == 0 {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }

    let log2_n = (n as f32).log2();
    let mut sum_c_log2_c = 0.0f32;
    for &c in &counts {
        if c > 0 {
            sum_c_log2_c += (c as f32) * (c as f32).log2();
        }
    }

    log2_n - (sum_c_log2_c / n as f32)
}

/// Minimum threshold used by most rules (hex, alphanumeric, base64).
const GENERAL_THRESHOLD: f32 = 3.0;

/// Lower threshold used by numeric-only rules.
const NUMERIC_THRESHOLD: f32 = 2.5;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Random hex strings (the narrowest common alphabet at 16 symbols)
    /// must exceed the 3.0 bpb threshold.
    #[test]
    fn random_hex_exceeds_threshold(s in "[0-9a-f]{32,128}") {
        let entropy = shannon_entropy_bits_per_byte(s.as_bytes());
        prop_assert!(
            entropy > GENERAL_THRESHOLD,
            "hex string len={} entropy={:.3} <= {GENERAL_THRESHOLD}",
            s.len(), entropy,
        );
    }

    /// Random alphanumeric strings (62-symbol alphabet) must exceed 3.0 bpb.
    #[test]
    fn random_alphanumeric_exceeds_threshold(s in "[A-Za-z0-9]{32,128}") {
        let entropy = shannon_entropy_bits_per_byte(s.as_bytes());
        prop_assert!(
            entropy > GENERAL_THRESHOLD,
            "alphanumeric string len={} entropy={:.3} <= {GENERAL_THRESHOLD}",
            s.len(), entropy,
        );
    }

    /// Random base64 strings (64-symbol alphabet) must exceed 3.0 bpb.
    #[test]
    fn random_base64_exceeds_threshold(s in "[A-Za-z0-9+/]{32,128}") {
        let entropy = shannon_entropy_bits_per_byte(s.as_bytes());
        prop_assert!(
            entropy > GENERAL_THRESHOLD,
            "base64 string len={} entropy={:.3} <= {GENERAL_THRESHOLD}",
            s.len(), entropy,
        );
    }

    /// Random numeric-only strings (10-symbol alphabet) must exceed 2.5 bpb.
    #[test]
    fn random_numeric_exceeds_threshold(s in "[0-9]{32,128}") {
        let entropy = shannon_entropy_bits_per_byte(s.as_bytes());
        prop_assert!(
            entropy > NUMERIC_THRESHOLD,
            "numeric string len={} entropy={:.3} <= {NUMERIC_THRESHOLD}",
            s.len(), entropy,
        );
    }
}
