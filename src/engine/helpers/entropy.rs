//! Entropy gating helpers for Shannon and min-entropy checks.

use crate::engine::rule_repr::EntropyCompiled;
use crate::engine::scratch::EntropyScratch;

/// Precomputes log2 values for entropy calculations.
///
/// The table is sized to the maximum entropy window length across rules and
/// can be shared across entropy checks to avoid repeated `log2` calls.
/// Index 0 is unused; index 1 is log2(1) = 0.
pub(crate) fn build_log2_table(max: usize) -> Vec<f32> {
    let len = max.saturating_add(1).max(2);
    let mut t = vec![0.0f32; len];
    for (i, val) in t.iter_mut().enumerate().skip(1) {
        *val = (i as f32).log2();
    }
    t
}

#[inline]
fn log2_lookup(table: &[f32], n: usize) -> f32 {
    if n < table.len() {
        table[n]
    } else {
        (n as f32).log2()
    }
}

/// Raw metric values from the entropy-family gate.
///
/// Computed in a single fused pass over the 256-bin histogram. Shannon entropy
/// uses all bins; min-entropy only needs `max_bin_count`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EntropyMetrics {
    /// Shannon entropy in bits per byte.
    pub(crate) shannon_bpb: f32,
    /// Maximum bin count across all 256 histogram bins.
    ///
    /// Used for min-entropy: `H_inf = log2(n) - log2(max_bin_count)`.
    pub(crate) max_bin_count: u32,
    /// Precomputed `log2(n)` where `n` is the input length.
    ///
    /// Cached here so that `entropy_gate_passes` can reuse the value for the
    /// min-entropy calculation without a second table lookup after the
    /// `scratch.reset()` / `bzero` barrier that prevents CSE.
    pub(crate) log2_n: f32,
}

/// Computes Shannon entropy and max-bin-count in a single fused pass.
///
/// # Effects
/// - Uses and resets `scratch` for histogram bookkeeping.
/// - `scratch` contents are unspecified after return; it is meant for reuse.
///
/// # Returns
/// - `EntropyMetrics { shannon_bpb: 0.0, max_bin_count: 0, log2_n: 0.0 }` for empty input.
#[inline]
pub(crate) fn compute_entropy_metrics(
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> EntropyMetrics {
    let n = bytes.len();
    if n == 0 {
        return EntropyMetrics {
            shannon_bpb: 0.0,
            max_bin_count: 0,
            log2_n: 0.0,
        };
    }

    // Branchless histogram: unconditionally increment the bin for each byte.
    // No "first touch" tracking — the reset zeroes all 256 bins via memset.
    for &b in bytes {
        // SAFETY: b is u8, so b as usize is in 0..256; counts has exactly 256 entries.
        unsafe { *scratch.counts.get_unchecked_mut(b as usize) += 1 };
    }

    // Shannon entropy: H = log2(n) - (1/n) * sum(c_i * log2(c_i))
    // This rearrangement avoids repeated divisions.
    let log2_n = log2_lookup(log2_table, n);
    let mut sum_c_log2_c = 0.0f32;
    let mut max_bin_count: u32 = 0;

    // Scan all 256 bins. For random data most bins are nonzero (predictable);
    // for short inputs most bins are zero (also predictable). Either way the
    // branch predictor handles this well, and we avoid the per-byte branch
    // that the previous "touched list" approach required in the hot histogram loop.
    //
    // The `max_bin_count` tracking adds ~1 instruction per iteration (cmov),
    // a <5% cost increase over the Shannon-only loop.
    for i in 0..256 {
        // SAFETY: loop bounds guarantee `i` is always in 0..256, which matches
        // the exact length of `counts`.
        let c = unsafe { *scratch.counts.get_unchecked(i) };
        if c > max_bin_count {
            max_bin_count = c;
        }
        let cu = c as usize;
        if cu > 0 {
            sum_c_log2_c += (cu as f32) * log2_lookup(log2_table, cu);
        }
    }

    scratch.reset();

    EntropyMetrics {
        shannon_bpb: log2_n - (sum_c_log2_c / (n as f32)),
        max_bin_count,
        log2_n,
    }
}

/// Computes Shannon entropy in bits per byte for the given slice.
///
/// Thin wrapper over [`compute_entropy_metrics`] for callers that only need
/// Shannon entropy. Kept as a separate function for benchmark helper
/// compatibility.
///
/// # Returns
/// - 0.0 for empty input.
#[inline]
#[allow(dead_code)] // Used by bench helpers and tests.
pub(crate) fn shannon_entropy_bits_per_byte(
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> f32 {
    compute_entropy_metrics(bytes, scratch, log2_table).shannon_bpb
}

/// Returns true when the entropy gate allows a buffer to proceed.
///
/// # Behavior
/// - Buffers shorter than `spec.min_len` always pass (entropy is noisy).
/// - Longer buffers are capped at `spec.max_len` for the computation.
/// - Shannon entropy is always checked first (rejects ~80-90% of non-secrets).
/// - Min-entropy (optional, per NIST SP 800-90B) is checked second: it catches
///   distributions where one byte dominates even though Shannon looks moderate.
///
/// # Preconditions
/// - `spec.min_len <= spec.max_len` and `spec.min_bits_per_byte` is in [0.0, 8.0].
#[inline]
pub(crate) fn entropy_gate_passes(
    spec: &EntropyCompiled,
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> bool {
    let len = bytes.len();
    if len < spec.min_len {
        // For tiny samples entropy is noisy; let them pass rather than
        // discarding true positives.
        return true;
    }
    let capped = len.min(spec.max_len);
    let metrics = compute_entropy_metrics(&bytes[..capped], scratch, log2_table);

    // Shannon (always checked).
    if metrics.shannon_bpb < spec.min_bits_per_byte {
        return false;
    }

    // Min-entropy (optional, per NIST SP 800-90B).
    if let Some(me_min) = spec.min_entropy_bits_per_byte {
        // max_bin_count == 0 only for empty input, guarded by min_len >= 1.
        if metrics.max_bin_count == 0 {
            return false;
        }
        let me = metrics.log2_n - log2_lookup(log2_table, metrics.max_bin_count as usize);
        if me < me_min {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sidekiq secrets are `[a-f0-9]{8}:[a-f0-9]{8}` (17 bytes). The embedded
    // colon and short length make Shannon entropy noisy — random hex pairs can
    // dip below 3.0 bits/byte. The gate is set to 2.5 to avoid false negatives.
    #[test]
    fn sidekiq_hex_pair_entropy_above_gate() {
        let secret = b"76609006:7d494d19";
        let table = build_log2_table(secret.len());
        let mut scratch = EntropyScratch::new();
        let e = shannon_entropy_bits_per_byte(secret, &mut scratch, &table);
        // Should pass the 2.5 gate but would fail a 3.0 gate.
        assert!(
            e >= 2.5,
            "sidekiq hex-pair secret has entropy {e:.3} bits/byte, below the 2.5 gate"
        );
        assert!(
            e < 3.0,
            "expected entropy below 3.0 for this hex-pair, got {e:.3}"
        );
    }

    // ---- min-entropy (NIST SP 800-90B) ----

    /// All-same-byte: max_count = n, H_inf = log2(n) - log2(n) = 0.0.
    #[test]
    fn min_entropy_all_same_byte() {
        let input = [0xAAu8; 100];
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 100);
        let me = (100f32).log2() - (100f32).log2();
        assert!((me - 0.0).abs() < f32::EPSILON, "expected 0.0, got {me}");
    }

    /// Perfectly uniform 256 values: max_count = 1, H_inf = log2(256) - log2(1) = 8.0.
    #[test]
    fn min_entropy_perfectly_uniform() {
        let input: Vec<u8> = (0..=255).collect();
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 1);
        let me = (256f32).log2() - (1f32).log2();
        assert!((me - 8.0).abs() < 0.001, "expected 8.0, got {me}");
    }

    /// Uniform hex 32 bytes (2 per bin for 16 bins): H_inf = log2(32) - log2(2) = 4.0.
    #[test]
    fn min_entropy_uniform_hex() {
        let input: Vec<u8> = (0..16u8).cycle().take(32).collect();
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 2);
        let me = (32f32).log2() - (2f32).log2();
        assert!((me - 4.0).abs() < 0.001, "expected 4.0, got {me}");
    }

    /// Discriminative power: 50 copies of 'a' + one each of 49 other chars.
    /// Shannon is moderate (many distinct chars). Min-entropy is extremely low
    /// (~1.0 bpb) because one char dominates. A `min_entropy_bits_per_byte: 2.0`
    /// rejects this while Shannon alone would pass.
    #[test]
    fn min_entropy_discriminates_skewed_distribution() {
        let mut input = vec![b'a'; 50];
        for i in 0..49u8 {
            input.push(b'b' + i);
        }
        let n = input.len(); // 99
        let table = build_log2_table(n);
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 50);
        let me = (n as f32).log2() - (50f32).log2();
        // me = log2(99) - log2(50) ~ 6.63 - 5.64 = 0.98
        assert!(me < 2.0, "expected min-entropy < 2.0, got {me}");
        // Shannon should be moderate (many distinct chars contribute)
        assert!(
            m.shannon_bpb > 2.5,
            "expected Shannon > 2.5, got {}",
            m.shannon_bpb
        );
    }

    /// n=1: max_count = 1, min-entropy = 0.0 (log2(1) - log2(1) = 0).
    #[test]
    fn min_entropy_single_byte() {
        let input = [42u8];
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 1);
        let me = (1f32).log2() - (1f32).log2();
        assert!((me - 0.0).abs() < f32::EPSILON);
    }

    /// entropy_gate_passes with min_entropy_bits_per_byte = None behaves like Shannon-only.
    #[test]
    fn entropy_gate_none_min_entropy_is_shannon_only() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 3.0,
            min_len: 1,
            max_len: 256,
            min_entropy_bits_per_byte: None,
        };
        // High-entropy random bytes should pass.
        let input: Vec<u8> = (0..=255).collect();
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        assert!(entropy_gate_passes(&spec, &input, &mut scratch, &table));
    }

    /// entropy_gate_passes rejects skewed distribution via min-entropy.
    #[test]
    fn entropy_gate_rejects_via_min_entropy() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 1.0, // Very low Shannon threshold (passes)
            min_len: 1,
            max_len: 256,
            min_entropy_bits_per_byte: Some(2.0), // Min-entropy gate catches it
        };
        // 50 copies of 'a' + one each of 49 other chars (99 bytes).
        let mut input = vec![b'a'; 50];
        for i in 0..49u8 {
            input.push(b'b' + i);
        }
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        // Shannon passes (> 1.0) but min-entropy (~0.98) fails the 2.0 gate.
        assert!(!entropy_gate_passes(&spec, &input, &mut scratch, &table));
    }

    /// Boundary: input at exactly min_len - 1 always passes (bypass).
    #[test]
    fn entropy_gate_below_min_len_passes() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 8.0, // Impossibly high
            min_len: 10,
            max_len: 256,
            min_entropy_bits_per_byte: Some(8.0), // Impossibly high
        };
        let input = [0u8; 9]; // Below min_len
        let table = build_log2_table(256);
        let mut scratch = EntropyScratch::new();
        assert!(entropy_gate_passes(&spec, &input, &mut scratch, &table));
    }

    /// Boundary: input at exactly max_len + 1 is capped to max_len.
    #[test]
    fn entropy_gate_caps_at_max_len() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 3.0,
            min_len: 1,
            max_len: 10,
            min_entropy_bits_per_byte: None,
        };
        // 10 unique + 10 zeros. If capped to 10, all unique -> high entropy.
        let mut input: Vec<u8> = (0..10).collect();
        input.extend([0u8; 10]);
        let table = build_log2_table(20);
        let mut scratch = EntropyScratch::new();
        // Capped to first 10 bytes (all unique) -> max entropy -> passes.
        assert!(entropy_gate_passes(&spec, &input, &mut scratch, &table));
    }

    /// Short hex tokens (n=17, k=16) without min-entropy pass the gate.
    ///
    /// `sidekiq-secret` / `sidekiq-sensitive-url` match `[a-f0-9]{8}:[a-f0-9]{8}`
    /// (17 bytes). At this length, a 2.0 bpb min-entropy gate rejects ~3.7%
    /// of uniformly random valid tokens (any hex nibble appearing 5+ times
    /// drives H_inf below 2.0). The production rule therefore omits the
    /// min-entropy gate and relies on Shannon + keyword alone.
    #[test]
    fn short_hex_token_passes_without_min_entropy_gate() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 2.5,
            min_len: 16,
            max_len: 256,
            min_entropy_bits_per_byte: None, // No min-entropy for short hex
        };
        let table = build_log2_table(256);
        let mut scratch = EntropyScratch::new();

        // Token with repeated nibble ('6' appears 5 times) -- would fail a
        // 2.0 bpb min-entropy gate but must pass Shannon-only.
        let token = b"66609066:7d494d16";
        assert!(
            entropy_gate_passes(&spec, token, &mut scratch, &table),
            "short hex token with repeated nibble should pass without min-entropy gate"
        );
    }
}
