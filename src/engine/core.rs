//! Core scanning engine implementation.
//!
//! Purpose: compile rules/transforms into prefilter and gating databases, then
//! drive bounded scans over raw and decoded buffers.
//!
//! Invariants / safety rules:
//! - Inputs passed to `scan_*` must be chunked so `buf.len() <= u32::MAX`.
//! - [`ScanScratch`] is single-threaded and must not be shared across threads.
//!
//! High-level algorithm:
//! 1. Build anchor sets (manual and/or derived) and Vectorscan prefilter DBs.
//! 2. For each buffer, prefilter -> build windows -> validate regexes.
//! 3. Optionally decode transform spans (gated and deduped) and rescan via a
//!    work queue while enforcing per-scan budgets.
//!
//! Design choices:
//! - Engine construction fails fast if prefilter DBs cannot be built.
//! - Base64 pre-gates are conservative and only avoid decode work; they never
//!   replace decoded-space validation.

use crate::api::*;
use crate::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig, PaddingPolicy, WhitespacePolicy};
use crate::regex2anchor::{
    compile_trigger_plan, AnchorDeriveConfig, TriggerPlan, UnfilterableReason,
};
use ahash::AHashMap;
#[cfg(feature = "stats")]
use std::sync::atomic::{AtomicU64, Ordering};

use super::helpers::u64_to_usize;
use super::rule_repr::{
    add_pat_owned, add_pat_raw, compile_confirm_all, compile_rule, map_to_patterns, utf16be_bytes,
    utf16le_bytes, RuleCompiled, Target, Variant,
};
use super::scratch::{RootSpanMapCtx, ScanScratch};
use super::transform::STREAM_DECODE_CHUNK_BYTES;
use super::vectorscan_prefilter::{
    AnchorInput, VsAnchorDb, VsGateDb, VsPrefilterDb, VsStreamDb, VsUtf16StreamDb,
};
use super::work_items::{BufRef, EncRef, WorkItem};
use crate::api::{Gate, TransformConfig, TransformId, TransformMode};

// --------------------------
// Statistics types
// --------------------------

/// Summary of anchor derivation choices during engine build.
#[cfg(feature = "stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct AnchorPlanStats {
    /// Rules that used manual anchors (policy allowed).
    pub manual_rules: usize,
    /// Rules that used derived anchors from regex analysis.
    pub derived_rules: usize,
    /// Rules gated by a residue plan instead of anchors.
    pub residue_rules: usize,
    /// Rules that could not be gated soundly and require full validation.
    pub unfilterable_rules: usize,
}

/// Vectorscan usage counters for a scan run (feature: `stats`).
#[cfg(feature = "stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct VectorscanStats {
    /// Whether the Vectorscan DB compiled successfully.
    pub db_built: bool,
    /// Whether the UTF-16 Vectorscan DB compiled successfully.
    pub utf16_db_built: bool,
    /// Number of buffers where a Vectorscan scan was attempted.
    pub scans_attempted: u64,
    /// Number of Vectorscan scans that completed successfully.
    pub scans_ok: u64,
    /// Number of Vectorscan scans that errored.
    pub scans_err: u64,
    /// Number of buffers where a UTF-16 Vectorscan scan was attempted.
    pub utf16_scans_attempted: u64,
    /// Number of UTF-16 Vectorscan scans that completed successfully.
    pub utf16_scans_ok: u64,
    /// Number of UTF-16 Vectorscan scans that errored.
    pub utf16_scans_err: u64,
    /// Buffers scanned without the raw Vectorscan prefilter (full-buffer fallback).
    pub anchor_only: u64,
    /// Buffers that used raw Vectorscan and also ran a UTF-16 anchor scan.
    pub anchor_after_vs: u64,
    /// Buffers where raw Vectorscan was used and UTF-16 scan was skipped.
    pub anchor_skipped: u64,
    /// Stream decode spans that fell back to full decode.
    pub stream_force_full: u64,
    /// Stream decode spans that exceeded the per-rule window cap.
    pub stream_window_cap_exceeded: u64,
}

/// Internal atomic counters used to build `VectorscanStats`.
#[cfg(feature = "stats")]
#[derive(Default)]
pub(super) struct VectorscanCounters {
    pub(super) scans_attempted: AtomicU64,
    pub(super) scans_ok: AtomicU64,
    pub(super) scans_err: AtomicU64,
    pub(super) utf16_scans_attempted: AtomicU64,
    pub(super) utf16_scans_ok: AtomicU64,
    pub(super) utf16_scans_err: AtomicU64,
    pub(super) anchor_only: AtomicU64,
    pub(super) anchor_after_vs: AtomicU64,
    pub(super) anchor_skipped: AtomicU64,
    pub(super) stream_force_full: AtomicU64,
    pub(super) stream_window_cap_exceeded: AtomicU64,
}

#[cfg(feature = "stats")]
impl VectorscanCounters {
    /// Captures a consistent snapshot of all counters with relaxed ordering.
    pub(super) fn snapshot(&self, db_built: bool, utf16_db_built: bool) -> VectorscanStats {
        VectorscanStats {
            db_built,
            utf16_db_built,
            scans_attempted: self.scans_attempted.load(Ordering::Relaxed),
            scans_ok: self.scans_ok.load(Ordering::Relaxed),
            scans_err: self.scans_err.load(Ordering::Relaxed),
            utf16_scans_attempted: self.utf16_scans_attempted.load(Ordering::Relaxed),
            utf16_scans_ok: self.utf16_scans_ok.load(Ordering::Relaxed),
            utf16_scans_err: self.utf16_scans_err.load(Ordering::Relaxed),
            anchor_only: self.anchor_only.load(Ordering::Relaxed),
            anchor_after_vs: self.anchor_after_vs.load(Ordering::Relaxed),
            anchor_skipped: self.anchor_skipped.load(Ordering::Relaxed),
            stream_force_full: self.stream_force_full.load(Ordering::Relaxed),
            stream_window_cap_exceeded: self.stream_window_cap_exceeded.load(Ordering::Relaxed),
        }
    }
}

// --------------------------
// Engine
// --------------------------

/// Compiled scanning engine with derived anchors, rules, and transforms.
///
/// Build once, then reuse with per-scan scratch buffers to avoid allocations.
///
/// # Guarantees
/// - Immutable after construction; methods only borrow `&self`.
/// - `scan_chunk_*` methods reset the provided [`ScanScratch`] before use and
///   enforce per-scan tuning budgets.
///
/// # Invariants
/// - Input buffers must be chunked so `buf.len() <= u32::MAX`.
/// - [`ScanScratch`] is single-threaded; use one scratch per worker/thread.
///
/// # Performance
/// - Prefilters and gates bound work; regex validation runs only inside
///   candidate windows.
///
/// # Failure modes
/// - Construction panics if required prefilter DBs cannot be built.
pub struct Engine {
    pub(super) rules: Vec<RuleCompiled>,
    pub(super) transforms: Vec<TransformConfig>,
    pub(crate) tuning: Tuning,

    // Log2 lookup table for entropy gating.
    pub(super) entropy_log2: Vec<f32>,

    // Unified Vectorscan/Hyperscan prefilter DB for raw scanning.
    //
    // Combines literal anchors with regex patterns into a single DB for efficient
    // multi-pattern matching. Built during engine construction; failures are fatal.
    pub(super) vs: Option<VsPrefilterDb>,
    // Optional Vectorscan DB for UTF-16 anchor scanning.
    //
    // When present, this prefilters UTF-16 variants using literal anchors.
    pub(super) vs_utf16: Option<VsAnchorDb>,
    // Vectorscan stream-mode DB for UTF-16 anchor scanning in decoded streams.
    pub(super) vs_utf16_stream: Option<VsUtf16StreamDb>,
    // Vectorscan stream-mode DB for decoded-byte scanning.
    pub(super) vs_stream: Option<VsStreamDb>,
    // Vectorscan stream-mode DB for decoded-space anchor gating.
    pub(super) vs_gate: Option<VsGateDb>,
    // Base64 pre-decode gate built from anchor patterns.
    //
    // This runs in *encoded space* and is deliberately conservative:
    // if a decoded buffer contains an anchor, at least one YARA-style base64
    // permutation of that anchor must appear in the encoded stream. We still
    // perform the decoded-space gate for correctness; this pre-gate exists
    // purely to skip wasteful span scans/decodes when no anchor could possibly appear.
    pub(super) b64_gate: Option<Base64YaraGate>,

    // Rules that cannot be given a sound prefilter gate under the policy.
    unfilterable_rules: Vec<(usize, UnfilterableReason)>,
    #[cfg(feature = "stats")]
    // Build-time summary of anchor selection decisions.
    anchor_plan_stats: AnchorPlanStats,
    #[cfg(feature = "stats")]
    pub(super) vs_stats: VectorscanCounters,

    /// True if any rule has UTF-16 anchor variants compiled.
    /// Controls whether UTF-16 scanning paths are active.
    pub(super) has_utf16_anchors: bool,
    /// Maximum window size (in bytes) across all rules.
    /// Determines buffer sizing for validation windows.
    pub(super) max_window_diameter_bytes: usize,
    /// Maximum prefilter width reported by Vectorscan for any pattern.
    /// Used for window expansion around match offsets.
    pub(super) max_prefilter_width: usize,
    /// Ring buffer size for stream-mode decoded scanning.
    /// Must accommodate the largest possible match span.
    pub(super) stream_ring_bytes: usize,
}

impl Engine {
    /// Compiles rule specs into an engine with Vectorscan prefilters and gates.
    ///
    /// Uses [`AnchorPolicy::PreferDerived`].
    ///
    /// # Panics
    /// Panics if any rule, transform, or tuning invariants are violated, or if
    /// the Vectorscan prefilter DB cannot be built.
    pub fn new(rules: Vec<RuleSpec>, transforms: Vec<TransformConfig>, tuning: Tuning) -> Self {
        Self::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::PreferDerived)
    }

    /// Compiles rule specs into an engine with a specific anchor policy.
    ///
    /// # Design Notes
    /// - `AnchorPolicy::ManualOnly` uses only explicit anchors provided by rules.
    /// - `AnchorPolicy::DerivedOnly` ignores manual anchors and relies on derived
    ///   anchors/residue gates; rules that cannot be gated are reported via
    ///   [`Engine::unfilterable_rules`].
    /// - `AnchorPolicy::PreferDerived` derives anchors when possible and falls
    ///   back to manual anchors when derivation is unavailable.
    ///
    /// # Outputs
    /// Populates `residue_rules` and `unfilterable_rules` based on regex analysis
    /// and the selected policy.
    ///
    /// # Panics
    /// Panics if any rule, transform, or tuning invariants are violated, or if
    /// the Vectorscan prefilter DB cannot be built.
    pub fn new_with_anchor_policy(
        rules: Vec<RuleSpec>,
        transforms: Vec<TransformConfig>,
        tuning: Tuning,
        policy: AnchorPolicy,
    ) -> Self {
        tuning.assert_valid();
        assert!(
            tuning.max_transform_depth.saturating_add(1) <= MAX_DECODE_STEPS,
            "max_transform_depth exceeds MAX_DECODE_STEPS"
        );
        for r in &rules {
            r.assert_valid();
        }
        for tc in &transforms {
            tc.assert_valid();
        }

        let mut rules_compiled = rules.iter().map(compile_rule).collect::<Vec<_>>();
        let max_entropy_len = rules_compiled
            .iter()
            .filter_map(|r| r.entropy.map(|e| e.max_len))
            .max()
            .unwrap_or(0);
        let entropy_log2 = super::helpers::build_log2_table(max_entropy_len);

        let raw_seed_radius_bytes = rules
            .iter()
            .map(|r| {
                let seed = if let Some(tp) = &r.two_phase {
                    tp.seed_radius
                } else {
                    r.radius
                };
                if seed > u32::MAX as usize {
                    u32::MAX
                } else {
                    seed as u32
                }
            })
            .collect::<Vec<_>>();

        let utf16_seed_radius_bytes = rules
            .iter()
            .map(|r| {
                let seed = if let Some(tp) = &r.two_phase {
                    tp.seed_radius
                } else {
                    r.radius
                };
                let bytes = seed.saturating_mul(2);
                if bytes > u32::MAX as usize {
                    u32::MAX
                } else {
                    bytes as u32
                }
            })
            .collect::<Vec<_>>();

        // Build deduped anchor patterns: pattern -> targets
        let mut pat_map_all: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(3).max(16));
        let mut pat_map_utf16: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(2).max(16));
        let mut unfilterable_rules: Vec<(usize, UnfilterableReason)> =
            Vec::with_capacity(rules.len());
        #[cfg(feature = "stats")]
        let mut anchor_plan_stats = AnchorPlanStats::default();
        let derive_cfg = AnchorDeriveConfig {
            utf8: false,
            ..AnchorDeriveConfig::default()
        };
        let allow_manual = matches!(
            policy,
            AnchorPolicy::ManualOnly | AnchorPolicy::PreferDerived
        );
        let allow_derive = matches!(
            policy,
            AnchorPolicy::DerivedOnly | AnchorPolicy::PreferDerived
        );

        for (rid, r) in rules.iter().enumerate() {
            assert!(rid <= u32::MAX as usize);
            let rid_u32 = rid as u32;
            let validator_match_start = r.validator != ValidatorKind::None;
            // If an anchor is also a keyword, the keyword gate is already satisfied
            // at that hit and the validator can remain authoritative.
            let keyword_implied_for_anchor = |anchor: &[u8]| -> bool {
                match r.keywords_any {
                    None => true,
                    Some(kws) => kws.contains(&anchor),
                }
            };
            let mut manual_used = false;
            let mut add_manual =
                |pat_map_all: &mut AHashMap<Vec<u8>, Vec<Target>>,
                 pat_map_utf16: &mut AHashMap<Vec<u8>, Vec<Target>>| {
                    if !allow_manual {
                        return;
                    }
                    if manual_used || r.anchors.is_empty() {
                        return;
                    }
                    manual_used = true;
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.manual_rules =
                            anchor_plan_stats.manual_rules.saturating_add(1);
                    }
                    for &a in r.anchors {
                        let keyword_implied = keyword_implied_for_anchor(a);
                        add_pat_raw(
                            pat_map_all,
                            a,
                            Target::new(
                                rid_u32,
                                Variant::Raw,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_all,
                            utf16le_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Le,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_all,
                            utf16be_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Be,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_utf16,
                            utf16le_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Le,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_utf16,
                            utf16be_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Be,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                    }
                };

            if !allow_derive {
                add_manual(&mut pat_map_all, &mut pat_map_utf16);
                continue;
            }

            let plan = match compile_trigger_plan(r.re.as_str(), &derive_cfg) {
                Ok(plan) => plan,
                Err(_) => {
                    unfilterable_rules.push((rid, UnfilterableReason::UnsupportedRegexFeatures));
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.unfilterable_rules =
                            anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_all, &mut pat_map_utf16);
                    continue;
                }
            };

            match plan {
                TriggerPlan::Anchored {
                    anchors,
                    mut confirm_all,
                } => {
                    if let Some(needle) = r.must_contain {
                        confirm_all.retain(|c| c.as_slice() != needle);
                    }
                    if let Some(compiled) = compile_confirm_all(confirm_all) {
                        rules_compiled[rid].confirm_all = Some(compiled);
                    }
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.derived_rules =
                            anchor_plan_stats.derived_rules.saturating_add(1);
                    }
                    for anchor in anchors {
                        let keyword_implied = keyword_implied_for_anchor(&anchor);
                        add_pat_raw(
                            &mut pat_map_all,
                            &anchor,
                            Target::new(rid_u32, Variant::Raw, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_all,
                            utf16le_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Le, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_all,
                            utf16be_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Be, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_utf16,
                            utf16le_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Le, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_utf16,
                            utf16be_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Be, false, keyword_implied),
                        );
                    }
                }
                TriggerPlan::Residue { gate: _ } => {
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.residue_rules =
                            anchor_plan_stats.residue_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_all, &mut pat_map_utf16);
                }
                TriggerPlan::Unfilterable { reason } => {
                    unfilterable_rules.push((rid, reason));
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.unfilterable_rules =
                            anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_all, &mut pat_map_utf16);
                }
            }
        }

        let (anchor_patterns_all, pat_targets_all, pat_offsets_all) = map_to_patterns(pat_map_all);
        let (anchor_patterns_utf16, pat_targets_utf16, pat_offsets_utf16) =
            map_to_patterns(pat_map_utf16);
        let has_utf16_anchors = !anchor_patterns_utf16.is_empty();
        let _has_any_anchors = !anchor_patterns_all.is_empty();
        let max_anchor_pat_len = anchor_patterns_all
            .iter()
            .map(|p| p.len())
            .max()
            .unwrap_or(0);

        // Build the base64 pre-gate from the same anchor universe as the decoded gate:
        // raw anchors plus UTF-16 variants. This keeps the pre-gate *sound* with
        // respect to anchor presence in decoded bytes, while allowing false positives.
        //
        // Padding/whitespace policy mirrors our span detection/decoder behavior:
        // - Stop at '=' (treat padding as end-of-span)
        // - Ignore RFC4648 whitespace (space is only allowed if the span finder allows it)
        let b64_gate = if anchor_patterns_all.is_empty() {
            None
        } else {
            Some(Base64YaraGate::build(
                anchor_patterns_all.iter().map(|p| p.as_slice()),
                Base64YaraGateConfig {
                    min_pattern_len: 0,
                    padding_policy: PaddingPolicy::StopAndHalt,
                    whitespace_policy: WhitespacePolicy::Rfc4648,
                },
            ))
        };

        // Warm regex caches at startup to avoid lazy allocations later.
        // `find_iter` always constructs the per-regex cache, so a tiny buffer
        // is sufficient here.
        let warm = [0u8; 1];
        for rule in &rules_compiled {
            let mut it = rule.re.find_iter(&warm);
            let _ = it.next();
        }

        let mut max_window_diameter_bytes = 0usize;
        for r in &rules {
            let base = if let Some(tp) = &r.two_phase {
                tp.full_radius
            } else {
                r.radius
            };
            // Account for raw (scale = 1) and UTF-16 (scale = 2) windows in bytes.
            for scale in [1usize, 2usize] {
                let diameter = base.saturating_mul(2).saturating_mul(scale);
                max_window_diameter_bytes = max_window_diameter_bytes.max(diameter);
            }
        }

        let max_decoded_cap = transforms
            .iter()
            .map(|tc| tc.max_decoded_bytes)
            .max()
            .unwrap_or(0);
        let max_encoded_len = transforms
            .iter()
            .map(|tc| tc.max_encoded_len)
            .max()
            .unwrap_or(0);

        // Compute per-rule flags for whether to include raw regex in prefilter DB.
        // Rules with strong literal anchors (5+ bytes, all anchors) can skip raw regex
        // prefiltering and rely on anchor patterns instead. This reduces Vectorscan DB
        // size and improves clean-data throughput.
        //
        // We require 5+ bytes (not 4) to be conservative:
        // - Short anchors may have case-sensitivity mismatches with the regex
        // - Longer anchors are more likely to be unique and correctly case-matched
        //
        // We also keep raw prefilter for case-insensitive regexes since anchor patterns
        // are byte-exact and won't match different-case variants.
        let use_raw_prefilter: Vec<bool> = rules
            .iter()
            .map(|r| {
                // Rule needs raw prefilter if:
                // 1. No anchors at all
                if r.anchors.is_empty() {
                    return true;
                }
                // 2. Regex is case-insensitive (anchors are byte-exact, won't match)
                let re_str = r.re.as_str();
                if re_str.starts_with("(?i)") || re_str.contains("(?i:") {
                    return true;
                }
                // 3. Any anchor is shorter than 5 bytes (weak anchor)
                !r.anchors.iter().all(|a| a.len() >= 5)
            })
            .collect();

        // Build prefilter anchor patterns: include UTF-16 patterns (as before) plus
        // raw patterns ONLY for rules that skip raw regex prefiltering.
        // This ensures rules with strong anchors can still be found without their
        // regex in the prefilter DB, while not adding redundant raw anchors for
        // rules that already have their regex compiled.
        let mut pat_map_prefilter: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(pat_targets_utf16.len().saturating_add(rules.len()));

        // Add all UTF-16 patterns (same as before).
        for (pat, targets) in anchor_patterns_utf16.iter().zip(
            pat_offsets_utf16
                .windows(2)
                .map(|w| &pat_targets_utf16[w[0] as usize..w[1] as usize]),
        ) {
            for &t in targets {
                add_pat_owned(&mut pat_map_prefilter, pat.clone(), t);
            }
        }

        // Add raw patterns only for rules that skip raw regex prefiltering.
        for (pat, targets) in anchor_patterns_all.iter().zip(
            pat_offsets_all
                .windows(2)
                .map(|w| &pat_targets_all[w[0] as usize..w[1] as usize]),
        ) {
            for &t in targets {
                let rid = t.rule_id();
                let var = t.variant();
                // Only add raw variant patterns for rules that skip raw regex.
                if var == Variant::Raw && !use_raw_prefilter[rid] {
                    add_pat_owned(&mut pat_map_prefilter, pat.clone(), t);
                }
            }
        }

        let (anchor_patterns_prefilter, pat_targets_prefilter, pat_offsets_prefilter) =
            map_to_patterns(pat_map_prefilter);
        let has_prefilter_anchors = !anchor_patterns_prefilter.is_empty();

        // Required: if the DB can't be built (e.g. regex incompatibility),
        // fail fast rather than falling back to full-buffer scans.
        let anchor_input = if has_prefilter_anchors {
            Some(AnchorInput {
                patterns: &anchor_patterns_prefilter,
                pat_targets: &pat_targets_prefilter,
                pat_offsets: &pat_offsets_prefilter,
                seed_radius_raw: &raw_seed_radius_bytes,
                seed_radius_utf16: &utf16_seed_radius_bytes,
            })
        } else {
            None
        };
        let vs = Some(
            VsPrefilterDb::try_new(&rules, &tuning, anchor_input, Some(&use_raw_prefilter))
                .expect("vectorscan prefilter db build failed (fallback disabled)"),
        );
        let max_regex_width = vs
            .as_ref()
            .and_then(|db| db.max_match_width_bounded())
            .map(|w| w as usize);
        // Prefer Vectorscan's bounded width; fall back to longest anchor length.
        let max_prefilter_width = max_regex_width.unwrap_or(max_anchor_pat_len);
        let vs_stream = VsStreamDb::try_new_stream(&rules, max_decoded_cap).ok();
        let needs_decoded_gate = transforms
            .iter()
            .any(|tc| tc.gate == Gate::AnchorsInDecoded);
        let vs_gate =
            if needs_decoded_gate && !anchor_patterns_all.is_empty() && vs_stream.is_some() {
                VsGateDb::try_new_gate(&anchor_patterns_all).ok()
            } else {
                None
            };
        let max_stream_window_bytes = vs_stream
            .as_ref()
            .and_then(|db| {
                db.meta()
                    .iter()
                    .map(|m| {
                        let maxw = m.max_width as usize;
                        let rad = m.radius as usize;
                        maxw.saturating_add(rad.saturating_mul(2))
                    })
                    .max()
            })
            .unwrap_or(0);
        let max_anchor_window_bytes = max_window_diameter_bytes.saturating_add(max_anchor_pat_len);
        let stream_ring_bytes = max_stream_window_bytes
            .max(max_encoded_len)
            .max(max_anchor_window_bytes)
            .max(STREAM_DECODE_CHUNK_BYTES)
            .max(1);
        let vs_utf16 = if !has_utf16_anchors {
            None
        } else {
            match VsAnchorDb::try_new_utf16(
                &anchor_patterns_utf16,
                &pat_targets_utf16,
                &pat_offsets_utf16,
                &raw_seed_radius_bytes,
                &utf16_seed_radius_bytes,
                &tuning,
            ) {
                Ok(db) => Some(db),
                Err(err) => {
                    if std::env::var_os("SCANNER_VS_UTF16_DEBUG").is_some() {
                        eprintln!("vectorscan utf16 db build failed: {err}");
                    }
                    None
                }
            }
        };
        let vs_utf16_stream = if !has_utf16_anchors {
            None
        } else {
            match VsUtf16StreamDb::try_new_utf16_stream(
                &anchor_patterns_utf16,
                &pat_targets_utf16,
                &pat_offsets_utf16,
                &raw_seed_radius_bytes,
                &utf16_seed_radius_bytes,
                &tuning,
            ) {
                Ok(db) => Some(db),
                Err(err) => {
                    if std::env::var_os("SCANNER_VS_UTF16_DEBUG").is_some() {
                        eprintln!("vectorscan utf16 stream db build failed: {err}");
                    }
                    None
                }
            }
        };
        Self {
            rules: rules_compiled,
            transforms,
            tuning,
            entropy_log2,
            vs,
            vs_utf16,
            vs_utf16_stream,
            vs_stream,
            vs_gate,
            b64_gate,
            unfilterable_rules,
            #[cfg(feature = "stats")]
            anchor_plan_stats,
            #[cfg(feature = "stats")]
            vs_stats: VectorscanCounters::default(),
            has_utf16_anchors,
            max_window_diameter_bytes,
            max_prefilter_width,
            stream_ring_bytes,
        }
    }

    /// Returns a summary of how anchors were chosen during compilation.
    #[cfg(feature = "stats")]
    pub fn anchor_plan_stats(&self) -> AnchorPlanStats {
        self.anchor_plan_stats
    }

    /// Returns Vectorscan usage counters (feature: `stats`).
    #[cfg(feature = "stats")]
    pub fn vectorscan_stats(&self) -> VectorscanStats {
        self.vs_stats
            .snapshot(self.vs.is_some(), self.vs_utf16.is_some())
    }

    /// Rules whose regex patterns could not be given a sound prefilter gate.
    ///
    /// The slice contains `(rule_index, reason)` pairs in original rule order.
    pub fn unfilterable_rules(&self) -> &[(usize, UnfilterableReason)] {
        &self.unfilterable_rules
    }

    /// Single-buffer scan helper (allocation-free after startup).
    ///
    /// Findings are stored in `scratch` and returned as a shared slice. The
    /// returned slice is valid until `scratch` is reused for another scan.
    ///
    /// Equivalent to `scan_chunk_into` with `file_id = 0` and `base_offset = 0`.
    pub fn scan_chunk<'a>(&self, hay: &[u8], scratch: &'a mut ScanScratch) -> &'a [FindingRec] {
        self.scan_chunk_into(hay, FileId(0), 0, scratch);
        scratch.findings()
    }

    /// Single-buffer scan helper that materializes findings into `out`.
    ///
    /// This clears `out` and appends all findings. `out` must have enough
    /// capacity to hold all findings; otherwise this will panic. Use
    /// `Vec::with_capacity(self.tuning.max_findings_per_chunk)` to pre-size.
    ///
    /// # Panics
    /// Panics if `out.capacity()` is smaller than the number of findings.
    pub fn scan_chunk_materialized(
        &self,
        hay: &[u8],
        scratch: &mut ScanScratch,
        out: &mut Vec<Finding>,
    ) {
        self.scan_chunk_into(hay, FileId(0), 0, scratch);
        let expected = scratch.findings().len();
        assert!(out.capacity() >= expected, "output capacity too small");
        out.clear();
        self.drain_findings_materialized(scratch, out);
    }

    /// Scans a buffer and appends findings into the provided scratch state.
    ///
    /// The scratch is reset before use and reuses its buffers to avoid per-call
    /// allocations. Findings are stored as compact [`FindingRec`] entries.
    /// When the per-chunk finding cap is exceeded, extra findings are dropped
    /// and counted in [`ScanScratch::dropped_findings`].
    ///
    /// `base_offset` is the absolute byte offset of `root_buf` within the file
    /// or stream and is used to compute `root_hint_*` fields for findings.
    ///
    /// # Preconditions
    /// - `root_buf.len() <= u32::MAX`.
    /// - `scratch` is exclusively owned for the duration of the call.
    ///
    /// # High-level flow
    /// 1. Prefilter the current buffer and build windows.
    /// 2. Run regex validation inside those windows (raw + UTF-16 variants).
    /// 3. Optionally decode transform spans (gated + deduped) and enqueue work
    ///    items for recursive scanning.
    ///
    /// Budgets (decode bytes, work items, depth) are enforced on the fly so no
    /// single input can force unbounded work.
    ///
    /// # Effects
    /// - Resets `scratch`, overwriting any pending findings.
    /// - Enqueues decode work items and updates per-scan counters.
    pub fn scan_chunk_into(
        &self,
        root_buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut ScanScratch,
    ) {
        let ((), _reset_nanos) = crate::git_scan::perf::time(|| {
            scratch.reset_for_scan(self);
        });
        crate::git_scan::perf::record_scan_reset(_reset_nanos);
        scratch.update_chunk_overlap(file_id, base_offset, root_buf.len());
        scratch.work_q.push(WorkItem::ScanBuf {
            buf: BufRef::Root,
            step_id: STEP_ROOT,
            root_hint: None,
            transform_idx: None,
            enc_ref: None,
            depth: 0,
        });

        while scratch.work_head < scratch.work_q.len() {
            // Work-queue traversal avoids recursion and makes transform depth
            // and total work item budgets explicit and enforceable.
            if scratch.total_decode_output_bytes >= self.tuning.max_total_decode_output_bytes {
                break;
            }

            let item = std::mem::take(&mut scratch.work_q[scratch.work_head]);
            scratch.work_head += 1;

            match item {
                WorkItem::ScanBuf {
                    buf,
                    step_id,
                    root_hint,
                    transform_idx,
                    enc_ref,
                    depth,
                } => {
                    let before = scratch.out.len();
                    let (buf_ptr, buf_len, buf_offset) = match &buf {
                        BufRef::Root => (root_buf.as_ptr(), root_buf.len(), 0usize),
                        BufRef::Slab(range) => unsafe {
                            debug_assert!(range.end <= scratch.slab.buf.len());
                            // SAFETY: `range` is sourced from decode output and stays in-bounds.
                            // The slab does not grow or reallocate during a scan (capacity is
                            // pre-allocated), and `scan_rules_on_buffer` never writes to the
                            // slab region backing `cur_buf`, so no aliasing violation occurs.
                            let ptr = scratch.slab.buf.as_ptr().add(range.start);
                            (ptr, range.end.saturating_sub(range.start), range.start)
                        },
                    };

                    // SAFETY: `buf_ptr` points into `root_buf` (caller-owned, immutable for
                    // the duration of the scan) or the decode slab (pre-allocated, not
                    // reallocated during a scan). `buf_len` is bounded by the checked range.
                    // No mutable references alias `cur_buf` while it is live.
                    let cur_buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len) };

                    // Build mapping context to translate decoded-space offsets back to root buffer
                    // positions. This is used when reporting findings: the `root_hint` in a finding
                    // should point to the *original* bytes in the root buffer, not intermediate
                    // decoded buffers.
                    //
                    // For nested transforms (e.g., URL inside Base64), we need to map through
                    // each decode layer. The context is only valid when the encoded span maps
                    // 1:1 with the root hint (either directly from root, or through a slab
                    // where lengths match).
                    scratch.root_span_map_ctx =
                        match (transform_idx, enc_ref.as_ref(), root_hint.as_ref()) {
                            // Encoded bytes come directly from root buffer.
                            (Some(tidx), Some(EncRef::Root(span)), Some(hint))
                                if hint.start == span.start && hint.end == span.end =>
                            {
                                Some(RootSpanMapCtx::new(
                                    &self.transforms[tidx],
                                    &root_buf[span.clone()],
                                    hint.start,
                                    scratch.chunk_overlap_backscan,
                                ))
                            }
                            // Encoded bytes are in the slab (from a prior decode). The hint length
                            // must match the span length to ensure correct offset translation.
                            (Some(tidx), Some(EncRef::Slab(span)), Some(hint))
                                if span.end <= scratch.slab.buf.len()
                                    && hint.end.saturating_sub(hint.start)
                                        == span.end.saturating_sub(span.start) =>
                            {
                                Some(RootSpanMapCtx::new(
                                    &self.transforms[tidx],
                                    &scratch.slab.buf[span.clone()],
                                    hint.start,
                                    scratch.chunk_overlap_backscan,
                                ))
                            }
                            _ => None,
                        };

                    self.scan_rules_on_buffer(
                        cur_buf,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                    );
                    scratch.root_span_map_ctx = None;
                    let found_any_in_this_buf = scratch.out.len() > before;

                    if depth >= self.tuning.max_transform_depth {
                        continue;
                    }
                    if scratch.work_items_enqueued >= self.tuning.max_work_items {
                        continue;
                    }

                    for (tidx, tc) in self.transforms.iter().enumerate() {
                        if tc.mode == TransformMode::Disabled {
                            continue;
                        }
                        if tc.mode == TransformMode::IfNoFindingsInThisBuffer
                            && found_any_in_this_buf
                        {
                            continue;
                        }
                        if cur_buf.len() < tc.min_len {
                            continue;
                        }
                        if !super::transform::transform_quick_trigger(tc, cur_buf) {
                            continue;
                        }
                        if !self.base64_buffer_gate(tc, cur_buf) {
                            continue;
                        }

                        super::transform::find_spans_into(tc, cur_buf, &mut scratch.spans);
                        if scratch.spans.is_empty() {
                            continue;
                        }

                        let span_len = scratch.spans.len().min(tc.max_spans_per_buffer);
                        for i in 0..span_len {
                            if scratch.work_items_enqueued >= self.tuning.max_work_items {
                                break;
                            }
                            if scratch.total_decode_output_bytes
                                >= self.tuning.max_total_decode_output_bytes
                            {
                                break;
                            }

                            let enc_span = scratch.spans[i].to_range();
                            let enc = &cur_buf[enc_span.clone()];
                            if tc.id == TransformId::Base64 {
                                // Base64-only prefilter: cheap encoded-space gate.
                                // This is only used when the decoded gate is enabled, and it never
                                // replaces the decoded check. It exists to avoid paying decode cost
                                // when a span cannot possibly contain any anchor after decoding.
                                #[cfg(feature = "b64-stats")]
                                {
                                    scratch.base64_stats.spans =
                                        scratch.base64_stats.spans.saturating_add(1);
                                    scratch.base64_stats.span_bytes = scratch
                                        .base64_stats
                                        .span_bytes
                                        .saturating_add(enc.len() as u64);
                                }
                                if tc.gate == Gate::AnchorsInDecoded {
                                    if let Some(gate) = &self.b64_gate {
                                        #[cfg(feature = "b64-stats")]
                                        {
                                            scratch.base64_stats.pre_gate_checks = scratch
                                                .base64_stats
                                                .pre_gate_checks
                                                .saturating_add(1);
                                        }
                                        if !gate.hits(enc) {
                                            #[cfg(feature = "b64-stats")]
                                            {
                                                scratch.base64_stats.pre_gate_skip = scratch
                                                    .base64_stats
                                                    .pre_gate_skip
                                                    .saturating_add(1);
                                                scratch.base64_stats.pre_gate_skip_bytes = scratch
                                                    .base64_stats
                                                    .pre_gate_skip_bytes
                                                    .saturating_add(enc.len() as u64);
                                            }
                                            continue;
                                        }
                                        #[cfg(feature = "b64-stats")]
                                        {
                                            scratch.base64_stats.pre_gate_pass = scratch
                                                .base64_stats
                                                .pre_gate_pass
                                                .saturating_add(1);
                                        }
                                    }
                                }
                            }

                            let mut span_starts = [0usize; 4];
                            let mut span_ends = [0usize; 4];
                            let mut span_count = 0usize;

                            if tc.id == TransformId::Base64 {
                                let allow_space_ws = tc.base64_allow_space_ws;
                                for shift in 0..4usize {
                                    let Some(rel) = super::transform::base64_skip_chars(
                                        enc,
                                        shift,
                                        allow_space_ws,
                                    ) else {
                                        break;
                                    };
                                    let start = enc_span.start.saturating_add(rel);
                                    if start >= enc_span.end {
                                        continue;
                                    }
                                    if span_starts[..span_count].contains(&start) {
                                        continue;
                                    }
                                    let enc_aligned = &cur_buf[start..enc_span.end];
                                    let remaining_chars = super::transform::base64_char_count(
                                        enc_aligned,
                                        allow_space_ws,
                                    );
                                    if remaining_chars < tc.min_len {
                                        continue;
                                    }
                                    span_starts[span_count] = start;
                                    span_ends[span_count] = enc_span.end;
                                    span_count += 1;
                                    if span_count >= span_starts.len() {
                                        break;
                                    }
                                }
                            } else {
                                span_starts[0] = enc_span.start;
                                span_ends[0] = enc_span.end;
                                span_count = 1;
                            }

                            for idx in 0..span_count {
                                if scratch.work_items_enqueued >= self.tuning.max_work_items {
                                    break;
                                }
                                if scratch.total_decode_output_bytes
                                    >= self.tuning.max_total_decode_output_bytes
                                {
                                    break;
                                }

                                let enc_span = span_starts[idx]..span_ends[idx];
                                let child_step_id = scratch.step_arena.push(
                                    step_id,
                                    DecodeStep::Transform {
                                        transform_idx: tidx,
                                        parent_span: enc_span.clone(),
                                    },
                                );

                                // Compute the child's root hint. For nested transforms, use the
                                // mapping context to translate the encoded span back to root-buffer
                                // coordinates. This ensures findings report offsets into the original
                                // input, not intermediate decoded buffers.
                                let child_root_hint =
                                    if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                                        Some(ctx.map_span(enc_span.clone()))
                                    } else if root_hint.is_none() {
                                        Some(enc_span.clone())
                                    } else {
                                        root_hint.clone()
                                    };

                                let enc_ref = match &buf {
                                    BufRef::Root => EncRef::Root(enc_span.clone()),
                                    BufRef::Slab(_) => {
                                        let start = buf_offset.saturating_add(enc_span.start);
                                        let end = buf_offset.saturating_add(enc_span.end);
                                        EncRef::Slab(start..end)
                                    }
                                };

                                scratch.work_q.push(WorkItem::DecodeSpan {
                                    transform_idx: tidx,
                                    enc_ref,
                                    step_id: child_step_id,
                                    root_hint: child_root_hint,
                                    depth: depth + 1,
                                });
                                scratch.work_items_enqueued += 1;
                            }
                        }
                    }
                }
                WorkItem::DecodeSpan {
                    transform_idx,
                    enc_ref,
                    step_id,
                    root_hint,
                    depth,
                } => {
                    #[cfg(feature = "git-perf")]
                    let _transform_start = std::time::Instant::now();

                    if scratch.total_decode_output_bytes
                        >= self.tuning.max_total_decode_output_bytes
                    {
                        continue;
                    }
                    let tc = &self.transforms[transform_idx];
                    if tc.mode == TransformMode::Disabled {
                        continue;
                    }

                    let (enc_ptr, enc_len) = match &enc_ref {
                        EncRef::Root(r) => {
                            if r.end <= root_buf.len() {
                                // SAFETY: bounds are checked against `root_buf`.
                                let ptr = unsafe { root_buf.as_ptr().add(r.start) };
                                (ptr, r.end - r.start)
                            } else {
                                continue;
                            }
                        }
                        EncRef::Slab(r) => {
                            if r.end <= scratch.slab.buf.len() {
                                // SAFETY: bounds are checked against the slab; it does not
                                // reallocate during a scan.
                                let ptr = unsafe { scratch.slab.buf.as_ptr().add(r.start) };
                                (ptr, r.end - r.start)
                            } else {
                                continue;
                            }
                        }
                    };
                    // SAFETY: `enc_ptr` points into `root_buf` or the decode slab. Both remain
                    // valid for the duration of this scan and are not reallocated.
                    let enc = unsafe { std::slice::from_raw_parts(enc_ptr, enc_len) };
                    let root_hint_maps_encoded = match (&enc_ref, &root_hint) {
                        (EncRef::Root(span), Some(hint)) => {
                            hint.start == span.start && hint.end == span.end
                        }
                        _ => false,
                    };

                    if let Some(vs_stream) = self.vs_stream.as_ref() {
                        self.decode_stream_and_scan(
                            vs_stream,
                            tc,
                            transform_idx,
                            &enc_ref,
                            enc,
                            step_id,
                            root_hint,
                            root_hint_maps_encoded,
                            depth,
                            base_offset,
                            file_id,
                            scratch,
                        );
                    } else {
                        self.decode_span_fallback(
                            tc,
                            transform_idx,
                            &enc_ref,
                            enc,
                            step_id,
                            root_hint,
                            depth,
                            base_offset,
                            file_id,
                            scratch,
                        );
                    }

                    #[cfg(feature = "git-perf")]
                    crate::git_scan::perf::record_scan_transform(
                        _transform_start.elapsed().as_nanos() as u64,
                    );
                }
            }
        }
    }

    /// Scans a buffer and returns a shared view of finding records.
    ///
    /// Delegates to [`Engine::scan_chunk_into`]; the same preconditions apply
    /// (`buf.len() <= u32::MAX`, exclusive `scratch` ownership).
    pub fn scan_chunk_records<'a>(
        &self,
        buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &'a mut ScanScratch,
    ) -> &'a [FindingRec] {
        self.scan_chunk_into(buf, file_id, base_offset, scratch);
        scratch.findings()
    }

    /// Returns the required overlap between chunks for correctness.
    ///
    /// This ensures verification windows (including two-phase expansions) fit
    /// across chunk boundaries. When scanning overlapping chunks, call
    /// [`ScanScratch::drop_prefix_findings`] with the new start offset to avoid
    /// emitting duplicates from the overlap prefix. The returned value is in
    /// bytes and already accounts for UTF-16 window scaling.
    pub fn required_overlap(&self) -> usize {
        self.max_window_diameter_bytes
            .saturating_add(self.max_prefilter_width.saturating_sub(1))
    }

    /// Returns the [`TransformId`] for the transform at position `idx` in the
    /// engine's transform list.
    ///
    /// # Panics
    /// Panics if `idx >= self.transforms.len()`.
    pub(crate) fn transform_id(&self, idx: usize) -> TransformId {
        self.transforms[idx].id
    }

    /// Returns the rule name for a rule id used in [`FindingRec`].
    pub fn rule_name(&self, rule_id: u32) -> &str {
        self.rules
            .get(rule_id as usize)
            .map(|r| r.name)
            .unwrap_or("<unknown-rule>")
    }

    /// Allocates a fresh scratch state sized for this engine.
    pub fn new_scratch(&self) -> ScanScratch {
        ScanScratch::new(self)
    }

    /// Cheap encoded-space gate for Base64 transforms.
    ///
    /// Returns `true` when the transform is not Base64 or when the encoded
    /// buffer could plausibly contain any anchor after decoding. This is a
    /// conservative optimization; decoded-space validation remains authoritative.
    #[inline]
    pub(super) fn base64_buffer_gate(&self, tc: &TransformConfig, buf: &[u8]) -> bool {
        if tc.id != TransformId::Base64 || tc.gate != Gate::AnchorsInDecoded {
            return true;
        }
        match &self.b64_gate {
            Some(gate) if gate.pattern_count() > 0 => gate.hits_anywhere(buf),
            _ => true,
        }
    }

    /// Drains compact findings from scratch and materializes provenance.
    ///
    /// This consumes `scratch.out` and appends to `out` without clearing it.
    pub fn drain_findings_materialized(&self, scratch: &mut ScanScratch, out: &mut Vec<Finding>) {
        for rec in scratch.out.drain() {
            let rule = &self.rules[rec.rule_id as usize];
            scratch
                .step_arena
                .materialize(rec.step_id, &mut scratch.steps_buf);
            let mut steps = DecodeSteps::new();
            steps.extend_from_slice(scratch.steps_buf.as_slice());
            out.push(Finding {
                rule: rule.name,
                span: (rec.span_start as usize)..(rec.span_end as usize),
                root_span_hint: u64_to_usize(rec.root_hint_start)..u64_to_usize(rec.root_hint_end),
                decode_steps: steps,
            });
        }
        scratch.norm_hash.clear();
        scratch.drop_hint_end.clear();
    }
}

/// Benchmark helper to expose span detection for transform configs.
#[cfg(feature = "bench")]
pub fn bench_find_spans_into(
    tc: &TransformConfig,
    buf: &[u8],
    out: &mut Vec<std::ops::Range<usize>>,
) {
    super::transform::find_spans_into(tc, buf, out);
}

#[cfg(feature = "bench")]
pub use super::transform::{bench_stream_decode_base64, bench_stream_decode_url};
