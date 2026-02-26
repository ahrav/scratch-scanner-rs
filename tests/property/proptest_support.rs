//! Proptest strategies and custom shrinker for `MutationPlan`.
//!
//! The core deliverable is `MutationPlanValueTree`, a custom `ValueTree` that
//! shrinks mutation plans in a structured priority order:
//!
//! 1. Truncate ops suffix (binary search on length)
//! 2. Remove individual ops (bitset soft deletion, backward cursor)
//! 3. Shrink op parameters (lazy binary search per field toward 0)
//! 4. Shrink context (walk ordinal toward `Raw`)
//!
//! Phase transitions are monotonic — once a phase exhausts, the shrinker
//! advances to the next phase and never returns.

use proptest::prelude::*;
use proptest::strategy::{NewTree, ValueTree};
use proptest::test_runner::TestRunner;

use scanner_rs::sim::mutation::{
    ContextWrap, MutOp, MutOpKind, MutationPlan, SecretRepr, TokenFamily,
};

// ---------------------------------------------------------------------------
// Conservative upper bounds per family (token length)
// ---------------------------------------------------------------------------

fn family_bound(family: TokenFamily) -> usize {
    match family {
        TokenFamily::AwsAccessKey => 20,
        TokenFamily::GithubFinegrainedPat => 93,
        TokenFamily::GithubClassicPat => 40,
        TokenFamily::JwtLike => 200,
        TokenFamily::Base64Blob => 68,
        TokenFamily::UrlEncodedBlob => 96,
    }
}

// ---------------------------------------------------------------------------
// Ordinal conversions
// ---------------------------------------------------------------------------

fn context_to_ordinal(ctx: ContextWrap) -> usize {
    match ctx {
        ContextWrap::Raw => 0,
        ContextWrap::EnvAssignment => 1,
        ContextWrap::JsonField => 2,
        ContextWrap::YamlValue => 3,
        ContextWrap::SingleLineComment => 4,
        ContextWrap::MultiLineString => 5,
    }
}

fn context_from_ordinal(ord: usize) -> ContextWrap {
    match ord {
        0 => ContextWrap::Raw,
        1 => ContextWrap::EnvAssignment,
        2 => ContextWrap::JsonField,
        3 => ContextWrap::YamlValue,
        4 => ContextWrap::SingleLineComment,
        _ => ContextWrap::MultiLineString,
    }
}

fn repr_to_ordinal(repr: &SecretRepr) -> usize {
    match repr {
        SecretRepr::Raw => 0,
        SecretRepr::Base64 => 1,
        SecretRepr::UrlPercent => 2,
        SecretRepr::Utf16Le => 3,
        SecretRepr::Utf16Be => 4,
        SecretRepr::Nested { depth } => 5 + (*depth as usize).saturating_sub(1),
    }
}

fn repr_from_ordinal(ord: usize) -> SecretRepr {
    match ord {
        0 => SecretRepr::Raw,
        1 => SecretRepr::Base64,
        2 => SecretRepr::UrlPercent,
        3 => SecretRepr::Utf16Le,
        4 => SecretRepr::Utf16Be,
        n => SecretRepr::Nested {
            depth: (n - 4) as u8,
        },
    }
}

// ---------------------------------------------------------------------------
// Validity check
// ---------------------------------------------------------------------------

/// Check that every op in the plan uses an op kind allowed by the family.
pub fn is_valid_plan(plan: &MutationPlan) -> bool {
    let allowed = plan.family.allowed_ops();
    plan.ops
        .iter()
        .all(|op: &MutOp| allowed.contains(&op.kind()))
}

// ---------------------------------------------------------------------------
// Leaf strategies (generation-only helpers)
// ---------------------------------------------------------------------------

/// Uniform strategy over all 6 `TokenFamily` variants.
fn arb_family() -> impl Strategy<Value = TokenFamily> {
    prop_oneof![
        Just(TokenFamily::AwsAccessKey),
        Just(TokenFamily::GithubFinegrainedPat),
        Just(TokenFamily::GithubClassicPat),
        Just(TokenFamily::JwtLike),
        Just(TokenFamily::Base64Blob),
        Just(TokenFamily::UrlEncodedBlob),
    ]
}

/// Uniform strategy over all 6 `ContextWrap` variants.
fn arb_context_wrap() -> impl Strategy<Value = ContextWrap> {
    prop_oneof![
        Just(ContextWrap::Raw),
        Just(ContextWrap::EnvAssignment),
        Just(ContextWrap::JsonField),
        Just(ContextWrap::YamlValue),
        Just(ContextWrap::SingleLineComment),
        Just(ContextWrap::MultiLineString),
    ]
}

/// Uniform strategy over `SecretRepr` unit variants + `Nested{1..=4}`.
fn arb_secret_repr() -> impl Strategy<Value = SecretRepr> {
    prop_oneof![
        Just(SecretRepr::Raw),
        Just(SecretRepr::Base64),
        Just(SecretRepr::UrlPercent),
        Just(SecretRepr::Utf16Le),
        Just(SecretRepr::Utf16Be),
        (1u8..=4).prop_map(|depth| SecretRepr::Nested { depth }),
    ]
}

/// Generate a `MutOp` from the family's allowed ops with bounded parameters.
fn arb_op_for_family(family: TokenFamily) -> BoxedStrategy<MutOp> {
    let allowed = family.allowed_ops();
    let bound = family_bound(family);

    let mut variants: Vec<BoxedStrategy<MutOp>> = Vec::new();

    for &kind in allowed {
        match kind {
            MutOpKind::Truncate => {
                variants.push((0..=bound).prop_map(|len| MutOp::Truncate { len }).boxed());
            }
            MutOpKind::CharsetViolate => {
                variants.push(
                    (proptest::collection::vec(0..bound, 0..=3), any::<u8>())
                        .prop_map(|(positions, replacement)| MutOp::CharsetViolate {
                            positions,
                            replacement,
                        })
                        .boxed(),
                );
            }
            MutOpKind::PrefixMangle => {
                variants.push(
                    proptest::collection::vec(any::<u8>(), 1..=8)
                        .prop_map(|replacement| MutOp::PrefixMangle { replacement })
                        .boxed(),
                );
            }
            MutOpKind::ChecksumCorrupt => {
                variants.push(Just(MutOp::ChecksumCorrupt).boxed());
            }
            MutOpKind::EntropyReduce => {
                variants.push(
                    (any::<u8>(), 0..=bound)
                        .prop_map(|(repeat_byte, count)| MutOp::EntropyReduce {
                            repeat_byte,
                            count,
                        })
                        .boxed(),
                );
            }
            MutOpKind::Encode => {
                variants.push(
                    arb_secret_repr()
                        .prop_map(|repr| MutOp::Encode { repr })
                        .boxed(),
                );
            }
            MutOpKind::Extend => {
                variants.push(
                    proptest::collection::vec(any::<u8>(), 0..=16)
                        .prop_map(|suffix| MutOp::Extend { suffix })
                        .boxed(),
                );
            }
        }
    }

    proptest::strategy::Union::new(variants).boxed()
}

// ---------------------------------------------------------------------------
// MutationPlanStrategy — the public entry point
// ---------------------------------------------------------------------------

const DEFAULT_MAX_OPS: usize = 8;

/// The public strategy for generating `MutationPlan` values with a custom
/// `ValueTree` that performs structured shrinking.
#[derive(Debug)]
pub struct MutationPlanStrategy;

/// Convenience constructor.
pub fn arb_plan() -> MutationPlanStrategy {
    MutationPlanStrategy
}

impl Strategy for MutationPlanStrategy {
    type Tree = MutationPlanValueTree;
    type Value = MutationPlan;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        // Generate initial values via combinator helpers.
        let family_tree = arb_family().new_tree(runner)?;
        let family = family_tree.current();

        let seed_tree = any::<u64>().new_tree(runner)?;
        let context_tree = arb_context_wrap().new_tree(runner)?;

        let ops_strategy =
            proptest::collection::vec(arb_op_for_family(family), 0..=DEFAULT_MAX_OPS);
        let ops_tree = ops_strategy.new_tree(runner)?;

        let initial = MutationPlan {
            family,
            base_seed: seed_tree.current(),
            case_id: 0,
            ops: ops_tree.current(),
            context: context_tree.current(),
        };

        Ok(MutationPlanValueTree::new(initial))
    }
}

// ---------------------------------------------------------------------------
// MutationPlanValueTree — custom shrinking
// ---------------------------------------------------------------------------

/// Shrinking phase — strictly sequential, monotonic transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShrinkPhase {
    OpsLength,
    RemoveOp,
    ShrinkParam,
    ShrinkContext,
    Done,
}

/// Tracks the last successful simplify action for `complicate()` undo.
#[derive(Clone, Debug)]
enum PrevShrink {
    /// Phase 0: restored ops length from `len` to `prev_hi`.
    TruncatedTo { prev_hi: usize },
    /// Phase 1: removed op at index `idx`.
    RemovedOp { idx: usize },
    /// Phase 2: shrank param at (op_idx_in_targets, field_idx) from prev_hi.
    ShrankParam {
        target_idx: usize,
        field_idx: usize,
        prev_hi: usize,
    },
    /// Phase 3: context ordinal was decremented.
    ShrankContext { prev_ordinal: usize },
}

/// Per-field binary search state for parameter shrinking.
#[derive(Clone, Debug)]
struct ParamSearch {
    lo: usize,
    hi: usize,
}

/// Per-op shrink targets — which fields to binary-search.
#[derive(Clone, Debug)]
struct OpParamTargets {
    /// Index into `self.ops` (the original backing vec).
    op_idx: usize,
    /// One `ParamSearch` per shrinkable field.
    fields: Vec<ParamSearch>,
}

/// Custom `ValueTree` for `MutationPlan` with structured multi-phase shrinking.
pub struct MutationPlanValueTree {
    /// The initial generated plan (family + base_seed are immutable).
    initial: MutationPlan,
    /// Backing ops storage (never modified during shrinking).
    ops: Vec<MutOp>,
    /// Bitset: which ops are included (soft deletion).
    included: Vec<bool>,

    // Phase 0 state: binary search on prefix length.
    phase: ShrinkPhase,
    len_lo: usize,
    len_hi: usize,

    // Phase 1 state: removal cursor.
    remove_cursor: usize,
    remove_exhausted: bool,

    // Phase 2 state: per-op param shrink targets (lazily built).
    param_targets: Vec<OpParamTargets>,
    param_target_idx: usize,
    param_field_idx: usize,

    // Phase 3 state: context ordinal.
    context_ordinal: usize,

    // Undo tracking.
    prev_shrink: Option<PrevShrink>,
}

impl MutationPlanValueTree {
    pub fn new(plan: MutationPlan) -> Self {
        let n = plan.ops.len();
        let context_ordinal = context_to_ordinal(plan.context);
        MutationPlanValueTree {
            ops: plan.ops.clone(),
            included: vec![true; n],
            initial: plan,
            phase: ShrinkPhase::OpsLength,
            len_lo: 0,
            len_hi: n,
            remove_cursor: n.saturating_sub(1),
            remove_exhausted: false,
            param_targets: Vec::new(),
            param_target_idx: 0,
            param_field_idx: 0,
            context_ordinal,
            prev_shrink: None,
        }
    }

    /// Reconstruct the current `MutationPlan` from the shrinker state.
    fn current_plan(&self) -> MutationPlan {
        MutationPlan {
            family: self.initial.family,
            base_seed: self.initial.base_seed,
            case_id: self.initial.case_id,
            ops: self.current_ops(),
            context: context_from_ordinal(self.context_ordinal),
        }
    }

    /// Collect included ops, applying any parameter shrinks from phase 2.
    fn current_ops(&self) -> Vec<MutOp> {
        let mut ops: Vec<MutOp> = self
            .ops
            .iter()
            .enumerate()
            .filter(|&(i, _)| self.included[i])
            .map(|(_, op): (usize, &MutOp)| op.clone())
            .collect();

        // Apply parameter shrinks from phase 2 targets.
        for target in &self.param_targets {
            // Find this op's position in the filtered list.
            let filtered_idx = self
                .ops
                .iter()
                .enumerate()
                .filter(|(i, _)| self.included[*i])
                .position(|(i, _)| i == target.op_idx);

            if let Some(idx) = filtered_idx {
                if idx < ops.len() {
                    ops[idx] = self.apply_param_shrinks(&ops[idx], target);
                }
            }
        }

        ops
    }

    /// Apply the current binary search values from a target's fields to an op.
    fn apply_param_shrinks(&self, op: &MutOp, target: &OpParamTargets) -> MutOp {
        match op {
            MutOp::Truncate { .. } => {
                let len = target.fields.first().map_or(0, |f| f.lo);
                MutOp::Truncate { len }
            }
            MutOp::CharsetViolate {
                positions,
                replacement,
            } => {
                // Shrink positions toward empty and replacement toward 0.
                let pos_count = target.fields.first().map_or(positions.len(), |f| f.lo);
                let repl = target.fields.get(1).map_or(*replacement, |f| f.lo as u8);
                MutOp::CharsetViolate {
                    positions: positions[..pos_count.min(positions.len())].to_vec(),
                    replacement: repl,
                }
            }
            MutOp::PrefixMangle { replacement } => {
                let len = target.fields.first().map_or(replacement.len(), |f| f.lo);
                MutOp::PrefixMangle {
                    replacement: replacement[..len.min(replacement.len())].to_vec(),
                }
            }
            MutOp::ChecksumCorrupt => MutOp::ChecksumCorrupt,
            MutOp::EntropyReduce { repeat_byte, count } => {
                let rb = target.fields.first().map_or(*repeat_byte, |f| f.lo as u8);
                let c = target.fields.get(1).map_or(*count, |f| f.lo);
                MutOp::EntropyReduce {
                    repeat_byte: rb,
                    count: c,
                }
            }
            MutOp::Encode { repr } => {
                let ord = target
                    .fields
                    .first()
                    .map_or(repr_to_ordinal(repr), |f| f.lo);
                MutOp::Encode {
                    repr: repr_from_ordinal(ord),
                }
            }
            MutOp::Extend { suffix } => {
                let len = target.fields.first().map_or(suffix.len(), |f| f.lo);
                MutOp::Extend {
                    suffix: suffix[..len.min(suffix.len())].to_vec(),
                }
            }
        }
    }

    /// Count currently included ops.
    fn included_count(&self) -> usize {
        self.included.iter().filter(|&&b| b).count()
    }

    /// Advance to the next phase.
    fn advance_phase(&mut self) {
        self.phase = match self.phase {
            ShrinkPhase::OpsLength => {
                // Set up phase 1 cursor based on current included ops.
                let count = self.included_count();
                self.remove_cursor = if count == 0 { 0 } else { self.ops.len() - 1 };
                ShrinkPhase::RemoveOp
            }
            ShrinkPhase::RemoveOp => {
                self.build_param_targets();
                self.param_target_idx = 0;
                self.param_field_idx = 0;
                ShrinkPhase::ShrinkParam
            }
            ShrinkPhase::ShrinkParam => ShrinkPhase::ShrinkContext,
            ShrinkPhase::ShrinkContext | ShrinkPhase::Done => ShrinkPhase::Done,
        };
    }

    /// Lazily build phase 2 shrink targets from the post-removal ops.
    fn build_param_targets(&mut self) {
        self.param_targets.clear();
        for (i, op) in self.ops.iter().enumerate() {
            if !self.included[i] {
                continue;
            }
            let fields = Self::extract_fields(op);
            if !fields.is_empty() {
                self.param_targets
                    .push(OpParamTargets { op_idx: i, fields });
            }
        }
    }

    /// Extract shrinkable fields from an op as binary search ranges.
    fn extract_fields(op: &MutOp) -> Vec<ParamSearch> {
        match op {
            MutOp::Truncate { len } => vec![ParamSearch { lo: 0, hi: *len }],
            MutOp::CharsetViolate {
                positions,
                replacement,
            } => {
                let mut fields = Vec::new();
                if !positions.is_empty() {
                    fields.push(ParamSearch {
                        lo: 0,
                        hi: positions.len(),
                    });
                }
                fields.push(ParamSearch {
                    lo: 0,
                    hi: *replacement as usize,
                });
                fields
            }
            MutOp::PrefixMangle { replacement } => {
                if replacement.is_empty() {
                    vec![]
                } else {
                    vec![ParamSearch {
                        lo: 0,
                        hi: replacement.len(),
                    }]
                }
            }
            MutOp::ChecksumCorrupt => vec![],
            MutOp::EntropyReduce {
                repeat_byte, count, ..
            } => vec![
                ParamSearch {
                    lo: 0,
                    hi: *repeat_byte as usize,
                },
                ParamSearch { lo: 0, hi: *count },
            ],
            MutOp::Encode { repr } => {
                let ord = repr_to_ordinal(repr);
                if ord == 0 {
                    vec![]
                } else {
                    vec![ParamSearch { lo: 0, hi: ord }]
                }
            }
            MutOp::Extend { suffix } => {
                if suffix.is_empty() {
                    vec![]
                } else {
                    vec![ParamSearch {
                        lo: 0,
                        hi: suffix.len(),
                    }]
                }
            }
        }
    }

    /// Phase 0: binary search on ops prefix length.
    fn simplify_ops_length(&mut self) -> bool {
        if self.len_lo >= self.len_hi {
            self.advance_phase();
            return self.simplify();
        }

        let mid = self.len_lo + (self.len_hi - self.len_lo) / 2;

        // Exclude ops beyond `mid`.
        let mut count = 0;
        for i in 0..self.ops.len() {
            if self.included[i] {
                if count >= mid {
                    self.included[i] = false;
                }
                count += 1;
            }
        }

        let plan = self.current_plan();
        if !is_valid_plan(&plan) {
            // Revert: restore all included, then re-exclude beyond len_hi.
            self.included = vec![true; self.ops.len()];
            for (i, b) in self.included.iter_mut().enumerate() {
                if i >= self.len_hi {
                    *b = false;
                }
            }
            self.len_lo = mid + 1;
            return self.simplify_ops_length();
        }

        self.prev_shrink = Some(PrevShrink::TruncatedTo {
            prev_hi: self.len_hi,
        });
        self.len_hi = mid;
        true
    }

    /// Phase 1: remove individual ops via bitset soft deletion.
    fn simplify_remove_op(&mut self) -> bool {
        if self.remove_exhausted {
            self.advance_phase();
            return self.simplify();
        }

        // Find next included index, scanning backward from cursor.
        loop {
            if !self.included.iter().any(|&b| b) {
                self.advance_phase();
                return self.simplify();
            }

            // Find an included index at or before cursor.
            let candidate = (0..=self.remove_cursor).rev().find(|&i| self.included[i]);

            let Some(idx) = candidate else {
                self.advance_phase();
                return self.simplify();
            };

            self.included[idx] = false;

            let plan = self.current_plan();
            if !is_valid_plan(&plan) {
                // Revert and try next position.
                self.included[idx] = true;
                if idx == 0 {
                    self.advance_phase();
                    return self.simplify();
                }
                self.remove_cursor = idx - 1;
                continue;
            }

            self.prev_shrink = Some(PrevShrink::RemovedOp { idx });
            if idx == 0 {
                // No lower indices left; next simplify should advance phase.
                self.remove_exhausted = true;
            } else {
                self.remove_cursor = idx - 1;
            }
            return true;
        }
    }

    /// Phase 2: shrink op parameters via binary search.
    fn simplify_shrink_param(&mut self) -> bool {
        loop {
            if self.param_target_idx >= self.param_targets.len() {
                self.advance_phase();
                return self.simplify();
            }

            let target = &self.param_targets[self.param_target_idx];
            if self.param_field_idx >= target.fields.len() {
                self.param_target_idx += 1;
                self.param_field_idx = 0;
                continue;
            }

            let field = &self.param_targets[self.param_target_idx].fields[self.param_field_idx];
            if field.lo >= field.hi {
                self.param_field_idx += 1;
                continue;
            }

            let mid = field.lo + (field.hi - field.lo) / 2;
            let prev_hi = self.param_targets[self.param_target_idx].fields[self.param_field_idx].hi;

            self.param_targets[self.param_target_idx].fields[self.param_field_idx].hi = mid;

            let plan = self.current_plan();
            if !is_valid_plan(&plan) {
                // Revert.
                self.param_targets[self.param_target_idx].fields[self.param_field_idx].hi = prev_hi;
                self.param_targets[self.param_target_idx].fields[self.param_field_idx].lo = mid + 1;
                continue;
            }

            self.prev_shrink = Some(PrevShrink::ShrankParam {
                target_idx: self.param_target_idx,
                field_idx: self.param_field_idx,
                prev_hi,
            });
            return true;
        }
    }

    /// Phase 3: shrink context ordinal toward Raw (0).
    fn simplify_shrink_context(&mut self) -> bool {
        if self.context_ordinal == 0 {
            self.advance_phase();
            return false;
        }

        let prev = self.context_ordinal;
        self.context_ordinal -= 1;
        self.prev_shrink = Some(PrevShrink::ShrankContext { prev_ordinal: prev });
        true
    }
}

impl ValueTree for MutationPlanValueTree {
    type Value = MutationPlan;

    fn current(&self) -> MutationPlan {
        self.current_plan()
    }

    fn simplify(&mut self) -> bool {
        match self.phase {
            ShrinkPhase::OpsLength => self.simplify_ops_length(),
            ShrinkPhase::RemoveOp => self.simplify_remove_op(),
            ShrinkPhase::ShrinkParam => self.simplify_shrink_param(),
            ShrinkPhase::ShrinkContext => self.simplify_shrink_context(),
            ShrinkPhase::Done => false,
        }
    }

    fn complicate(&mut self) -> bool {
        let Some(prev) = self.prev_shrink.take() else {
            return false;
        };

        match prev {
            PrevShrink::TruncatedTo { prev_hi } => {
                // Undo: restore len_hi, set lo = current hi + 1.
                let current_hi = self.len_hi;
                self.len_hi = prev_hi;
                self.len_lo = current_hi + 1;

                // Re-include ops up to prev_hi.
                self.included = vec![false; self.ops.len()];
                for (i, b) in self.included.iter_mut().enumerate() {
                    if i < prev_hi {
                        *b = true;
                    }
                }
                true
            }
            PrevShrink::RemovedOp { idx } => {
                self.included[idx] = true;
                // After re-including, cursor is already past this index,
                // so the next simplify won't retry it. If we were at idx=0
                // and flagged exhausted, clear the flag but keep phase at
                // RemoveOp so the next simplify transitions to Phase 2.
                if idx == 0 {
                    self.remove_exhausted = true;
                }
                true
            }
            PrevShrink::ShrankParam {
                target_idx,
                field_idx,
                prev_hi,
            } => {
                if target_idx < self.param_targets.len()
                    && field_idx < self.param_targets[target_idx].fields.len()
                {
                    let field = &mut self.param_targets[target_idx].fields[field_idx];
                    field.lo = field.hi + 1;
                    field.hi = prev_hi;
                    true
                } else {
                    false
                }
            }
            PrevShrink::ShrankContext { prev_ordinal } => {
                self.context_ordinal = prev_ordinal;
                true
            }
        }
    }
}

impl std::fmt::Debug for MutationPlanValueTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationPlanValueTree")
            .field("phase", &self.phase)
            .field("included_count", &self.included_count())
            .field("context_ordinal", &self.context_ordinal)
            .finish()
    }
}
