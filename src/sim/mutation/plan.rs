//! Mutation plan execution and context wrapping.
//!
//! A [`MutationPlan`] is the fully specified recipe for a single counterexample
//! test case. It names a token family, a deterministic seed, an ordered list of
//! mutation operators, and a surrounding-context wrapper. [`execute_plan`]
//! materializes it through a four-stage pipeline:
//!
//! 1. **Generate** -- produce a valid canonical token from the family + seed.
//! 2. **Mutate** -- apply operators left-to-right to perturb the token.
//! 3. **Predict** -- query the family's oracle for the expected detection
//!    outcome (`MustMatch`, `MustNotMatch`, or `MayMatch`).
//! 4. **Wrap** -- embed the mutated token in surrounding context bytes (JSON
//!    field, env assignment, etc.) and record the token's offset within them.
//!
//! The output [`GeneratedCase`] carries every intermediate artifact so that
//! test harnesses can assert on the canonical token, the mutated form, the
//! final wrapped bytes, and the predicted outcome.

use serde::{Deserialize, Serialize};

use super::family::TokenFamily;
use super::op::{apply_ops, MutOp};
use crate::sim::rng::SimRng;

/// Expected detection outcome for a mutated token.
///
/// This three-valued logic lets the test oracle distinguish between mutations
/// that **provably** break a detection invariant and mutations whose effect
/// depends on engine heuristics (entropy thresholds, boundary lookahead, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The engine **must** detect this token. No mutation alters a property
    /// the engine checks, so a miss is a false negative bug.
    MustMatch,
    /// The engine **must not** detect this token. At least one mutation breaks
    /// a hard constraint (length, charset, prefix, or checksum), so a hit is
    /// a false positive bug.
    MustNotMatch,
    /// The engine **may or may not** detect this token. The mutation affects
    /// a soft heuristic (entropy, encoding depth, trailing bytes), so either
    /// outcome is acceptable.
    MayMatch,
}

/// Surrounding context in which a mutated token is embedded.
///
/// Detection engines often behave differently depending on what surrounds a
/// candidate token (e.g. a JSON string value vs. a bare line). These wrappers
/// exercise different context-sensitivity code paths without changing the token
/// bytes themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextWrap {
    /// No wrapping -- the token bytes are the entire input.
    Raw,
    /// Shell-style environment assignment: `SECRET_KEY=<token>\n`.
    EnvAssignment,
    /// JSON object with a string field: `{"token":"<token>"}`.
    JsonField,
    /// YAML key-value: `token: <token>\n`.
    YamlValue,
    /// C-style single-line comment: `// <token>\n`.
    SingleLineComment,
    /// Python-style triple-quoted string: `"""\n<token>\n"""`.
    MultiLineString,
}

/// A token embedded within surrounding context bytes.
///
/// **Invariant:** `bytes[token_offset .. token_offset + token_len]` always
/// exactly recovers the original (possibly mutated) token bytes that were
/// passed to [`ContextWrap::wrap`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedToken {
    /// The full byte buffer including context prefix, token, and suffix.
    pub bytes: Vec<u8>,
    /// Byte offset where the token begins within `bytes`.
    pub token_offset: usize,
    /// Length of the token in bytes.
    pub token_len: usize,
}

/// A complete mutation test plan -- the serializable recipe for one test case.
///
/// Plans are designed to be generated in bulk (e.g. by a fuzzer or a property
/// test), serialized to JSON for corpus storage, and replayed deterministically
/// via [`execute_plan`]. The `base_seed` and `family` together fully determine
/// the canonical token; `ops` and `context` determine the mutation and wrapping.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutationPlan {
    /// Which secret format archetype to generate.
    pub family: TokenFamily,
    /// Seed for the deterministic RNG that produces the canonical token.
    pub base_seed: u64,
    /// Unique identifier for this case within a test run (informational only).
    pub case_id: u64,
    /// Ordered list of mutation operators applied left-to-right.
    pub ops: Vec<MutOp>,
    /// Surrounding-context wrapper applied after mutation.
    pub context: ContextWrap,
}

/// A fully materialized test case produced by [`execute_plan`].
///
/// Retains every intermediate artifact so that test assertions can inspect
/// the canonical token, the mutated form, and the final wrapped output
/// independently.
#[derive(Clone, Debug)]
pub struct GeneratedCase {
    /// Raw valid token bytes (pre-mutation).
    pub canonical: Vec<u8>,
    /// Token bytes after mutation (pre-wrap).
    pub mutated: Vec<u8>,
    /// Context-wrapped output with offset metadata.
    pub wrapped: WrappedToken,
    /// Expected detection result.
    pub expectation: Outcome,
    /// The input plan (cloned).
    pub plan: MutationPlan,
}

impl ContextWrap {
    /// Embed `token` in surrounding context bytes.
    ///
    /// Returns a [`WrappedToken`] whose `token_offset` and `token_len` fields
    /// locate the token within the output buffer. The token bytes are copied
    /// verbatim -- no escaping or encoding is applied, even for wrappers like
    /// `JsonField` where real-world usage would require escaping. This is
    /// intentional: the test exercises the engine's raw byte scanning, not
    /// JSON-aware parsing.
    pub fn wrap(self, token: &[u8]) -> WrappedToken {
        match self {
            ContextWrap::Raw => WrappedToken {
                bytes: token.to_vec(),
                token_offset: 0,
                token_len: token.len(),
            },
            ContextWrap::EnvAssignment => {
                let prefix = b"SECRET_KEY=";
                let suffix = b"\n";
                let mut bytes = Vec::with_capacity(prefix.len() + token.len() + suffix.len());
                bytes.extend_from_slice(prefix);
                let offset = bytes.len();
                bytes.extend_from_slice(token);
                bytes.extend_from_slice(suffix);
                WrappedToken {
                    bytes,
                    token_offset: offset,
                    token_len: token.len(),
                }
            }
            ContextWrap::JsonField => {
                let prefix = br#"{"token":""#;
                let suffix = br#""}"#;
                let mut bytes = Vec::with_capacity(prefix.len() + token.len() + suffix.len());
                bytes.extend_from_slice(prefix);
                let offset = bytes.len();
                bytes.extend_from_slice(token);
                bytes.extend_from_slice(suffix);
                WrappedToken {
                    bytes,
                    token_offset: offset,
                    token_len: token.len(),
                }
            }
            ContextWrap::YamlValue => {
                let prefix = b"token: ";
                let suffix = b"\n";
                let mut bytes = Vec::with_capacity(prefix.len() + token.len() + suffix.len());
                bytes.extend_from_slice(prefix);
                let offset = bytes.len();
                bytes.extend_from_slice(token);
                bytes.extend_from_slice(suffix);
                WrappedToken {
                    bytes,
                    token_offset: offset,
                    token_len: token.len(),
                }
            }
            ContextWrap::SingleLineComment => {
                let prefix = b"// ";
                let suffix = b"\n";
                let mut bytes = Vec::with_capacity(prefix.len() + token.len() + suffix.len());
                bytes.extend_from_slice(prefix);
                let offset = bytes.len();
                bytes.extend_from_slice(token);
                bytes.extend_from_slice(suffix);
                WrappedToken {
                    bytes,
                    token_offset: offset,
                    token_len: token.len(),
                }
            }
            ContextWrap::MultiLineString => {
                let prefix = b"\"\"\"\n";
                let suffix = b"\n\"\"\"";
                let mut bytes = Vec::with_capacity(prefix.len() + token.len() + suffix.len());
                bytes.extend_from_slice(prefix);
                let offset = bytes.len();
                bytes.extend_from_slice(token);
                bytes.extend_from_slice(suffix);
                WrappedToken {
                    bytes,
                    token_offset: offset,
                    token_len: token.len(),
                }
            }
        }
    }
}

/// Execute a mutation plan through the generate-mutate-predict-wrap pipeline.
///
/// The function is **pure and deterministic**: the same `plan` always produces
/// byte-identical output. This property is what makes corpus replay work --
/// a serialized plan can be re-executed months later and still produce the
/// exact same test case.
pub fn execute_plan(plan: &MutationPlan) -> GeneratedCase {
    let mut rng = SimRng::new(plan.base_seed);
    let canonical = plan.family.gen_valid(&mut rng);
    let mutated = apply_ops(&canonical, &plan.ops);
    let expectation = plan.family.expectation(&canonical, &plan.ops);
    let wrapped = plan.context.wrap(&mutated);
    GeneratedCase {
        canonical,
        mutated,
        wrapped,
        expectation,
        plan: plan.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_wrap_preserves_token_at_offset() {
        let token = b"my_secret_token";
        for ctx in [
            ContextWrap::Raw,
            ContextWrap::EnvAssignment,
            ContextWrap::JsonField,
            ContextWrap::YamlValue,
            ContextWrap::SingleLineComment,
            ContextWrap::MultiLineString,
        ] {
            let wrapped = ctx.wrap(token);
            let extracted =
                &wrapped.bytes[wrapped.token_offset..wrapped.token_offset + wrapped.token_len];
            assert_eq!(extracted, token, "context {ctx:?} broke offset invariant");
        }
    }

    #[test]
    fn serde_roundtrip_outcome() {
        for outcome in [Outcome::MustMatch, Outcome::MustNotMatch, Outcome::MayMatch] {
            let json = serde_json::to_string(&outcome).unwrap();
            let de: Outcome = serde_json::from_str(&json).unwrap();
            assert_eq!(de, outcome);
        }
    }

    #[test]
    fn serde_roundtrip_context_wrap() {
        for ctx in [
            ContextWrap::Raw,
            ContextWrap::EnvAssignment,
            ContextWrap::JsonField,
            ContextWrap::YamlValue,
            ContextWrap::SingleLineComment,
            ContextWrap::MultiLineString,
        ] {
            let json = serde_json::to_string(&ctx).unwrap();
            let de: ContextWrap = serde_json::from_str(&json).unwrap();
            assert_eq!(de, ctx);
        }
    }

    #[test]
    fn serde_roundtrip_mutation_plan() {
        use super::super::op::MutOp;
        let plan = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 42,
            case_id: 1,
            ops: vec![MutOp::Truncate { len: 10 }],
            context: ContextWrap::JsonField,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let de: MutationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(de.family, plan.family);
        assert_eq!(de.base_seed, plan.base_seed);
        assert_eq!(de.case_id, plan.case_id);
    }
}
