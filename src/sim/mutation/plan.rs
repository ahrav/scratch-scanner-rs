//! Mutation plan execution and context wrapping.
//!
//! A `MutationPlan` describes a complete test case: which token family to use,
//! which mutations to apply, and what surrounding context to wrap the result in.
//! `execute_plan` produces a `GeneratedCase` with the canonical token, mutated
//! token, wrapped output, and expected detection outcome.

use serde::{Deserialize, Serialize};

use super::family::TokenFamily;
use super::op::{apply_ops, MutOp};
use crate::sim::rng::SimRng;

/// Expected detection outcome for a mutated token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    MustMatch,
    MustNotMatch,
    MayMatch,
}

/// Surrounding context for a mutated token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextWrap {
    Raw,
    EnvAssignment,
    JsonField,
    YamlValue,
    SingleLineComment,
    MultiLineString,
}

/// A token embedded within surrounding context bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedToken {
    pub bytes: Vec<u8>,
    pub token_offset: usize,
    pub token_len: usize,
}

/// A complete mutation test plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutationPlan {
    pub family: TokenFamily,
    pub base_seed: u64,
    pub case_id: u64,
    pub ops: Vec<MutOp>,
    pub context: ContextWrap,
}

/// A fully materialized test case produced by `execute_plan`.
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
    /// Wrap a token in surrounding context, returning the wrapped bytes
    /// and the offset/length of the token within them.
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

/// Execute a mutation plan, producing a fully materialized test case.
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
