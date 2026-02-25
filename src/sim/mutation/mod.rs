//! Shared deterministic mutation framework for counterexample generation.
//!
//! Provides encoding functions, token family definitions, mutation operators,
//! and plan execution that both property tests and sim-harness tests consume.

pub mod encode;
pub mod family;
pub mod op;
pub mod plan;

pub use encode::{
    base62_encode_u32, base64_encode_std, base64url_encode_nopad, encode_nested, encode_secret,
    encode_utf16, hex_nibble, percent_encode_all, SecretRepr, BASE62_CHARS, BASE64_STD,
    TOKEN_ALPHABET,
};
pub use family::{Outcome, TokenFamily};
pub use op::{apply_ops, MutOp, MutOpKind};
pub use plan::{execute_plan, ContextWrap, GeneratedCase, MutationPlan, WrappedToken};
