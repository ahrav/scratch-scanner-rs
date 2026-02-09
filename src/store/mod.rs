//! Persistence store contracts shared by filesystem persistence phases.
//!
//! Phase A provides:
//! - key bootstrap and run metadata (`keys`)
//! - versioned identity derivation (`identity`)

pub mod identity;
pub mod keys;

pub use identity::{
    occurrence_id, rule_fingerprint, secret_hash, IdentityError, IdentityFlags, OccurrenceId,
    OccurrenceInput, RuleFingerprint, SecretHash, VariantDiscriminant, IDENTITY_CONTRACT_VERSION,
};
pub use keys::{
    CorrelationMode, KeySource, RunModeMetadata, StoreKeys, SCANNER_SECRET_KEY_ENV,
    STORE_KEYS_VERSION,
};
