//! Triage storage — user triage decisions that survive findings.db deletion.
//!
//! Stored in a separate `triage.sqlite` database alongside a `triage.meta`
//! binary file that tracks the Lamport clock and node identity.
//!
//! # Layout
//!
//! ```text
//! <store_root>/triage/
//!     triage.sqlite   # user triage state
//!     triage.meta     # Lamport clock + node identity (24 bytes)
//! ```

pub mod clock;
pub mod ops;
pub mod schema;

pub use clock::TriageClock;
pub use ops::{OccurrenceTriageRow, SecretTriageRow, TriageStatus, TriageStore};
pub use schema::{configure_triage_connection, ensure_triage_schema, TRIAGE_SCHEMA_VERSION};
