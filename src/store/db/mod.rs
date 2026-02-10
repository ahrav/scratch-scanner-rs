//! SQLite persistence backend for findings.
//!
//! Replaces the binary append-only log with a single SQLite database.
//!
//! # Layout
//!
//! ```text
//! <store_root>/
//!     findings.db         # main SQLite (WAL mode)
//! ```
//!
//! # Submodules
//!
//! - [`schema`] — DDL, `ensure_schema()`, migrations via `PRAGMA user_version`.
//! - [`writer`] — [`SqliteStoreProducer`] implementing [`StoreProducer`] trait.
//! - [`query`] — Read-path queries for CLI commands.

pub mod query;
pub mod schema;
pub mod writer;

pub use query::{
    diff_runs, list_findings, list_runs, list_secrets, resolve_run_pk, DiffResult, FindingRow,
    RunSummary, SecretSummary,
};
pub use schema::{
    configure_connection, configure_readonly_connection, ensure_schema, SCHEMA_VERSION,
};
pub use writer::{RunCounters, RunStatus, SqliteStoreConfig, SqliteStoreProducer};
