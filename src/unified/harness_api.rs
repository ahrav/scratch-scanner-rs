//! Feature-gated facade for benchmark and fuzz harnesses.
//!
//! This module re-exports selected internal encoder/json-writer entry points
//! without making those internals unconditional public API.

use crate::git_scan::object_id::OidBytes;

use super::events::{self, CommitMetaEvent, FindingEvent};
use super::json_write;

/// Encode a finding event into JSON object bytes (no trailing newline).
#[inline(always)]
pub fn encode_finding(f: &FindingEvent<'_>, buf: &mut Vec<u8>) {
    events::encode_finding(f, buf);
}

/// Encode a commit-meta event into JSON object bytes (no trailing newline).
#[inline(always)]
pub fn encode_commit_meta(m: &CommitMetaEvent, buf: &mut Vec<u8>) {
    events::encode_commit_meta(m, buf);
}

/// Write a `u64` as decimal ASCII.
#[inline(always)]
pub fn write_u64(n: u64, buf: &mut Vec<u8>) {
    json_write::write_u64(n, buf);
}

/// Write an [`OidBytes`] as lowercase hex (without surrounding quotes).
#[inline(always)]
pub fn write_oid_hex(oid: &OidBytes, buf: &mut Vec<u8>) {
    json_write::write_oid_hex(oid, buf);
}

/// Write an `f64` as decimal with exactly two fractional digits.
#[inline(always)]
pub fn write_f64(n: f64, buf: &mut Vec<u8>) {
    json_write::write_f64(n, buf);
}

/// Write a JSON-escaped UTF-8 string (without surrounding quotes).
#[inline(always)]
pub fn write_json_str(s: &str, buf: &mut Vec<u8>) {
    json_write::write_json_str(s, buf);
}

/// Write raw bytes as a JSON string value (without surrounding quotes).
#[inline(always)]
pub fn write_json_bytes(bytes: &[u8], buf: &mut Vec<u8>) {
    json_write::write_json_bytes(bytes, buf);
}
