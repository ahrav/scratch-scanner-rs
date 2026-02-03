//! Vectorscan/Hyperscan prefilter integration for raw-byte and decoded-stream scanning.
//!
//! # Scope
//! This module builds and runs Vectorscan databases for three prefilter paths:
//! - Raw bytes (block mode) via `VsPrefilterDb`.
//! - Decoded streams (stream mode) via `VsStreamDb`.
//! - UTF-16 anchors and decoded-space gating via `VsAnchorDb`, `VsUtf16StreamDb`,
//!   and `VsGateDb`.
//!
//! # Pattern id layout
//! - Raw rule expressions are compiled first; their ids are `0..raw_rule_count`.
//! - Optional anchor literal patterns are appended; their ids start at `anchor_id_base`.
//! - `raw_rule_ids` maps raw pattern index -> rule id; anchor patterns map via
//!   the `anchor_*` tables.
//!
//! # Coordinate systems
//! - Raw/UTF-16 anchor scans operate on raw-byte offsets in the scanned buffer.
//! - Stream prefilters emit decoded-byte offsets in the post-transform stream.
//!
//! # Match offsets
//! Vectorscan reports `from`/`to` offsets in the coordinate system of the scan
//! input. We treat `to` as the match end offset for window seeding and derive
//! the start from the bounded `max_width` estimate when available.
//!
//! # Correctness contract
//! Prefiltering is conservative: it may add extra windows but must never drop
//! true matches. Window math is saturating and clamped to the available
//! haystack length when known to avoid under-seeding on overflow.
//!
//! # Invariants and safety
//! - Compiled databases are immutable and may be shared across threads.
//! - Each scanning thread must use its own `hs_scratch_t` (`VsScratch`).
//! - Match callbacks must never panic or unwind across the FFI boundary.
//! - Callback `ctx` pointers are valid only for the duration of a scan.
//! - Scan buffers must fit in `u32`; some entrypoints return errors when lengths
//!   exceed that bound, others assume callers pre-chunk input accordingly.
//!
//! # Window seeding
//! 1. Compile each rule regex in block mode with `HS_FLAG_PREFILTER` to get
//!    conservative hits.
//! 2. Use `hs_expression_info` to estimate `max_width` for overlap sizing.
//! 3. On a match, seed a window around the match end (conservative).
//! 4. Optionally include UTF-16 anchor patterns in the same database to avoid
//!    a second scan pass.
//!
//! # Design choices
//! - If window math saturates `u32`, we fall back to whole-buffer windows rather
//!   than risking under-seeding.
//! - UTF-16 scanning always uses anchor databases; Vectorscan only gates
//!   raw-byte and decoded-stream variants.
//!
//! # Limits and fallback behavior
//! - Scan APIs accept `u32` lengths; we return errors when a haystack exceeds
//!   that bound.
//! - If multi-compile fails for raw rules, we fall back to per-rule compilation
//!   to pinpoint rejects; any rejected pattern returns an error.
//! - Empty UTF-16/gate pattern sets return an error early.
use crate::api::{RuleSpec, Tuning};
use libc::{c_char, c_int, c_uint, c_void};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::ptr;

use vectorscan_rs_sys as vs;

use super::hit_pool::SpanU32;
use super::rule_repr::{Target, Variant};
use super::scratch::ScanScratch;

/// Compiled Vectorscan database plus per-rule window metadata for raw-byte scanning.
///
/// The database is immutable after compilation and can be shared across
/// threads, but each thread must allocate its own `VsScratch`.
///
/// Raw pattern ids follow compile order; `raw_rule_ids` maps expression index
/// -> rule id. If we fall back to per-rule compilation, `raw_missing_rules`
/// records rejected rules (and the build fails). Optional UTF-16 anchor patterns are
/// appended after raw patterns and resolved via the `anchor_*` mapping tables.
pub(crate) struct VsPrefilterDb {
    /// Compiled Vectorscan block-mode database.
    db: *mut vs::hs_database_t,
    /// Number of raw rule patterns in the database.
    raw_rule_count: u32,
    /// Per-raw-pattern seed radius for window expansion.
    raw_seed_radius: Vec<u32>,
    /// Maps raw pattern index to rule id.
    raw_rule_ids: Vec<u32>,
    /// Per-raw-pattern maximum match width from `hs_expression_info`.
    raw_match_widths: Vec<u32>,
    /// Rule ids that failed individual compilation (fallback path).
    raw_missing_rules: Vec<u32>,
    /// Pattern id where anchor literals begin (equals `raw_rule_count`).
    anchor_id_base: u32,
    /// Number of anchor literal patterns.
    anchor_pat_count: u32,
    /// Rule/variant targets for anchor patterns.
    anchor_targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `anchor_targets`.
    anchor_pat_offsets: Vec<u32>,
    /// Byte length of each anchor pattern.
    anchor_pat_lens: Vec<u32>,
    /// Max bounded width across all rules.
    max_width: u32,
    /// True if any rule reports an unbounded width.
    unbounded: bool,
}

/// Per-rule metadata for stream-mode window seeding.
///
/// `max_width` is derived from `hs_expression_info` in decoded-byte space and may
/// be capped; a reported 0 width is treated as unbounded. When unbounded,
/// `whole_buffer_on_hit` is set and the callback asks the caller to scan the
/// full decoded stream instead of emitting offsets. `radius` comes from rule
/// tuning and expands windows around the match end.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VsStreamMeta {
    pub(crate) max_width: u32,
    pub(crate) radius: u32,
    pub(crate) whole_buffer_on_hit: u32,
}

/// Compiled Vectorscan database for stream-mode scanning.
///
/// This is used for decoded-stream prefiltering; matches are converted into
/// candidate windows in the caller using `VsStreamMeta` indexed by rule id.
/// The `meta` vector is aligned to rule ids assigned at compile time.
pub(crate) struct VsStreamDb {
    /// Compiled Vectorscan stream-mode database.
    db: *mut vs::hs_database_t,
    /// Per-rule window metadata indexed by rule id.
    meta: Vec<VsStreamMeta>,
}

/// Vectorscan stream database for decoded-space anchor gating.
///
/// Uses literal byte patterns to detect whether any anchor variant appears in
/// a decoded stream. Patterns are compiled with `HS_FLAG_SINGLEMATCH` to avoid
/// repeated callbacks once a hit is detected.
/// A hit serves as a decoded-space gate signal; callers may skip downstream
/// scanning when no anchors are observed.
pub(crate) struct VsGateDb {
    /// Compiled Vectorscan stream-mode database for gate detection.
    db: *mut vs::hs_database_t,
}

// Safe because hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsStreamDb {}
unsafe impl Sync for VsStreamDb {}

// Safe because hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsGateDb {}
unsafe impl Sync for VsGateDb {}

impl Drop for VsStreamDb {
    fn drop(&mut self) {
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

impl Drop for VsGateDb {
    fn drop(&mut self) {
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

// Safe because hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsPrefilterDb {}
unsafe impl Sync for VsPrefilterDb {}

impl Drop for VsPrefilterDb {
    fn drop(&mut self) {
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

/// Per-thread Vectorscan scratch space bound to a specific database.
///
/// This must only be used with the database it was allocated for and must not
/// be used concurrently from multiple threads. Dropping it releases the
/// underlying `hs_scratch_t`.
pub(crate) struct VsScratch {
    /// Opaque Vectorscan scratch handle (must not be shared across threads).
    scratch: *mut vs::hs_scratch_t,
    /// Database this scratch was allocated for (used for binding validation).
    db: *mut vs::hs_database_t,
}

impl VsScratch {
    /// Returns the database pointer this scratch was allocated for.
    #[inline]
    pub(crate) fn bound_db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }
}

/// Opaque stream handle for stream-mode scanning.
///
/// Must be closed with `close_stream` to flush end-of-stream matches.
pub(crate) struct VsStream {
    /// Opaque Vectorscan stream handle.
    stream: *mut vs::hs_stream_t,
}

impl VsStreamDb {
    /// Build a stream-mode database for decoded-byte scanning.
    ///
    /// Uses `hs_expression_info` to estimate match width; a zero width is
    /// treated as unbounded and capped by `max_decoded_cap` when nonzero.
    /// Patterns are compiled with `HS_FLAG_PREFILTER`; hits are conservative
    /// and used only for window seeding.
    pub(crate) fn try_new_stream(
        rules: &[RuleSpec],
        max_decoded_cap: usize,
    ) -> Result<Self, String> {
        let mut c_patterns: Vec<CString> = Vec::with_capacity(rules.len());
        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(rules.len());
        let mut flags: Vec<c_uint> = Vec::with_capacity(rules.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(rules.len());
        let mut meta: Vec<VsStreamMeta> = Vec::with_capacity(rules.len());

        for (rid, r) in rules.iter().enumerate() {
            let radius = if let Some(tp) = &r.two_phase {
                tp.full_radius
            } else {
                r.radius
            };

            let radius_u32 = usize_to_u32_saturating(radius);
            let (mut max_width_u32, c_pat) = expression_info_prefilter_max_width(r.re.as_str())?;
            let mut whole_buffer_on_hit = 0u32;
            if max_width_u32 == 0 {
                whole_buffer_on_hit = 1;
                max_width_u32 = u32::MAX;
            }
            if max_width_u32 == u32::MAX {
                let cap = usize_to_u32_saturating(max_decoded_cap);
                if cap > 0 {
                    max_width_u32 = cap;
                }
            }

            meta.push(VsStreamMeta {
                max_width: max_width_u32,
                radius: radius_u32,
                whole_buffer_on_hit,
            });

            c_patterns.push(c_pat);
            expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
            flags.push(vs::HS_FLAG_PREFILTER as c_uint);
            ids.push(rid as c_uint);
        }

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        let platform = unsafe { platform.assume_init() };

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_STREAM as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        Ok(Self { db, meta })
    }

    /// Allocates a new scratch space bound to this database.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns per-rule window metadata for stream match processing.
    #[inline]
    pub(crate) fn meta(&self) -> &[VsStreamMeta] {
        &self.meta
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Opens a new stream handle bound to this database.
    pub(crate) fn open_stream(&self) -> Result<VsStream, String> {
        let mut stream: *mut vs::hs_stream_t = ptr::null_mut();
        let rc = unsafe { vs::hs_open_stream(self.db, 0, &mut stream) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_open_stream failed: rc={rc}"));
        }
        Ok(VsStream { stream })
    }

    /// Scans a stream chunk and delivers matches to `on_event`.
    ///
    /// `scratch` must be allocated for this database; `ctx` must remain valid
    /// for the duration of the call. `HS_SCAN_TERMINATED` is treated as success to
    /// allow early termination in callbacks.
    pub(crate) fn scan_stream(
        &self,
        stream: &mut VsStream,
        data: &[u8],
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let len_u32: c_uint = data
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan_stream: {} bytes", data.len()))?;
        let rc = unsafe {
            vs::hs_scan_stream(
                stream.stream,
                data.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                scratch.scratch,
                on_event,
                ctx,
            )
        };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_scan_stream failed: rc={rc}"))
        }
    }

    /// Closes a stream, flushing end-of-stream matches via `on_event`.
    ///
    /// `scratch` must be allocated for this database; `ctx` must remain valid
    /// for the duration of the call.
    pub(crate) fn close_stream(
        &self,
        stream: VsStream,
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let rc = unsafe { vs::hs_close_stream(stream.stream, scratch.scratch, on_event, ctx) };
        if rc == vs::HS_SUCCESS as c_int {
            Ok(())
        } else {
            Err(format!("hs_close_stream failed: rc={rc}"))
        }
    }
}

/// Stream match event used by decoded-byte scanning.
///
/// `lo`/`hi` bound the candidate window (decoded-byte offsets, half-open
/// `[lo, hi)`) to verify.
/// `variant_idx` matches `Variant::idx()`. `force_full` asks the caller to
/// fall back to a full decode scan and ignore `lo`/`hi`.
/// `lo`/`hi` are not clamped to the current stream length; callers must clamp
/// when materializing decode work.
///
/// `anchor_hint` is Vectorscan's `from` match offset, preserved to start regex
/// searches near the anchor instead of at window start.
#[repr(C)]
pub(crate) struct VsStreamWindow {
    pub(crate) rule_id: u32,
    pub(crate) lo: u64,
    pub(crate) hi: u64,
    pub(crate) variant_idx: u8,
    pub(crate) force_full: bool,
    /// Anchor hint from Vectorscan's `from` offset.
    pub(crate) anchor_hint: u64,
}

/// Callback context for stream-mode scans on decoded byte streams.
///
/// Unlike `VsUtf16StreamMatchCtx`, this does not include a `base_offset` field
/// because standard stream scanning processes the entire decoded buffer in a
/// single stream, so match offsets are already absolute within that buffer.
///
/// Safety invariants:
/// - `pending` points to a live `Vec<VsStreamWindow>` for the duration of the scan.
/// - `pending` is not accessed concurrently while the scan runs.
/// - `meta` points to an array of `meta_len` entries indexed by rule id.
/// - `meta_len` matches the number of compiled rules; ids are expected to be `< meta_len`.
#[repr(C)]
pub(crate) struct VsStreamMatchCtx {
    pub(crate) pending: *mut Vec<VsStreamWindow>,
    pub(crate) meta: *const VsStreamMeta,
    pub(crate) meta_len: u32,
}

/// Callback context for UTF-16 anchor stream scans.
///
/// Unlike `VsStreamMatchCtx`, this includes a `base_offset` field because UTF-16
/// decoded streams may be processed across multiple chunks, and each scan_stream
/// call reports offsets relative to that chunk. `base_offset` translates those
/// stream-local offsets into absolute positions within the full decoded output.
///
/// Safety invariants:
/// - `pending` points to a live `Vec<VsStreamWindow>` for the duration of the scan.
/// - `pending` is not accessed concurrently while the scan runs.
/// - `targets`/`pat_offsets`/`pat_lens` describe the UTF-16 anchor mapping tables.
/// - `pat_offsets` has length `pat_count + 1` and is monotonically increasing.
/// - `pat_offsets[pat_count]` equals the number of `targets` entries.
/// - `pat_lens` has length `pat_count`.
/// - `base_offset` converts stream-local match offsets into absolute decoded offsets.
#[repr(C)]
pub(crate) struct VsUtf16StreamMatchCtx {
    pub(crate) pending: *mut Vec<VsStreamWindow>,
    pub(crate) targets: *const VsAnchorTarget,
    pub(crate) pat_offsets: *const u32,
    pub(crate) pat_lens: *const u32,
    pub(crate) pat_count: u32,
    pub(crate) base_offset: u64,
}

/// Stream-mode match callback. Pushes window seeds into `pending`.
///
/// # Safety
/// - `ctx` must be non-null and point to a valid `VsStreamMatchCtx`.
/// - `pending` and `meta` must outlive the call and not be accessed concurrently.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_on_stream_match(
    id: c_uint,
    from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let c = &mut *(ctx as *mut VsStreamMatchCtx);
    if id >= c.meta_len {
        return 0;
    }
    let meta = *c.meta.add(id as usize);
    if meta.whole_buffer_on_hit != 0 {
        let pending = &mut *c.pending;
        pending.push(VsStreamWindow {
            rule_id: id,
            lo: 0,
            hi: 0,
            variant_idx: 0,
            force_full: true,
            anchor_hint: from,
        });
        return 0;
    }
    let max_width = meta.max_width as u64;
    let radius = meta.radius as u64;
    let lo = to.saturating_sub(max_width.saturating_add(radius));
    let hi = to.saturating_add(radius);

    // Clamp anchor hint to window bounds.
    let anchor_hint = from.clamp(lo, to);

    let pending = &mut *c.pending;
    pending.push(VsStreamWindow {
        rule_id: id,
        lo,
        hi,
        variant_idx: 0,
        force_full: false,
        anchor_hint,
    });
    0
}

pub(crate) fn stream_match_callback() -> vs::match_event_handler {
    Some(vs_on_stream_match)
}

/// Decoded-space gate callback. Marks a hit and continues scanning.
///
/// # Safety
/// - `ctx` must point to a valid `u8` flag for the duration of the call.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_gate_on_match(
    _id: c_uint,
    _from: u64,
    _to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let hit = &mut *(ctx as *mut u8);
    *hit = 1;
    0
}

pub(crate) fn gate_match_callback() -> vs::match_event_handler {
    Some(vs_gate_on_match)
}

/// UTF-16 stream match callback. Seeds UTF-16 variant windows into `pending`.
///
/// Converts stream-local match offsets into absolute decoded offsets using
/// `base_offset`.
///
/// # Safety
/// - `ctx` must point to a valid `VsUtf16StreamMatchCtx`.
/// - `pending` and UTF-16 mapping tables must outlive the call and not be
///   accessed concurrently.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_utf16_stream_on_match(
    id: c_uint,
    from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let c = &mut *(ctx as *mut VsUtf16StreamMatchCtx);
    if id >= c.pat_count {
        return 0;
    }

    let pid = id as usize;
    let len = *c.pat_lens.add(pid) as u64;
    let end = c.base_offset.saturating_add(to);
    let start = end.saturating_sub(len);

    // Compute absolute anchor hint from base_offset + from.
    let abs_from = c.base_offset.saturating_add(from);

    let off_start = *c.pat_offsets.add(pid) as usize;
    let off_end = *c.pat_offsets.add(pid + 1) as usize;

    let pending = &mut *c.pending;
    for i in off_start..off_end {
        let target = *c.targets.add(i);
        let seed = target.seed_radius_bytes as u64;
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed);
        // Clamp anchor hint to window bounds.
        let anchor_hint = abs_from.clamp(lo, end);
        pending.push(VsStreamWindow {
            rule_id: target.rule_id,
            lo,
            hi,
            variant_idx: target.variant_idx,
            force_full: false,
            anchor_hint,
        });
    }
    0
}

pub(crate) fn utf16_stream_match_callback() -> vs::match_event_handler {
    Some(vs_utf16_stream_on_match)
}

/// Mapping from UTF-16 anchor patterns to rule/variant targets.
///
/// `seed_radius_bytes` is the extra padding (raw bytes, in the UTF-16 byte
/// stream) applied around the matched anchor when seeding windows.
/// `variant_idx` matches `Variant::idx()` (0=raw, 1=utf16-le, 2=utf16-be).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VsAnchorTarget {
    rule_id: u32,
    variant_idx: u8,
    seed_radius_bytes: u32,
}

/// Inputs describing anchor literal patterns and their target rules.
///
/// `patterns` holds raw byte patterns (raw and/or UTF-16-encoded). `pat_targets`
/// is a flat list of rule/variant targets, and `pat_offsets` is a prefix-sum
/// table mapping each pattern to its target slice.
///
/// `seed_radius_raw` and `seed_radius_utf16` are indexed by rule id and used
/// based on each target's variant.
///
/// Expected shape (defensively validated):
/// - `pat_offsets.len()` should be `patterns.len() + 1`, with the last offset
///   equal to `pat_targets.len()`.
/// - Out-of-range offsets are treated as empty ranges.
/// - Missing `seed_radius_*` entries default to zero padding.
pub(crate) struct AnchorInput<'a> {
    pub(crate) patterns: &'a [Vec<u8>],
    pub(crate) pat_targets: &'a [Target],
    pub(crate) pat_offsets: &'a [u32],
    pub(crate) seed_radius_raw: &'a [u32],
    pub(crate) seed_radius_utf16: &'a [u32],
}

/// Intermediate anchor pattern data for database compilation.
///
/// Produced by `build_anchor_data` after filtering empty patterns and
/// compacting offset tables. Consumed by `VsAnchorDb` and `VsUtf16StreamDb`
/// constructors.
struct AnchorData {
    /// Compiled literal patterns as `\xNN` regex strings.
    patterns: Vec<CString>,
    /// Per-target rule/variant mapping with seed radius.
    targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `targets` for each pattern.
    pat_offsets: Vec<u32>,
    /// Length in bytes of each pattern.
    pat_lens: Vec<u32>,
}

/// Builds the filtered pattern table and target mappings for anchor literals.
///
/// Empty patterns are dropped, offsets are compacted, and out-of-range target
/// ranges are ignored. Each surviving pattern is encoded as a `\xNN` literal
/// byte regex so Vectorscan treats it as a raw-byte match. When `debug` is
/// true, basic pattern stats are logged.
///
/// # Errors
/// Returns an error if no non-empty patterns remain or if pattern encoding fails.
fn build_anchor_data(
    patterns: &[Vec<u8>],
    pat_targets: &[Target],
    pat_offsets: &[u32],
    seed_radius_raw: &[u32],
    seed_radius_utf16: &[u32],
    debug: bool,
) -> Result<AnchorData, String> {
    if patterns.is_empty() {
        return Err("no anchor patterns".to_string());
    }
    let mut filtered_patterns: Vec<&[u8]> = Vec::with_capacity(patterns.len());
    let mut filtered_offsets: Vec<u32> = Vec::with_capacity(pat_offsets.len());
    let mut filtered_targets: Vec<Target> = Vec::with_capacity(pat_targets.len());

    filtered_offsets.push(0);
    for (pid, pat) in patterns.iter().enumerate() {
        if pat.is_empty() {
            continue;
        }
        let off_start = *pat_offsets.get(pid).unwrap_or(&0) as usize;
        let off_end = *pat_offsets.get(pid + 1).unwrap_or(&0) as usize;
        if off_start < off_end && off_end <= pat_targets.len() {
            filtered_targets.extend_from_slice(&pat_targets[off_start..off_end]);
        }
        filtered_patterns.push(pat.as_slice());
        filtered_offsets.push(filtered_targets.len() as u32);
    }

    if filtered_patterns.is_empty() {
        return Err("no non-empty anchor patterns".to_string());
    }

    if debug {
        let mut zero_len = 0usize;
        let mut leading_nul = 0usize;
        let mut min_len = usize::MAX;
        let mut max_len = 0usize;
        for pat in &filtered_patterns {
            let len = pat.len();
            if len == 0 {
                zero_len = zero_len.saturating_add(1);
            }
            if matches!(pat.first(), Some(0)) {
                leading_nul = leading_nul.saturating_add(1);
            }
            min_len = min_len.min(len);
            max_len = max_len.max(len);
        }
        if min_len == usize::MAX {
            min_len = 0;
        }
        let first = filtered_patterns.first().unwrap();
        eprintln!(
            "vectorscan anchor db build: patterns={} zero_len={} leading_nul={} min_len={} max_len={} first_len={} first_byte={}",
            filtered_patterns.len(),
            zero_len,
            leading_nul,
            min_len,
            max_len,
            first.len(),
            first.first().copied().unwrap_or(0),
        );
    }

    let mut c_patterns: Vec<CString> = Vec::with_capacity(filtered_patterns.len());
    for pat in &filtered_patterns {
        let mut expr = String::with_capacity(pat.len().saturating_mul(4));
        for b in *pat {
            use std::fmt::Write;
            let _ = write!(expr, "\\x{b:02X}");
        }
        let c_pat =
            CString::new(expr).map_err(|_| "anchor pattern contains unexpected NUL".to_string())?;
        c_patterns.push(c_pat);
    }

    let mut targets = Vec::with_capacity(filtered_targets.len());
    for t in &filtered_targets {
        let rule_id = t.rule_id() as u32;
        let variant = t.variant();
        let variant_idx = variant.idx() as u8;
        let seed_radius_bytes = match variant {
            Variant::Raw => *seed_radius_raw.get(rule_id as usize).unwrap_or(&0),
            Variant::Utf16Le | Variant::Utf16Be => {
                *seed_radius_utf16.get(rule_id as usize).unwrap_or(&0)
            }
        };
        targets.push(VsAnchorTarget {
            rule_id,
            variant_idx,
            seed_radius_bytes,
        });
    }

    let mut pat_lens = Vec::with_capacity(filtered_patterns.len());
    for pat in &filtered_patterns {
        pat_lens.push(usize_to_u32_saturating(pat.len()));
    }

    Ok(AnchorData {
        patterns: c_patterns,
        targets,
        pat_offsets: filtered_offsets,
        pat_lens,
    })
}

/// Vectorscan database for UTF-16 anchor prefiltering.
///
/// Patterns are literal bytes (encoded as `\xNN` regexes); matches are expanded
/// into rule/variant windows using the `targets` mapping.
/// `pat_offsets` is a prefix-sum table: pattern `i` maps to
/// `targets[pat_offsets[i]..pat_offsets[i + 1]]`.
/// Window offsets are in raw-byte coordinates of the scanned buffer.
pub(crate) struct VsAnchorDb {
    /// Compiled Vectorscan block-mode database.
    db: *mut vs::hs_database_t,
    /// Rule/variant targets for each anchor pattern.
    targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `targets` for each pattern.
    pat_offsets: Vec<u32>,
    /// Byte length of each anchor pattern.
    pat_lens: Vec<u32>,
}

/// Vectorscan stream database for UTF-16 anchor scanning.
///
/// Uses the same mapping tables as `VsAnchorDb`, but runs in stream mode and
/// emits `VsStreamWindow` entries via the UTF-16 stream callback.
/// Window offsets are in decoded-byte coordinates of the stream output.
pub(crate) struct VsUtf16StreamDb {
    /// Compiled Vectorscan stream-mode database.
    db: *mut vs::hs_database_t,
    /// Rule/variant targets for each anchor pattern.
    targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `targets` for each pattern.
    pat_offsets: Vec<u32>,
    /// Byte length of each anchor pattern.
    pat_lens: Vec<u32>,
}

// Safe because hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsUtf16StreamDb {}
unsafe impl Sync for VsUtf16StreamDb {}

impl Drop for VsUtf16StreamDb {
    fn drop(&mut self) {
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

// Safe because hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsAnchorDb {}
unsafe impl Sync for VsAnchorDb {}

impl Drop for VsAnchorDb {
    fn drop(&mut self) {
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

impl VsAnchorDb {
    /// Builds the UTF-16 anchor database and mapping tables.
    ///
    /// Empty patterns are filtered out; offsets are compacted accordingly.
    /// Each remaining pattern is compiled as a literal byte regex.
    /// Out-of-range offsets are ignored, yielding zero targets for that pattern.
    /// If `SCANNER_VS_UTF16_DEBUG` is set, basic pattern stats are logged.
    ///
    /// # Errors
    /// Returns an error if there are no non-empty patterns or if compilation fails.
    pub(crate) fn try_new_utf16(
        patterns: &[Vec<u8>],
        pat_targets: &[Target],
        pat_offsets: &[u32],
        seed_radius_raw: &[u32],
        seed_radius_utf16: &[u32],
        _tuning: &Tuning,
    ) -> Result<Self, String> {
        let debug = std::env::var("SCANNER_VS_UTF16_DEBUG").is_ok();
        let data = build_anchor_data(
            patterns,
            pat_targets,
            pat_offsets,
            seed_radius_raw,
            seed_radius_utf16,
            debug,
        )?;

        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(data.patterns.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(data.patterns.len());

        for (id, pat) in data.patterns.iter().enumerate() {
            expr_ptrs.push(pat.as_ptr());
            ids.push(id as c_uint);
        }

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        let platform = unsafe { platform.assume_init() };

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();

        if debug {
            eprintln!(
                "vectorscan utf16 db build: using regex compiler for {} patterns",
                expr_ptrs.len()
            );
        }

        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                ptr::null(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_BLOCK as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        Ok(Self {
            db,
            targets: data.targets,
            pat_offsets: data.pat_offsets,
            pat_lens: data.pat_lens,
        })
    }

    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Scans raw bytes for UTF-16 anchor hits and seeds per-variant windows.
    ///
    /// The callback performs window math using the precomputed target mapping.
    /// `vs_scratch` must be allocated for this database and not shared across
    /// threads; `scratch` must not be accessed concurrently. Window ends are
    /// clamped to the haystack length, and per-(rule, variant) hits are capped to
    /// `max_hits_per_rule_variant`.
    pub(crate) fn scan_utf16(
        &self,
        hay: &[u8],
        scratch: &mut ScanScratch,
        vs_scratch: &mut VsScratch,
    ) -> Result<bool, String> {
        let len_u32: c_uint = hay
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan: {} bytes", hay.len()))?;

        let mut ctx = VsAnchorMatchCtx {
            scratch: scratch as *mut ScanScratch,
            targets: self.targets.as_ptr(),
            pat_offsets: self.pat_offsets.as_ptr(),
            pat_lens: self.pat_lens.as_ptr(),
            pat_count: self.pat_lens.len() as u32,
            hay_len: len_u32,
            saw_utf16: false,
        };

        let rc = unsafe {
            vs::hs_scan(
                self.db,
                hay.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                vs_scratch.scratch,
                Some(vs_anchor_on_match),
                (&mut ctx as *mut VsAnchorMatchCtx).cast::<c_void>(),
            )
        };

        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(ctx.saw_utf16)
        } else {
            Err(format!("hs_scan failed: rc={rc}"))
        }
    }
}

impl VsUtf16StreamDb {
    /// Builds the UTF-16 anchor stream database and mapping tables.
    ///
    /// Empty patterns are filtered out; offsets are compacted accordingly.
    /// Each remaining pattern is compiled as a literal byte regex.
    /// Out-of-range offsets are ignored, yielding zero targets for that pattern.
    /// If `SCANNER_VS_UTF16_DEBUG` is set, basic pattern stats are logged.
    ///
    /// # Errors
    /// Returns an error if there are no non-empty patterns or if compilation fails.
    pub(crate) fn try_new_utf16_stream(
        patterns: &[Vec<u8>],
        pat_targets: &[Target],
        pat_offsets: &[u32],
        seed_radius_raw: &[u32],
        seed_radius_utf16: &[u32],
        _tuning: &Tuning,
    ) -> Result<Self, String> {
        let debug = std::env::var("SCANNER_VS_UTF16_DEBUG").is_ok();
        let data = build_anchor_data(
            patterns,
            pat_targets,
            pat_offsets,
            seed_radius_raw,
            seed_radius_utf16,
            debug,
        )?;

        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(data.patterns.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(data.patterns.len());

        for (id, pat) in data.patterns.iter().enumerate() {
            expr_ptrs.push(pat.as_ptr());
            ids.push(id as c_uint);
        }

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        let platform = unsafe { platform.assume_init() };

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();

        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                ptr::null(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_STREAM as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        Ok(Self {
            db,
            targets: data.targets,
            pat_offsets: data.pat_offsets,
            pat_lens: data.pat_lens,
        })
    }

    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns the rule/variant target mapping for anchor patterns.
    #[inline]
    pub(crate) fn targets(&self) -> &[VsAnchorTarget] {
        &self.targets
    }

    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Returns the prefix-sum offset table for pattern-to-target mapping.
    #[inline]
    pub(crate) fn pat_offsets(&self) -> &[u32] {
        &self.pat_offsets
    }

    /// Returns the byte length of each anchor pattern.
    #[inline]
    pub(crate) fn pat_lens(&self) -> &[u32] {
        &self.pat_lens
    }

    pub(crate) fn open_stream(&self) -> Result<VsStream, String> {
        let mut stream: *mut vs::hs_stream_t = ptr::null_mut();
        let rc = unsafe { vs::hs_open_stream(self.db, 0, &mut stream) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_open_stream failed: rc={rc}"));
        }
        Ok(VsStream { stream })
    }

    /// Scans a decoded stream chunk for UTF-16 anchor hits.
    ///
    /// The chunk length must fit in `u32` (Vectorscan API constraint).
    /// `scratch` must be allocated for this database; `ctx` must remain valid
    /// for the duration of the call. `HS_SCAN_TERMINATED` is treated as success to
    /// allow early termination in callbacks.
    pub(crate) fn scan_stream(
        &self,
        stream: &mut VsStream,
        chunk: &[u8],
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let rc = unsafe {
            vs::hs_scan_stream(
                stream.stream,
                chunk.as_ptr().cast::<c_char>(),
                chunk.len() as c_uint,
                0,
                scratch.scratch,
                on_event,
                ctx,
            )
        };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_scan_stream failed: rc={rc}"))
        }
    }

    pub(crate) fn close_stream(
        &self,
        stream: VsStream,
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let rc = unsafe { vs::hs_close_stream(stream.stream, scratch.scratch, on_event, ctx) };
        if rc == vs::HS_SUCCESS as c_int {
            Ok(())
        } else {
            Err(format!("hs_close_stream failed: rc={rc}"))
        }
    }
}

impl VsGateDb {
    /// Builds a decoded-space gate DB from literal anchor patterns.
    ///
    /// Empty patterns are filtered out. Each remaining pattern is compiled as
    /// a literal byte regex in stream mode.
    ///
    /// # Errors
    /// Returns an error if there are no non-empty patterns or if compilation fails.
    pub(crate) fn try_new_gate(patterns: &[Vec<u8>]) -> Result<Self, String> {
        if patterns.is_empty() {
            return Err("no gate anchor patterns".to_string());
        }

        let mut filtered: Vec<&[u8]> = Vec::with_capacity(patterns.len());
        for pat in patterns {
            if !pat.is_empty() {
                filtered.push(pat.as_slice());
            }
        }
        if filtered.is_empty() {
            return Err("no non-empty gate anchor patterns".to_string());
        }

        let mut c_patterns: Vec<CString> = Vec::with_capacity(filtered.len());
        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(filtered.len());
        let mut flags: Vec<c_uint> = Vec::with_capacity(filtered.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(filtered.len());

        for (id, pat) in filtered.iter().enumerate() {
            let mut expr = String::with_capacity(pat.len().saturating_mul(4));
            for b in *pat {
                use std::fmt::Write;
                let _ = write!(expr, "\\x{b:02X}");
            }
            let c_pat =
                CString::new(expr).map_err(|_| "gate anchor pattern contains NUL".to_string())?;
            c_patterns.push(c_pat);
            expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
            flags.push(vs::HS_FLAG_SINGLEMATCH as c_uint);
            ids.push(id as c_uint);
        }

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        let platform = unsafe { platform.assume_init() };

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_STREAM as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        Ok(Self { db })
    }

    /// Allocates a new scratch space bound to this database.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Opens a new stream handle bound to this database.
    pub(crate) fn open_stream(&self) -> Result<VsStream, String> {
        let mut stream: *mut vs::hs_stream_t = ptr::null_mut();
        let rc = unsafe { vs::hs_open_stream(self.db, 0, &mut stream) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_open_stream failed: rc={rc}"));
        }
        Ok(VsStream { stream })
    }

    /// Scans a stream chunk and delivers matches to `on_event`.
    ///
    /// `scratch` must be allocated for this database; `ctx` must remain valid
    /// for the duration of the call. `HS_SCAN_TERMINATED` is treated as success to
    /// allow early termination in callbacks.
    pub(crate) fn scan_stream(
        &self,
        stream: &mut VsStream,
        data: &[u8],
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let len_u32: c_uint = data
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan_stream: {} bytes", data.len()))?;
        let rc = unsafe {
            vs::hs_scan_stream(
                stream.stream,
                data.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                scratch.scratch,
                on_event,
                ctx,
            )
        };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_scan_stream failed: rc={rc}"))
        }
    }

    /// Closes a stream, flushing end-of-stream matches via `on_event`.
    pub(crate) fn close_stream(
        &self,
        stream: VsStream,
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let rc = unsafe { vs::hs_close_stream(stream.stream, scratch.scratch, on_event, ctx) };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_close_stream failed: rc={rc}"))
        }
    }
}

impl Drop for VsScratch {
    fn drop(&mut self) {
        unsafe {
            if !self.scratch.is_null() {
                vs::hs_free_scratch(self.scratch);
            }
        }
    }
}

impl VsPrefilterDb {
    /// Builds a Vectorscan DB for raw regex prefilter matches and optional anchor hits.
    ///
    /// # Arguments
    /// * `rules` - Rule specifications to compile
    /// * `_tuning` - Tuning parameters (currently unused)
    /// * `anchor` - Optional anchor patterns to include as exact literals
    /// * `use_raw_prefilter` - Per-rule flags indicating whether to include raw regex.
    ///   When `None`, all rules use raw regex prefiltering. When `Some`, only rules
    ///   with `use_raw_prefilter[rid] == true` have their regex compiled. Rules with
    ///   `false` rely on anchor patterns for window seeding.
    ///
    /// Returns an error if the database cannot be compiled or if any rule
    /// pattern is rejected by `hs_expression_info`. If multi-compile fails, we
    /// recompile patterns individually to surface the specific rule errors.
    pub(crate) fn try_new(
        rules: &[RuleSpec],
        _tuning: &Tuning,
        anchor: Option<AnchorInput<'_>>,
        use_raw_prefilter: Option<&[bool]>,
    ) -> Result<Self, String> {
        const RAW_FLAGS: c_uint = vs::HS_FLAG_PREFILTER as c_uint;

        #[derive(Clone)]
        struct RawPattern<'a> {
            rule_id: u32,
            seed_radius: u32,
            c_pat: CString,
            name: &'a str,
            pattern: &'a str,
            max_width: u32,
        }

        let mut raw_patterns: Vec<RawPattern<'_>> = Vec::with_capacity(rules.len());
        let mut max_width = 0u32;
        let mut unbounded = false;

        for (rid, r) in rules.iter().enumerate() {
            let seed_radius = if let Some(tp) = &r.two_phase {
                tp.seed_radius
            } else {
                r.radius
            };

            let (mut max_width_u32, c_pat) = expression_info_max_width(r.re.as_str(), RAW_FLAGS)?;
            if max_width_u32 == 0 {
                max_width_u32 = u32::MAX;
            }
            if max_width_u32 == u32::MAX {
                unbounded = true;
            }
            // Always track max_width for all rules (needed for window expansion).
            max_width = max_width.max(max_width_u32);

            // Skip adding raw regex pattern for rules where use_raw_prefilter[rid] is false.
            // These rules rely on anchor patterns (in the anchor input) for window seeding.
            if let Some(flags) = use_raw_prefilter {
                if rid < flags.len() && !flags[rid] {
                    continue;
                }
            }

            raw_patterns.push(RawPattern {
                rule_id: rid as u32,
                seed_radius: usize_to_u32_saturating(seed_radius),
                c_pat,
                name: r.name,
                pattern: r.re.as_str(),
                max_width: max_width_u32,
            });
        }

        let anchor_data = if let Some(anchor) = anchor {
            let debug = std::env::var("SCANNER_VS_UTF16_DEBUG").is_ok();
            Some(build_anchor_data(
                anchor.patterns,
                anchor.pat_targets,
                anchor.pat_offsets,
                anchor.seed_radius_raw,
                anchor.seed_radius_utf16,
                debug,
            )?)
        } else {
            None
        };

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        unsafe {
            // Best-effort: if this fails, Hyperscan/Vectorscan will fall back to defaults.
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        let platform = unsafe { platform.assume_init() };

        let compile_db = |raw: &[RawPattern<'_>]| -> Result<*mut vs::hs_database_t, String> {
            let anchor_len = anchor_data.as_ref().map_or(0, |d| d.pat_lens.len());
            let mut c_patterns: Vec<CString> =
                Vec::with_capacity(raw.len().saturating_add(anchor_len));
            let mut expr_ptrs: Vec<*const c_char> =
                Vec::with_capacity(raw.len().saturating_add(anchor_len));
            let mut flags: Vec<c_uint> = Vec::with_capacity(raw.len().saturating_add(anchor_len));
            let mut ids: Vec<c_uint> = Vec::with_capacity(raw.len().saturating_add(anchor_len));

            for (idx, pat) in raw.iter().enumerate() {
                c_patterns.push(pat.c_pat.clone());
                expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
                flags.push(RAW_FLAGS);
                ids.push(idx as c_uint);
            }

            if let Some(data) = &anchor_data {
                let base = raw.len() as u32;
                for (idx, pat) in data.patterns.iter().enumerate() {
                    c_patterns.push(pat.clone());
                    expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
                    flags.push(0);
                    ids.push(base + idx as u32);
                }
            }

            if expr_ptrs.is_empty() {
                return Err("no patterns to compile".to_string());
            }

            let mut db: *mut vs::hs_database_t = ptr::null_mut();
            let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
            let rc = unsafe {
                vs::hs_compile_multi(
                    expr_ptrs.as_ptr(),
                    flags.as_ptr(),
                    ids.as_ptr(),
                    expr_ptrs.len() as c_uint,
                    vs::HS_MODE_BLOCK as c_uint,
                    &platform as *const vs::hs_platform_info_t,
                    &mut db as *mut *mut vs::hs_database_t,
                    &mut compile_err as *mut *mut vs::hs_compile_error_t,
                )
            };

            if rc != vs::HS_SUCCESS as c_int {
                let msg = unsafe {
                    if compile_err.is_null() {
                        "hs_compile_multi failed (no error message)".to_string()
                    } else {
                        let s = if (*compile_err).message.is_null() {
                            "hs_compile_multi failed (null error message)".to_string()
                        } else {
                            let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                            format!(
                                "hs_compile_multi failed at expression {}: {}",
                                (*compile_err).expression,
                                cstr.to_string_lossy()
                            )
                        };
                        vs::hs_free_compile_error(compile_err);
                        s
                    }
                };
                return Err(msg);
            }

            Ok(db)
        };

        let compile_single = |pat: &RawPattern<'_>| -> Result<(), String> {
            let expr_ptrs = [pat.c_pat.as_ptr()];
            let flags = [RAW_FLAGS];
            let ids = [0u32];
            let mut db: *mut vs::hs_database_t = ptr::null_mut();
            let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
            let rc = unsafe {
                vs::hs_compile_multi(
                    expr_ptrs.as_ptr(),
                    flags.as_ptr(),
                    ids.as_ptr(),
                    1,
                    vs::HS_MODE_BLOCK as c_uint,
                    &platform as *const vs::hs_platform_info_t,
                    &mut db as *mut *mut vs::hs_database_t,
                    &mut compile_err as *mut *mut vs::hs_compile_error_t,
                )
            };
            if rc != vs::HS_SUCCESS as c_int {
                let msg = unsafe {
                    if compile_err.is_null() {
                        "hs_compile_multi failed (no error message)".to_string()
                    } else {
                        let s = if (*compile_err).message.is_null() {
                            "hs_compile_multi failed (null error message)".to_string()
                        } else {
                            let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                            format!(
                                "hs_compile_multi failed at expression {}: {}",
                                (*compile_err).expression,
                                cstr.to_string_lossy()
                            )
                        };
                        vs::hs_free_compile_error(compile_err);
                        s
                    }
                };
                return Err(msg);
            }
            unsafe {
                if !db.is_null() {
                    vs::hs_free_database(db);
                }
            }
            Ok(())
        };

        let mut raw_kept = raw_patterns.clone();
        let mut raw_missing_rules = Vec::new();
        let db = match compile_db(&raw_kept) {
            Ok(db) => db,
            Err(_err) => {
                raw_kept.clear();
                let mut errors = Vec::new();
                for pat in &raw_patterns {
                    match compile_single(pat) {
                        Ok(()) => raw_kept.push(pat.clone()),
                        Err(err) => {
                            raw_missing_rules.push(pat.rule_id);
                            errors.push(format!(
                                "rule='{}' pattern='{}' error={}",
                                pat.name, pat.pattern, err
                            ));
                        }
                    }
                }

                if !errors.is_empty() {
                    return Err(format!(
                        "vectorscan raw db compile failed for {} rules:\n{}",
                        errors.len(),
                        errors.join("\n")
                    ));
                }

                if raw_kept.is_empty() && anchor_data.as_ref().is_none_or(|d| d.pat_lens.is_empty())
                {
                    return Err("vectorscan raw db compile failed for all patterns".to_string());
                }
                compile_db(&raw_kept)?
            }
        };

        let raw_rule_ids: Vec<u32> = raw_kept.iter().map(|p| p.rule_id).collect();
        let raw_seed_radius: Vec<u32> = raw_kept.iter().map(|p| p.seed_radius).collect();
        let raw_match_widths: Vec<u32> = raw_kept.iter().map(|p| p.max_width).collect();
        let raw_rule_count = raw_kept.len() as u32;

        let (anchor_id_base, anchor_pat_count, anchor_targets, anchor_pat_offsets, anchor_pat_lens) =
            if let Some(data) = anchor_data {
                let pat_count = data.pat_lens.len() as u32;
                if pat_count == 0 {
                    (raw_rule_count, 0, Vec::new(), Vec::new(), Vec::new())
                } else {
                    (
                        raw_rule_count,
                        pat_count,
                        data.targets,
                        data.pat_offsets,
                        data.pat_lens,
                    )
                }
            } else {
                (raw_rule_count, 0, Vec::new(), Vec::new(), Vec::new())
            };

        Ok(Self {
            db,
            raw_rule_count,
            raw_seed_radius,
            raw_rule_ids,
            raw_match_widths,
            raw_missing_rules,
            anchor_id_base,
            anchor_pat_count,
            anchor_targets,
            anchor_pat_offsets,
            anchor_pat_lens,
            max_width,
            unbounded,
        })
    }

    /// Returns the maximum bounded match width across all rules.
    pub(crate) fn max_match_width_bounded(&self) -> Option<u32> {
        if self.unbounded {
            None
        } else {
            Some(self.max_width)
        }
    }

    /// Allocates a new scratch space bound to this database.
    ///
    /// Callers should reuse the returned scratch across scans on the same
    /// thread to avoid allocation overhead.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    #[inline]
    pub(crate) fn raw_missing_rules(&self) -> &[u32] {
        &self.raw_missing_rules
    }

    /// Scan raw bytes and seed per-rule candidate windows.
    ///
    /// Prefilter matches seed raw windows; anchor patterns (when
    /// present in the database) seed raw/UTF-16 windows.
    ///
    /// `vs_scratch` must be allocated for this database and not shared across
    /// threads; `scratch` must not be accessed concurrently. Per-(rule, variant)
    /// hits are capped to `max_hits_per_rule_variant` and may coalesce when the cap
    /// is exceeded.
    ///
    /// Returns `Ok(true)` if any UTF-16 anchor hit was observed.
    pub(crate) fn scan_raw(
        &self,
        hay: &[u8],
        scratch: &mut ScanScratch,
        vs_scratch: &mut VsScratch,
    ) -> Result<bool, String> {
        let len_u32: c_uint = hay
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan: {} bytes", hay.len()))?;

        let mut ctx = VsMatchCtx {
            scratch: scratch as *mut ScanScratch,
            hay_len: len_u32,
            raw_rule_count: self.raw_rule_count,
            raw_seed_radius: self.raw_seed_radius.as_ptr(),
            raw_rule_ids: self.raw_rule_ids.as_ptr(),
            raw_match_widths: self.raw_match_widths.as_ptr(),
            anchor_id_base: self.anchor_id_base,
            anchor_pat_count: self.anchor_pat_count,
            anchor_targets: self.anchor_targets.as_ptr(),
            anchor_pat_offsets: self.anchor_pat_offsets.as_ptr(),
            anchor_pat_lens: self.anchor_pat_lens.as_ptr(),
            saw_utf16: false,
        };

        let rc = unsafe {
            vs::hs_scan(
                self.db,
                hay.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                vs_scratch.scratch,
                Some(vs_on_match),
                (&mut ctx as *mut VsMatchCtx).cast::<c_void>(),
            )
        };

        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(ctx.saw_utf16)
        } else {
            Err(format!("hs_scan failed: rc={rc}"))
        }
    }
}

#[repr(C)]
/// Callback context for `hs_scan`.
///
/// Safety invariants:
/// - `scratch` points to a live `ScanScratch` for the duration of the scan.
/// - `hay_len` matches the length passed to `hs_scan`.
/// - If `anchor_pat_count > 0`, the anchor mapping tables are valid and
///   `anchor_pat_offsets` has length `anchor_pat_count + 1`.
/// - `raw_rule_ids`/`raw_seed_radius`/`raw_match_widths` each have length
///   `raw_rule_count`.
struct VsMatchCtx {
    scratch: *mut ScanScratch,
    hay_len: u32,
    raw_rule_count: u32,
    raw_seed_radius: *const u32,
    raw_rule_ids: *const u32,
    raw_match_widths: *const u32,
    anchor_id_base: u32,
    anchor_pat_count: u32,
    anchor_targets: *const VsAnchorTarget,
    anchor_pat_offsets: *const u32,
    anchor_pat_lens: *const u32,
    saw_utf16: bool,
}

#[repr(C)]
/// Callback context for anchor literal scans.
///
/// Safety invariants:
/// - `scratch` points to a live `ScanScratch` for the duration of the scan.
/// - `targets` points to `pat_offsets[pat_count]` entries indexed by pattern id.
/// - `pat_offsets` has length `pat_count + 1` and is monotonically increasing.
/// - `pat_lens` has length `pat_count`.
/// - `hay_len` matches the length passed to `hs_scan`.
struct VsAnchorMatchCtx {
    scratch: *mut ScanScratch,
    targets: *const VsAnchorTarget,
    pat_offsets: *const u32,
    pat_lens: *const u32,
    pat_count: u32,
    hay_len: u32,
    saw_utf16: bool,
}

/// Prefilter match callback for raw-byte scanning.
///
/// Seeds per-rule raw windows in `ScanScratch` based on the match end offset.
/// `id` values below `raw_rule_count` denote raw rules; ids at or above
/// `anchor_id_base` denote anchor literal patterns.
///
/// # Safety
/// - `ctx` must be non-null and point to a valid `VsMatchCtx`.
/// - `scratch` and mapping tables referenced by `ctx` must remain valid and not
///   be accessed concurrently for the duration of the scan.
/// - This callback must never panic or unwind across the FFI boundary.
extern "C" fn vs_on_match(
    id: c_uint,
    from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    // Absolutely no panics across FFI.
    let c = unsafe { &mut *(ctx as *mut VsMatchCtx) };
    if id < c.raw_rule_count {
        let raw_idx = id as usize;
        let rid = unsafe { *c.raw_rule_ids.add(raw_idx) as usize };

        // SAFETY: `scratch` is valid for the duration of the scan and is not used concurrently.
        let scratch = unsafe { &mut *c.scratch };

        const RAW_IDX: usize = 0;

        let end = to as u32;
        if end > c.hay_len {
            return 0;
        }
        let max_width = unsafe { *c.raw_match_widths.add(raw_idx) };
        let start = if max_width == u32::MAX {
            0
        } else {
            end.saturating_sub(max_width)
        };
        let seed = unsafe { *c.raw_seed_radius.add(raw_idx) };
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed).min(c.hay_len);

        // Clamp anchor hint to window bounds.
        let anchor_hint = (from as u32).clamp(lo, end);

        let pair = rid * 3 + RAW_IDX;
        scratch.hit_acc_pool.push_span(
            pair,
            SpanU32 {
                start: lo,
                end: hi,
                anchor_hint,
            },
            &mut scratch.touched_pairs,
        );
        return 0;
    }

    if c.anchor_pat_count == 0 || id < c.anchor_id_base {
        return 0;
    }

    let pid = (id - c.anchor_id_base) as usize;
    if pid >= c.anchor_pat_count as usize {
        return 0;
    }

    let len = unsafe { *c.anchor_pat_lens.add(pid) };
    let end = to as u32;
    if end > c.hay_len {
        return 0;
    }
    let start = end.saturating_sub(len);

    let off_start = unsafe { *c.anchor_pat_offsets.add(pid) } as usize;
    let off_end = unsafe { *c.anchor_pat_offsets.add(pid + 1) } as usize;

    // SAFETY: `scratch` is valid for the duration of the scan and not used concurrently.
    let scratch = unsafe { &mut *c.scratch };

    for i in off_start..off_end {
        let target = unsafe { *c.anchor_targets.add(i) };
        let seed = target.seed_radius_bytes;
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed).min(c.hay_len);

        // Anchor patterns are fixed-width; use the computed start as the hint to
        // avoid relying on `from` for prefilter-style callbacks.
        let anchor_hint = start.clamp(lo, end);

        let rid = target.rule_id as usize;
        let vidx = target.variant_idx as usize;

        let pair = rid * 3 + vidx;
        scratch.hit_acc_pool.push_span(
            pair,
            SpanU32 {
                start: lo,
                end: hi,
                anchor_hint,
            },
            &mut scratch.touched_pairs,
        );
        if matches!(target.variant_idx, 1 | 2) {
            c.saw_utf16 = true;
        }
    }

    0
}

/// Anchor literal match callback.
///
/// Expands each anchor match into windows for all rule/variant targets tied to
/// the matched pattern.
///
/// # Safety
/// - `ctx` must be non-null and point to a valid `VsAnchorMatchCtx`.
/// - `scratch` and mapping tables referenced by `ctx` must remain valid and not
///   be accessed concurrently for the duration of the scan.
/// - This callback must never panic or unwind across the FFI boundary.
extern "C" fn vs_anchor_on_match(
    id: c_uint,
    _from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    // Absolutely no panics across FFI.
    let c = unsafe { &mut *(ctx as *mut VsAnchorMatchCtx) };

    let pid = id as usize;
    debug_assert!(pid < c.pat_count as usize);

    let len = unsafe { *c.pat_lens.add(pid) };
    let end = to as u32;
    debug_assert!(end <= c.hay_len);
    let start = end.saturating_sub(len);

    let off_start = unsafe { *c.pat_offsets.add(pid) } as usize;
    let off_end = unsafe { *c.pat_offsets.add(pid + 1) } as usize;

    // SAFETY: scratch is valid for the duration of the scan and not used concurrently.
    let scratch = unsafe { &mut *c.scratch };

    for i in off_start..off_end {
        let target = unsafe { *c.targets.add(i) };
        let seed = target.seed_radius_bytes;
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed).min(c.hay_len);

        // Anchor patterns are fixed-width; use the computed start as the hint to
        // avoid relying on `from` for prefilter-style callbacks.
        let anchor_hint = start.clamp(lo, end);

        let rid = target.rule_id as usize;
        let vidx = target.variant_idx as usize;

        let pair = rid * 3 + vidx;
        scratch.hit_acc_pool.push_span(
            pair,
            SpanU32 {
                start: lo,
                end: hi,
                anchor_hint,
            },
            &mut scratch.touched_pairs,
        );
        if matches!(target.variant_idx, 1 | 2) {
            c.saw_utf16 = true;
        }
    }

    0
}

/// Returns `(max_width, c_pattern)` for use in compilation.
///
/// Errors if the pattern contains NUL bytes or if `hs_expression_info` fails.
/// A reported `max_width` of zero is treated as "unbounded" by callers.
fn expression_info_max_width(pattern: &str, flags: c_uint) -> Result<(u32, CString), String> {
    let c_pat = CString::new(pattern).map_err(|_| "pattern contains NUL byte".to_string())?;

    let mut info_ptr: *mut vs::hs_expr_info_t = ptr::null_mut();
    let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
    let rc =
        unsafe { vs::hs_expression_info(c_pat.as_ptr(), flags, &mut info_ptr, &mut compile_err) };
    if rc != vs::HS_SUCCESS as c_int {
        let msg = unsafe {
            if compile_err.is_null() {
                format!("hs_expression_info failed: rc={rc}")
            } else {
                let s = if (*compile_err).message.is_null() {
                    format!("hs_expression_info failed: rc={rc}")
                } else {
                    let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                    format!(
                        "hs_expression_info failed at expression {}: {}",
                        (*compile_err).expression,
                        cstr.to_string_lossy()
                    )
                };
                vs::hs_free_compile_error(compile_err);
                s
            }
        };
        return Err(msg);
    }
    if info_ptr.is_null() {
        return Err("hs_expression_info returned null info".to_string());
    }

    let maxw = unsafe { (*info_ptr).max_width };
    unsafe {
        // Allocated by the misc allocator; we assume default malloc/free.
        libc::free(info_ptr.cast());
    }

    Ok((maxw, c_pat))
}

/// Convenience wrapper for `expression_info_max_width` with `HS_FLAG_PREFILTER`.
fn expression_info_prefilter_max_width(pattern: &str) -> Result<(u32, CString), String> {
    expression_info_max_width(pattern, vs::HS_FLAG_PREFILTER as c_uint)
}

/// Saturating conversion from `usize` to `u32`.
///
/// Returns `u32::MAX` if the value exceeds `u32::MAX`.
#[inline]
fn usize_to_u32_saturating(v: usize) -> u32 {
    if v > u32::MAX as usize {
        u32::MAX
    } else {
        v as u32
    }
}
