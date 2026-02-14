//! Shared archive scanning scaffolding.
//!
//! Types and helpers used by all archive format modules (`local_fs_gzip`,
//! `local_fs_tar`, `local_fs_zip`).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::api::FileId;
use crate::archive::formats::TarCursor;
use crate::archive::formats::TarRead;
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, ArchiveKind, ArchiveSkipReason, BudgetHit, ChargeResult,
    EntryPathCanonicalizer, PartialReason, VirtualPathBuilder,
};
use crate::store::{FsFindingRecord, StoreProducer};

use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::WorkerCtx;
use super::local_fs_gzip::process_gzip_file;
use super::local_fs_owner::{FileTask, LocalScratch};
use super::local_fs_tar::{process_tar_file, process_targz_file};
use super::local_fs_zip::process_zip_file;
use super::metrics::WorkerMetricsLocal;
use super::ts_buffer_pool::TsBufferPool;

/// Allocate a virtual `FileId` for archive entries.
///
/// Virtual IDs live in the high-bit namespace (`0x8000_0000..=0xFFFF_FFFF`)
/// to avoid collision with real file IDs (which start at 0 and grow upward).
/// The counter wraps after ~2^31 entries, but collisions are tolerable:
/// `FileId` is only used by the engine for internal attribution, not for
/// deduplication or correctness in the scheduler.
#[inline]
pub(super) fn alloc_virtual_file_id(next_virtual_file_id: &mut u32) -> FileId {
    const VIRTUAL_FILE_ID_BASE: u32 = 0x8000_0000;
    const VIRTUAL_FILE_ID_MASK: u32 = 0x7FFF_FFFF;

    let id = *next_virtual_file_id;
    let next = (id.wrapping_add(1) & VIRTUAL_FILE_ID_MASK) | VIRTUAL_FILE_ID_BASE;
    *next_virtual_file_id = next;
    FileId(id)
}

/// Length of a locator suffix: `@` + kind byte + 16 hex digits = 18 bytes.
///
/// Locators are appended to virtual path segments to disambiguate entries
/// that share the same display name within an archive. The format is
/// `@<kind><hex64>` where `kind` identifies the offset type:
/// - `t` = tar header block index
/// - `z` = ZIP local file header offset (when valid)
/// - `c` = ZIP central directory file header offset (fallback)
pub(super) const LOCATOR_LEN: usize = 18;

/// Write a `u64` as 16 lowercase hex digits into `out16`.
#[inline(always)]
pub(super) fn write_u64_hex_lower(x: u64, out16: &mut [u8]) {
    debug_assert_eq!(out16.len(), 16);
    for (i, out) in out16.iter_mut().enumerate().take(16) {
        let shift = (15 - i) * 4;
        let nyb = ((x >> shift) & 0xF) as u8;
        *out = match nyb {
            0..=9 => b'0' + nyb,
            _ => b'a' + (nyb - 10),
        };
    }
}

/// Format a locator suffix into `out` and return the full slice.
///
/// See [`LOCATOR_LEN`] for format description.
#[inline]
pub(super) fn build_locator(out: &mut [u8; LOCATOR_LEN], kind: u8, value: u64) -> &[u8] {
    out[0] = b'@';
    out[1] = kind;
    write_u64_hex_lower(value, &mut out[2..]);
    out
}

/// Dispatch archive scanning by kind.
///
/// Routes to `process_gzip_file`, `process_tar_file`, `process_targz_file`,
/// or `process_zip_file` based on the detected [`ArchiveKind`].
///
/// The caller is responsible for recording archive-level stats
/// (`record_archive_scanned` / `record_archive_skipped` / `record_archive_partial`)
/// based on the returned [`ArchiveEnd`].
#[inline]
pub(super) fn dispatch_archive_scan<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    kind: ArchiveKind,
) -> ArchiveEnd {
    match kind {
        ArchiveKind::Gzip => process_gzip_file(task, ctx),
        ArchiveKind::Tar => process_tar_file(task, ctx),
        ArchiveKind::TarGz => process_targz_file(task, ctx),
        ArchiveKind::Zip => process_zip_file(task, ctx),
    }
}

/// Hard cap on per-read output for archive streams (256 KiB).
///
/// Archive entry reads are clamped to this value even when the pool buffer
/// is larger. This bounds decompressor output per iteration, keeping
/// inflation-ratio checks responsive and limiting peak stack/heap pressure
/// from a single decompression call.
pub(super) const ARCHIVE_STREAM_READ_MAX: usize = 256 * 1024;

/// Outcome of scanning an archive container.
///
/// Used by `dispatch_archive_scan` and its callees to communicate
/// whether the archive was fully consumed, entirely skipped, or
/// partially scanned (budget exhaustion, corruption, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ArchiveEnd {
    /// All entries in the archive were scanned to completion.
    Scanned,
    /// The archive was not scanned at all (e.g., I/O error, encrypted,
    /// unsupported format). The reason is recorded for telemetry.
    Skipped(ArchiveSkipReason),
    /// Scanning stopped partway through the archive (budget exceeded,
    /// malformed entry, inflation ratio exceeded). Some entries may
    /// have been fully scanned before the stop.
    Partial(PartialReason),
}

/// Map an archive-level skip reason to the corresponding partial-scan reason.
///
/// Used when a nested archive is skipped mid-stream, promoting the skip into
/// a partial outcome for the parent entry/archive. Unmapped variants fall
/// through to `MalformedZip` as a conservative default.
#[inline(always)]
pub(super) fn map_archive_skip_to_partial(reason: ArchiveSkipReason) -> PartialReason {
    match reason {
        ArchiveSkipReason::MetadataBudgetExceeded => PartialReason::MetadataBudgetExceeded,
        ArchiveSkipReason::PathBudgetExceeded => PartialReason::PathBudgetExceeded,
        ArchiveSkipReason::EntryCountExceeded => PartialReason::EntryCountExceeded,
        ArchiveSkipReason::ArchiveOutputBudgetExceeded => {
            PartialReason::ArchiveOutputBudgetExceeded
        }
        ArchiveSkipReason::RootOutputBudgetExceeded => PartialReason::RootOutputBudgetExceeded,
        ArchiveSkipReason::InflationRatioExceeded => PartialReason::InflationRatioExceeded,
        ArchiveSkipReason::UnsupportedFeature => PartialReason::UnsupportedFeature,
        _ => PartialReason::MalformedZip,
    }
}

/// Extract the [`PartialReason`] from a [`BudgetHit`].
///
/// Every budget violation carries a reason; this collapses the four `BudgetHit`
/// variants into a flat `PartialReason` for recording in metrics and diagnostics.
#[inline(always)]
pub(super) fn budget_hit_to_partial_reason(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => map_archive_skip_to_partial(r),
        BudgetHit::SkipEntry(_) => PartialReason::EntryOutputBudgetExceeded,
    }
}

/// Convert a [`BudgetHit`] into the corresponding [`ArchiveEnd`] outcome.
///
/// `SkipArchive` maps to `Skipped`; all others map to `Partial`.
#[inline(always)]
pub(super) fn budget_hit_to_archive_end(hit: BudgetHit) -> ArchiveEnd {
    match hit {
        BudgetHit::SkipArchive(r) => ArchiveEnd::Skipped(r),
        BudgetHit::PartialArchive(r) => ArchiveEnd::Partial(r),
        BudgetHit::StopRoot(r) => ArchiveEnd::Partial(r),
        BudgetHit::SkipEntry(_) => ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded),
    }
}

/// Borrowed view into [`LocalScratch`] for archive scanning.
///
/// Splits the per-worker scratch into disjoint borrows so nested archive
/// scans can recurse without aliasing. Each nesting level consumes the
/// head element of `vpaths`, `path_budget_used`, and `tar_cursors` via
/// `split_first_mut`, passing the tail to the child `ArchiveScanCtx`.
///
/// # Invariants
/// - All buffers are preallocated in `LocalScratch` and must not grow.
/// - Nested scans borrow disjoint slices of scratch buffers (no aliasing).
/// - `budgets` is shared across nested scans to enforce global caps.
/// - `path_budget_used` tracks per-depth virtual path byte usage.
/// - `abort_run` is set when `FailRun` policies trigger; callers must stop
///   dispatching new files once it becomes true.
pub(super) struct ArchiveScanCtx<'a, E: ScanEngine> {
    pub(super) engine: &'a Arc<E>,
    pub(super) pool: &'a TsBufferPool,
    pub(super) event_sink: &'a dyn crate::unified::events::EventSink,
    pub(super) store_producer: Option<&'a dyn StoreProducer>,
    pub(super) scan_scratch: &'a mut E::Scratch,
    /// Reusable findings drain buffer (cleared before each `drain_findings_into`).
    pub(super) pending: &'a mut Vec<<E::Scratch as EngineScratch>::Finding>,
    /// Reusable persistence batch buffer.
    pub(super) persist_batch: &'a mut Vec<FsFindingRecord>,
    /// Shared budget tracker — enforces archive, entry, and root output caps.
    pub(super) budgets: &'a mut ArchiveBudgets,
    pub(super) canon: &'a mut EntryPathCanonicalizer,
    /// Per-depth virtual path builders. Head is consumed at this depth.
    pub(super) vpaths: &'a mut [VirtualPathBuilder],
    /// Per-depth byte counters for virtual path budget enforcement.
    pub(super) path_budget_used: &'a mut [usize],
    /// Per-depth tar header cursors. Head is consumed at this depth.
    pub(super) tar_cursors: &'a mut [TarCursor],
    pub(super) gzip_header_buf: &'a mut Vec<u8>,
    pub(super) gzip_name_buf: &'a mut Vec<u8>,
    pub(super) next_virtual_file_id: &'a mut u32,
    pub(super) metrics: &'a mut WorkerMetricsLocal,
    pub(super) archive: &'a ArchiveConfig,
    pub(super) dedupe: bool,
    pub(super) chunk_size: usize,
    /// Shared abort flag; set by `FailRun` policy handlers.
    pub(super) abort_run: &'a AtomicBool,
}

impl<'a, E: ScanEngine> ArchiveScanCtx<'a, E> {
    /// Create a top-level archive scan context from per-worker scratch.
    ///
    /// Borrows all depth-indexed slices at full length; nested calls peel off
    /// the head element via `split_first_mut` before constructing child contexts.
    pub(super) fn new(
        scratch: &'a mut LocalScratch<E>,
        metrics: &'a mut WorkerMetricsLocal,
    ) -> Self {
        Self {
            engine: &scratch.engine,
            pool: &scratch.pool,
            event_sink: &*scratch.event_sink,
            store_producer: scratch.store_producer.as_deref(),
            scan_scratch: &mut scratch.scan_scratch,
            pending: &mut scratch.pending,
            persist_batch: &mut scratch.persist_batch,
            budgets: &mut scratch.budgets,
            canon: &mut scratch.canon,
            vpaths: scratch.vpaths.as_mut_slice(),
            path_budget_used: scratch.path_budget_used.as_mut_slice(),
            tar_cursors: scratch.tar_cursors.as_mut_slice(),
            gzip_header_buf: &mut scratch.gzip_header_buf,
            gzip_name_buf: &mut scratch.gzip_name_buf,
            next_virtual_file_id: &mut scratch.next_virtual_file_id,
            metrics,
            archive: &scratch.archive,
            dedupe: scratch.dedupe_within_chunk,
            chunk_size: scratch.chunk_size,
            abort_run: scratch.abort_run.as_ref(),
        }
    }
}

/// Charge decompressed bytes that were read but not scanned (entry truncation).
///
/// Discarded bytes still count against archive and root output budgets because
/// the decompressor already produced them. Returns `Err` with the triggering
/// [`PartialReason`] if charging the discard pushes a budget over its limit.
#[inline(always)]
pub(super) fn charge_discarded_bytes(
    budgets: &mut ArchiveBudgets,
    bytes: u64,
) -> Result<(), PartialReason> {
    if bytes == 0 {
        return Ok(());
    }
    match budgets.charge_discarded_out(bytes) {
        ChargeResult::Ok => Ok(()),
        ChargeResult::Clamp { hit, .. } => Err(budget_hit_to_partial_reason(hit)),
    }
}

/// Apply decompressed-output budgeting for a read of `n` bytes.
///
/// Returns `(allowed, clamped)` where:
/// - `allowed` is the prefix length to scan/emits.
/// - `clamped` signals the caller must stop after this iteration.
///
/// If the decoder produced more bytes than allowed, the extra bytes are charged
/// as discarded output so archive/root caps remain accurate.
#[inline(always)]
pub(super) fn apply_entry_budget_clamp(
    budgets: &mut ArchiveBudgets,
    n: usize,
    entry_partial_reason: &mut Option<PartialReason>,
    outcome: &mut ArchiveEnd,
    stop_archive: &mut bool,
) -> (u64, bool) {
    let mut allowed = n as u64;
    if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
        let r = budget_hit_to_partial_reason(hit);
        allowed = a;
        *entry_partial_reason = Some(r);
        if !matches!(hit, BudgetHit::SkipEntry(_)) {
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
    }

    if allowed == 0 {
        if let Err(r) = charge_discarded_bytes(budgets, n as u64) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (0, true);
    }

    if allowed < n as u64 {
        let extra = (n as u64).saturating_sub(allowed);
        if let Err(r) = charge_discarded_bytes(budgets, extra) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (allowed, true);
    }

    (allowed, false)
}

/// Drain remaining tar entry payload bytes to realign the stream.
///
/// After a nested archive scan or a budget clamp, the tar entry may have
/// unread payload bytes. These must be consumed so the tar cursor stays
/// aligned to the next entry header. Discarded bytes are charged against
/// the decompressed-output budgets via [`charge_discarded_bytes`].
///
/// Returns `Err(MalformedTar)` on EOF or I/O error mid-drain.
pub(super) fn discard_remaining_payload(
    input: &mut dyn TarRead,
    budgets: &mut ArchiveBudgets,
    buf: &mut [u8],
    mut remaining: u64,
) -> Result<(), PartialReason> {
    while remaining > 0 {
        let step = buf.len().min(remaining as usize);
        let n = match input.read(&mut buf[..step]) {
            Ok(n) => n,
            Err(_) => return Err(PartialReason::MalformedTar),
        };
        if n == 0 {
            return Err(PartialReason::MalformedTar);
        }
        budgets.charge_compressed_in(input.take_compressed_delta());
        charge_discarded_bytes(budgets, n as u64)?;
        remaining = remaining.saturating_sub(n as u64);
    }
    Ok(())
}
