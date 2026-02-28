//! Shared archive scanning scaffolding.
//!
//! Types and helpers used by all archive format modules (`local_fs_gzip`,
//! `local_fs_tar`, `local_fs_zip`).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::api::FileId;
use crate::archive::formats::TarCursor;
use crate::archive::formats::TarRead;
use crate::archive::util::write_u64_hex_lower;
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, ArchiveKind, ArchiveSkipReason, BudgetHit, ChargeResult,
    EntryPathCanonicalizer, PartialReason, VirtualPathBuilder,
};
use crate::store::{FsFindingRecord, StoreProducer};

use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::WorkerCtx;
use super::local_fs_bzip2::process_bzip2_file;
use super::local_fs_gzip::process_gzip_file;
use super::local_fs_owner::{
    account_effective_dropped_findings, apply_cross_rule_dedupe, emit_findings,
    emit_persistence_batch, FileTask, LocalScratch,
};
use super::local_fs_tar::{process_tar_file, process_tarbz2_file, process_targz_file};
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
/// Routes to `process_gzip_file`, `process_bzip2_file`, `process_tar_file`,
/// `process_targz_file`, `process_tarbz2_file`, or `process_zip_file`
/// based on the detected [`ArchiveKind`].
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
        ArchiveKind::Bzip2 => process_bzip2_file(task, ctx),
        ArchiveKind::Tar => process_tar_file(task, ctx),
        ArchiveKind::TarGz => process_targz_file(task, ctx),
        ArchiveKind::TarBz2 => process_tarbz2_file(task, ctx),
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
/// a partial outcome for the parent entry/archive. Variants without a direct
/// `PartialReason` counterpart map to `MalformedZip` as a conservative fallback.
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
        ArchiveSkipReason::Disabled
        | ArchiveSkipReason::UnsupportedFormat
        | ArchiveSkipReason::EncryptedArchive
        | ArchiveSkipReason::DepthExceeded
        | ArchiveSkipReason::NeedsRandomAccessNoSpill
        | ArchiveSkipReason::IoError
        | ArchiveSkipReason::Corrupt => PartialReason::MalformedZip,
    }
}

/// Extract the [`PartialReason`] from a [`BudgetHit`].
///
/// Every budget violation carries a reason; this collapses the four `BudgetHit`
/// variants into a flat `PartialReason` for recording in metrics and diagnostics.
/// `SkipEntry` is promoted to an entry-level partial reason.
#[inline(always)]
pub(super) fn budget_hit_to_partial_reason(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => map_archive_skip_to_partial(r),
        BudgetHit::SkipEntry(r) => r.to_partial(),
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
        BudgetHit::SkipEntry(r) => ArchiveEnd::Partial(r.to_partial()),
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
    /// Shared budget tracker — enforces output caps and inflation-ratio gates.
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
            chunk_size: scratch.chunk_size,
            abort_run: scratch.abort_run.as_ref(),
        }
    }

    /// Scan a buffer chunk, drain/dedupe findings, emit events + persistence,
    /// and update chunk metrics.
    ///
    /// Shared core used by archive entry scanning loops (currently gzip).
    /// The caller is responsible for reading bytes, charging budgets, and
    /// managing the outer loop condition — this method handles everything
    /// from `scan_chunk_into` through carry/offset bookkeeping.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn scan_and_emit_chunk(
        &mut self,
        buf: &[u8],
        carry: usize,
        offset: u64,
        allowed: u64,
        overlap: usize,
        file_id: FileId,
        display: &[u8],
        entry_scanned: &mut bool,
    ) -> ChunkScanResult {
        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;
        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf[..read_len];

        self.engine
            .scan_chunk_into(data, file_id, base_offset, self.scan_scratch);
        let engine_dropped = self.scan_scratch.dropped_findings();
        let before_prefix = self.scan_scratch.pending_findings_len();
        if !*entry_scanned {
            self.metrics.archive.record_entry_scanned();
            *entry_scanned = true;
        }

        self.scan_scratch.drop_prefix_findings(offset);
        let after_prefix = self.scan_scratch.pending_findings_len();

        self.pending.clear();
        self.scan_scratch.drain_findings_into(self.pending);

        let dedupe_removed = apply_cross_rule_dedupe(self.pending, self.engine.as_ref());
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(dedupe_removed);
        account_effective_dropped_findings(self.metrics, engine_dropped, scheduler_pruned);

        self.metrics.findings_emitted = self
            .metrics
            .findings_emitted
            .wrapping_add(self.pending.len() as u64);

        emit_persistence_batch(
            self.store_producer,
            self.event_sink,
            display,
            self.pending,
            self.persist_batch,
            self.metrics,
        );
        emit_findings(self.engine.as_ref(), self.event_sink, display, self.pending);

        self.metrics.chunks_scanned = self.metrics.chunks_scanned.saturating_add(1);
        self.metrics.bytes_scanned = self.metrics.bytes_scanned.saturating_add(allowed);

        ChunkScanResult {
            offset: offset.saturating_add(allowed),
            have: read_len,
            carry: overlap.min(read_len),
        }
    }
}

/// Loop-iteration state returned by [`ArchiveScanCtx::scan_and_emit_chunk`].
pub(super) struct ChunkScanResult {
    /// Byte offset for the next iteration.
    pub offset: u64,
    /// Number of valid bytes currently in the buffer.
    pub have: usize,
    /// Carry-forward overlap for the next read.
    pub carry: usize,
}

/// Charge decompressed bytes that were read but not scanned (entry truncation).
///
/// Discarded bytes still count against archive/root output budgets and, when
/// an entry is open, against the per-entry inflation ratio because the
/// decompressor already produced them. Per-entry output-byte caps are
/// intentionally bypassed for this discarded path.
///
/// Returns `Err` with the triggering [`PartialReason`] if charging the discard
/// pushes a budget over its limit.
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
/// - `allowed` is the prefix length to scan/emit.
/// - `clamped` signals the caller must stop after this iteration.
///
/// If the decoder produced more bytes than allowed, the extra bytes are charged
/// as discarded output so archive/root counters and entry-ratio accounting stay
/// consistent.
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
        if budgets.is_deadline_expired() {
            return Err(PartialReason::WallClockTimeout);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_virtual_file_id_sequential_and_wrapping() {
        let mut next = 0x8000_0000u32;

        let id0 = alloc_virtual_file_id(&mut next);
        assert_eq!(id0.0, 0x8000_0000);
        assert_eq!(next, 0x8000_0001);

        let id1 = alloc_virtual_file_id(&mut next);
        assert_eq!(id1.0, 0x8000_0001);
        assert_eq!(next, 0x8000_0002);
    }

    #[test]
    fn alloc_virtual_file_id_wraps_at_boundary() {
        // Just before the mask wraps.
        let mut next = 0xFFFF_FFFFu32;

        let id = alloc_virtual_file_id(&mut next);
        assert_eq!(id.0, 0xFFFF_FFFF);
        // After wrapping: (0xFFFF_FFFF + 1) & 0x7FFF_FFFF | 0x8000_0000
        assert_eq!(next, 0x8000_0000);
    }

    #[test]
    fn build_locator_format() {
        let mut buf = [0u8; LOCATOR_LEN];
        let loc = build_locator(&mut buf, b't', 0x0000_0000_0000_1234);

        assert_eq!(loc[0], b'@');
        assert_eq!(loc[1], b't');
        assert_eq!(&loc[2..], b"0000000000001234");
    }

    #[test]
    fn build_locator_zero_value() {
        let mut buf = [0u8; LOCATOR_LEN];
        let loc = build_locator(&mut buf, b'z', 0);
        assert_eq!(&loc[2..], b"0000000000000000");
    }
}
