//! Gzip archive scanning.
//!
//! Handles `.gz` files as single-entry virtual archives, and nested gzip
//! streams within tar archives.

use std::fs::File;
use std::io::Read;

use crate::archive::formats::GzipStream;
use crate::archive::{
    ArchiveSkipReason, BudgetHit, ChargeResult, EntrySkipReason, PartialReason,
    DEFAULT_MAX_COMPONENTS,
};

use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::WorkerCtx;
use super::local_fs_archive_ctx::{
    alloc_virtual_file_id, budget_hit_to_archive_end, budget_hit_to_partial_reason, ArchiveEnd,
    ArchiveScanCtx, ARCHIVE_STREAM_READ_MAX,
};
use super::local_fs_owner::{
    account_effective_dropped_findings, apply_cross_rule_dedupe, emit_findings,
    emit_persistence_batch, FileTask, LocalScratch,
};

/// Scan a `.gz` file as a single virtual entry (`<gunzip>`).
///
/// # Invariants
/// - Offsets are decompressed byte offsets.
/// - Concatenated gzip members are treated as one stream.
pub(super) fn process_gzip_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
) -> ArchiveEnd {
    let scratch = &mut ctx.scratch;
    let metrics = &mut ctx.metrics;
    let engine = &scratch.engine;
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);

    let file = match File::open(&task.path) {
        Ok(f) => f,
        Err(_) => {
            metrics.io_errors = metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    let parent_bytes = task.path.as_os_str().as_encoded_bytes();
    let max_len = scratch.archive.max_virtual_path_len_per_entry;
    debug_assert!(scratch.vpaths.len() > 1);
    debug_assert!(scratch.path_budget_used.len() > 1);
    scratch.path_budget_used[1] = 0;

    let (mut gz, name_len) = match GzipStream::new_with_header(
        file,
        &mut scratch.gzip_header_buf,
        &mut scratch.gzip_name_buf,
        max_len,
    ) {
        Ok(v) => v,
        Err(_) => {
            metrics.io_errors = metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    let entry_name_bytes = if let Some(len) = name_len {
        let c = scratch.canon.canonicalize(
            &scratch.gzip_name_buf[..len],
            DEFAULT_MAX_COMPONENTS,
            max_len,
        );
        if c.had_traversal {
            metrics.archive.record_path_had_traversal();
        }
        if c.component_cap_exceeded {
            metrics.archive.record_component_cap_exceeded();
        }
        if c.truncated {
            metrics.archive.record_path_truncated();
        }
        c.bytes
    } else {
        b"<gunzip>"
    };

    let path_bytes = scratch.vpaths[1]
        .build(parent_bytes, entry_name_bytes, max_len)
        .bytes;
    let need = path_bytes.len();
    if scratch.path_budget_used[1].saturating_add(need)
        > scratch.archive.max_virtual_path_bytes_per_archive
    {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
    }
    scratch.path_budget_used[1] = scratch.path_budget_used[1].saturating_add(need);

    scratch.budgets.reset();
    if let Err(hit) = scratch.budgets.enter_archive() {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return budget_hit_to_archive_end(hit);
    }
    if let Err(hit) = scratch.budgets.begin_entry() {
        scratch.budgets.exit_archive();
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return budget_hit_to_archive_end(hit);
    }

    let mut buf = scratch.pool.acquire();

    let entry_file_id = alloc_virtual_file_id(&mut scratch.next_virtual_file_id);
    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;

    loop {
        if carry > 0 && have > 0 {
            buf.as_mut_slice().copy_within(have - carry..have, 0);
        }

        let allowance = scratch
            .budgets
            .remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

        let n = match gz.read(dst) {
            Ok(n) => n,
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
                entry_partial_reason = Some(PartialReason::GzipCorrupt);
                break;
            }
        };

        if n == 0 {
            break;
        }

        scratch
            .budgets
            .charge_compressed_in(gz.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } =
            scratch.budgets.charge_decompressed_out(allowed)
        {
            let r = budget_hit_to_partial_reason(hit);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;

        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf.as_slice()[..read_len];

        engine.scan_chunk_into(data, entry_file_id, base_offset, &mut scratch.scan_scratch);
        let engine_dropped = scratch.scan_scratch.dropped_findings();
        let before_prefix = scratch.scan_scratch.pending_findings_len();
        if !entry_scanned {
            metrics.archive.record_entry_scanned();
            entry_scanned = true;
        }

        let new_bytes_start = offset;
        scratch.scan_scratch.drop_prefix_findings(new_bytes_start);
        let after_prefix = scratch.scan_scratch.pending_findings_len();

        scratch.pending.clear();
        scratch
            .scan_scratch
            .drain_findings_into(&mut scratch.pending);

        let dedupe_removed = apply_cross_rule_dedupe(&mut scratch.pending, engine.as_ref());
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(dedupe_removed);
        account_effective_dropped_findings(metrics, engine_dropped, scheduler_pruned);

        metrics.findings_emitted = metrics
            .findings_emitted
            .wrapping_add(scratch.pending.len() as u64);

        emit_persistence_batch(
            scratch.store_producer.as_deref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
            &mut scratch.persist_batch,
            metrics,
        );
        emit_findings(
            engine.as_ref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
        );

        metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(1);
        metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(allowed);

        offset = offset.saturating_add(allowed);
        have = read_len;
        carry = overlap.min(read_len);

        if allowed_usize < n {
            break;
        }
    }

    scratch.budgets.end_entry(offset > 0);
    scratch.budgets.exit_archive();

    let (_inner, hdr_buf) = gz.into_inner().into_parts();
    scratch.gzip_header_buf = hdr_buf;

    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
        entry_partial_reason = Some(PartialReason::GzipCorrupt);
    }

    if let Some(r) = entry_partial_reason {
        metrics.archive.record_entry_partial(r, path_bytes, false);
    }

    outcome
}

/// Scan a gzip stream as a single virtual entry.
///
/// # Invariants
/// - Offsets are decompressed byte offsets.
/// - Budget clamps stop scanning deterministically.
pub(super) fn scan_gzip_stream_nested<E: ScanEngine, R: Read>(
    scan: &mut ArchiveScanCtx<'_, E>,
    gz: &mut GzipStream<R>,
    display: &[u8],
) -> ArchiveEnd {
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let overlap = scan.engine.required_overlap();
    let file_id = alloc_virtual_file_id(scan.next_virtual_file_id);

    if let Err(hit) = scan.budgets.begin_entry() {
        return budget_hit_to_archive_end(hit);
    }

    let mut buf = scan.pool.acquire();

    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;
    let mut entry_skip_reason: Option<EntrySkipReason> = None;

    loop {
        if carry > 0 && have > 0 {
            buf.as_mut_slice().copy_within(have - carry..have, 0);
        }

        let allowance = scan
            .budgets
            .remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = scan.budgets.charge_decompressed_out(1) {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = scan.budgets.charge_decompressed_out(1) {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

        let n = match gz.read(dst) {
            Ok(n) => n,
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
                entry_partial_reason = Some(PartialReason::GzipCorrupt);
                break;
            }
        };

        if n == 0 {
            break;
        }

        scan.budgets
            .charge_compressed_in(gz.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } =
            scan.budgets.charge_decompressed_out(allowed)
        {
            if let BudgetHit::SkipEntry(reason) = hit {
                entry_skip_reason = Some(reason);
            }
            let r = budget_hit_to_partial_reason(hit);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let result = scan.scan_and_emit_chunk(
            buf.as_slice(),
            carry,
            offset,
            allowed,
            overlap,
            file_id,
            display,
            &mut entry_scanned,
        );
        offset = result.offset;
        have = result.have;
        carry = result.carry;

        if (allowed as usize) < n {
            break;
        }
    }

    scan.budgets.end_entry(offset > 0);
    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
        entry_partial_reason = Some(PartialReason::GzipCorrupt);
    }
    if let Some(reason) = entry_skip_reason {
        scan.metrics
            .archive
            .record_entry_skipped(reason, display, false);
    }
    if let Some(r) = entry_partial_reason {
        scan.metrics.archive.record_entry_partial(r, display, false);
    }

    outcome
}
