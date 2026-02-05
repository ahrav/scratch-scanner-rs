//! Archive scanning core with a sink-driven entry interface.
//!
//! # Scope
//! - Streaming archive parsing (gzip/tar/tar.gz/zip) with deterministic budgets.
//! - Virtual path construction + path budget enforcement.
//! - Entry scanning is delegated to an `ArchiveEntrySink` to avoid coupling
//!   to the pipeline or simulation harness.
//!
//! # Design Notes
//! - No OS dependencies: callers provide `Read`/`Read+Seek` sources.
//! - All hot-path buffers live in `ArchiveScratch` and are reused.
//! - Callers control chunk overlap semantics via the sink.

use std::io::Read;

use crate::archive::detect_kind_from_name_bytes;
use crate::archive::formats::zip::LimitedRead;
use crate::archive::formats::{GzipStream, TarCursor, TarNext, TarRead, ZipCursor, ZipEntryMeta};
use crate::archive::formats::{ZipNext, ZipOpen, ZipSource};
use crate::archive::path::apply_hash_suffix_truncation;
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, ArchiveKind, ArchiveSkipReason, ArchiveStats, BudgetHit,
    ChargeResult, EntryPathCanonicalizer, EntrySkipReason, PartialReason, VirtualPathBuilder,
    DEFAULT_MAX_COMPONENTS,
};

const LOCATOR_LEN: usize = 18;
const ARCHIVE_STREAM_READ_MAX: usize = 256 * 1024;

/// Outcome for a single archive scan.
///
/// `Scanned` means the archive was fully processed without a terminal stop.
/// `Skipped` reflects a policy decision (unsupported feature, encryption, etc).
/// `Partial` indicates malformed input or a budget stop; some entries may have
/// been scanned and findings emitted before the stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveEnd {
    Scanned,
    Skipped(ArchiveSkipReason),
    Partial(PartialReason),
}

/// Metadata for a single archive entry delivered to the sink.
///
/// `display_path` is the virtual path bytes (root + entry + locator suffix).
/// `size_hint` is the uncompressed size when known, or 0 when unknown.
/// `flags` is reserved for future per-entry metadata.
pub struct EntryMeta<'a> {
    pub display_path: &'a [u8],
    pub size_hint: u64,
    pub flags: u32,
}

/// Chunk of entry data delivered to the sink.
///
/// The slice includes the overlap prefix from the previous chunk (if any).
/// The newly read bytes are always the suffix of `data` with length
/// `new_bytes_len`.
pub struct EntryChunk<'a> {
    /// Entry data covering `[base_offset, base_offset + data.len())`.
    pub data: &'a [u8],
    /// Entry offset corresponding to `data[0]`.
    pub base_offset: u64,
    /// Entry offset of the first newly read byte in this chunk.
    pub new_bytes_start: u64,
    /// Length of newly read bytes at the end of `data`.
    pub new_bytes_len: usize,
}

/// Sink interface used by the archive core to scan entry data.
///
/// Call order is: `on_entry_start`, zero or more `on_entry_chunk` calls,
/// then `on_entry_end`. Implementations must tolerate empty entries.
/// Returning an error aborts the scan and is propagated to the caller.
pub trait ArchiveEntrySink {
    type Error;

    fn on_entry_start(&mut self, meta: &EntryMeta<'_>) -> Result<(), Self::Error>;
    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error>;
    fn on_entry_end(&mut self) -> Result<(), Self::Error>;
}

/// Reusable scratch state for archive scanning.
///
/// Buffers are preallocated to avoid per-entry allocations. This type is not
/// thread-safe and is intended to be reused across scans by a single worker.
/// `chunk_size` and `overlap` must match the engine/pipeline settings.
pub struct ArchiveScratch<Z: ZipSource> {
    canon: EntryPathCanonicalizer,
    vpaths: Vec<VirtualPathBuilder>,
    path_budget_used: Vec<usize>,
    budgets: ArchiveBudgets,
    tar_cursors: Vec<TarCursor>,
    zip_cursor: ZipCursor<Z>,
    entry_display_buf: Vec<u8>,
    gzip_header_buf: Vec<u8>,
    gzip_name_buf: Vec<u8>,
    stream_buf: Vec<u8>,
    chunk_size: usize,
    overlap: usize,
    /// Flag set by policy to abort the whole run (not just the archive).
    abort_run: bool,
}

impl<Z: ZipSource> ArchiveScratch<Z> {
    /// Preallocate buffers sized from the archive config and chunk geometry.
    ///
    /// `chunk_size` is the non-overlap payload size; `overlap` is carried
    /// forward between chunks to preserve windowed scanning.
    pub fn new(archive: &ArchiveConfig, chunk_size: usize, overlap: usize) -> Self {
        let depth_cap = archive.max_archive_depth as usize + 2;
        let mut vpaths = Vec::with_capacity(depth_cap);
        for _ in 0..depth_cap {
            vpaths.push(VirtualPathBuilder::with_capacity(
                archive.max_virtual_path_len_per_entry,
            ));
        }
        let mut tar_cursors = Vec::with_capacity(depth_cap);
        for _ in 0..depth_cap {
            tar_cursors.push(TarCursor::with_capacity(archive));
        }
        let entry_display_cap = archive.max_virtual_path_len_per_entry;
        let path_budget_used = vec![0usize; depth_cap];
        let gzip_name_cap = archive.max_virtual_path_len_per_entry;
        let gzip_header_cap = archive
            .max_virtual_path_len_per_entry
            .saturating_add(256)
            .min(archive.max_archive_metadata_bytes as usize)
            .clamp(64, 64 * 1024);
        let buf_len = chunk_size
            .saturating_add(overlap)
            .max(overlap.saturating_add(1));

        Self {
            canon: EntryPathCanonicalizer::with_capacity(
                DEFAULT_MAX_COMPONENTS,
                archive.max_virtual_path_len_per_entry,
            ),
            vpaths,
            path_budget_used,
            budgets: ArchiveBudgets::new(archive),
            tar_cursors,
            zip_cursor: ZipCursor::with_capacity(archive),
            entry_display_buf: Vec::with_capacity(entry_display_cap),
            gzip_header_buf: vec![0u8; gzip_header_cap],
            gzip_name_buf: Vec::with_capacity(gzip_name_cap),
            stream_buf: vec![0u8; buf_len],
            chunk_size,
            overlap,
            abort_run: false,
        }
    }

    #[inline]
    pub fn abort_run(&self) -> bool {
        self.abort_run
    }

    #[inline]
    pub fn clear_abort(&mut self) {
        self.abort_run = false;
    }
}

struct ArchiveScanCtx<'a, S, Z: ZipSource> {
    sink: &'a mut S,
    stats: &'a mut ArchiveStats,
    budgets: &'a mut ArchiveBudgets,
    canon: &'a mut EntryPathCanonicalizer,
    vpaths: &'a mut [VirtualPathBuilder],
    path_budget_used: &'a mut [usize],
    tar_cursors: &'a mut [TarCursor],
    zip_cursor: &'a mut ZipCursor<Z>,
    entry_display_buf: &'a mut Vec<u8>,
    gzip_header_buf: &'a mut Vec<u8>,
    gzip_name_buf: &'a mut Vec<u8>,
    stream_buf: &'a mut Vec<u8>,
    archive: &'a ArchiveConfig,
    chunk_size: usize,
    overlap: usize,
    abort_run: &'a mut bool,
}

impl<'a, S, Z: ZipSource> ArchiveScanCtx<'a, S, Z> {
    fn new(
        sink: &'a mut S,
        stats: &'a mut ArchiveStats,
        archive: &'a ArchiveConfig,
        scratch: &'a mut ArchiveScratch<Z>,
    ) -> Self {
        Self {
            sink,
            stats,
            budgets: &mut scratch.budgets,
            canon: &mut scratch.canon,
            vpaths: scratch.vpaths.as_mut_slice(),
            path_budget_used: scratch.path_budget_used.as_mut_slice(),
            tar_cursors: scratch.tar_cursors.as_mut_slice(),
            zip_cursor: &mut scratch.zip_cursor,
            entry_display_buf: &mut scratch.entry_display_buf,
            gzip_header_buf: &mut scratch.gzip_header_buf,
            gzip_name_buf: &mut scratch.gzip_name_buf,
            stream_buf: &mut scratch.stream_buf,
            archive,
            chunk_size: scratch.chunk_size,
            overlap: scratch.overlap,
            abort_run: &mut scratch.abort_run,
        }
    }
}

#[inline(always)]
fn map_archive_skip_to_partial(reason: ArchiveSkipReason) -> PartialReason {
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

#[inline(always)]
fn budget_hit_to_partial_reason(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => map_archive_skip_to_partial(r),
        BudgetHit::SkipEntry(_) => PartialReason::EntryOutputBudgetExceeded,
    }
}

#[inline(always)]
fn budget_hit_to_archive_end(hit: BudgetHit) -> ArchiveEnd {
    match hit {
        BudgetHit::SkipArchive(r) => ArchiveEnd::Skipped(r),
        BudgetHit::PartialArchive(r) => ArchiveEnd::Partial(r),
        BudgetHit::StopRoot(r) => ArchiveEnd::Partial(r),
        BudgetHit::SkipEntry(_) => ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded),
    }
}

#[inline(always)]
fn write_u64_hex_lower(x: u64, out16: &mut [u8]) {
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

#[inline]
fn build_locator(out: &mut [u8; LOCATOR_LEN], kind: u8, value: u64) -> &[u8] {
    out[0] = b'@';
    out[1] = kind;
    write_u64_hex_lower(value, &mut out[2..]);
    out
}

#[inline(always)]
fn charge_discarded_bytes(budgets: &mut ArchiveBudgets, bytes: u64) -> Result<(), PartialReason> {
    if bytes == 0 {
        return Ok(());
    }
    match budgets.charge_discarded_out(bytes) {
        ChargeResult::Ok => Ok(()),
        ChargeResult::Clamp { hit, .. } => Err(budget_hit_to_partial_reason(hit)),
    }
}

fn discard_remaining_payload(
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

/// Scan a gzip stream as a single virtual entry (root scan).
///
/// The sink sees exactly one entry (`<gunzip>` when the gzip name is missing).
/// Budgets are reset and charged against the archive limits in `archive`.
pub fn scan_gzip_stream<R: Read, S: ArchiveEntrySink, Z: ZipSource>(
    reader: R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let mut scan = ArchiveScanCtx::new(sink, stats, archive, scratch);
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);

    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(scan.vpaths.len() > 1);
    debug_assert!(scan.path_budget_used.len() > 1);
    scan.path_budget_used[1] = 0;

    let (mut gz, name_len) = match GzipStream::new_with_header(
        reader,
        scan.gzip_header_buf,
        scan.gzip_name_buf,
        max_len,
    ) {
        Ok(v) => v,
        Err(_) => return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError)),
    };

    let entry_name_bytes = if let Some(len) = name_len {
        let c =
            scan.canon
                .canonicalize(&scan.gzip_name_buf[..len], DEFAULT_MAX_COMPONENTS, max_len);
        if c.had_traversal {
            scan.stats.record_path_had_traversal();
        }
        if c.component_cap_exceeded {
            scan.stats.record_component_cap_exceeded();
        }
        if c.truncated {
            scan.stats.record_path_truncated();
        }
        c.bytes
    } else {
        b"<gunzip>"
    };

    let need;
    {
        let built = scan.vpaths[1].build(root_display, entry_name_bytes, max_len);
        need = built.bytes.len();
        scan.entry_display_buf.clear();
        scan.entry_display_buf.extend_from_slice(built.bytes);
    }
    if scan.path_budget_used[1].saturating_add(need) > archive.max_virtual_path_bytes_per_archive {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        *scan.gzip_header_buf = hdr_buf;
        return Ok(ArchiveEnd::Partial(PartialReason::PathBudgetExceeded));
    }
    scan.path_budget_used[1] = scan.path_budget_used[1].saturating_add(need);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        *scan.gzip_header_buf = hdr_buf;
        return Ok(budget_hit_to_archive_end(hit));
    }

    let display_buf = std::mem::take(scan.entry_display_buf);
    let display = display_buf.as_slice();
    let outcome = scan_gzip_entry_stream(&mut scan, &mut gz, display, chunk_size);
    *scan.entry_display_buf = display_buf;
    let outcome = outcome?;
    scan.budgets.exit_archive();

    let (_inner, hdr_buf) = gz.into_inner().into_parts();
    *scan.gzip_header_buf = hdr_buf;
    Ok(outcome)
}

fn scan_gzip_entry_stream<R: Read, S: ArchiveEntrySink, Z: ZipSource>(
    scan: &mut ArchiveScanCtx<'_, S, Z>,
    gz: &mut GzipStream<R>,
    display: &[u8],
    chunk_size: usize,
) -> Result<ArchiveEnd, S::Error> {
    let budgets = &mut *scan.budgets;
    let overlap = scan.overlap;

    if let Err(hit) = budgets.begin_entry() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let meta = EntryMeta {
        display_path: display,
        size_hint: 0,
        flags: 0,
    };
    scan.sink.on_entry_start(&meta)?;

    let buf = &mut scan.stream_buf;

    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;

    loop {
        if carry > 0 && have > 0 {
            buf.copy_within(have - carry..have, 0);
        }

        let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
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
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf[carry..carry + read_max];
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

        budgets.charge_compressed_in(gz.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
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
        let data = &buf[..read_len];
        let chunk = EntryChunk {
            data,
            base_offset,
            new_bytes_start: offset,
            new_bytes_len: allowed_usize,
        };
        scan.sink.on_entry_chunk(chunk)?;
        if !entry_scanned {
            scan.stats.record_entry_scanned();
            entry_scanned = true;
        }

        offset = offset.saturating_add(allowed);
        have = read_len;
        carry = overlap.min(read_len);

        if allowed_usize < n {
            break;
        }
    }

    scan.sink.on_entry_end()?;
    budgets.end_entry(offset > 0);
    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
        entry_partial_reason = Some(PartialReason::GzipCorrupt);
    }
    if let Some(r) = entry_partial_reason {
        scan.stats.record_entry_partial(r, display, false);
    }

    Ok(outcome)
}

/// Scan a tar stream (plain or gzip-wrapped) as sequential entries.
///
/// `ratio_active` controls whether inflation-ratio accounting is enforced for
/// entry payload reads (true for gzip-wrapped tar streams).
#[allow(clippy::too_many_arguments)]
pub fn scan_tar_stream<R: TarRead, S: ArchiveEntrySink, Z: ZipSource>(
    input: &mut R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
    ratio_active: bool,
) -> Result<ArchiveEnd, S::Error> {
    let mut scan = ArchiveScanCtx::new(sink, stats, archive, scratch);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let outcome = scan_tar_stream_nested(&mut scan, input, root_display, 1, ratio_active)?;
    scan.budgets.exit_archive();
    Ok(outcome)
}

fn scan_tar_stream_nested<S: ArchiveEntrySink, Z: ZipSource>(
    scan: &mut ArchiveScanCtx<'_, S, Z>,
    input: &mut dyn TarRead,
    container_display: &[u8],
    depth: u8,
    ratio_active: bool,
) -> Result<ArchiveEnd, S::Error> {
    let budgets = &mut *scan.budgets;
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let overlap = scan.overlap;
    let max_len = scan.archive.max_virtual_path_len_per_entry;
    let max_depth = scan.archive.max_archive_depth;

    let (cur_vpath, rest_vpaths) = scan
        .vpaths
        .split_first_mut()
        .expect("vpath scratch exhausted");
    let (cur_path_used, rest_path_used) = scan
        .path_budget_used
        .split_first_mut()
        .expect("path budget scratch exhausted");
    let (cur_cursor, rest_cursors) = scan
        .tar_cursors
        .split_first_mut()
        .expect("tar cursor scratch exhausted");

    cur_cursor.reset();
    *cur_path_used = 0;

    let mut outcome = ArchiveEnd::Scanned;

    loop {
        let (entry_display, entry_size, entry_pad, entry_typeflag, nested_kind) = {
            let meta = match cur_cursor.next_entry(input, budgets, scan.archive) {
                Ok(TarNext::End) => break,
                Ok(TarNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(TarNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            };

            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, b't', meta.header_block_index);
            let entry_display = {
                let c = scan
                    .canon
                    .canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    scan.stats.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    scan.stats.record_component_cap_exceeded();
                }
                if c.truncated {
                    scan.stats.record_path_truncated();
                }
                cur_vpath
                    .build_with_suffix(container_display, c.bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if cur_path_used.saturating_add(need) > scan.archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            *cur_path_used = cur_path_used.saturating_add(need);

            let nested_kind = detect_kind_from_name_bytes(meta.name);

            (
                entry_display,
                meta.size,
                meta.pad,
                meta.typeflag,
                nested_kind,
            )
        };

        let is_regular = entry_typeflag == 0 || entry_typeflag == b'0';
        if !is_regular {
            scan.stats
                .record_entry_skipped(EntrySkipReason::NonRegular, entry_display, false);
            match cur_cursor.skip_payload_and_pad(input, budgets, entry_size, entry_pad) {
                Ok(Ok(())) => continue,
                _ => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            }
        }

        budgets.begin_entry_scan();
        let mut stop_archive = false;

        if let Some(kind) = nested_kind {
            match kind {
                ArchiveKind::Zip => {
                    scan.stats.record_archive_skipped(
                        ArchiveSkipReason::NeedsRandomAccessNoSpill,
                        entry_display,
                        false,
                    );
                    match scan.archive.unsupported_policy {
                        crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                            // Fall back to scanning raw bytes.
                        }
                        crate::archive::UnsupportedPolicy::FailArchive => {
                            scan.stats.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                        crate::archive::UnsupportedPolicy::FailRun => {
                            *scan.abort_run = true;
                            scan.stats.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                    }
                }
                ArchiveKind::Gzip | ArchiveKind::Tar | ArchiveKind::TarGz => {
                    if depth >= max_depth {
                        scan.stats.record_archive_skipped(
                            ArchiveSkipReason::DepthExceeded,
                            entry_display,
                            false,
                        );
                    } else if let Err(hit) = budgets.enter_archive() {
                        let r = budget_hit_to_archive_end(hit);
                        match r {
                            ArchiveEnd::Skipped(reason) => {
                                scan.stats
                                    .record_archive_skipped(reason, entry_display, false)
                            }
                            ArchiveEnd::Partial(reason) => {
                                scan.stats
                                    .record_archive_partial(reason, entry_display, false)
                            }
                            _ => {}
                        }
                    } else {
                        scan.stats.record_archive_seen();
                        scan.stats.record_entry_scanned();

                        let nested_outcome = match kind {
                            ArchiveKind::Gzip => {
                                let (gunzip_vpath, vpaths_tail) = rest_vpaths
                                    .split_first_mut()
                                    .expect("vpath scratch exhausted");
                                let (gunzip_path_used, path_used_tail) = rest_path_used
                                    .split_first_mut()
                                    .expect("path budget scratch exhausted");
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: vpaths_tail,
                                    path_budget_used: path_used_tail,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };

                                let (mut gz, name_len) = match GzipStream::new_with_header(
                                    LimitedRead::new(input, entry_size),
                                    child.gzip_header_buf,
                                    child.gzip_name_buf,
                                    max_len,
                                ) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                        budgets.exit_archive();
                                        budgets.end_entry(true);
                                        break;
                                    }
                                };
                                let entry_name_bytes = if let Some(len) = name_len {
                                    let c = child.canon.canonicalize(
                                        &child.gzip_name_buf[..len],
                                        DEFAULT_MAX_COMPONENTS,
                                        max_len,
                                    );
                                    if c.had_traversal {
                                        child.stats.record_path_had_traversal();
                                    }
                                    if c.component_cap_exceeded {
                                        child.stats.record_component_cap_exceeded();
                                    }
                                    if c.truncated {
                                        child.stats.record_path_truncated();
                                    }
                                    c.bytes
                                } else {
                                    b"<gunzip>"
                                };
                                let gunzip_display = gunzip_vpath
                                    .build(entry_display, entry_name_bytes, max_len)
                                    .bytes;
                                *gunzip_path_used = 0;
                                let need = gunzip_display.len();
                                if gunzip_path_used.saturating_add(need)
                                    > scan.archive.max_virtual_path_bytes_per_archive
                                {
                                    outcome =
                                        ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                                    budgets.exit_archive();
                                    budgets.end_entry(true);
                                    break;
                                }
                                *gunzip_path_used = gunzip_path_used.saturating_add(need);

                                let out = scan_gzip_entry_stream(
                                    &mut child,
                                    &mut gz,
                                    gunzip_display,
                                    chunk_size,
                                )?;
                                let (entry_reader, hdr_buf) = gz.into_inner().into_parts();
                                *child.gzip_header_buf = hdr_buf;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Tar => {
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };
                                let mut entry_reader = LimitedRead::new(input, entry_size);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut entry_reader,
                                    entry_display,
                                    depth + 1,
                                    ratio_active,
                                )?;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::TarGz => {
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };
                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut gz = GzipStream::new(entry_reader);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut gz,
                                    entry_display,
                                    depth + 1,
                                    true,
                                )?;
                                let entry_reader = gz.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Zip => unreachable!(),
                        };

                        budgets.exit_archive();

                        let mut entry_partial_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
                            ArchiveEnd::Scanned => None,
                        };

                        match nested_outcome.0 {
                            ArchiveEnd::Scanned => scan.stats.record_archive_scanned(),
                            ArchiveEnd::Skipped(r) => {
                                scan.stats.record_archive_skipped(r, entry_display, false)
                            }
                            ArchiveEnd::Partial(r) => {
                                scan.stats.record_archive_partial(r, entry_display, false);
                            }
                        }

                        budgets.end_entry(true);

                        let stop_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
                            ArchiveEnd::Scanned => None,
                        };
                        if let Some(r) = stop_reason {
                            if matches!(r, PartialReason::RootOutputBudgetExceeded) {
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        if !stop_archive && nested_outcome.1 > 0 {
                            if entry_partial_reason.is_none() {
                                entry_partial_reason = Some(PartialReason::MalformedTar);
                            }
                            if let Err(r) = discard_remaining_payload(
                                input,
                                budgets,
                                scan.stream_buf.as_mut_slice(),
                                nested_outcome.1,
                            ) {
                                if entry_partial_reason.is_none() {
                                    entry_partial_reason = Some(r);
                                }
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        if let Some(r) = entry_partial_reason {
                            scan.stats.record_entry_partial(r, entry_display, false);
                        }

                        if !stop_archive {
                            match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
                                Ok(Ok(())) => {}
                                _ => {
                                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                    stop_archive = true;
                                }
                            }
                        }

                        if stop_archive {
                            break;
                        }

                        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
                        continue;
                    }
                }
            }
        }

        let entry_meta = EntryMeta {
            display_path: entry_display,
            size_hint: entry_size,
            flags: 0,
        };
        scan.sink.on_entry_start(&entry_meta)?;

        let mut remaining = entry_size;
        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;

        while remaining > 0 {
            if carry > 0 && have > 0 {
                scan.stream_buf.copy_within(have - carry..have, 0);
            }

            let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allowance == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    outcome = ArchiveEnd::Partial(r);
                    entry_partial_reason = Some(r);
                }
                break;
            }

            let read_max = chunk_size
                .min(scan.stream_buf.len().saturating_sub(carry))
                .min(allowance.min(u64::from(u32::MAX)) as usize)
                .min(remaining.min(u64::from(u32::MAX)) as usize);

            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    outcome = ArchiveEnd::Partial(r);
                    entry_partial_reason = Some(r);
                }
                break;
            }

            let dst = &mut scan.stream_buf[carry..carry + read_max];
            let n = match input.read(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    entry_partial_reason = Some(PartialReason::MalformedTar);
                    break;
                }
            };

            if n == 0 {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                entry_partial_reason = Some(PartialReason::MalformedTar);
                break;
            }

            budgets.charge_compressed_in(input.take_compressed_delta());

            let mut allowed = n as u64;
            if let ChargeResult::Clamp { allowed: a, hit } =
                budgets.charge_decompressed_out(allowed)
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
            let data = &scan.stream_buf[..read_len];
            let chunk = EntryChunk {
                data,
                base_offset,
                new_bytes_start: offset,
                new_bytes_len: allowed_usize,
            };
            scan.sink.on_entry_chunk(chunk)?;
            if !entry_scanned {
                scan.stats.record_entry_scanned();
                entry_scanned = true;
            }

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = overlap.min(read_len);

            remaining = remaining.saturating_sub(allowed);

            if allowed_usize < n {
                break;
            }
        }

        scan.sink.on_entry_end()?;
        budgets.end_entry(offset > 0);

        if remaining > 0 {
            if let Err(r) =
                discard_remaining_payload(input, budgets, scan.stream_buf.as_mut_slice(), remaining)
            {
                if entry_partial_reason.is_none() {
                    entry_partial_reason = Some(r);
                }
                outcome = ArchiveEnd::Partial(r);
            }
        }

        if let Some(r) = entry_partial_reason {
            scan.stats.record_entry_partial(r, entry_display, false);
        }

        match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
            Ok(Ok(())) => {}
            _ => {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                break;
            }
        }

        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
    }

    Ok(outcome)
}

/// Scan a gzip-compressed tar stream (tar.gz).
///
/// This wraps `scan_tar_stream` with a gzip decoder and inflation-ratio
/// accounting enabled.
pub fn scan_targz_stream<R: Read, S: ArchiveEntrySink, Z: ZipSource>(
    reader: R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let mut gz = GzipStream::new(reader);
    scan_tar_stream(&mut gz, root_display, archive, scratch, sink, stats, true)
}

/// Scan a zip source with random access.
///
/// The source must support `Read + Seek` and be cloneable for payload reads.
/// Entry names are canonicalized and combined with locator suffixes to form
/// virtual paths before delivery to the sink.
pub fn scan_zip_source<S: ArchiveEntrySink, Z: ZipSource>(
    source: Z,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);

    scratch.budgets.reset();
    if let Err(hit) = scratch.budgets.enter_archive() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let cursor = &mut scratch.zip_cursor;
    let open = match cursor.open(source, &mut scratch.budgets, archive) {
        Ok(open) => open,
        Err(_) => {
            scratch.budgets.exit_archive();
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    match open {
        ZipOpen::Ready => {}
        ZipOpen::Skip(r) => {
            scratch.budgets.exit_archive();
            if r == ArchiveSkipReason::UnsupportedFeature {
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry
                    | crate::archive::UnsupportedPolicy::FailArchive => {
                        return Ok(ArchiveEnd::Skipped(r));
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        scratch.abort_run = true;
                        return Ok(ArchiveEnd::Skipped(r));
                    }
                }
            }
            return Ok(ArchiveEnd::Skipped(r));
        }
        ZipOpen::Stop(r) => {
            scratch.budgets.exit_archive();
            return Ok(ArchiveEnd::Partial(r));
        }
    }

    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(scratch.path_budget_used.len() > 1);
    scratch.path_budget_used[1] = 0;

    let buf = &mut scratch.stream_buf;
    let mut outcome = ArchiveEnd::Scanned;

    loop {
        let (
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
            entry_display,
        ) = {
            let meta = match cursor.next_entry(&mut scratch.budgets, archive) {
                Ok(ZipNext::End) => break,
                Ok(ZipNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(ZipNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    break;
                }
            };

            let (locator_kind, locator_value) = if meta.lfh_offset_valid {
                (b'z', meta.local_header_offset)
            } else {
                (b'c', meta.cdfh_offset)
            };
            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, locator_kind, locator_value);
            let entry_display = {
                let c = scratch
                    .canon
                    .canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    stats.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    stats.record_component_cap_exceeded();
                }
                let entry_bytes = if meta.name_truncated {
                    stats.record_path_truncated();
                    scratch.entry_display_buf.clear();
                    scratch.entry_display_buf.extend_from_slice(c.bytes);
                    apply_hash_suffix_truncation(
                        &mut scratch.entry_display_buf,
                        meta.name_hash64,
                        max_len,
                    );
                    scratch.entry_display_buf.as_slice()
                } else {
                    if c.truncated {
                        stats.record_path_truncated();
                    }
                    c.bytes
                };
                scratch.vpaths[1]
                    .build_with_suffix(root_display, entry_bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if scratch.path_budget_used[1].saturating_add(need)
                > archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            scratch.path_budget_used[1] = scratch.path_budget_used[1].saturating_add(need);

            if meta.is_dir {
                stats.record_entry_skipped(EntrySkipReason::NonRegular, entry_display, false);
                continue;
            }

            if meta.is_encrypted() {
                stats.record_entry_skipped(EntrySkipReason::EncryptedEntry, entry_display, false);
                match archive.encrypted_policy {
                    crate::archive::EncryptedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::EncryptedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                    crate::archive::EncryptedPolicy::FailRun => {
                        scratch.abort_run = true;
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                }
            }
            if !meta.compression_supported() {
                stats.record_entry_skipped(
                    EntrySkipReason::UnsupportedCompression,
                    entry_display,
                    false,
                );
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::UnsupportedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        scratch.abort_run = true;
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                }
            }

            (
                meta.flags,
                meta.method,
                meta.compressed_size,
                meta.uncompressed_size,
                meta.local_header_offset,
                meta.cdfh_offset,
                meta.lfh_offset_valid,
                meta.is_dir,
                meta.name_truncated,
                meta.name_hash64,
                entry_display,
            )
        };

        let meta = ZipEntryMeta {
            name: b"",
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
        };

        scratch.budgets.begin_entry_scan();

        let mut reader = match cursor.open_entry_reader(&meta, &mut scratch.budgets) {
            Ok(Ok(r)) => r,
            Ok(Err(r)) => {
                if r == PartialReason::MalformedZip {
                    stats.record_entry_skipped(EntrySkipReason::CorruptEntry, entry_display, false);
                    scratch.budgets.end_entry(false);
                    continue;
                }
                outcome = ArchiveEnd::Partial(r);
                scratch.budgets.end_entry(false);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
                scratch.budgets.end_entry(false);
                break;
            }
        };

        let entry_meta = EntryMeta {
            display_path: entry_display,
            size_hint: meta.uncompressed_size,
            flags: 0,
        };
        sink.on_entry_start(&entry_meta)?;

        let mut last_comp = 0u64;
        let ratio_active = meta.method == 8;

        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;

        loop {
            if carry > 0 && have > 0 {
                buf.copy_within(have - carry..have, 0);
            }

            let allowance = scratch
                .budgets
                .remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allowance == 0 {
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
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
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
                    let r = budget_hit_to_partial_reason(hit);
                    outcome = ArchiveEnd::Partial(r);
                    entry_partial_reason = Some(r);
                }
                break;
            }

            let dst = &mut buf[carry..carry + read_max];

            let n = match reader.read_decompressed(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    entry_partial_reason = Some(PartialReason::MalformedZip);
                    break;
                }
            };

            let now = reader.total_compressed();
            let delta = now.saturating_sub(last_comp);
            last_comp = now;
            if delta > 0 {
                scratch.budgets.charge_compressed_in(delta);
            }

            if n == 0 {
                break;
            }

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
            let data = &buf[..read_len];
            let chunk = EntryChunk {
                data,
                base_offset,
                new_bytes_start: offset,
                new_bytes_len: allowed_usize,
            };
            sink.on_entry_chunk(chunk)?;
            if !entry_scanned {
                stats.record_entry_scanned();
                entry_scanned = true;
            }

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = scratch.overlap.min(read_len);

            if allowed_usize < n {
                break;
            }
        }

        sink.on_entry_end()?;
        scratch.budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            stats.record_entry_partial(r, entry_display, false);
        }
    }

    scratch.budgets.exit_archive();
    Ok(outcome)
}
