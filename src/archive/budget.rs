//! Deterministic budget tracking for archive expansion/scanning.
//!
//! # Invariants
//! - Budgets are enforced by counts/bytes only (no wall-clock time).
//! - All accounting is saturating; overflows are treated as budget hits.
//! - Callers must enter/exit archive frames correctly.
//! - If no archive frame is active, charge methods clamp to 0 and remaining allowance is 0.
//!
//! # Algorithm
//! - Track a fixed-size stack of archive frames plus a root-wide output counter.
//! - Charge metadata, compressed input, and decompressed output deterministically.
//! - Return a `Clamp { allowed, hit }` result to let callers stop cleanly.
//!
//! # Design Notes
//! - This module does **not** perform I/O or decompression.
//! - Per-entry vs per-archive limits are separated to avoid ambiguity.
//! - The frame stack is preallocated to `max_archive_depth` and never grows
//!   after startup (no `Vec` push/pop on hot paths).

use super::{ArchiveConfig, ArchiveSkipReason, EntrySkipReason, PartialReason};

/// Classification of a budget limit hit.
///
/// Callers should map this to either an entry skip, an archive skip, or a
/// partial outcome depending on the current scan progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetHit {
    /// Skip the current entry and continue the archive.
    SkipEntry(EntrySkipReason),
    /// Skip the entire archive (typically before any scanning progress).
    SkipArchive(ArchiveSkipReason),
    /// Stop scanning this archive, but report as "partial".
    PartialArchive(PartialReason),
    /// Stop scanning further archive output for this root (report as partial at the root/archive level).
    StopRoot(PartialReason),
}

/// Result of charging a quantity where partial progress is meaningful (bytes).
///
/// `Clamp` indicates the caller must scan/emits only the prefix length `allowed`
/// and then stop, using `hit` to report the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeResult {
    /// Full requested amount is allowed and was charged.
    Ok,
    /// Only `allowed` bytes were charged; caller must stop after scanning/emitting that prefix.
    Clamp { allowed: u64, hit: BudgetHit },
}

/// Deterministic budget tracker for nested archive scanning.
///
/// # Invariants
/// - `enter_archive` / `exit_archive` must be balanced.
/// - `begin_entry` / `end_entry` must be balanced within the current frame.
/// - All methods are panic-free for hostile inputs.
/// - Frame storage is a fixed-size stack preallocated to `max_archive_depth`.
#[derive(Clone, Debug)]
pub struct ArchiveBudgets {
    // caps
    max_depth: u8,
    max_entries_per_archive: u32,
    max_uncompressed_bytes_per_entry: u64,
    max_total_uncompressed_bytes_per_archive: u64,
    max_total_uncompressed_bytes_per_root: u64,
    max_archive_metadata_bytes: u64,
    max_inflation_ratio: u32,

    // root counters
    root_decompressed_out: u64,

    // fixed-size stack frames, one per nested archive (preallocated)
    frames: Box<[ArchiveFrame]>,
    depth: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct ArchiveFrame {
    entries_seen: u32,
    entries_scanned: u32,

    metadata_bytes: u64,
    compressed_in: u64,
    decompressed_out: u64,

    entry_open: bool,
    entry_decompressed_out: u64,
}

impl ArchiveBudgets {
    #[inline(always)]
    fn has_active_frame(&self) -> bool {
        self.depth > 0
    }

    #[inline(always)]
    fn no_frame_hit(&self) -> BudgetHit {
        BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
    }

    /// Construct a budget tracker with fixed-size frame storage derived from config.
    ///
    /// The frame stack is preallocated to `cfg.max_archive_depth` and never grows.
    pub fn new(cfg: &ArchiveConfig) -> Self {
        let frames_cap = cfg.max_archive_depth as usize;
        Self {
            max_depth: cfg.max_archive_depth,
            max_entries_per_archive: cfg.max_entries_per_archive,
            max_uncompressed_bytes_per_entry: cfg.max_uncompressed_bytes_per_entry,
            max_total_uncompressed_bytes_per_archive: cfg.max_total_uncompressed_bytes_per_archive,
            max_total_uncompressed_bytes_per_root: cfg.max_total_uncompressed_bytes_per_root,
            max_archive_metadata_bytes: cfg.max_archive_metadata_bytes,
            max_inflation_ratio: cfg.max_inflation_ratio,

            root_decompressed_out: 0,
            frames: vec![ArchiveFrame::default(); frames_cap].into_boxed_slice(),
            depth: 0,
        }
    }

    /// Reset all counters and frame state for reuse.
    ///
    /// This allows callers to reuse a single `ArchiveBudgets` instance without
    /// allocating per-archive.
    #[inline]
    pub fn reset(&mut self) {
        self.root_decompressed_out = 0;
        self.depth = 0;
        self.debug_assert_no_growth();
    }

    /// Debug-only guard: ensure the frame stack never grows beyond its
    /// preallocated capacity.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                self.frames.len(),
                self.max_depth as usize,
                "archive budget frame stack length changed after startup"
            );
        }
    }

    #[inline(always)]
    pub fn depth(&self) -> u8 {
        self.depth as u8
    }

    #[inline(always)]
    pub fn root_decompressed_out(&self) -> u64 {
        self.root_decompressed_out
    }

    #[inline(always)]
    fn cur_mut(&mut self) -> &mut ArchiveFrame {
        debug_assert!(self.depth > 0, "enter_archive must be called first");
        &mut self.frames[self.depth - 1]
    }

    #[inline(always)]
    fn cur(&self) -> &ArchiveFrame {
        debug_assert!(self.depth > 0, "enter_archive must be called first");
        &self.frames[self.depth - 1]
    }

    /// Enter a new archive scope (pushes a frame) and enforces max depth.
    pub fn enter_archive(&mut self) -> Result<(), BudgetHit> {
        let next_depth = self.depth.saturating_add(1);
        if next_depth > self.max_depth as usize {
            return Err(BudgetHit::SkipArchive(ArchiveSkipReason::DepthExceeded));
        }
        self.frames[self.depth] = ArchiveFrame::default();
        self.depth = next_depth;
        Ok(())
    }

    /// Exit current archive scope (pops a frame).
    pub fn exit_archive(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
        }
    }

    /// Count an archive entry record without opening an output-accounted payload stream.
    ///
    /// Used by tar for header records and metadata-only records (PAX, GNU longname),
    /// and for non-regular entries we skip.
    pub fn note_entry(&mut self) -> Result<(), BudgetHit> {
        if !self.has_active_frame() {
            return Err(self.no_frame_hit());
        }
        let max_entries = self.max_entries_per_archive;
        let f = self.cur_mut();
        if f.entries_seen == max_entries {
            if f.decompressed_out > 0 || f.entries_scanned > 0 {
                return Err(BudgetHit::PartialArchive(PartialReason::EntryCountExceeded));
            }
            return Err(BudgetHit::SkipArchive(
                ArchiveSkipReason::EntryCountExceeded,
            ));
        }
        f.entries_seen = f.entries_seen.saturating_add(1);
        Ok(())
    }

    /// Open the current entry for output accounting.
    ///
    /// Caller must have already called `note_entry()` for this record.
    pub fn begin_entry_scan(&mut self) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        f.entry_open = true;
        f.entry_decompressed_out = 0;
    }

    /// Begin processing a new entry (enforces entry count cap).
    ///
    /// Callers should call `end_entry(scanned)` once done.
    pub fn begin_entry(&mut self) -> Result<(), BudgetHit> {
        self.note_entry()?;
        self.begin_entry_scan();
        Ok(())
    }

    /// Close the current entry accounting scope.
    ///
    /// `scanned=true` means at least one payload byte was scanned/emitted and
    /// counts toward `entries_scanned`. Call with `false` for metadata-only or
    /// skipped entries to keep progress accounting consistent.
    pub fn end_entry(&mut self, scanned: bool) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        if scanned {
            f.entries_scanned = f.entries_scanned.saturating_add(1);
        }
        f.entry_open = false;
        f.entry_decompressed_out = 0;
    }

    /// Charge archive metadata bytes (central directory bytes, tar headers, pax, etc).
    pub fn charge_metadata(&mut self, bytes: u64) -> ChargeResult {
        if bytes == 0 {
            return ChargeResult::Ok;
        }
        if !self.has_active_frame() {
            return ChargeResult::Clamp {
                allowed: 0,
                hit: self.no_frame_hit(),
            };
        }
        let hit = self.metadata_budget_hit_kind();
        let cap = self.max_archive_metadata_bytes;
        let f = self.cur_mut();
        charge_u64_with_cap(&mut f.metadata_bytes, bytes, cap, hit)
    }

    /// Charge compressed input bytes consumed for ratio tracking.
    ///
    /// This never triggers a budget directly; ratio enforcement happens when charging decompressed output.
    pub fn charge_compressed_in(&mut self, bytes: u64) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        f.compressed_in = f.compressed_in.saturating_add(bytes);
    }

    /// Charge decompressed output bytes produced for the current entry/archive/root.
    ///
    /// Returns:
    /// - Ok if all bytes may be scanned/emitted
    /// - Clamp with `allowed` prefix bytes that may be scanned/emitted, then stop with `hit`
    ///
    /// Notes:
    /// - Per-entry caps are enforced only when an entry is open (`begin_entry_scan`).
    /// - `allowed` is the tightest remaining allowance across entry/archive/root/ratio caps;
    ///   `hit` reports the constraint that became tightest for this charge.
    pub fn charge_decompressed_out(&mut self, bytes: u64) -> ChargeResult {
        if bytes == 0 {
            return ChargeResult::Ok;
        }
        if !self.has_active_frame() {
            return ChargeResult::Clamp {
                allowed: 0,
                hit: self.no_frame_hit(),
            };
        }

        let max_entry = self.max_uncompressed_bytes_per_entry;
        let max_archive = self.max_total_uncompressed_bytes_per_archive;
        let max_root = self.max_total_uncompressed_bytes_per_root;
        let max_ratio = self.max_inflation_ratio;
        let root_out = self.root_decompressed_out;

        let (entry_open, entry_out, arch_out, comp_in, entries_scanned) = {
            let f = self.cur();
            (
                f.entry_open,
                f.entry_decompressed_out,
                f.decompressed_out,
                f.compressed_in,
                f.entries_scanned,
            )
        };
        let progressed = arch_out > 0 || entries_scanned > 0;

        // Determine per-constraint remaining allowance.
        let mut allowed = bytes;
        let mut hit: Option<BudgetHit> = None;

        // 1) Entry cap (skip entry).
        if entry_open {
            let rem_entry = remaining(max_entry, entry_out);
            if rem_entry < allowed {
                allowed = rem_entry;
                hit = Some(BudgetHit::SkipEntry(
                    EntrySkipReason::EntryOutputBudgetExceeded,
                ));
            }
        }

        // 2) Per-archive cap (skip vs partial depends on progress).
        {
            let rem_arch = remaining(max_archive, arch_out);
            if rem_arch < allowed {
                allowed = rem_arch;
                hit = Some(if progressed {
                    BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
                } else {
                    BudgetHit::SkipArchive(ArchiveSkipReason::ArchiveOutputBudgetExceeded)
                });
            }
        }

        // 3) Per-root cap (always stop root).
        {
            let rem_root = remaining(max_root, root_out);
            if rem_root < allowed {
                allowed = rem_root;
                hit = Some(BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded));
            }
        }

        // 4) Inflation ratio best-effort: out <= in * ratio (only if in > 0).
        if max_ratio > 0 && comp_in > 0 {
            let max_out = comp_in.saturating_mul(max_ratio as u64);
            let rem_ratio = remaining(max_out, arch_out);
            if rem_ratio < allowed {
                allowed = rem_ratio;
                hit = Some(if progressed {
                    BudgetHit::PartialArchive(PartialReason::InflationRatioExceeded)
                } else {
                    BudgetHit::SkipArchive(ArchiveSkipReason::InflationRatioExceeded)
                });
            }
        }

        // Charge the allowed portion.
        if allowed > 0 {
            let f = self.cur_mut();
            if f.entry_open {
                f.entry_decompressed_out = f.entry_decompressed_out.saturating_add(allowed);
            }
            f.decompressed_out = f.decompressed_out.saturating_add(allowed);
            self.root_decompressed_out = self.root_decompressed_out.saturating_add(allowed);
        }

        if allowed == bytes {
            ChargeResult::Ok
        } else {
            // allowed may be 0; caller must stop immediately.
            ChargeResult::Clamp {
                allowed,
                hit: hit.unwrap_or(BudgetHit::PartialArchive(
                    PartialReason::ArchiveOutputBudgetExceeded,
                )),
            }
        }
    }

    /// Charge decompressed bytes that were discarded (not scanned) within an entry.
    ///
    /// This enforces per-archive and per-root caps (and ratio), but does **not**
    /// apply per-entry caps since the entry is already being truncated.
    ///
    /// `allowed` is the tightest remaining allowance across archive/root/ratio caps.
    pub fn charge_discarded_out(&mut self, bytes: u64) -> ChargeResult {
        if bytes == 0 {
            return ChargeResult::Ok;
        }
        if !self.has_active_frame() {
            return ChargeResult::Clamp {
                allowed: 0,
                hit: self.no_frame_hit(),
            };
        }

        let max_archive = self.max_total_uncompressed_bytes_per_archive;
        let max_root = self.max_total_uncompressed_bytes_per_root;
        let max_ratio = self.max_inflation_ratio;
        let root_out = self.root_decompressed_out;

        let (arch_out, comp_in, entries_scanned) = {
            let f = self.cur();
            (f.decompressed_out, f.compressed_in, f.entries_scanned)
        };
        let progressed = arch_out > 0 || entries_scanned > 0;

        let mut allowed = bytes;
        let mut hit: Option<BudgetHit> = None;

        // Per-archive cap.
        {
            let rem_arch = remaining(max_archive, arch_out);
            if rem_arch < allowed {
                allowed = rem_arch;
                hit = Some(if progressed {
                    BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
                } else {
                    BudgetHit::SkipArchive(ArchiveSkipReason::ArchiveOutputBudgetExceeded)
                });
            }
        }

        // Per-root cap.
        {
            let rem_root = remaining(max_root, root_out);
            if rem_root < allowed {
                allowed = rem_root;
                hit = Some(BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded));
            }
        }

        // Inflation ratio best-effort: out <= in * ratio (only if in > 0).
        if max_ratio > 0 && comp_in > 0 {
            let max_out = comp_in.saturating_mul(max_ratio as u64);
            let rem_ratio = remaining(max_out, arch_out);
            if rem_ratio < allowed {
                allowed = rem_ratio;
                hit = Some(if progressed {
                    BudgetHit::PartialArchive(PartialReason::InflationRatioExceeded)
                } else {
                    BudgetHit::SkipArchive(ArchiveSkipReason::InflationRatioExceeded)
                });
            }
        }

        if allowed > 0 {
            let f = self.cur_mut();
            f.decompressed_out = f.decompressed_out.saturating_add(allowed);
            self.root_decompressed_out = self.root_decompressed_out.saturating_add(allowed);
        }

        if allowed == bytes {
            ChargeResult::Ok
        } else {
            ChargeResult::Clamp {
                allowed,
                hit: hit.unwrap_or(BudgetHit::PartialArchive(
                    PartialReason::ArchiveOutputBudgetExceeded,
                )),
            }
        }
    }

    /// Best-effort remaining decompressed bytes that may be produced/scanned right now.
    ///
    /// This is used to cap read sizes so we do not overshoot budgets by large amounts
    /// in a single decoder read.
    ///
    /// Semantics:
    /// - If no archive frame is active, returns 0.
    /// - Includes per-entry (if entry open), per-archive, and per-root limits.
    /// - Ratio enforcement is applied by `remaining_decompressed_allowance_with_ratio_probe`.
    pub fn remaining_decompressed_allowance(&self) -> u64 {
        self.remaining_decompressed_allowance_with_ratio_probe(false)
    }

    /// Remaining decompressed bytes allowed, with optional ratio probing.
    ///
    /// If `ratio_active` is true, we apply a conservative ratio cap even when
    /// no compressed bytes have been observed yet. This avoids a single large
    /// read overshooting the inflation ratio by more than one probe-sized chunk.
    ///
    /// This should be enabled for compressed formats (gzip/deflate) and left
    /// disabled for uncompressed containers (plain tar, stored zip entries).
    pub fn remaining_decompressed_allowance_with_ratio_probe(&self, ratio_active: bool) -> u64 {
        if !self.has_active_frame() {
            return 0;
        }
        let f = self.cur();

        let mut rem = remaining(
            self.max_total_uncompressed_bytes_per_root,
            self.root_decompressed_out,
        );

        let rem_arch = remaining(
            self.max_total_uncompressed_bytes_per_archive,
            f.decompressed_out,
        );
        rem = rem.min(rem_arch);

        if f.entry_open {
            let rem_entry = remaining(
                self.max_uncompressed_bytes_per_entry,
                f.entry_decompressed_out,
            );
            rem = rem.min(rem_entry);
        }

        // Ratio enforcement (optional): out <= in * ratio.
        if ratio_active && self.max_inflation_ratio > 0 {
            let comp_in = if f.compressed_in > 0 {
                f.compressed_in
            } else {
                // Conservative probe: assume at least 1 compressed byte to cap
                // the first read and avoid large overshoot.
                1
            };
            let max_out = comp_in.saturating_mul(self.max_inflation_ratio as u64);
            let rem_ratio = remaining(max_out, f.decompressed_out);
            rem = rem.min(rem_ratio);
        }

        rem
    }

    fn metadata_budget_hit_kind(&self) -> BudgetHit {
        let f = self.cur();
        if f.decompressed_out == 0 && f.entries_scanned == 0 {
            BudgetHit::SkipArchive(ArchiveSkipReason::MetadataBudgetExceeded)
        } else {
            BudgetHit::PartialArchive(PartialReason::MetadataBudgetExceeded)
        }
    }
}

#[inline(always)]
fn remaining(cap: u64, used: u64) -> u64 {
    cap.saturating_sub(used)
}

fn charge_u64_with_cap(counter: &mut u64, bytes: u64, cap: u64, hit: BudgetHit) -> ChargeResult {
    if bytes == 0 {
        return ChargeResult::Ok;
    }
    let rem = remaining(cap, *counter);
    let allowed = bytes.min(rem);
    if allowed > 0 {
        *counter = counter.saturating_add(allowed);
    }
    if allowed == bytes {
        ChargeResult::Ok
    } else {
        ChargeResult::Clamp { allowed, hit }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveConfig;

    fn cfg() -> ArchiveConfig {
        ArchiveConfig {
            enabled: true,
            max_archive_depth: 2,
            max_entries_per_archive: 2,
            max_uncompressed_bytes_per_entry: 10,
            max_total_uncompressed_bytes_per_archive: 20,
            max_total_uncompressed_bytes_per_root: 30,
            max_archive_metadata_bytes: 8,
            max_inflation_ratio: 2,
            ..ArchiveConfig::default()
        }
    }

    #[test]
    fn depth_zero_calls_are_safe() {
        let mut b = ArchiveBudgets::new(&cfg());
        let hit = BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded);

        assert_eq!(b.remaining_decompressed_allowance(), 0);
        assert_eq!(b.remaining_decompressed_allowance_with_ratio_probe(true), 0);
        assert_eq!(
            b.charge_metadata(1),
            ChargeResult::Clamp { allowed: 0, hit }
        );
        b.charge_compressed_in(5);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp { allowed: 0, hit }
        );
        assert_eq!(b.note_entry().unwrap_err(), hit);
        assert_eq!(b.begin_entry().unwrap_err(), hit);
        b.begin_entry_scan();
        b.end_entry(false);
        b.exit_archive();
        assert_eq!(b.root_decompressed_out(), 0);
    }

    #[test]
    fn depth_is_enforced() {
        let mut b = ArchiveBudgets::new(&cfg());
        assert!(b.enter_archive().is_ok());
        assert!(b.enter_archive().is_ok());
        assert_eq!(
            b.enter_archive().unwrap_err(),
            BudgetHit::SkipArchive(ArchiveSkipReason::DepthExceeded)
        );
    }

    #[test]
    fn metadata_budget_clamps_and_reports_skip_before_progress() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();

        let r = b.charge_metadata(100);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 8,
                hit: BudgetHit::SkipArchive(ArchiveSkipReason::MetadataBudgetExceeded)
            }
        );
    }

    #[test]
    fn entry_count_reports_partial_after_progress() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();

        // Scan one entry with 1 byte to create progress.
        b.begin_entry().unwrap();
        assert_eq!(b.charge_decompressed_out(1), ChargeResult::Ok);
        b.end_entry(true);

        // Second entry ok.
        b.begin_entry().unwrap();
        b.end_entry(false);

        // Third entry exceeds cap -> partial.
        assert_eq!(
            b.begin_entry().unwrap_err(),
            BudgetHit::PartialArchive(PartialReason::EntryCountExceeded)
        );
    }

    #[test]
    fn entry_output_cap_clamps_and_skips_entry() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // Request 15 bytes; entry cap is 10.
        let r = b.charge_decompressed_out(15);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 10,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
            }
        );
    }

    #[test]
    fn archive_output_cap_clamps_and_reports_partial_after_progress() {
        let mut c = cfg();
        c.max_uncompressed_bytes_per_entry = 100;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // Fill archive to cap (20) across requests.
        assert_eq!(b.charge_decompressed_out(20), ChargeResult::Ok);

        // Next byte clamps to 0 and reports partial.
        let r = b.charge_decompressed_out(1);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
            }
        );
    }

    #[test]
    fn root_output_cap_stops_root() {
        let mut c = cfg();
        c.max_total_uncompressed_bytes_per_root = 5;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        assert_eq!(b.charge_decompressed_out(5), ChargeResult::Ok);
        let r = b.charge_decompressed_out(1);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded)
            }
        );
    }

    #[test]
    fn inflation_ratio_is_enforced_best_effort() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // compressed_in=2, ratio=2 => max_out=4
        b.charge_compressed_in(2);
        assert_eq!(b.charge_decompressed_out(4), ChargeResult::Ok);

        let r = b.charge_decompressed_out(1);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::PartialArchive(PartialReason::InflationRatioExceeded)
            }
        );
    }

    #[test]
    fn ratio_probe_caps_initial_allowance() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // No compressed bytes observed yet; probe should cap to ratio (2).
        let rem = b.remaining_decompressed_allowance_with_ratio_probe(true);
        assert_eq!(rem, 2);
    }
}
