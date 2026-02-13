//! Deterministic budget tracking for archive expansion/scanning.
//!
//! Prevents resource exhaustion from zip bombs and deeply nested archives by
//! enforcing hard caps on entry counts, decompressed output, metadata, nesting
//! depth, and inflation ratio.  Budgets are purely deterministic — no wall-clock
//! timeouts — so identical inputs always produce identical outcomes.
//!
//! # Budget Hierarchy
//!
//! Three nested scopes, each with independent caps:
//!
//! ```text
//! Root (per-source-file)
//!  └─ Archive (per-container: zip, tar, tar.gz, …)
//!      └─ Entry (per-file inside the container)
//! ```
//!
//! When charging decompressed output the tightest remaining allowance across
//! all three scopes wins, and the corresponding [`BudgetHit`] variant is
//! returned so callers can decide whether to skip just the entry, mark the
//! archive partial, or stop the entire root.
//!
//! # Caller Protocol
//!
//! ```text
//! new(cfg) / reset()
//!   enter_archive()          ← push a frame, enforce depth cap
//!     note_entry() / begin_entry()   ← count + optionally open entry scope
//!       charge_metadata(n)
//!       charge_compressed_in(n)
//!       charge_decompressed_out(n) / charge_discarded_out(n)
//!     end_entry(scanned)     ← close entry scope
//!   exit_archive()           ← pop frame
//! ```
//!
//! `enter_archive`/`exit_archive` and `begin_entry`/`end_entry` must be
//! balanced.  Calling charge methods without an active frame is safe (returns
//! a clamp-to-zero result).
//!
//! # Invariants
//!
//! - Budgets are enforced by counts/bytes only (no wall-clock time).
//! - All accounting is saturating; overflows are treated as budget hits.
//! - If no archive frame is active, charge methods clamp to 0 and remaining
//!   allowance is 0.
//!
//! # Design Notes
//!
//! - This module does **not** perform I/O or decompression.
//! - Per-entry vs per-archive limits are separated to avoid ambiguity.
//! - The frame stack is preallocated to `max_archive_depth` and never grows
//!   after startup (no `Vec` push/pop on hot paths).

use super::{ArchiveConfig, ArchiveSkipReason, EntrySkipReason, PartialReason};

/// Classification of a budget limit hit.
///
/// Variants are ordered by blast radius — `SkipEntry` affects only the
/// current file inside the archive, while `StopRoot` halts all archive
/// processing for the entire source file.
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
    /// Stop scanning further archive output for this root (report as partial at the root level).
    StopRoot(PartialReason),
}

/// Result of charging a quantity where partial progress is meaningful (bytes).
///
/// `Clamp` indicates the caller must scan/emit only the first `allowed` bytes
/// and then stop, using `hit` to report the reason.  `allowed` may be zero,
/// meaning no bytes should be processed at all.
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

/// Sentinel value indicating no entry is currently open.
/// Using a sentinel instead of a separate `bool` eliminates 7 bytes of padding
/// and keeps the struct at 40 bytes with `#[repr(C)]`.
const ENTRY_NOT_OPEN: u64 = u64::MAX;

/// Per-archive accounting frame pushed/popped by `enter_archive`/`exit_archive`.
///
/// Tracks entry counts, byte counters, and per-entry state for a single level
/// of archive nesting.  `#[repr(C)]` with a compile-time size assertion keeps
/// the layout predictable and padding-free (40 bytes).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct ArchiveFrame {
    /// Total entry records observed (headers, metadata records, regular files).
    entries_seen: u32,
    /// Entries for which at least one payload byte was scanned/emitted.
    entries_scanned: u32,
    /// Cumulative metadata bytes charged (central directory, tar headers, etc.).
    metadata_bytes: u64,
    /// Cumulative compressed input bytes consumed (for inflation ratio tracking).
    compressed_in: u64,
    /// Cumulative decompressed output bytes produced across all entries.
    decompressed_out: u64,
    /// Decompressed bytes produced for the *current* entry.
    /// [`ENTRY_NOT_OPEN`] (`u64::MAX`) means no entry scope is active.
    entry_decompressed_out: u64,
}

impl Default for ArchiveFrame {
    #[inline]
    fn default() -> Self {
        Self {
            entries_seen: 0,
            entries_scanned: 0,
            metadata_bytes: 0,
            compressed_in: 0,
            decompressed_out: 0,
            entry_decompressed_out: ENTRY_NOT_OPEN,
        }
    }
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

    /// Return a mutable reference to the topmost archive frame.
    ///
    /// # Safety
    ///
    /// `self.depth` is always in `0..=self.max_depth`, and `self.frames` is
    /// preallocated to exactly `self.max_depth` elements.  Every caller checks
    /// `has_active_frame()` (i.e. `depth > 0`) before reaching this method, so
    /// `depth - 1` is always a valid index.  The `debug_assert` catches
    /// violations in test builds.
    #[inline(always)]
    fn cur_mut(&mut self) -> &mut ArchiveFrame {
        debug_assert!(self.depth > 0, "enter_archive must be called first");
        // SAFETY: depth ∈ 1..=max_depth and frames.len() == max_depth.
        unsafe { self.frames.get_unchecked_mut(self.depth - 1) }
    }

    /// Return a shared reference to the topmost archive frame.
    ///
    /// See [`Self::cur_mut`] for the safety argument.
    #[inline(always)]
    fn cur(&self) -> &ArchiveFrame {
        debug_assert!(self.depth > 0, "enter_archive must be called first");
        // SAFETY: same as cur_mut.
        unsafe { self.frames.get_unchecked(self.depth - 1) }
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
    ///
    /// No-ops at depth 0 so that error-recovery paths can call this
    /// unconditionally without tracking whether `enter_archive` succeeded.
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
    #[inline]
    pub fn begin_entry_scan(&mut self) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        f.entry_decompressed_out = 0;
    }

    /// Convenience: [`note_entry`](Self::note_entry) + [`begin_entry_scan`](Self::begin_entry_scan).
    ///
    /// Use this for regular file entries where you intend to read payload bytes.
    /// Callers must call [`end_entry`](Self::end_entry) once done.
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
    #[inline]
    pub fn end_entry(&mut self, scanned: bool) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        if scanned {
            f.entries_scanned = f.entries_scanned.saturating_add(1);
        }
        f.entry_decompressed_out = ENTRY_NOT_OPEN;
    }

    /// Charge archive metadata bytes (central directory bytes, tar headers, pax, etc).
    #[inline]
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
    #[inline]
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
    #[inline]
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

        let (entry_out, arch_out, comp_in, entries_scanned) = {
            let f = self.cur();
            (
                f.entry_decompressed_out,
                f.decompressed_out,
                f.compressed_in,
                f.entries_scanned,
            )
        };
        let entry_open = entry_out != ENTRY_NOT_OPEN;

        // Compute remaining headroom under each independent cap.
        // The tightest (smallest) wins and determines `allowed`.
        let rem_entry = if entry_open {
            remaining(max_entry, entry_out)
        } else {
            u64::MAX // no entry scope → entry cap does not apply
        };
        let rem_arch = remaining(max_archive, arch_out);
        let rem_root = remaining(max_root, root_out);
        let rem_ratio = if max_ratio > 0 && comp_in > 0 {
            remaining(comp_in.saturating_mul(max_ratio as u64), arch_out)
        } else {
            u64::MAX // ratio disabled or no compressed input observed yet
        };

        let min_rem = rem_entry.min(rem_arch).min(rem_root).min(rem_ratio);
        let allowed = bytes.min(min_rem);

        if allowed > 0 {
            let f = self.cur_mut();
            if f.entry_decompressed_out != ENTRY_NOT_OPEN {
                f.entry_decompressed_out = f.entry_decompressed_out.saturating_add(allowed);
            }
            f.decompressed_out = f.decompressed_out.saturating_add(allowed);
            self.root_decompressed_out = self.root_decompressed_out.saturating_add(allowed);
        }

        if allowed == bytes {
            return ChargeResult::Ok;
        }

        // Identify which cap was the binding constraint.
        //
        // `progressed` distinguishes "we scanned nothing from this archive"
        // (→ SkipArchive, the archive is treated as if it was never opened)
        // from "we scanned some entries/bytes" (→ PartialArchive, results so
        // far are still reported to the caller).
        let progressed = arch_out > 0 || entries_scanned > 0;
        let hit = if allowed == rem_entry {
            BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
        } else if allowed == rem_arch {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::ArchiveOutputBudgetExceeded)
            }
        } else if allowed == rem_root {
            BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded)
        } else if allowed == rem_ratio {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::InflationRatioExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::InflationRatioExceeded)
            }
        } else {
            // Defensive fallback — should not be reachable when caps are finite.
            BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
        };

        ChargeResult::Clamp { allowed, hit }
    }

    /// Charge decompressed bytes that were discarded (not scanned) within an entry.
    ///
    /// This enforces per-archive and per-root caps (and ratio), but does **not**
    /// apply per-entry caps since the entry is already being truncated.
    ///
    /// `allowed` is the tightest remaining allowance across archive/root/ratio caps.
    #[inline]
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

        let rem_arch = remaining(max_archive, arch_out);
        let rem_root = remaining(max_root, root_out);
        let rem_ratio = if max_ratio > 0 && comp_in > 0 {
            remaining(comp_in.saturating_mul(max_ratio as u64), arch_out)
        } else {
            u64::MAX
        };

        let min_rem = rem_arch.min(rem_root).min(rem_ratio);
        let allowed = bytes.min(min_rem);

        if allowed > 0 {
            let f = self.cur_mut();
            f.decompressed_out = f.decompressed_out.saturating_add(allowed);
            self.root_decompressed_out = self.root_decompressed_out.saturating_add(allowed);
        }

        if allowed == bytes {
            return ChargeResult::Ok;
        }

        let progressed = arch_out > 0 || entries_scanned > 0;
        let hit = if allowed == rem_arch {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::ArchiveOutputBudgetExceeded)
            }
        } else if allowed == rem_root {
            BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded)
        } else if allowed == rem_ratio {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::InflationRatioExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::InflationRatioExceeded)
            }
        } else {
            BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
        };

        ChargeResult::Clamp { allowed, hit }
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
    #[inline]
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
    #[inline]
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

        if f.entry_decompressed_out != ENTRY_NOT_OPEN {
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

    /// Return the appropriate [`BudgetHit`] for a metadata budget overrun.
    ///
    /// If no payload data has been scanned yet the archive can be skipped
    /// entirely; otherwise it is reported as partial.
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

/// Charge `bytes` against `counter` up to `cap`, returning [`ChargeResult::Ok`]
/// when the full amount fits or [`ChargeResult::Clamp`] with the allowed prefix.
///
/// This is the shared primitive behind [`ArchiveBudgets::charge_metadata`] and
/// similar single-counter charge paths.
#[inline]
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

// Compile-time assertion: ArchiveFrame is tightly packed at 40 bytes.
const _: () = assert!(std::mem::size_of::<ArchiveFrame>() == 40);

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

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::archive::ArchiveConfig;

    /// Prove that `depth - 1` is always a valid index into `frames` whenever
    /// `has_active_frame()` returns true, for any sequence of enter/exit ops.
    ///
    /// This is the safety invariant relied on by `cur()` and `cur_mut()`.
    /// The proof bounds `max_archive_depth` to 3 (the production default)
    /// and explores 6 symbolic operations to keep the state space tractable.
    #[kani::proof]
    #[kani::unwind(8)]
    fn verify_budget_cur_bounds() {
        let depth: u16 = kani::any();
        kani::assume(depth >= 1 && depth <= 4);

        let cfg = ArchiveConfig {
            max_archive_depth: depth,
            ..ArchiveConfig::default()
        };
        let mut b = ArchiveBudgets::new(&cfg);

        kani::assert(
            b.frames.len() == depth as usize,
            "frames must be preallocated to max_depth",
        );

        // Perform a symbolic sequence of enter/exit operations.
        // 6 ops with max_depth ≤ 4 exercises all reachable depth transitions.
        let mut i = 0u32;
        while i < 6 {
            let enter: bool = kani::any();
            if enter {
                let _ = b.enter_archive();
            } else {
                b.exit_archive();
            }

            // Core invariant: whenever depth > 0, depth - 1 is in bounds.
            if b.has_active_frame() {
                kani::assert(b.depth >= 1, "has_active_frame implies depth >= 1");
                kani::assert(
                    b.depth - 1 < b.frames.len(),
                    "depth - 1 must be a valid frame index",
                );
            }

            // Secondary invariant: depth never exceeds max_depth.
            kani::assert(
                b.depth <= depth as usize,
                "depth must never exceed max_depth",
            );

            i += 1;
        }
    }
}
