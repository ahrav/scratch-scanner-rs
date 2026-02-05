//! tar streaming helpers.
//!
//! # Invariants
//! - Parsing is sequential; no seeks are performed.
//! - Size fields are untrusted; overflow or short reads are treated as malformed.
//! - Metadata bytes are charged to `ArchiveBudgets::charge_metadata`.
//!
//! # Algorithm
//! - Read 512-byte header blocks.
//! - Resolve GNU longname (`L`) and PAX `path=` overrides for the next entry.
//! - Yield only regular file entries (typeflag `0`/NUL) to callers.
//!
//! # Design Notes
//! - This is a scanner-oriented parser, not a general extraction library.
//! - Global PAX `path` is parsed but intentionally not applied.

use crate::archive::formats::GzipStream;
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, ArchiveSkipReason, BudgetHit, ChargeResult, PartialReason,
};

use std::fs::File;
use std::io::{self, Read};
use std::sync::Arc;

pub const TAR_BLOCK_LEN: usize = 512;
pub const USTAR_MAGIC_OFFSET: usize = 257;

#[inline(always)]
pub fn is_ustar_header(header: &[u8]) -> bool {
    header.len() >= TAR_BLOCK_LEN && &header[USTAR_MAGIC_OFFSET..USTAR_MAGIC_OFFSET + 5] == b"ustar"
}

/// Input source for tar scanning: plain tar file or gzip-decoded tar stream.
///
/// # Design Notes
/// - Used by the scheduler to distinguish compressed input for ratio accounting.
#[allow(clippy::large_enum_variant)]
pub enum TarInput {
    Plain(File),
    Gzip(GzipStream<File>),
}

impl TarInput {
    #[inline(always)]
    pub fn take_compressed_delta(&mut self) -> u64 {
        match self {
            TarInput::Plain(_) => 0,
            TarInput::Gzip(gz) => gz.take_compressed_delta(),
        }
    }
}

impl Read for TarInput {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        match self {
            TarInput::Plain(f) => read_some(f, dst),
            TarInput::Gzip(gz) => gz.read(dst),
        }
    }
}

/// Reader trait for tar parsing that can optionally report compressed input deltas.
///
/// # Guarantees
/// - `take_compressed_delta()` returns the number of compressed bytes consumed
///   since the last call (or 0 for uncompressed sources).
pub trait TarRead: Read {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        0
    }
}

impl TarRead for TarInput {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        TarInput::take_compressed_delta(self)
    }
}

impl TarRead for File {}

impl<R: Read> TarRead for GzipStream<R> {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        self.take_compressed_delta()
    }
}

impl<T: TarRead + ?Sized> TarRead for &mut T {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        (**self).take_compressed_delta()
    }
}

impl TarRead for std::io::Cursor<Vec<u8>> {}

impl TarRead for std::io::Cursor<Arc<[u8]>> {}

/// A parsed tar entry header (after applying GNU/PAX overrides).
pub struct TarEntryMeta<'a> {
    pub name: &'a [u8], // raw entry name bytes (not canonicalized)
    pub size: u64,
    pub pad: u64,
    pub typeflag: u8,
    pub header_block_index: u64,
}

impl<'a> TarEntryMeta<'a> {
    #[inline(always)]
    pub fn is_regular(&self) -> bool {
        self.typeflag == 0 || self.typeflag == b'0'
    }
}

pub enum TarNext<'a> {
    End,
    Entry(TarEntryMeta<'a>),
    Stop(PartialReason),
}

/// Stateful tar header/metadata parser.
///
/// # Invariants
/// - Callers must consume or skip payload bytes to keep alignment.
/// - GNU/PAX overrides apply to the next non-metadata entry only.
///
/// This does not scan payloads; it only yields entry metadata and consumes
/// metadata-only records (GNU longname, PAX headers), charging metadata budgets.
pub struct TarCursor {
    hdr: [u8; TAR_BLOCK_LEN],
    zero_blocks: u8,
    block_index: u64,

    // Per-file overrides (apply to next real entry only).
    gnu_longname: Vec<u8>,
    pax_path: Vec<u8>,

    // Global pax data (we parse but do NOT apply `path=` globally; doing so can
    // misattribute multi-entry archives. Kept only to consume safely).
    pax_global_saw_path: bool,

    // Current computed name for yielded entry.
    name_buf: Vec<u8>,

    // Scratch for skipping/reading.
    discard: [u8; 8192],
    pax_carry: Vec<u8>,
    /// Read cursor into `pax_carry` to avoid `drain()` (O(n^2)) when parsing
    /// many small PAX records. We compact the buffer in-place when the cursor
    /// grows large or the buffer is full.
    pax_carry_pos: usize,

    // Debug-only capacity guards.
    #[cfg(debug_assertions)]
    gnu_cap: usize,
    #[cfg(debug_assertions)]
    pax_cap: usize,
    #[cfg(debug_assertions)]
    name_cap: usize,
    #[cfg(debug_assertions)]
    carry_cap: usize,
}

impl TarCursor {
    /// Construct a cursor with preallocated buffers sized from `ArchiveConfig`.
    ///
    /// All buffers are allocated once here and reused via `reset()` to avoid
    /// runtime allocations while scanning.
    pub fn with_capacity(cfg: &ArchiveConfig) -> Self {
        let path_cap = cfg
            .max_virtual_path_len_per_entry
            .saturating_add(1)
            .min(16 * 1024);
        let carry_cap = 4096;
        Self {
            hdr: [0; TAR_BLOCK_LEN],
            zero_blocks: 0,
            block_index: 0,
            gnu_longname: Vec::with_capacity(path_cap),
            pax_path: Vec::with_capacity(path_cap),
            pax_global_saw_path: false,
            name_buf: Vec::with_capacity(path_cap),
            discard: [0; 8192],
            pax_carry: Vec::with_capacity(carry_cap),
            pax_carry_pos: 0,

            #[cfg(debug_assertions)]
            gnu_cap: path_cap,
            #[cfg(debug_assertions)]
            pax_cap: path_cap,
            #[cfg(debug_assertions)]
            name_cap: path_cap,
            #[cfg(debug_assertions)]
            carry_cap,
        }
    }

    /// Backwards-compatible constructor (kept for call sites).
    #[inline]
    pub fn new(cfg: &ArchiveConfig) -> Self {
        Self::with_capacity(cfg)
    }

    /// Reset cursor state for reuse without allocating.
    #[inline]
    pub fn reset(&mut self) {
        self.zero_blocks = 0;
        self.block_index = 0;
        self.gnu_longname.clear();
        self.pax_path.clear();
        self.pax_global_saw_path = false;
        self.name_buf.clear();
        self.pax_carry.clear();
        self.pax_carry_pos = 0;
        self.debug_assert_no_growth();
    }

    /// Debug-only guard: ensure internal buffers never grow after startup.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                self.gnu_longname.capacity(),
                self.gnu_cap,
                "gnu_longname grew after startup"
            );
            debug_assert_eq!(
                self.pax_path.capacity(),
                self.pax_cap,
                "pax_path grew after startup"
            );
            debug_assert_eq!(
                self.name_buf.capacity(),
                self.name_cap,
                "name_buf grew after startup"
            );
            debug_assert_eq!(
                self.pax_carry.capacity(),
                self.carry_cap,
                "pax_carry grew after startup"
            );
        }
    }

    /// Read and parse until a non-meta entry is found, or end, or deterministic stop.
    ///
    /// This consumes only header/metadata records. For regular entries, the
    /// caller must read (or skip) the payload and then advance alignment via
    /// `advance_entry_blocks` or the helper skip methods.
    pub fn next_entry<'a, R: TarRead + ?Sized>(
        &'a mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
    ) -> io::Result<TarNext<'a>> {
        self.debug_assert_no_growth();
        loop {
            // Charge 1 header block before we read it (prevents overshoot).
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_metadata(TAR_BLOCK_LEN as u64) {
                return Ok(TarNext::Stop(map_budget_hit_to_partial(hit)));
            }

            // Read header block.
            if !read_exact_or_eof(input, &mut self.hdr)? {
                // Clean EOF at header boundary.
                return Ok(TarNext::End);
            }
            budgets.charge_compressed_in(input.take_compressed_delta());

            let header_block_index = self.block_index;
            self.block_index = self.block_index.saturating_add(1);

            if is_zero_block(&self.hdr) {
                self.zero_blocks = self.zero_blocks.saturating_add(1);
                if self.zero_blocks >= 2 {
                    return Ok(TarNext::End);
                }
                continue;
            }
            self.zero_blocks = 0;

            // Count this record.
            if let Err(hit) = budgets.note_entry() {
                return Ok(TarNext::Stop(map_budget_hit_to_partial(hit)));
            }

            let typeflag = self.hdr[156];
            let size = match parse_tar_size_octal(&self.hdr[124..136]) {
                Some(s) => s,
                None => return Ok(TarNext::Stop(PartialReason::MalformedTar)),
            };
            let pad = tar_pad(size);

            // GNU longname record.
            if typeflag == b'L' {
                self.gnu_longname.clear();
                if let Err(stop) = self.read_gnu_longname(input, budgets, cfg, size, pad)? {
                    return Ok(TarNext::Stop(stop));
                }
                self.advance_entry_blocks(size, pad);
                continue;
            }

            // PAX headers.
            if typeflag == b'x' {
                self.pax_path.clear();
                if let Err(stop) =
                    self.read_pax_path(input, budgets, cfg, size, pad, PaxTarget::PerFile)?
                {
                    return Ok(TarNext::Stop(stop));
                }
                self.advance_entry_blocks(size, pad);
                continue;
            }
            if typeflag == b'g' {
                self.pax_global_saw_path = false;
                if let Err(stop) =
                    self.read_pax_path(input, budgets, cfg, size, pad, PaxTarget::Global)?
                {
                    return Ok(TarNext::Stop(stop));
                }
                self.advance_entry_blocks(size, pad);
                continue;
            }

            // Compute base name from header, then apply overrides (per-file only).
            self.name_buf.clear();
            let max_name = cfg
                .max_virtual_path_len_per_entry
                .min(self.name_buf.capacity());
            build_ustar_name(&self.hdr, &mut self.name_buf, max_name);

            if !self.pax_path.is_empty() {
                self.name_buf.clear();
                self.name_buf.extend_from_slice(&self.pax_path);
            } else if !self.gnu_longname.is_empty() {
                self.name_buf.clear();
                self.name_buf.extend_from_slice(&self.gnu_longname);
            }

            // Overrides apply to exactly one real entry.
            self.pax_path.clear();
            self.gnu_longname.clear();

            return Ok(TarNext::Entry(TarEntryMeta {
                name: &self.name_buf,
                size,
                pad,
                typeflag,
                header_block_index,
            }));
        }
    }

    /// Skip non-regular entry payload and padding as metadata-bounded work.
    pub fn skip_payload_and_pad<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        size: u64,
        pad: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        // Treat skipped payload as metadata work to keep bounded.
        if let Err(stop) = self.skip_bytes_as_metadata(input, budgets, size)? {
            return Ok(Err(stop));
        }
        if let Err(stop) = self.skip_bytes_as_metadata(input, budgets, pad)? {
            return Ok(Err(stop));
        }
        self.advance_entry_blocks(size, pad);
        Ok(Ok(()))
    }

    #[inline]
    pub fn advance_entry_blocks(&mut self, size: u64, pad: u64) {
        let total = size.saturating_add(pad);
        debug_assert_eq!(total % TAR_BLOCK_LEN as u64, 0);
        self.block_index = self
            .block_index
            .saturating_add(total / TAR_BLOCK_LEN as u64);
    }

    /// Skip padding bytes after a payload read, charging metadata budget.
    pub fn skip_padding_only<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        pad: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        if let Err(stop) = self.skip_bytes_as_metadata(input, budgets, pad)? {
            return Ok(Err(stop));
        }
        Ok(Ok(()))
    }

    fn skip_bytes_as_metadata<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        mut n: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        while n > 0 {
            let step = (self.discard.len() as u64).min(n) as usize;

            if let ChargeResult::Clamp { allowed, hit } = budgets.charge_metadata(step as u64) {
                let allowed_usize = allowed as usize;
                if allowed_usize == 0 {
                    return Ok(Err(map_budget_hit_to_partial(hit)));
                }
                read_exact_n(input, &mut self.discard[..allowed_usize])?;
                budgets.charge_compressed_in(input.take_compressed_delta());
                return Ok(Err(map_budget_hit_to_partial(hit)));
            }

            read_exact_n(input, &mut self.discard[..step])?;
            budgets.charge_compressed_in(input.take_compressed_delta());
            n -= step as u64;
        }
        Ok(Ok(()))
    }

    fn read_gnu_longname<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
        size: u64,
        pad: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        // Read payload as metadata, store up to a bounded prefix.
        let cap = cfg
            .max_virtual_path_len_per_entry
            .saturating_add(1)
            .min(16 * 1024)
            .min(self.gnu_longname.capacity());
        let mut remaining = size;
        while remaining > 0 {
            let step = (self.discard.len() as u64).min(remaining) as usize;

            if let ChargeResult::Clamp { allowed, hit } = budgets.charge_metadata(step as u64) {
                let a = allowed as usize;
                if a == 0 {
                    return Ok(Err(map_budget_hit_to_partial(hit)));
                }
                read_exact_n(input, &mut self.discard[..a])?;
                budgets.charge_compressed_in(input.take_compressed_delta());
                append_longname_bytes(&mut self.gnu_longname, &self.discard[..a], cap);
                return Ok(Err(map_budget_hit_to_partial(hit)));
            }

            read_exact_n(input, &mut self.discard[..step])?;
            budgets.charge_compressed_in(input.take_compressed_delta());
            append_longname_bytes(&mut self.gnu_longname, &self.discard[..step], cap);
            remaining -= step as u64;
        }

        // Trim trailing NUL/newlines.
        while let Some(&b) = self.gnu_longname.last() {
            if b == 0 || b == b'\n' {
                self.gnu_longname.pop();
            } else {
                break;
            }
        }

        // Skip pad.
        match self.skip_bytes_as_metadata(input, budgets, pad)? {
            Ok(()) => Ok(Ok(())),
            Err(stop) => Ok(Err(stop)),
        }
    }

    fn read_pax_path<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
        size: u64,
        pad: u64,
        target: PaxTarget,
    ) -> io::Result<Result<(), PartialReason>> {
        // Parse records with a bounded carry buffer; store only `path=` value prefix.
        self.pax_carry.clear();
        self.pax_carry_pos = 0;
        let mut remaining = size;

        // Value storage cap.
        let cap = cfg
            .max_virtual_path_len_per_entry
            .saturating_add(1)
            .min(32 * 1024)
            .min(self.pax_path.capacity());

        while remaining > 0 {
            let step = (self.discard.len() as u64).min(remaining) as usize;

            if let ChargeResult::Clamp { allowed, hit } = budgets.charge_metadata(step as u64) {
                let a = allowed as usize;
                if a == 0 {
                    return Ok(Err(map_budget_hit_to_partial(hit)));
                }
                read_exact_n(input, &mut self.discard[..a])?;
                budgets.charge_compressed_in(input.take_compressed_delta());
                consume_pax_bytes(
                    &mut self.pax_carry,
                    &mut self.pax_carry_pos,
                    &mut self.pax_path,
                    &mut self.pax_global_saw_path,
                    &self.discard[..a],
                    target,
                    cap,
                );
                return Ok(Err(map_budget_hit_to_partial(hit)));
            }

            read_exact_n(input, &mut self.discard[..step])?;
            budgets.charge_compressed_in(input.take_compressed_delta());
            consume_pax_bytes(
                &mut self.pax_carry,
                &mut self.pax_carry_pos,
                &mut self.pax_path,
                &mut self.pax_global_saw_path,
                &self.discard[..step],
                target,
                cap,
            );

            remaining -= step as u64;
        }

        // Skip pad.
        match self.skip_bytes_as_metadata(input, budgets, pad)? {
            Ok(()) => Ok(Ok(())),
            Err(stop) => Ok(Err(stop)),
        }
    }
}

#[derive(Clone, Copy)]
enum PaxTarget {
    PerFile,
    Global,
}

#[inline(always)]
fn map_budget_hit_to_partial(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => match r {
            ArchiveSkipReason::MetadataBudgetExceeded => PartialReason::MetadataBudgetExceeded,
            ArchiveSkipReason::PathBudgetExceeded => PartialReason::PathBudgetExceeded,
            ArchiveSkipReason::EntryCountExceeded => PartialReason::EntryCountExceeded,
            ArchiveSkipReason::ArchiveOutputBudgetExceeded => {
                PartialReason::ArchiveOutputBudgetExceeded
            }
            ArchiveSkipReason::RootOutputBudgetExceeded => PartialReason::RootOutputBudgetExceeded,
            ArchiveSkipReason::InflationRatioExceeded => PartialReason::InflationRatioExceeded,
            _ => PartialReason::MalformedTar,
        },
        BudgetHit::SkipEntry(_) => PartialReason::EntryOutputBudgetExceeded,
    }
}

#[inline(always)]
fn tar_pad(size: u64) -> u64 {
    let rem = size % TAR_BLOCK_LEN as u64;
    if rem == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - rem
    }
}

#[inline(always)]
fn is_zero_block(b: &[u8; TAR_BLOCK_LEN]) -> bool {
    // Constant-time-ish scan, cheap enough (512 bytes).
    for &x in b.iter() {
        if x != 0 {
            return false;
        }
    }
    true
}

fn build_ustar_name(hdr: &[u8; TAR_BLOCK_LEN], out: &mut Vec<u8>, max_len: usize) {
    out.clear();
    if max_len == 0 {
        return;
    }

    let name = cstr_bytes(&hdr[0..100]);
    let prefix = cstr_bytes(&hdr[345..500]);

    let is_ustar = &hdr[USTAR_MAGIC_OFFSET..USTAR_MAGIC_OFFSET + 5] == b"ustar";
    let mut remaining = max_len;

    if is_ustar && !prefix.is_empty() {
        append_clamped(out, prefix, &mut remaining);
        if remaining > 0 && !out.ends_with(b"/") {
            out.push(b'/');
            remaining = remaining.saturating_sub(1);
        }
    }
    append_clamped(out, name, &mut remaining);
}

#[inline]
fn append_clamped(out: &mut Vec<u8>, bytes: &[u8], remaining: &mut usize) {
    if *remaining == 0 {
        return;
    }
    let take = bytes.len().min(*remaining);
    out.extend_from_slice(&bytes[..take]);
    *remaining = remaining.saturating_sub(take);
}

fn cstr_bytes(field: &[u8]) -> &[u8] {
    match memchr_byte(0, field) {
        Some(i) => &field[..i],
        None => field,
    }
}

fn parse_tar_size_octal(field: &[u8]) -> Option<u64> {
    // tar size field is NUL/space padded octal.
    let mut i = 0;
    while i < field.len() && (field[i] == 0 || field[i] == b' ') {
        i += 1;
    }
    let mut end = i;
    while end < field.len() && (b'0'..=b'7').contains(&field[end]) {
        end += 1;
    }
    if end == i {
        return Some(0);
    }
    let mut v: u64 = 0;
    for &d in &field[i..end] {
        v = v.checked_mul(8)?;
        v = v.checked_add((d - b'0') as u64)?;
    }
    Some(v)
}

fn memchr_byte(needle: u8, hay: &[u8]) -> Option<usize> {
    // small, dependency-free
    for (i, &b) in hay.iter().enumerate() {
        if b == needle {
            return Some(i);
        }
    }
    None
}

fn append_longname_bytes(longname: &mut Vec<u8>, bytes: &[u8], cap: usize) {
    if longname.len() >= cap {
        return;
    }
    let take = (cap - longname.len()).min(bytes.len());
    longname.extend_from_slice(&bytes[..take]);
}

fn consume_pax_bytes(
    pax_carry: &mut Vec<u8>,
    pax_carry_pos: &mut usize,
    pax_path: &mut Vec<u8>,
    pax_global_saw_path: &mut bool,
    bytes: &[u8],
    target: PaxTarget,
    cap: usize,
) {
    // PAX parsing is best-effort and strictly bounded:
    // - We never grow `pax_carry` beyond its startup capacity.
    // - We advance a cursor instead of draining to avoid O(n^2).
    // - On malformed records, we drop the carry to prevent re-parsing loops.
    // Append at most the fixed carry capacity; never grow after startup.
    let cap_bytes = pax_carry.capacity();
    if pax_carry.len() < cap_bytes {
        let take = (cap_bytes - pax_carry.len()).min(bytes.len());
        pax_carry.extend_from_slice(&bytes[..take]);
    }

    let mut malformed = false;

    loop {
        let start = *pax_carry_pos;
        if start >= pax_carry.len() {
            break;
        }

        let space = match memchr_byte_from(b' ', pax_carry, start) {
            Some(i) => i,
            None => break,
        };
        if space == start {
            malformed = true;
            break;
        }

        let mut rec_len: usize = 0;
        for &d in &pax_carry[start..space] {
            if !d.is_ascii_digit() {
                malformed = true;
                break;
            }
            rec_len = rec_len
                .saturating_mul(10)
                .saturating_add((d - b'0') as usize);
        }
        if malformed {
            break;
        }
        if rec_len == 0 {
            malformed = true;
            break;
        }
        if rec_len > cap_bytes {
            // Record is larger than our bounded carry buffer; drop parsing.
            malformed = true;
            break;
        }

        let rec_end = start.saturating_add(rec_len);
        if rec_end <= space || rec_end > pax_carry.len() {
            // Need more bytes, or malformed length that doesn't cover its own prefix.
            if rec_end <= space {
                malformed = true;
            }
            break;
        }

        let rec = &pax_carry[space + 1..rec_end];
        if let Some(eq) = memchr_byte(b'=', rec) {
            let key = &rec[..eq];
            let mut val = &rec[eq + 1..];
            if val.last() == Some(&b'\n') {
                val = &val[..val.len() - 1];
            }
            if key == b"path" {
                match target {
                    PaxTarget::PerFile => {
                        if pax_path.len() < cap {
                            let take = (cap - pax_path.len()).min(val.len());
                            pax_path.extend_from_slice(&val[..take]);
                        }
                    }
                    PaxTarget::Global => {
                        *pax_global_saw_path = true;
                    }
                }
            }
        }

        *pax_carry_pos = rec_end;
    }

    // On malformed input, drop carry to avoid spinning on the same bytes.
    if malformed {
        *pax_carry_pos = pax_carry.len();
    }

    // Compact buffer when the cursor advances enough or the buffer is full.
    if *pax_carry_pos > 0 {
        if *pax_carry_pos >= pax_carry.len() {
            pax_carry.clear();
            *pax_carry_pos = 0;
        } else if *pax_carry_pos >= (cap_bytes / 2) || pax_carry.len() == cap_bytes {
            let len = pax_carry.len();
            pax_carry.copy_within(*pax_carry_pos..len, 0);
            pax_carry.truncate(len - *pax_carry_pos);
            *pax_carry_pos = 0;
        }
    }
}

fn memchr_byte_from(needle: u8, hay: &[u8], start: usize) -> Option<usize> {
    if start >= hay.len() {
        return None;
    }
    for (i, &b) in hay[start..].iter().enumerate() {
        if b == needle {
            return Some(start + i);
        }
    }
    None
}

fn read_some<R: Read + ?Sized>(r: &mut R, dst: &mut [u8]) -> io::Result<usize> {
    loop {
        match r.read(dst) {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn read_exact_or_eof<R: Read + ?Sized>(r: &mut R, dst: &mut [u8]) -> io::Result<bool> {
    let mut off = 0;
    while off < dst.len() {
        let n = read_some(r, &mut dst[off..])?;
        if n == 0 {
            // EOF before full block: clean EOF only if nothing was read.
            if off == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tar truncated header",
            ));
        }
        off += n;
    }
    Ok(true)
}

fn read_exact_n<R: Read + ?Sized>(r: &mut R, dst: &mut [u8]) -> io::Result<()> {
    let mut off = 0;
    while off < dst.len() {
        let n = read_some(r, &mut dst[off..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tar truncated",
            ));
        }
        off += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchiveBudgets, ArchiveConfig};
    use std::io;

    fn tar_write_header(buf: &mut [u8; TAR_BLOCK_LEN], name: &str, size: u64, typeflag: u8) {
        buf.fill(0);
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(100);
        buf[0..name_len].copy_from_slice(&name_bytes[..name_len]);
        buf[100..108].copy_from_slice(b"0000777\0");
        buf[108..116].copy_from_slice(b"0000000\0");
        buf[116..124].copy_from_slice(b"0000000\0");
        let mut size_field = [b'0'; 11];
        let mut v = size;
        for i in (0..11).rev() {
            size_field[i] = b'0' + ((v & 7) as u8);
            v >>= 3;
        }
        buf[124..135].copy_from_slice(&size_field);
        buf[135] = 0;
        buf[136..148].copy_from_slice(b"00000000000\0");
        for b in &mut buf[148..156] {
            *b = b' ';
        }
        buf[156] = typeflag;
        buf[257..263].copy_from_slice(b"ustar\0");
        buf[263..265].copy_from_slice(b"00");
        let sum: u32 = buf.iter().map(|&b| b as u32).sum();
        let chk = format!("{:06o}\0 ", sum);
        buf[148..156].copy_from_slice(chk.as_bytes());
    }

    #[test]
    fn parse_octal_size() {
        assert_eq!(parse_tar_size_octal(b"0000000010\0"), Some(8));
        assert_eq!(parse_tar_size_octal(b"        \0"), Some(0));
    }

    #[test]
    fn pad_math() {
        assert_eq!(tar_pad(0), 0);
        assert_eq!(tar_pad(1), 511);
        assert_eq!(tar_pad(512), 0);
        assert_eq!(tar_pad(513), 511);
    }

    #[test]
    fn truncated_header_returns_error() {
        let cfg = ArchiveConfig::default();
        let mut budgets = ArchiveBudgets::new(&cfg);
        budgets.enter_archive().unwrap();

        let mut cursor = TarCursor::new(&cfg);
        let mut input = io::Cursor::new(vec![0u8; 10]); // shorter than a header block

        match cursor.next_entry(&mut input, &mut budgets, &cfg) {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof),
            Ok(_) => panic!("expected truncated header error"),
        }
    }

    #[test]
    fn pax_parser_handles_invalid_length_without_panicking() {
        let mut carry = Vec::with_capacity(64);
        let mut pos = 0usize;
        let mut path = Vec::new();
        let mut saw_global = false;

        // Length says 1 byte, but record is longer (malformed).
        consume_pax_bytes(
            &mut carry,
            &mut pos,
            &mut path,
            &mut saw_global,
            b"1 path=evil\n",
            PaxTarget::PerFile,
            64,
        );

        assert!(pos <= carry.len());
        assert!(carry.len() <= carry.capacity());
        assert!(path.is_empty());
        assert!(!saw_global);
    }

    #[test]
    fn pax_parser_extracts_path_across_chunks() {
        fn build_record(key: &str, val: &str) -> Vec<u8> {
            let body = format!("{key}={val}\n");
            // length includes digits + space + body
            let mut len = body.len() + 1;
            loop {
                let len_str = len.to_string();
                let new_len = len_str.len() + 1 + body.len();
                if new_len == len {
                    let mut v = Vec::new();
                    v.extend_from_slice(len_str.as_bytes());
                    v.push(b' ');
                    v.extend_from_slice(body.as_bytes());
                    return v;
                }
                len = new_len;
            }
        }

        let mut carry = Vec::with_capacity(64);
        let mut pos = 0usize;
        let mut path = Vec::new();
        let mut saw_global = false;

        let rec = build_record("path", "a/b/c.txt");
        let split = rec.len() / 2;

        consume_pax_bytes(
            &mut carry,
            &mut pos,
            &mut path,
            &mut saw_global,
            &rec[..split],
            PaxTarget::PerFile,
            128,
        );
        consume_pax_bytes(
            &mut carry,
            &mut pos,
            &mut path,
            &mut saw_global,
            &rec[split..],
            PaxTarget::PerFile,
            128,
        );

        assert_eq!(path, b"a/b/c.txt");
        assert!(!saw_global);
    }

    #[test]
    fn pax_path_is_capped_to_buffer_capacity() {
        fn build_record(key: &str, val: &str) -> Vec<u8> {
            let body = format!("{key}={val}\n");
            let mut len = body.len() + 1;
            loop {
                let len_str = len.to_string();
                let new_len = len_str.len() + 1 + body.len();
                if new_len == len {
                    let mut v = Vec::new();
                    v.extend_from_slice(len_str.as_bytes());
                    v.push(b' ');
                    v.extend_from_slice(body.as_bytes());
                    return v;
                }
                len = new_len;
            }
        }

        let cfg = ArchiveConfig {
            max_virtual_path_len_per_entry: 8,
            ..ArchiveConfig::default()
        };
        let mut budgets = ArchiveBudgets::new(&cfg);
        budgets.enter_archive().unwrap();

        let mut cursor = TarCursor::with_capacity(&cfg);
        let cap = cursor.pax_path.capacity();

        let pax_path = "a/".repeat(64) + "file.txt";
        let record = build_record("path", &pax_path);

        let mut tar = Vec::new();
        let mut hdr = [0u8; TAR_BLOCK_LEN];
        tar_write_header(&mut hdr, "PaxHeader", record.len() as u64, b'x');
        tar.extend_from_slice(&hdr);
        tar.extend_from_slice(&record);
        tar.extend_from_slice(&vec![0u8; tar_pad(record.len() as u64) as usize]);

        let payload = b"hello";
        tar_write_header(&mut hdr, "ignored.txt", payload.len() as u64, b'0');
        tar.extend_from_slice(&hdr);
        tar.extend_from_slice(payload);
        tar.extend_from_slice(&vec![0u8; tar_pad(payload.len() as u64) as usize]);

        tar.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
        tar.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);

        let mut input = io::Cursor::new(tar);
        let entry = match cursor.next_entry(&mut input, &mut budgets, &cfg).unwrap() {
            TarNext::Entry(m) => m,
            _ => panic!("expected entry after PAX header"),
        };
        assert!(entry.name.len() <= cap);
        assert_eq!(cursor.pax_path.capacity(), cap);
        cursor.debug_assert_no_growth();
    }
}
