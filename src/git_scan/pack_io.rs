//! Pack I/O utilities for external base resolution.
//!
//! This module manages pack file access and bounded object decoding for
//! cross-pack REF delta bases. It is intentionally narrow in scope:
//! callers provide OIDs, and `PackIo` resolves them via the MIDX to pack
//! offsets, loads pack bytes (mmap-backed by default), and decodes the object with strict
//! limits on header size, delta payload size, and output size.
//!
//! # Scope
//! - MIDX-backed pack lookup only (no loose objects).
//! - Bounded delta decoding with configurable depth limits.
//! - Pack files are memory-mapped on demand and cached for reuse.
//!
//! # Invariants
//! - `pack_paths` is indexed by pack_id in PNAM order.
//! - Pack files are immutable for the lifetime of a repo job.
//! - Object sizes never exceed `limits.decode.max_object_bytes`.
//! - Delta payload sizes never exceed `limits.decode.max_delta_bytes`.
//! - Delta chains are bounded by `limits.max_delta_depth`.
//! - Missing bases are treated as missing objects (`None`).

use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use super::bytes::BytesView;
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_decode::{
    entry_header_at, inflate_entry_payload, PackDecodeError, PackDecodeLimits,
};
use super::pack_delta::{apply_delta, DeltaError};
use super::pack_exec::{ExternalBase, ExternalBaseProvider, PackExecError};
use super::pack_inflate::{EntryKind, ObjectKind, PackFile, PackParseError};
use super::repo::GitRepoPaths;
use super::repo_open::RepoJobState;

/// Limits for pack I/O decoding.
#[derive(Clone, Copy, Debug)]
pub struct PackIoLimits {
    /// Limits for header parsing and inflation.
    pub decode: PackDecodeLimits,
    /// Maximum delta chain depth across packs.
    ///
    /// Depth counts delta edges. A value of 0 rejects any delta entry.
    pub max_delta_depth: u8,
}

impl PackIoLimits {
    /// Creates a new pack I/O limits struct.
    #[must_use]
    pub const fn new(decode: PackDecodeLimits, max_delta_depth: u8) -> Self {
        Self {
            decode,
            max_delta_depth,
        }
    }
}

/// Errors from pack I/O.
#[derive(Debug)]
pub enum PackIoError {
    /// Repository artifacts are not ready.
    ArtifactsNotReady,
    /// MIDX bytes are missing.
    MissingMidx,
    /// MIDX parsing or lookup failed.
    Midx(MidxError),
    /// Pack file I/O failed.
    Io(io::Error),
    /// Pack header parsing failed.
    PackParse(PackParseError),
    /// Entry decode failed.
    Decode(PackDecodeError),
    /// Delta application failed.
    Delta(DeltaError),
    /// Pack ID does not exist in the pack list.
    PackIdOutOfRange { pack_id: u16, pack_count: usize },
    /// Pack list length does not match the MIDX pack count.
    PackCountMismatch { expected: usize, actual: usize },
    /// Delta chain exceeded the configured depth.
    DeltaDepthExceeded { max_depth: u8 },
    /// OID length does not match the configured MIDX format.
    OidLengthMismatch { got: u8, expected: u8 },
}

impl std::fmt::Display for PackIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArtifactsNotReady => write!(f, "repo artifacts not ready"),
            Self::MissingMidx => write!(f, "midx bytes missing"),
            Self::Midx(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "pack I/O error: {err}"),
            Self::PackParse(err) => write!(f, "{err}"),
            Self::Decode(err) => write!(f, "{err}"),
            Self::Delta(err) => write!(f, "{err}"),
            Self::PackIdOutOfRange {
                pack_id,
                pack_count,
            } => write!(
                f,
                "pack id {pack_id} out of range (pack count {pack_count})"
            ),
            Self::PackCountMismatch { expected, actual } => write!(
                f,
                "pack count mismatch: midx expects {expected}, provided {actual}"
            ),
            Self::DeltaDepthExceeded { max_depth } => {
                write!(f, "delta depth exceeded (max {max_depth})")
            }
            Self::OidLengthMismatch { got, expected } => {
                write!(f, "OID length mismatch: got {got}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for PackIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Midx(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::PackParse(err) => Some(err),
            Self::Decode(err) => Some(err),
            Self::Delta(err) => Some(err),
            _ => None,
        }
    }
}

impl From<MidxError> for PackIoError {
    fn from(err: MidxError) -> Self {
        Self::Midx(err)
    }
}

impl From<io::Error> for PackIoError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<PackParseError> for PackIoError {
    fn from(err: PackParseError) -> Self {
        Self::PackParse(err)
    }
}

impl From<PackDecodeError> for PackIoError {
    fn from(err: PackDecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<DeltaError> for PackIoError {
    fn from(err: DeltaError) -> Self {
        Self::Delta(err)
    }
}

/// Pack I/O helper for external base resolution.
#[derive(Debug)]
pub struct PackIo<'a> {
    oid_len: u8,
    midx: MidxView<'a>,
    pack_paths: Vec<PathBuf>,
    pack_cache: Vec<Option<BytesView>>,
    limits: PackIoLimits,
}

impl<'a> PackIo<'a> {
    /// Opens pack I/O for a repository job.
    ///
    /// # Errors
    /// Returns `PackIoError` if artifacts are missing, the MIDX is invalid,
    /// or pack files cannot be resolved.
    pub fn open(repo: &'a RepoJobState, limits: PackIoLimits) -> Result<Self, PackIoError> {
        if !repo.artifact_status.is_ready() {
            return Err(PackIoError::ArtifactsNotReady);
        }

        let midx_bytes = repo.mmaps.midx.as_ref().ok_or(PackIoError::MissingMidx)?;
        let midx = MidxView::parse(midx_bytes.as_slice(), repo.object_format)?;

        let pack_dirs = collect_pack_dirs(&repo.paths);
        let pack_names = list_pack_files(&pack_dirs)?;
        midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;

        let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
        Self::from_parts(midx, pack_paths, limits)
    }

    /// Constructs pack I/O from pre-parsed parts.
    ///
    /// This is intended for tests or callers that already resolved pack paths.
    /// `pack_paths` must be ordered by pack id (PNAM order).
    ///
    /// # Errors
    /// Returns `PackCountMismatch` if `pack_paths` doesn't match the MIDX
    /// pack count.
    pub fn from_parts(
        midx: MidxView<'a>,
        pack_paths: Vec<PathBuf>,
        limits: PackIoLimits,
    ) -> Result<Self, PackIoError> {
        let expected = midx.pack_count() as usize;
        if pack_paths.len() != expected {
            return Err(PackIoError::PackCountMismatch {
                expected,
                actual: pack_paths.len(),
            });
        }

        Ok(Self {
            oid_len: midx.oid_len(),
            midx,
            pack_paths,
            pack_cache: vec![None; expected],
            limits,
        })
    }

    /// Loads an object by OID, returning `None` if the OID is missing.
    ///
    /// Missing delta bases also return `None`; they are treated the same
    /// as missing OIDs to keep the API a simple optional lookup.
    ///
    /// Delta depth is enforced across pack hops using `limits.max_delta_depth`.
    ///
    /// # Errors
    /// Returns `PackIoError` for malformed pack data or delta failures.
    pub fn load_object(
        &mut self,
        oid: &OidBytes,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        self.load_object_with_depth(oid, self.limits.max_delta_depth)
    }

    /// Loads an object by OID with an explicit remaining delta depth.
    ///
    /// This is used internally to enforce `max_delta_depth` across pack hops.
    fn load_object_with_depth(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        if oid.len() != self.oid_len {
            return Err(PackIoError::OidLengthMismatch {
                got: oid.len(),
                expected: self.oid_len,
            });
        }

        let idx = match self.midx.find_oid(oid)? {
            Some(idx) => idx,
            None => return Ok(None),
        };
        let (pack_id, offset) = self.midx.offset_at(idx)?;
        self.load_object_by_offset(pack_id, offset, depth)
    }

    fn load_object_by_offset(
        &mut self,
        pack_id: u16,
        offset: u64,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        let pack = self.pack_data(pack_id)?;
        let pack_file = PackFile::parse(pack.as_ref(), self.oid_len as usize)?;
        self.read_pack_object(&pack_file, offset, depth)
    }

    /// Reads an object from a pack, resolving in-pack deltas recursively.
    ///
    /// Returns `Ok(None)` if a required base object cannot be loaded.
    fn read_pack_object(
        &mut self,
        pack: &PackFile<'_>,
        offset: u64,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        let header = entry_header_at(pack, offset, &self.limits.decode)?;

        match header.kind {
            EntryKind::NonDelta { kind } => {
                let mut out = Vec::with_capacity(header.size as usize);
                inflate_entry_payload(pack, &header, &mut out, &self.limits.decode)?;
                Ok(Some((kind, out)))
            }
            EntryKind::OfsDelta { base_offset } => {
                if depth == 0 {
                    return Err(PackIoError::DeltaDepthExceeded {
                        max_depth: self.limits.max_delta_depth,
                    });
                }
                let Some((base_kind, base_bytes)) =
                    self.read_pack_object(pack, base_offset, depth - 1)?
                else {
                    return Ok(None);
                };
                let out = apply_delta_entry(pack, &header, &base_bytes, &self.limits.decode)?;
                Ok(Some((base_kind, out)))
            }
            EntryKind::RefDelta { base_oid } => {
                if depth == 0 {
                    return Err(PackIoError::DeltaDepthExceeded {
                        max_depth: self.limits.max_delta_depth,
                    });
                }
                let Some((base_kind, base_bytes)) =
                    self.load_object_with_depth(&base_oid, depth - 1)?
                else {
                    return Ok(None);
                };
                let out = apply_delta_entry(pack, &header, &base_bytes, &self.limits.decode)?;
                Ok(Some((base_kind, out)))
            }
        }
    }

    /// Returns the pack bytes for `pack_id`, mapping lazily.
    fn pack_data(&mut self, pack_id: u16) -> Result<BytesView, PackIoError> {
        let idx = pack_id as usize;
        let pack_count = self.pack_paths.len();
        let path = self
            .pack_paths
            .get(idx)
            .ok_or(PackIoError::PackIdOutOfRange {
                pack_id,
                pack_count,
            })?;

        if self.pack_cache.get(idx).is_none() {
            // Defensive check in case the cache length diverges from pack_paths.
            return Err(PackIoError::PackIdOutOfRange {
                pack_id,
                pack_count,
            });
        }

        if self.pack_cache[idx].is_none() {
            let file = File::open(path)?;
            // SAFETY: pack files are immutable for the duration of a repo job.
            let mmap = unsafe { memmap2::Mmap::map(&file)? };
            self.pack_cache[idx] = Some(BytesView::from_mmap(mmap));
        }

        Ok(self.pack_cache[idx]
            .as_ref()
            .expect("pack bytes present")
            .clone())
    }
}

impl ExternalBaseProvider for PackIo<'_> {
    fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
        match self.load_object(oid) {
            Ok(Some((kind, bytes))) => Ok(Some(ExternalBase { kind, bytes })),
            Ok(None) => Ok(None),
            Err(err) => Err(PackExecError::ExternalBase(err.to_string())),
        }
    }
}

fn apply_delta_entry(
    pack: &PackFile<'_>,
    header: &super::pack_inflate::EntryHeader,
    base_bytes: &[u8],
    limits: &PackDecodeLimits,
) -> Result<Vec<u8>, PackIoError> {
    // Inflate the delta payload with a hard cap, then apply it to the base.
    let mut delta = Vec::with_capacity(limits.max_delta_bytes);
    inflate_entry_payload(pack, header, &mut delta, limits)?;

    let mut out = Vec::with_capacity(header.size as usize);
    apply_delta(
        base_bytes,
        &delta,
        &mut out,
        header.size as usize,
        limits.max_object_bytes,
    )?;

    Ok(out)
}

fn collect_pack_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.join("pack"));
    }
    dirs
}

fn list_pack_files(pack_dirs: &[PathBuf]) -> Result<Vec<Vec<u8>>, PackIoError> {
    let mut names = Vec::new();

    for dir in pack_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(PackIoError::Io(err)),
        };

        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            let file_name = entry.file_name();
            if is_pack_file(&file_name) {
                names.push(file_name.to_string_lossy().as_bytes().to_vec());
            }
        }
    }

    Ok(names)
}

fn resolve_pack_paths(
    midx: &MidxView<'_>,
    pack_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, PackIoError> {
    let mut paths = Vec::with_capacity(midx.pack_count() as usize);

    for name in midx.pack_names() {
        let mut base = strip_pack_suffix(name);
        base.extend_from_slice(b".pack");
        let file_name = String::from_utf8_lossy(&base).into_owned();

        let mut found = None;
        for dir in pack_dirs {
            let candidate = dir.join(&file_name);
            if is_file(&candidate) {
                found = Some(candidate);
                break;
            }
        }

        match found {
            Some(path) => paths.push(path),
            None => {
                return Err(PackIoError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("pack file not found for {}", String::from_utf8_lossy(name)),
                )))
            }
        }
    }

    Ok(paths)
}

fn strip_pack_suffix(name: &[u8]) -> Vec<u8> {
    if name.ends_with(b".pack") || name.ends_with(b".idx") {
        let mut base = name.to_vec();
        if let Some(idx) = base.iter().rposition(|&b| b == b'.') {
            base.truncate(idx);
        }
        base
    } else {
        name.to_vec()
    }
}

fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tempfile::tempdir;

    use super::super::object_id::{ObjectFormat, OidBytes};

    #[derive(Default)]
    struct MidxBuilder {
        pack_names: Vec<Vec<u8>>,
        objects: Vec<([u8; 20], u16, u64)>,
    }

    impl MidxBuilder {
        fn add_pack(&mut self, name: &[u8]) {
            self.pack_names.push(name.to_vec());
        }

        fn add_object(&mut self, oid: [u8; 20], pack_id: u16, offset: u64) {
            self.objects.push((oid, pack_id, offset));
        }

        fn build(&self) -> Vec<u8> {
            let oid_len = 20;
            let pack_count = self.pack_names.len() as u32;
            let mut objects = self.objects.clone();
            objects.sort_by(|a, b| a.0.cmp(&b.0));

            let mut pnam = Vec::new();
            for name in &self.pack_names {
                pnam.extend_from_slice(name);
                pnam.push(0);
            }

            let mut oidf = vec![0u8; 256 * 4];
            let mut counts = [0u32; 256];
            for (oid, _, _) in &objects {
                counts[oid[0] as usize] += 1;
            }
            let mut running = 0u32;
            for (i, count) in counts.iter().enumerate() {
                running += count;
                let off = i * 4;
                oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
            }

            let mut oidl = Vec::with_capacity(objects.len() * oid_len);
            for (oid, _, _) in &objects {
                oidl.extend_from_slice(oid);
            }

            let mut ooff = Vec::with_capacity(objects.len() * 8);
            for (_, pack_id, offset) in &objects {
                ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
                ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
            }

            let chunk_count = 4u8;
            let header_size = 12usize;
            let chunk_table_size = (chunk_count as usize + 1) * 12;

            let pnam_off = (header_size + chunk_table_size) as u64;
            let oidf_off = pnam_off + pnam.len() as u64;
            let oidl_off = oidf_off + oidf.len() as u64;
            let ooff_off = oidl_off + oidl.len() as u64;
            let end_off = ooff_off + ooff.len() as u64;

            let mut out = Vec::new();
            out.extend_from_slice(b"MIDX");
            out.push(1);
            out.push(1); // SHA-1
            out.push(chunk_count);
            out.push(0); // base count
            out.extend_from_slice(&pack_count.to_be_bytes());

            let mut push_chunk = |id: [u8; 4], off: u64| {
                out.extend_from_slice(&id);
                out.extend_from_slice(&off.to_be_bytes());
            };

            push_chunk(*b"PNAM", pnam_off);
            push_chunk(*b"OIDF", oidf_off);
            push_chunk(*b"OIDL", oidl_off);
            push_chunk(*b"OOFF", ooff_off);
            push_chunk([0, 0, 0, 0], end_off);

            out.extend_from_slice(&pnam);
            out.extend_from_slice(&oidf);
            out.extend_from_slice(&oidl);
            out.extend_from_slice(&ooff);
            out
        }
    }

    fn encode_entry_header(obj_type: u8, mut size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut first = (obj_type & 0x07) << 4;
        first |= (size & 0x0f) as u8;
        size >>= 4;
        if size != 0 {
            first |= 0x80;
        }
        out.push(first);
        while size != 0 {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
        out
    }

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn build_pack_blob(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&encode_entry_header(3, data.len() as u64));
        out.extend_from_slice(&compress(data));
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    fn build_pack_ref_delta(base_oid: [u8; 20], result: &[u8], base_len: usize) -> Vec<u8> {
        let mut delta = Vec::new();
        delta.extend_from_slice(&encode_varint(base_len as u64));
        delta.extend_from_slice(&encode_varint(result.len() as u64));
        delta.push(result.len() as u8);
        delta.extend_from_slice(result);

        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&encode_entry_header(7, result.len() as u64));
        out.extend_from_slice(&base_oid);
        out.extend_from_slice(&compress(&delta));
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    #[test]
    fn load_cross_pack_ref_delta() {
        let base_oid = [0x11; 20];
        let delta_oid = [0x22; 20];

        let base_bytes = b"base";
        let result_bytes = b"base!";

        let pack_base = build_pack_blob(base_bytes);
        let pack_delta = build_pack_ref_delta(base_oid, result_bytes, base_bytes.len());

        let temp = tempdir().unwrap();
        let pack_base_path = temp.path().join("pack-base.pack");
        let pack_delta_path = temp.path().join("pack-delta.pack");
        fs::write(&pack_base_path, &pack_base).unwrap();
        fs::write(&pack_delta_path, &pack_delta).unwrap();

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-base");
        builder.add_pack(b"pack-delta");
        builder.add_object(base_oid, 0, 12);
        builder.add_object(delta_oid, 1, 12);
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 8);
        let mut io =
            PackIo::from_parts(midx, vec![pack_base_path, pack_delta_path], limits).unwrap();

        let base = io.load_object(&OidBytes::sha1(base_oid)).unwrap().unwrap();
        assert_eq!(base.0, ObjectKind::Blob);
        assert_eq!(base.1, base_bytes);

        let delta = io.load_object(&OidBytes::sha1(delta_oid)).unwrap().unwrap();
        assert_eq!(delta.0, ObjectKind::Blob);
        assert_eq!(delta.1, result_bytes);
    }
}
