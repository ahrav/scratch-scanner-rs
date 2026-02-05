//! Pack byte adapters for Git simulation.
//!
//! This module converts embedded pack bytes into `PackView`s and provides
//! accessors suitable for in-memory execution and planning.
//! Pack ids are expected to be contiguous starting at 0; duplicates are
//! rejected so the id can be used as a dense index.

use crate::git_scan::{BytesView, ObjectFormat, PackPlanError, PackView};

use super::convert::to_object_format;
use super::error::SimGitError;
use super::scenario::{GitArtifactBundle, GitPackBytes, GitRepoModel};

/// In-memory pack bytes for simulation.
#[derive(Debug, Clone)]
pub struct SimPackBytes {
    object_format: ObjectFormat,
    packs: Vec<BytesView>,
}

impl SimPackBytes {
    /// Build pack bytes from the repo model and artifact bundle.
    pub fn from_repo(
        repo: &GitRepoModel,
        artifacts: &GitArtifactBundle,
    ) -> Result<Self, SimGitError> {
        let object_format = to_object_format(repo.object_format);
        let packs = collect_packs(&artifacts.packs)?;
        Ok(Self {
            object_format,
            packs,
        })
    }

    /// Returns pack views for planning.
    pub fn pack_views(&self) -> Result<Vec<PackView<'_>>, PackPlanError> {
        let mut out = Vec::with_capacity(self.packs.len());
        for pack in &self.packs {
            let view = PackView::parse(pack.as_slice(), self.object_format.oid_len())?;
            out.push(view);
        }
        Ok(out)
    }

    /// Returns a pack byte view by pack id.
    pub fn pack_bytes(&self, pack_id: u16) -> Result<BytesView, SimGitError> {
        let idx = pack_id as usize;
        let count = self.packs.len();
        self.packs
            .get(idx)
            .cloned()
            .ok_or(SimGitError::PackIdOutOfRange {
                pack_id,
                pack_count: count,
            })
    }

    /// Returns the number of packs.
    #[must_use]
    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }
}

fn collect_packs(packs: &[GitPackBytes]) -> Result<Vec<BytesView>, SimGitError> {
    if packs.is_empty() {
        return Ok(Vec::new());
    }
    let mut max_id = 0u16;
    for pack in packs {
        if pack.pack_id > max_id {
            max_id = pack.pack_id;
        }
    }
    let expected = max_id as usize + 1;
    if packs.len() != expected {
        return Err(SimGitError::PackCountMismatch {
            expected,
            actual: packs.len(),
        });
    }

    let mut out = vec![None; expected];
    for pack in packs {
        let idx = pack.pack_id as usize;
        if out[idx].is_some() {
            return Err(SimGitError::DuplicatePackId {
                pack_id: pack.pack_id,
            });
        }
        out[idx] = Some(BytesView::from_vec(pack.bytes.clone()));
    }

    Ok(out.into_iter().map(|b| b.expect("pack bytes")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::pack_inflate::ObjectKind;
    use crate::git_scan::pack_plan_model::CandidateAtOffset;
    use crate::git_scan::{
        execute_pack_plan_with_reader, ByteArena, CandidateContext, ChangeKind, PackCache,
        PackCandidate, PackDecodeLimits, PackExecError, PackObjectSink, PackPlan, PackPlanStats,
    };
    use crate::git_scan::{ExternalBase, ExternalBaseProvider};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[derive(Default)]
    struct CollectingSink {
        bytes: Vec<u8>,
    }

    struct NoExternal;

    impl ExternalBaseProvider for NoExternal {
        fn load_base(
            &mut self,
            _oid: &crate::git_scan::OidBytes,
        ) -> Result<Option<ExternalBase>, PackExecError> {
            Ok(None)
        }
    }

    impl PackObjectSink for CollectingSink {
        fn emit(
            &mut self,
            _candidate: &PackCandidate,
            _path: &[u8],
            bytes: &[u8],
        ) -> Result<(), PackExecError> {
            self.bytes = bytes.to_vec();
            Ok(())
        }
    }

    fn encode_entry_header(kind: ObjectKind, size: usize) -> Vec<u8> {
        let obj_type = match kind {
            ObjectKind::Commit => 1u8,
            ObjectKind::Tree => 2u8,
            ObjectKind::Blob => 3u8,
            ObjectKind::Tag => 4u8,
        };
        let mut out = Vec::new();
        let mut remaining = size as u64;
        let mut first = ((obj_type & 0x07) << 4) | ((remaining & 0x0f) as u8);
        remaining >>= 4;
        if remaining != 0 {
            first |= 0x80;
        }
        out.push(first);
        while remaining != 0 {
            let mut byte = (remaining & 0x7f) as u8;
            remaining >>= 7;
            if remaining != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
        out
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn build_pack(entries: &[(ObjectKind, &[u8])]) -> (Vec<u8>, Vec<u64>) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        let mut offsets = Vec::with_capacity(entries.len());
        for (kind, data) in entries {
            offsets.push(bytes.len() as u64);
            bytes.extend_from_slice(&encode_entry_header(*kind, data.len()));
            bytes.extend_from_slice(&compress(data));
        }

        bytes.extend_from_slice(&[0u8; 20]);
        (bytes, offsets)
    }

    #[test]
    fn execute_with_reader_decodes_blob() {
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"hello")]);

        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 0,
            candidates: vec![PackCandidate {
                oid: crate::git_scan::OidBytes::sha1([0x11; 20]),
                ctx: CandidateContext {
                    commit_id: 1,
                    parent_idx: 0,
                    change_kind: ChangeKind::Add,
                    ctx_flags: 0,
                    cand_flags: 0,
                    path_ref: crate::git_scan::ByteRef::new(0, 0),
                },
                pack_id: 0,
                offset: offsets[0],
            }],
            candidate_offsets: vec![CandidateAtOffset {
                offset: offsets[0],
                cand_idx: 0,
            }],
            need_offsets: vec![offsets[0]],
            delta_deps: Vec::new(),
            delta_dep_index: Vec::new(),
            exec_order: None,
            clusters: Vec::new(),
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 1,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: 0,
            },
        };

        let arena = ByteArena::with_capacity(32);
        let mut reader = BytesView::from_vec(pack);
        let mut cache = PackCache::new(64 * 1024);
        let mut sink = CollectingSink::default();
        let mut external = NoExternal;

        let limits = PackDecodeLimits::new(64, 1024, 1024);
        let _report = execute_pack_plan_with_reader(
            &plan,
            &mut reader,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        )
        .expect("execute");

        assert_eq!(sink.bytes, b"hello".to_vec());
    }
}
