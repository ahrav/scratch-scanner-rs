//! Deterministic in-memory filesystem for simulation.
//!
//! The simulator uses `SimFs` to provide stable directory listings and file
//! contents without OS interaction. Paths are stored as raw bytes to preserve
//! invalid UTF-8 sequences.
//!
//! Invariants:
//! - Directory listings are sorted lexicographically by path bytes.
//! - File reads never panic; missing paths return `io::ErrorKind::NotFound`.
//! - Reads past EOF return an empty slice.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Path stored as raw bytes to support invalid UTF-8.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SimPath {
    pub bytes: Vec<u8>,
}

impl SimPath {
    #[inline(always)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Declarative filesystem layout for a scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimFsSpec {
    pub nodes: Vec<SimNodeSpec>,
}

/// Filesystem node specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SimNodeSpec {
    Dir {
        path: SimPath,
        children: Vec<SimPath>,
    },
    File {
        path: SimPath,
        contents: Vec<u8>,
    },
}

/// Deterministic in-memory filesystem.
#[derive(Clone, Debug)]
pub struct SimFs {
    files: BTreeMap<Vec<u8>, Vec<u8>>,
    dirs: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl SimFs {
    /// Build a filesystem instance from a spec.
    pub fn from_spec(spec: &SimFsSpec) -> Self {
        let mut files = BTreeMap::new();
        let mut dirs = BTreeMap::new();

        for node in &spec.nodes {
            match node {
                SimNodeSpec::File { path, contents } => {
                    files.insert(path.bytes.clone(), contents.clone());
                }
                SimNodeSpec::Dir { path, children } => {
                    let mut child_bytes: Vec<Vec<u8>> =
                        children.iter().map(|p| p.bytes.clone()).collect();
                    child_bytes.sort();
                    dirs.insert(path.bytes.clone(), child_bytes);
                }
            }
        }

        Self { files, dirs }
    }

    /// List a directory's immediate children in deterministic order.
    pub fn list_dir(&self, dir: &SimPath) -> std::io::Result<&[Vec<u8>]> {
        self.dirs
            .get(&dir.bytes)
            .map(|v| v.as_slice())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "dir not found"))
    }

    /// Open a file handle for a path.
    pub fn open_file(&self, path: &SimPath) -> std::io::Result<SimFileHandle> {
        let data = self
            .files
            .get(&path.bytes)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"))?;

        Ok(SimFileHandle {
            path: path.bytes.clone(),
            cursor: 0,
            len: data.len() as u64,
        })
    }

    /// Read a slice at an absolute offset.
    pub fn read_at(
        &self,
        handle: &SimFileHandle,
        offset: u64,
        len: usize,
    ) -> std::io::Result<&[u8]> {
        let data = self
            .files
            .get(&handle.path)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "file missing"))?;

        let start = match usize::try_from(offset) {
            Ok(v) => v,
            Err(_) => return Ok(&[]),
        };
        if start >= data.len() {
            return Ok(&[]);
        }

        let end = start.saturating_add(len).min(data.len());
        Ok(&data[start..end])
    }

    /// Read from the handle's current cursor and advance it by the bytes read.
    pub fn read_next(&self, handle: &mut SimFileHandle, len: usize) -> std::io::Result<&[u8]> {
        let offset = handle.cursor;
        let data = self.read_at(handle, offset, len)?;
        handle.cursor = offset.saturating_add(data.len() as u64);
        Ok(data)
    }

    /// Return file paths in deterministic order.
    pub fn file_paths(&self) -> Vec<SimPath> {
        self.files
            .keys()
            .map(|bytes| SimPath::new(bytes.clone()))
            .collect()
    }
}

/// Handle to a simulated file.
#[derive(Clone, Debug)]
pub struct SimFileHandle {
    pub path: Vec<u8>,
    pub cursor: u64,
    pub len: u64,
}
