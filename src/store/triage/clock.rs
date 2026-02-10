//! Lamport clock and node identity for triage conflict resolution.
//!
//! The `triage.meta` file stores a fixed-size binary record:
//!
//! ```text
//! [magic: "TRM1" (4B)] [node_id: u64 LE] [max_clock: u64 LE] [crc32: u32 LE]
//! ```
//!
//! Total: 24 bytes. Written via atomic rename for crash safety.

use std::io;
use std::path::{Path, PathBuf};

/// Fixed magic bytes identifying the triage meta file.
const META_MAGIC: &[u8; 4] = b"TRM1";

/// Size of the triage.meta file: 4 (magic) + 8 (node_id) + 8 (clock) + 4 (crc32).
const META_SIZE: usize = 24;

/// Lamport clock for ordering triage operations across nodes.
pub struct TriageClock {
    node_id: u64,
    clock: u64,
    meta_path: PathBuf,
}

impl TriageClock {
    /// Load or initialize the triage clock from `triage.meta`.
    ///
    /// If the file doesn't exist or is corrupt, a new clock is initialized
    /// with a random node_id and clock=0.
    pub fn open(triage_dir: &Path) -> io::Result<Self> {
        let meta_path = triage_dir.join("triage.meta");

        if meta_path.exists() {
            match Self::read_meta(&meta_path) {
                Ok((node_id, clock)) => {
                    return Ok(Self {
                        node_id,
                        clock,
                        meta_path,
                    });
                }
                Err(_) => {
                    // Corrupt meta file — reinitialize.
                    eprintln!("warn: corrupt triage.meta, reinitializing");
                }
            }
        }

        let node_id = generate_node_id();
        let c = Self {
            node_id,
            clock: 0,
            meta_path,
        };
        c.persist()?;
        Ok(c)
    }

    /// Increment the clock and return the new value.
    pub fn tick(&mut self) -> io::Result<u64> {
        self.clock += 1;
        self.persist()?;
        Ok(self.clock)
    }

    /// Merge with a remote clock: `max(local, remote) + 1`.
    pub fn merge(&mut self, remote_clock: u64) -> io::Result<u64> {
        self.clock = self.clock.max(remote_clock) + 1;
        self.persist()?;
        Ok(self.clock)
    }

    /// Current clock value.
    pub fn value(&self) -> u64 {
        self.clock
    }

    /// Node identity.
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Read the triage.meta binary file.
    fn read_meta(path: &Path) -> io::Result<(u64, u64)> {
        let data = std::fs::read(path)?;
        if data.len() != META_SIZE {
            return Err(io::Error::other("triage.meta: wrong size"));
        }
        if &data[0..4] != META_MAGIC {
            return Err(io::Error::other("triage.meta: bad magic"));
        }

        let node_id = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let clock = u64::from_le_bytes(data[12..20].try_into().unwrap());
        let stored_crc = u32::from_le_bytes(data[20..24].try_into().unwrap());

        let computed_crc = crc32fast::hash(&data[0..20]);
        if stored_crc != computed_crc {
            return Err(io::Error::other("triage.meta: CRC mismatch"));
        }

        Ok((node_id, clock))
    }

    /// Persist via atomic rename.
    fn persist(&self) -> io::Result<()> {
        let mut buf = [0u8; META_SIZE];
        buf[0..4].copy_from_slice(META_MAGIC);
        buf[4..12].copy_from_slice(&self.node_id.to_le_bytes());
        buf[12..20].copy_from_slice(&self.clock.to_le_bytes());
        let crc = crc32fast::hash(&buf[0..20]);
        buf[20..24].copy_from_slice(&crc.to_le_bytes());

        let tmp_path = self.meta_path.with_extension("tmp");
        std::fs::write(&tmp_path, buf)?;
        std::fs::rename(&tmp_path, &self.meta_path)?;
        Ok(())
    }
}

/// Generate a random node_id using available entropy.
fn generate_node_id() -> u64 {
    // Use the same approach as SqliteStoreProducer::generate_run_id —
    // /dev/urandom on unix, BCryptGenRandom on Windows.
    let mut buf = [0u8; 8];
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut buf);
        }
    }
    #[cfg(not(unix))]
    {
        // Fallback: hash of current time + PID.
        use std::time::SystemTime;
        let t = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let pid = std::process::id() as u64;
        buf = (t ^ (pid << 32)).to_le_bytes();
    }
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_tick_increments() {
        let dir = tempfile::tempdir().unwrap();
        let mut clock = TriageClock::open(dir.path()).unwrap();
        assert_eq!(clock.value(), 0);

        let v1 = clock.tick().unwrap();
        assert_eq!(v1, 1);

        let v2 = clock.tick().unwrap();
        assert_eq!(v2, 2);
    }

    #[test]
    fn clock_merge_takes_max() {
        let dir = tempfile::tempdir().unwrap();
        let mut clock = TriageClock::open(dir.path()).unwrap();
        clock.tick().unwrap(); // 1

        let merged = clock.merge(10).unwrap();
        assert_eq!(merged, 11);
        assert_eq!(clock.value(), 11);

        // Local is higher — still increments.
        let merged2 = clock.merge(5).unwrap();
        assert_eq!(merged2, 12);
    }

    #[test]
    fn clock_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let node_id;
        {
            let mut clock = TriageClock::open(dir.path()).unwrap();
            clock.tick().unwrap();
            clock.tick().unwrap();
            clock.tick().unwrap();
            node_id = clock.node_id();
        }

        let clock2 = TriageClock::open(dir.path()).unwrap();
        assert_eq!(clock2.value(), 3);
        assert_eq!(clock2.node_id(), node_id);
    }

    #[test]
    fn corrupt_meta_reinitializes() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("triage.meta");

        // Write garbage.
        std::fs::write(&meta_path, b"garbage data here!!!").unwrap();

        let clock = TriageClock::open(dir.path()).unwrap();
        // Should reinitialize to 0.
        assert_eq!(clock.value(), 0);
    }
}
