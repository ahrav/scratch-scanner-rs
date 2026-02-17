//! Lamport clock and node identity for triage conflict resolution.
//!
//! The `triage.meta` file stores a fixed-size binary record:
//!
//! ```text
//! [magic: "TRM1" (4B)] [node_id: u64 LE] [clock: u64 LE] [crc32: u32 LE]
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
        self.clock = self
            .clock
            .checked_add(1)
            .ok_or_else(|| io::Error::other("lamport clock overflow"))?;
        self.persist()?;
        Ok(self.clock)
    }

    /// Merge with a remote clock: `max(local, remote) + 1`.
    pub fn merge(&mut self, remote_clock: u64) -> io::Result<u64> {
        self.clock = self
            .clock
            .max(remote_clock)
            .checked_add(1)
            .ok_or_else(|| io::Error::other("lamport clock overflow"))?;
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
    // Similar /dev/urandom approach as generate_run_id in store::db::writer —
    // /dev/urandom on unix, fallback to time+PID XOR otherwise.
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut buf = [0u8; 8];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut buf).is_ok() {
                return u64::from_le_bytes(buf);
            }
        }
    }
    // Fallback: hash of current time + PID (used on non-unix or if /dev/urandom fails).
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    t ^ (pid << 32)
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

    // ======================================================================
    // Step 7: Specific corruption patterns
    // ======================================================================

    #[test]
    fn clock_corrupt_meta_specific_patterns() {
        // Pattern 1: correct magic but bad CRC.
        {
            let dir = tempfile::tempdir().unwrap();
            let meta_path = dir.path().join("triage.meta");
            let mut buf = [0u8; META_SIZE];
            buf[0..4].copy_from_slice(META_MAGIC);
            buf[4..12].copy_from_slice(&42u64.to_le_bytes());
            buf[12..20].copy_from_slice(&99u64.to_le_bytes());
            // Write wrong CRC (all zeros).
            buf[20..24].copy_from_slice(&0u32.to_le_bytes());
            std::fs::write(&meta_path, buf).unwrap();

            let clock = TriageClock::open(dir.path()).unwrap();
            assert_eq!(clock.value(), 0, "bad CRC should reinitialize");
        }

        // Pattern 2: truncated file (only magic bytes).
        {
            let dir = tempfile::tempdir().unwrap();
            let meta_path = dir.path().join("triage.meta");
            std::fs::write(&meta_path, META_MAGIC).unwrap();

            let clock = TriageClock::open(dir.path()).unwrap();
            assert_eq!(clock.value(), 0, "truncated file should reinitialize");
        }

        // Pattern 3: zero-length file.
        {
            let dir = tempfile::tempdir().unwrap();
            let meta_path = dir.path().join("triage.meta");
            std::fs::write(&meta_path, b"").unwrap();

            let clock = TriageClock::open(dir.path()).unwrap();
            assert_eq!(clock.value(), 0, "empty file should reinitialize");
        }
    }

    // ======================================================================
    // Step 8: Rapid-tick monotonicity
    // ======================================================================

    #[test]
    fn clock_rapid_tick_monotonicity() {
        let dir = tempfile::tempdir().unwrap();
        let mut clock = TriageClock::open(dir.path()).unwrap();

        let mut prev = 0u64;
        for _ in 0..1000 {
            let val = clock.tick().unwrap();
            assert!(
                val > prev,
                "clock must be strictly monotonic: prev={prev}, val={val}"
            );
            prev = val;
        }
        assert_eq!(clock.value(), 1000);
    }

    #[test]
    fn generate_node_id_never_zero() {
        for _ in 0..100 {
            let id = generate_node_id();
            assert_ne!(id, 0, "node_id must never be zero");
        }
    }

    #[test]
    fn generate_node_id_uniqueness() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..100 {
            let id = generate_node_id();
            assert!(ids.insert(id), "duplicate node_id generated");
        }
    }
}
