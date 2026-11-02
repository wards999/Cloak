//! Crash-safe file writes for the store's own metadata (manifests, the store
//! header, the journal).
//!
//! Writing a file in place and crashing part-way leaves it torn; for a
//! directory manifest that means every real name in the folder is gone. So
//! metadata is written to a side file, flushed to the disk, and renamed over
//! the original: after a crash the file is either the old version or the new
//! one, never a mix. Renaming without the flush is not enough — NTFS and APFS
//! journal the rename but not the data, so the renamed file can come back full
//! of zeros.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

/// Suffix of the side file a write goes through. Never a boring name (those
/// always contain `_`), and ignored on load if a crash leaves one behind.
pub const SIDE_SUFFIX: &str = ".new";

/// Replace `path` with `bytes` atomically and durably.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut side = path.as_os_str().to_owned();
    side.push(SIDE_SUFFIX);
    let side = Path::new(&side);
    {
        let mut f = File::create(side)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(side, path)?;
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

/// Write `bytes` to `path` and flush it to disk (no rename: for a file whose
/// readers treat a torn copy as absent).
pub fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Make a directory's entries (a rename, a new or deleted file) durable. On
/// Windows that comes with the metadata journal and a directory can't be
/// opened for syncing.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn atomic_write_replaces_and_leaves_no_side_file() {
        let d = tempdir().unwrap();
        let p = d.path().join("manifest.idx");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }
}
