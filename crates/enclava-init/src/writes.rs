//! Atomic file writes via tmp+rename. A SIGKILL between write and rename
//! leaves only the tmp file at a sibling path; the destination is either the
//! prior contents or absent — never a partial write.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::errors::Result;

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::errors::InitError::Config("seed path has no parent".into()))?;
    fs::create_dir_all(parent)?;

    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("seed")
    ));

    {
        let mut f: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use tempfile::tempdir;

    #[test]
    fn atomic_write_creates_file_with_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seed");
        atomic_write(&path, b"hello", 0o600).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn atomic_write_replaces_existing_atomically() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seed");
        atomic_write(&path, b"v1", 0o600).unwrap();
        atomic_write(&path, b"v2", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v2");
    }

    #[test]
    fn atomic_write_no_partial_on_simulated_kill() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("seed");
        atomic_write(&dest, b"original", 0o600).unwrap();

        let tmp = dir.path().join(".seed.tmp");
        std::fs::write(&tmp, b"partial").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"original");
        assert!(tmp.exists());
    }
}
