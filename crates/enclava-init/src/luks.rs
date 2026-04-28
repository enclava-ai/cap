//! cryptsetup luksOpen / luksFormat via `libcryptsetup-rs`.
//!
//! Requires `libcryptsetup-dev` (Debian) / `cryptsetup-devel` (Fedora) at
//! build time and `libcryptsetup.so.12` at runtime. Inside the Kata SEV-SNP
//! guest the `dm_mod` and `dm_crypt` kernel modules must be loadable — the
//! StatefulSet sets `io.katacontainers.config.agent.kernel_modules` as
//! defense-in-depth (B2 investigation).
//!
//! The dm-crypt mapping persists across init-container exit because the
//! sandbox VM kernel outlives the init container's userspace; after we open
//! the volume here, the app and caddy containers see `/dev/mapper/<name>`
//! for the rest of the pod's lifetime. Fresh LUKS2 volumes are formatted ext4
//! before the first mount, so the runtime image must include `mkfs.ext4`.

use std::path::{Path, PathBuf};

use libcryptsetup_rs::{CryptInit, consts::flags::CryptActivate, consts::vals::EncryptionFormat};

use crate::errors::{InitError, Result};
use crate::secrets::DerivedSeed;

/// Path to the activated mapper device.
#[derive(Debug, Clone)]
pub struct LuksOpened {
    pub mapper_path: PathBuf,
}

/// True iff the device already carries a LUKS2 header that loads cleanly.
pub fn is_formatted(device: &Path) -> Result<bool> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;
    Ok(dev
        .context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)
        .is_ok())
}

/// Format `device` as LUKS2 and add `key` as keyslot 0.
///
/// Used on first boot when the underlying block device is fresh.
pub fn format(device: &Path, key: &DerivedSeed) -> Result<()> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;

    dev.context_handle()
        .format::<()>(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain64"),
            None,
            libcryptsetup_rs::Either::Right(64),
            None,
        )
        .map_err(|e| InitError::Luks(format!("format: {e}")))?;

    dev.keyslot_handle()
        .add_by_key(
            None,
            None,
            key.as_bytes(),
            libcryptsetup_rs::consts::flags::CryptVolumeKey::empty(),
        )
        .map_err(|e| InitError::Luks(format!("add_by_key: {e}")))?;

    Ok(())
}

/// Open `device` to `/dev/mapper/<mapping_name>` using `key`.
///
/// The header must already exist (call [`format`] first on a fresh device).
pub fn open(device: &Path, mapping_name: &str, key: &DerivedSeed) -> Result<LuksOpened> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;

    dev.context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)
        .map_err(|e| InitError::Luks(format!("load: {e}")))?;

    dev.activate_handle()
        .activate_by_passphrase(
            Some(mapping_name),
            None,
            key.as_bytes(),
            CryptActivate::empty(),
        )
        .map_err(|e| InitError::Luks(format!("activate: {e}")))?;

    Ok(LuksOpened {
        mapper_path: PathBuf::from(format!("/dev/mapper/{mapping_name}")),
    })
}

/// Format the device if it's not yet a LUKS2 volume, then activate it.
pub fn format_if_unformatted_then_open(
    device: &Path,
    mapping_name: &str,
    key: &DerivedSeed,
) -> Result<LuksOpened> {
    let needs_mkfs = !is_formatted(device)?;
    if needs_mkfs {
        format(device, key)?;
    }
    let opened = open(device, mapping_name, key)?;
    if needs_mkfs {
        mkfs_ext4(&opened.mapper_path)?;
    }
    Ok(opened)
}

fn mkfs_ext4(mapper_path: &Path) -> Result<()> {
    let status = std::process::Command::new("mkfs.ext4")
        .arg("-F")
        .arg(mapper_path)
        .status()
        .map_err(|e| InitError::Luks(format!("mkfs.ext4 {}: {e}", mapper_path.display())))?;
    if !status.success() {
        return Err(InitError::Luks(format!(
            "mkfs.ext4 {} exited with {status}",
            mapper_path.display()
        )));
    }
    Ok(())
}

/// Mount `mapper_path` (a filesystem) at `mount_point`.
pub fn mount(mapper_path: &Path, mount_point: &Path) -> Result<()> {
    use nix::mount::{MsFlags, mount as nix_mount};
    std::fs::create_dir_all(mount_point)?;
    nix_mount(
        Some(mapper_path),
        mount_point,
        Some("ext4"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| {
        InitError::Luks(format!(
            "mount {} -> {}: {e}",
            mapper_path.display(),
            mount_point.display()
        ))
    })?;
    Ok(())
}

#[cfg(all(test, feature = "luks-integration"))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::tempdir;

    fn make_backing_file(size_mb: u64) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("disk.img");
        let mut f = File::create(&path).unwrap();
        f.seek(SeekFrom::Start(size_mb * 1024 * 1024 - 1)).unwrap();
        f.write_all(&[0u8]).unwrap();
        (dir, path)
    }

    #[test]
    fn format_then_open_round_trip() {
        let (_dir, img) = make_backing_file(32);
        let key = DerivedSeed([0x11u8; 32]);
        format(&img, &key).expect("format");
        let opened = open(&img, "enclava-init-test", &key).expect("open");
        assert!(opened.mapper_path.starts_with("/dev/mapper/"));
    }
}
