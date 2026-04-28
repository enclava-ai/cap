//! Per-user CLI Ed25519 keypair management (Phase 7 — D10).
//!
//! On first authenticated command the CLI generates an Ed25519 keypair and
//! stores the seed at `~/.enclava/keys/<user_id>.priv` mode 0600. The public
//! half is registered with the platform via `POST /users/me/public-keys`
//! (API-side endpoint pending — see TODO(phase-7-api)).

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum KeysError {
    #[error("home directory not available")]
    NoHome,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key file (expected 32 bytes, got {0})")]
    InvalidLength(usize),
    #[error("signature verification failed: {0}")]
    Verify(String),
    #[error("key file `{0}` is world-readable; refusing to load (expected mode 0600)")]
    InsecurePermissions(PathBuf),
    #[error("Windows is not supported in v1 — keypair storage requires POSIX mode bits")]
    UnsupportedPlatform,
}

/// A user's signing key. The secret seed is zeroed on drop.
#[derive(Debug)]
pub struct UserSigningKey {
    pub user_id: Uuid,
    pub public: VerifyingKey,
    secret: SigningKey,
    // Retain raw seed bytes alongside the dalek SigningKey so we can zero
    // them ourselves on drop. SigningKey itself does not implement Zeroize
    // in dalek 2.x, but the seed it derives from does.
    seed: [u8; 32],
}

impl UserSigningKey {
    pub fn generate(user_id: Uuid) -> Self {
        let secret = SigningKey::generate(&mut OsRng);
        let seed = secret.to_bytes();
        let public = secret.verifying_key();
        Self {
            user_id,
            public,
            secret,
            seed,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    pub fn verify(public: &VerifyingKey, message: &[u8], sig: &Signature) -> Result<(), KeysError> {
        public
            .verify(message, sig)
            .map_err(|e| KeysError::Verify(e.to_string()))
    }
}

impl Drop for UserSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Resolve the per-user keys directory, creating it (mode 0700) if needed.
pub fn keys_dir() -> Result<PathBuf, KeysError> {
    let home = dirs::home_dir().ok_or(KeysError::NoHome)?;
    let dir = home.join(".enclava").join("keys");
    fs::create_dir_all(&dir)?;
    set_dir_perms_0700(&dir)?;
    Ok(dir)
}

fn key_path_for(user_id: &Uuid) -> Result<PathBuf, KeysError> {
    Ok(keys_dir()?.join(format!("{user_id}.priv")))
}

#[cfg(unix)]
fn set_file_perms_0600(path: &Path) -> Result<(), KeysError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_perms_0700(path: &Path) -> Result<(), KeysError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn assert_mode_0600(path: &Path) -> Result<(), KeysError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeysError::InsecurePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_file_perms_0600(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn set_dir_perms_0700(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn assert_mode_0600(_: &Path) -> Result<(), KeysError> {
    Err(KeysError::UnsupportedPlatform)
}

/// Generate a fresh keypair and persist it under `~/.enclava/keys/<user_id>.priv`.
/// Refuses to overwrite an existing file.
pub fn create_and_store(user_id: Uuid) -> Result<UserSigningKey, KeysError> {
    let path = key_path_for(&user_id)?;
    if path.exists() {
        return load(user_id);
    }
    let key = UserSigningKey::generate(user_id);
    fs::write(&path, key.seed)?;
    set_file_perms_0600(&path)?;
    Ok(key)
}

/// Load the stored keypair for `user_id`. Refuses to read files with insecure
/// permissions; refuses on Windows entirely.
pub fn load(user_id: Uuid) -> Result<UserSigningKey, KeysError> {
    let path = key_path_for(&user_id)?;
    assert_mode_0600(&path)?;
    let bytes = fs::read(&path)?;
    if bytes.len() != 32 {
        return Err(KeysError::InvalidLength(bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let secret = SigningKey::from_bytes(&seed);
    let public = secret.verifying_key();
    Ok(UserSigningKey {
        user_id,
        public,
        secret,
        seed,
    })
}

/// Stub client function for `POST /users/me/public-keys`.
/// TODO(phase-7-api): wire to enclava-api once the endpoint is implemented.
pub struct RegisterPublicKeyRequest {
    pub user_id: Uuid,
    pub public_key: VerifyingKey,
    pub label: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialise tests that mutate $HOME (test impacts a shared global).
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn with_isolated_home<F: FnOnce()>(f: F) {
        let _guard = HOME_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", tmp.path());
        }
        f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn round_trip_create_load_sign_verify() {
        with_isolated_home(|| {
            let user = Uuid::new_v4();
            let key = create_and_store(user).unwrap();
            let sig = key.sign(b"hello");
            UserSigningKey::verify(&key.public, b"hello", &sig).unwrap();

            let loaded = load(user).unwrap();
            assert_eq!(loaded.public.to_bytes(), key.public.to_bytes());
            UserSigningKey::verify(&loaded.public, b"hello", &sig).unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_key_file() {
        with_isolated_home(|| {
            use std::os::unix::fs::PermissionsExt;
            let user = Uuid::new_v4();
            let _ = create_and_store(user).unwrap();
            let path = key_path_for(&user).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let err = load(user).unwrap_err();
            assert!(matches!(err, KeysError::InsecurePermissions(_)));
        });
    }
}
