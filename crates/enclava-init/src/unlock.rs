//! Argon2id-based unlock plus a tmpfs-backed rate limiter.
//!
//! The rate limiter is a single file holding newline-separated unix
//! timestamps; before each attempt we drop entries older than the window and
//! count what remains. The salt is supplied per-app via cc_init_data and is
//! operator-readable by design — Argon2id makes that leak survivable.

use argon2::{Algorithm, Argon2, Params, Version};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{InitError, Result};
use crate::secrets::{OwnerSeed, Password};

pub const RATE_LIMIT_MAX_ATTEMPTS: usize = 5;
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

pub fn derive_owner_seed(password: &Password, salt: &[u8]) -> Result<OwnerSeed> {
    if salt.len() < 8 {
        return Err(InitError::Argon2("salt < 8 bytes".into()));
    }
    let params = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(32),
    )
    .map_err(|e| InitError::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| InitError::Argon2(e.to_string()))?;
    Ok(OwnerSeed(out))
}

pub fn check_rate_limit(attempts_path: &Path, now: u64) -> Result<()> {
    let existing = match std::fs::read_to_string(attempts_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(InitError::Io(e)),
    };

    let cutoff = now.saturating_sub(RATE_LIMIT_WINDOW_SECS);
    let recent: Vec<u64> = existing
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .filter(|t| *t >= cutoff)
        .collect();

    if recent.len() >= RATE_LIMIT_MAX_ATTEMPTS {
        return Err(InitError::RateLimited);
    }
    Ok(())
}

pub fn record_attempt(attempts_path: &Path, now: u64) -> Result<()> {
    if let Some(parent) = attempts_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(attempts_path).unwrap_or_default();
    let cutoff = now.saturating_sub(RATE_LIMIT_WINDOW_SECS);
    let mut lines: Vec<u64> = existing
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .filter(|t| *t >= cutoff)
        .collect();
    lines.push(now);
    let text = lines
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(attempts_path, text)?;
    Ok(())
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn argon2id_deterministic() {
        let pw = Password::from_plaintext("hunter2");
        let salt = b"per-app-salt-1234";
        let a = derive_owner_seed(&pw, salt).unwrap();
        let b = derive_owner_seed(&pw, salt).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn argon2id_different_password_yields_different_seed() {
        let salt = b"per-app-salt-1234";
        let a = derive_owner_seed(&Password::from_plaintext("hunter2"), salt).unwrap();
        let b = derive_owner_seed(&Password::from_plaintext("letmein"), salt).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn argon2id_known_answer_via_independent_recompute() {
        // Pin the Argon2id parameters to defaults; recompute the digest via
        // the argon2 crate directly and compare. If our wrapper changes
        // params, this test fails.
        let pw = Password::from_plaintext("password");
        let salt = b"somesalt12345678";
        let derived = derive_owner_seed(&pw, salt).unwrap();

        let params = Params::new(
            Params::DEFAULT_M_COST,
            Params::DEFAULT_T_COST,
            Params::DEFAULT_P_COST,
            Some(32),
        )
        .unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut expected = [0u8; 32];
        argon
            .hash_password_into(pw.as_bytes(), salt, &mut expected)
            .unwrap();
        assert_eq!(derived.as_bytes(), &expected);
    }

    #[test]
    fn rate_limit_triggers_at_sixth_attempt_within_window() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("attempts");
        let now = 1_000_000u64;
        for _ in 0..5 {
            check_rate_limit(&path, now).unwrap();
            record_attempt(&path, now).unwrap();
        }
        match check_rate_limit(&path, now) {
            Err(InitError::RateLimited) => {}
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_resets_after_window() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("attempts");
        let t0 = 1_000_000u64;
        for _ in 0..5 {
            record_attempt(&path, t0).unwrap();
        }
        let t1 = t0 + RATE_LIMIT_WINDOW_SECS + 1;
        check_rate_limit(&path, t1).unwrap();
    }
}
