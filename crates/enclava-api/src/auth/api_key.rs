//! API key creation, hashing, and validation.
//!
//! API keys are prefixed with "enc_" for easy identification.
//! The raw key is shown once at creation; only the argon2 hash is stored.

use crate::auth::email::{hash_password, verify_password};
use chrono::{DateTime, Utc};
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

/// Valid API key scopes.
pub const VALID_SCOPES: &[&str] = &["apps:read", "apps:write", "config:write", "org:admin"];

/// Database row for API key lookup.
type ApiKeyRow = (Uuid, Uuid, Uuid, String, Vec<String>, Option<DateTime<Utc>>);

#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    #[error("name is required")]
    NameRequired,
    #[error("API key not found or expired")]
    NotFound,
    #[error("API key does not have required scope: {0}")]
    InsufficientScope(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("hashing error: {0}")]
    Hash(String),
}

/// Result of creating a new API key.
#[derive(Debug)]
pub struct CreatedApiKey {
    pub id: Uuid,
    /// The raw key -- shown once, never stored.
    pub raw_key: String,
    pub name: String,
    pub scopes: Vec<String>,
}

/// Generate a random API key string.
fn generate_raw_key() -> String {
    let mut rng = rand::rngs::OsRng;
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    format!("enc_{}", hex::encode(random_bytes))
}

/// Create a new API key for an org.
pub async fn create_api_key(
    pool: &PgPool,
    org_id: Uuid,
    created_by: Uuid,
    name: &str,
    scopes: &[String],
    expires_at: Option<DateTime<Utc>>,
) -> Result<CreatedApiKey, ApiKeyError> {
    if name.is_empty() {
        return Err(ApiKeyError::NameRequired);
    }

    for scope in scopes {
        if !VALID_SCOPES.contains(&scope.as_str()) {
            return Err(ApiKeyError::InvalidScope(scope.clone()));
        }
    }

    let raw_key = generate_raw_key();
    let key_hash = hash_password(&raw_key).map_err(|e| ApiKeyError::Hash(e.to_string()))?;
    let key_prefix = &raw_key[..8]; // "enc_" + first 4 hex chars
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO api_keys (id, org_id, created_by, key_hash, key_prefix, name, scopes, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(org_id)
    .bind(created_by)
    .bind(&key_hash)
    .bind(key_prefix)
    .bind(name)
    .bind(scopes)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(CreatedApiKey {
        id,
        raw_key,
        name: name.to_string(),
        scopes: scopes.to_vec(),
    })
}

/// Validated API key result.
#[derive(Debug, Clone)]
pub struct ValidatedApiKey {
    pub id: Uuid,
    pub org_id: Uuid,
    pub created_by: Uuid,
    pub scopes: Vec<String>,
}

/// Validate an API key against database. Returns key metadata if valid.
pub async fn validate_api_key(
    pool: &PgPool,
    raw_key: &str,
) -> Result<ValidatedApiKey, ApiKeyError> {
    if !raw_key.starts_with("enc_") || raw_key.len() < 8 {
        return Err(ApiKeyError::NotFound);
    }

    let prefix = &raw_key[..8];

    // Find candidate keys by prefix (fast index lookup), then verify hash
    let candidates: Vec<ApiKeyRow> = sqlx::query_as(
        "SELECT id, org_id, created_by, key_hash, scopes, expires_at
         FROM api_keys WHERE key_prefix = $1",
    )
    .bind(prefix)
    .fetch_all(pool)
    .await?;

    // Filter expired keys first
    let valid_candidates: Vec<(Uuid, Uuid, Uuid, String, Vec<String>)> = candidates
        .into_iter()
        .filter_map(|(id, org_id, created_by, key_hash, scopes, expires_at)| {
            // Check expiry
            if let Some(exp) = expires_at {
                if exp < Utc::now() {
                    return None;
                }
            }
            Some((id, org_id, created_by, key_hash, scopes))
        })
        .collect();

    // Verify all candidates with constant-time comparison
    for (id, org_id, created_by, key_hash, scopes) in valid_candidates {
        // Use constant-time comparison to prevent timing attacks
        let valid =
            verify_password(raw_key, &key_hash).map_err(|e| ApiKeyError::Hash(e.to_string()))?;

        if valid {
            // Update last_used_at
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;

            return Ok(ValidatedApiKey {
                id,
                org_id,
                created_by,
                scopes,
            });
        }
    }

    Err(ApiKeyError::NotFound)
}

/// Check that a validated key has a required scope.
pub fn require_scope(key: &ValidatedApiKey, scope: &str) -> Result<(), ApiKeyError> {
    if key.scopes.iter().any(|s| s == scope) {
        Ok(())
    } else {
        Err(ApiKeyError::InsufficientScope(scope.to_string()))
    }
}

/// Revoke an API key.
pub async fn revoke_api_key(
    pool: &PgPool,
    key_id: Uuid,
    org_id: Uuid,
) -> Result<bool, ApiKeyError> {
    let result = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND org_id = $2")
        .bind(key_id)
        .bind(org_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
