use chrono::{Duration, Utc};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String, // user_id
    pub exp: i64,
    pub iat: i64,
    pub org_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigTokenClaims {
    pub sub: String, // user_id
    pub org_id: String,
    pub app_id: String,
    pub scopes: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token encoding failed: {0}")]
    Encode(#[from] jsonwebtoken::errors::Error),
    #[error("token expired")]
    Expired,
    #[error("invalid token")]
    Invalid,
    #[error("key encoding failed: {0}")]
    KeyEncoding(String),
}

/// Generate a secure HMAC key for JWT signing.
pub fn generate_hmac_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Issue a session JWT (HS256, signed with a dedicated HMAC key).
/// Session tokens last 24 hours.
pub fn issue_session_token(hmac_key: &[u8; 32], user_id: Uuid) -> Result<String, JwtError> {
    let now = Utc::now();
    let claims = SessionClaims {
        sub: user_id.to_string(),
        exp: (now + Duration::hours(24)).timestamp(),
        iat: now.timestamp(),
        org_id: None,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(hmac_key),
    )?;
    Ok(token)
}

/// Verify and decode a session JWT.
pub fn verify_session_token(hmac_key: &[u8; 32], token: &str) -> Result<SessionClaims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["sub", "exp", "iat"]);

    let data = decode::<SessionClaims>(token, &DecodingKey::from_secret(hmac_key), &validation)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid,
        })?;

    Ok(data.claims)
}

/// Issue a short-lived config token (5 minutes) for CLI -> TEE config writes.
/// Uses Ed25519 (EdDSA) so the TEE can verify with the public key embedded in cc_init_data.
pub fn issue_config_token(
    signing_key: &SigningKey,
    user_id: Uuid,
    org_id: Uuid,
    app_id: Uuid,
    scopes: Vec<String>,
) -> Result<String, JwtError> {
    let now = Utc::now();
    let claims = ConfigTokenClaims {
        sub: user_id.to_string(),
        org_id: org_id.to_string(),
        app_id: app_id.to_string(),
        scopes,
        exp: (now + Duration::minutes(5)).timestamp(),
        iat: now.timestamp(),
    };

    let secret = signing_key
        .to_pkcs8_der()
        .map_err(|e| JwtError::KeyEncoding(e.to_string()))?;
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &EncodingKey::from_ed_der(secret.as_bytes()),
    )?;
    Ok(token)
}

/// Get the Ed25519 verifying (public) key as base64 for embedding in cc_init_data.
pub fn public_key_base64(signing_key: &SigningKey) -> String {
    use base64::Engine;
    let vk: VerifyingKey = signing_key.verifying_key();
    base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_config_token_produces_compact_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let token = issue_config_token(
            &signing_key,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec!["config:write".to_string()],
        )
        .expect("failed to issue config token");

        assert_eq!(token.matches('.').count(), 2);
    }
}
