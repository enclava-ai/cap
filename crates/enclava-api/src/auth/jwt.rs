use chrono::{Duration, Utc};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Issuer claim baked into every API-issued token.
pub const TOKEN_ISSUER: &str = "enclava-cap";
/// Audience for browser/CLI session tokens.
pub const SESSION_AUDIENCE: &str = "enclava:session";
/// Audience for short-lived config tokens consumed by the TEE.
pub const CONFIG_AUDIENCE: &str = "enclava:config";

/// `typ` claim value for session tokens.
pub const SESSION_TYP: &str = "session";
/// `typ` claim value for config tokens.
pub const CONFIG_TYP: &str = "config";

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String, // user_id
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigTokenClaims {
    pub sub: String, // user_id
    pub org_id: String,
    pub app_id: String,
    pub instance_id: String,
    pub scopes: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub jti: String,
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

fn new_jti() -> String {
    Uuid::new_v4().to_string()
}

fn session_validator() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[SESSION_AUDIENCE]);
    validation
}

fn config_validator() -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[CONFIG_AUDIENCE]);
    validation
}

/// Issue a session JWT (HS256, signed with a dedicated HMAC key).
/// Session tokens last 24 hours.
pub fn issue_session_token(hmac_key: &[u8; 32], user_id: Uuid) -> Result<String, JwtError> {
    let now = Utc::now();
    let claims = SessionClaims {
        sub: user_id.to_string(),
        exp: (now + Duration::hours(24)).timestamp(),
        iat: now.timestamp(),
        iss: TOKEN_ISSUER.to_string(),
        aud: SESSION_AUDIENCE.to_string(),
        typ: SESSION_TYP.to_string(),
        jti: new_jti(),
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
    let validation = session_validator();
    let data = decode::<SessionClaims>(token, &DecodingKey::from_secret(hmac_key), &validation)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid,
        })?;

    if data.claims.typ != SESSION_TYP {
        return Err(JwtError::Invalid);
    }

    Ok(data.claims)
}

/// Issue a short-lived config token (5 minutes) for CLI -> TEE config writes.
/// Uses Ed25519 (EdDSA) so the TEE can verify with the public key embedded in cc_init_data.
pub fn issue_config_token(
    signing_key: &SigningKey,
    user_id: Uuid,
    org_id: Uuid,
    app_id: Uuid,
    instance_id: &str,
    scopes: Vec<String>,
) -> Result<String, JwtError> {
    let now = Utc::now();
    let claims = ConfigTokenClaims {
        sub: user_id.to_string(),
        org_id: org_id.to_string(),
        app_id: app_id.to_string(),
        instance_id: instance_id.to_string(),
        scopes,
        exp: (now + Duration::minutes(5)).timestamp(),
        iat: now.timestamp(),
        iss: TOKEN_ISSUER.to_string(),
        aud: CONFIG_AUDIENCE.to_string(),
        typ: CONFIG_TYP.to_string(),
        jti: new_jti(),
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

/// Verify a config token using an Ed25519 verifying key. Used in tests and
/// for any future API-side verification path; the TEE has its own verifier.
pub fn verify_config_token(
    verifying_key: &VerifyingKey,
    token: &str,
) -> Result<ConfigTokenClaims, JwtError> {
    use base64::Engine;
    let validation = config_validator();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    let key = DecodingKey::from_ed_components(&x).map_err(JwtError::Encode)?;
    let data =
        decode::<ConfigTokenClaims>(token, &key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid,
        })?;

    if data.claims.typ != CONFIG_TYP {
        return Err(JwtError::Invalid);
    }
    Ok(data.claims)
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
            "test-instance",
            vec!["config:write".to_string()],
        )
        .expect("failed to issue config token");

        assert_eq!(token.matches('.').count(), 2);
    }

    #[test]
    fn session_token_round_trip_includes_required_claims() {
        let key = generate_hmac_key();
        let user = Uuid::new_v4();
        let token = issue_session_token(&key, user).unwrap();
        let claims = verify_session_token(&key, &token).unwrap();
        assert_eq!(claims.iss, TOKEN_ISSUER);
        assert_eq!(claims.aud, SESSION_AUDIENCE);
        assert_eq!(claims.typ, SESSION_TYP);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn config_token_round_trip_includes_required_claims() {
        let signing = SigningKey::generate(&mut OsRng);
        let token = issue_config_token(
            &signing,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-instance",
            vec!["config:write".into()],
        )
        .unwrap();
        let claims = verify_config_token(&signing.verifying_key(), &token).unwrap();
        assert_eq!(claims.iss, TOKEN_ISSUER);
        assert_eq!(claims.aud, CONFIG_AUDIENCE);
        assert_eq!(claims.typ, CONFIG_TYP);
        assert_eq!(claims.instance_id, "test-instance");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn session_validator_rejects_config_token() {
        // Cross-audience swap: a config token must not pass session checks.
        let hmac = generate_hmac_key();
        let signing = SigningKey::generate(&mut OsRng);
        let config_token = issue_config_token(
            &signing,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-instance",
            vec!["config:write".into()],
        )
        .unwrap();
        // Different signing material AND different audience: should fail.
        assert!(verify_session_token(&hmac, &config_token).is_err());
    }

    #[test]
    fn token_with_wrong_audience_rejected() {
        use jsonwebtoken::{EncodingKey, Header};
        let key = generate_hmac_key();
        let now = Utc::now();
        let claims = SessionClaims {
            sub: Uuid::new_v4().to_string(),
            exp: (now + Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            iss: TOKEN_ISSUER.to_string(),
            aud: "evil:audience".to_string(),
            typ: SESSION_TYP.to_string(),
            jti: Uuid::new_v4().to_string(),
            org_id: None,
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&key),
        )
        .unwrap();
        assert!(matches!(
            verify_session_token(&key, &token),
            Err(JwtError::Invalid)
        ));
    }

    #[test]
    fn token_missing_iss_rejected() {
        use jsonwebtoken::{EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct NoIss {
            sub: String,
            exp: i64,
            iat: i64,
            aud: String,
            typ: String,
        }
        let key = generate_hmac_key();
        let now = Utc::now();
        let claims = NoIss {
            sub: Uuid::new_v4().to_string(),
            exp: (now + Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            aud: SESSION_AUDIENCE.to_string(),
            typ: SESSION_TYP.to_string(),
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&key),
        )
        .unwrap();
        assert!(matches!(
            verify_session_token(&key, &token),
            Err(JwtError::Invalid)
        ));
    }
}
