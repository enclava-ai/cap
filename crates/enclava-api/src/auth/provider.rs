use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A verified identity from any auth provider.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// The provider-specific identifier (email address, npub, etc.).
    pub identifier: String,
    /// The provider name.
    pub provider: String,
    /// Display name extracted from the identity (email local part, nostr name, etc.).
    pub display_name: String,
}

/// Request payload for authentication initiation.
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub provider: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Nostr NIP-98 signed event (JSON string).
    #[serde(default)]
    pub nostr_event: Option<String>,
}

/// Signup response.
#[derive(Debug, Serialize)]
pub struct SignupResponse {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub token: String,
}

/// Login response.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub token: String,
}
