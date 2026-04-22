//! Request and response types for the Platform API.
//! These mirror the API's JSON contract. They are CLI-local types,
//! not shared with the API crate (the CLI does not depend on enclava-api).

use serde::{Deserialize, Serialize};

// --- Auth ---

#[derive(Debug, Serialize)]
pub struct SignupRequest {
    pub provider: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub npub: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub provider: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub npub: Option<String>,
    /// NIP-98 signed event (JSON string)
    pub nostr_event: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: String,
    pub org_id: String,
    pub org_name: String,
}

// --- Apps ---

#[derive(Debug, Serialize)]
pub struct CreateAppRequest {
    pub name: String,
    pub port: u16,
    pub image: Option<String>,
    pub unlock_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_pubkey_hash: Option<String>,
    pub storage_size: String,
    pub tls_storage_size: String,
    pub storage_paths: Vec<String>,
    pub cpu: String,
    pub memory: String,
    pub services: Vec<ServiceSpec>,
    pub health_path: Option<String>,
    pub health_interval: Option<u32>,
    pub health_timeout: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ServiceSpec {
    pub name: String,
    pub image: String,
    pub port: Option<u16>,
    pub storage_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AppResponse {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub instance_id: String,
    pub domain: String,
    pub custom_domain: Option<String>,
    pub status: String,
    pub unlock_mode: String,
    pub created_at: String,
}

// --- Deploy ---

#[derive(Debug, Serialize)]
pub struct DeployRequest {
    pub image: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeployResponse {
    pub deployment_id: String,
    pub status: String,
    pub app_domain: String,
}

// --- Status ---

#[derive(Debug, Deserialize)]
pub struct AppStatus {
    pub app_name: String,
    pub status: String,
    pub pod_phase: Option<String>,
    pub tee_status: Option<String>,
    pub unlock_status: Option<String>,
    pub domain: String,
    pub last_deployed: Option<String>,
}

// --- Logs ---

#[derive(Debug, Deserialize)]
pub struct LogLine {
    pub timestamp: String,
    pub container: String,
    pub message: String,
}

// --- Config ---

#[derive(Debug, Deserialize)]
pub struct ConfigTokenResponse {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UnlockStatusResponse {
    pub unlock_mode: String,
    pub tee_url: String,
    pub ownership_state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUnlockModeRequest {
    pub mode: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUnlockModeResponse {
    pub app_name: String,
    pub unlock_mode: String,
    pub deployment_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigKeysResponse {
    pub keys: Vec<ConfigKeyMeta>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigKeyMeta {
    pub key: String,
    pub updated_at: String,
}

// --- Domains ---

#[derive(Debug, Serialize)]
pub struct SetDomainRequest {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct DomainResponse {
    pub platform_domain: String,
    pub custom_domain: Option<String>,
    pub dns_instructions: Option<String>,
}

// --- Rollback ---

#[derive(Debug, Serialize)]
pub struct RollbackRequest {
    pub deployment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RollbackResponse {
    pub deployment_id: String,
    pub rolled_back_to: String,
    pub status: String,
}

// --- Deployments ---

#[derive(Debug, Deserialize)]
pub struct DeploymentEntry {
    pub id: String,
    pub status: String,
    pub image_digest: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

// --- Billing ---

#[derive(Debug, Deserialize)]
pub struct TierInfo {
    pub name: String,
    pub max_apps: u32,
    pub max_cpu: String,
    pub max_memory: String,
    pub max_storage: String,
    pub price_sats: u64,
}

#[derive(Debug, Deserialize)]
pub struct InvoiceResponse {
    pub invoice_id: String,
    pub payment_url: String,
    pub amount_sats: u64,
    pub lightning_invoice: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct BillingStatus {
    pub tier: String,
    pub status: String,
    pub period_end: Option<String>,
    #[serde(default)]
    pub grace_period_ends: Option<String>,
}

// --- Orgs ---

#[derive(Debug, Serialize)]
pub struct CreateOrgRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct OrgResponse {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub display_name: Option<String>,
    pub tier: String,
    pub is_personal: bool,
}

#[derive(Debug, Serialize)]
pub struct InviteRequest {
    pub identifier: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct MemberResponse {
    pub user_id: String,
    pub display_name: Option<String>,
    pub role: String,
}

// --- Unlock ---

#[derive(Debug, Deserialize)]
pub struct UnlockEndpointResponse {
    pub tee_url: String,
    pub unlock_endpoint: String,
    pub claim_endpoint: String,
}

// --- Errors ---

#[derive(Debug, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
    pub detail: Option<String>,
}
