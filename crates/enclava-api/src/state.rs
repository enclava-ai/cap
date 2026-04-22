use crate::dns::DnsConfig;
use crate::kbs::KbsPolicyConfig;
use ed25519_dalek::SigningKey;
use enclava_engine::types::AttestationConfig;
use sqlx::PgPool;
use std::sync::Arc;

/// Shared application state accessible from all axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// Ed25519 signing key for config JWTs.
    pub signing_key: Arc<SigningKey>,
    /// HMAC key for session JWT signing.
    pub hmac_key: Arc<[u8; 32]>,
    /// Base URL of this API server (for config metadata sync callbacks).
    pub api_url: String,
    /// BTCPay Server base URL.
    pub btcpay_url: String,
    /// BTCPay Server API key.
    pub btcpay_api_key: String,
    /// Platform domain suffix (e.g., "enclava.dev").
    pub platform_domain: String,
    /// HTTP client for outbound requests.
    pub http_client: reqwest::Client,
    /// HTTP client for tenant TEE endpoints. Test environments may use staging
    /// ACME certificates that are not trusted by the public WebPKI roots.
    pub tee_http_client: reqwest::Client,
    /// BTCPay webhook HMAC secret for signature verification.
    pub btcpay_webhook_secret: String,
    /// Sidecar/runtime settings used when generating Kubernetes manifests.
    pub attestation: Option<AttestationConfig>,
    /// Cloudflare DNS settings for CAP-managed tenant host records.
    pub dns: Option<DnsConfig>,
    /// Trustee KBS policy settings for CAP-managed owner-resource bindings.
    pub kbs_policy: Option<KbsPolicyConfig>,
}
