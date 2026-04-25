use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::Deserialize;

/// Direct HTTPS client for the attestation proxy running inside a TEE.
/// All requests go to https://{app-domain}/.well-known/confidential/...
pub struct TeeClient {
    confidential_base_url: String,
    http: reqwest::Client,
}

fn accepts_invalid_tee_certs() -> bool {
    std::env::var("ENCLAVA_TEE_TLS_MODE")
        .map(|mode| matches!(mode.as_str(), "staging" | "insecure"))
        .unwrap_or(false)
        || std::env::var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
}

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("TEE error ({status}): {message}")]
    Tee { status: u16, message: String },
}

/// Response from the bootstrap challenge endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    #[serde(
        alias = "expires_in_seconds",
        deserialize_with = "deserialize_seconds_as_u64"
    )]
    pub ttl_seconds: u64,
}

/// Response from the claim endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct ClaimResponse {
    pub status: String,
    /// BIP39 mnemonic backup (shown to user once, never stored by CLI)
    pub mnemonic: Option<String>,
}

/// Response from status endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct TeeStatusResponse {
    pub ownership_state: String,
    pub unlock_state: String,
    pub auto_unlock_enabled: bool,
}

fn deserialize_seconds_as_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(number) => {
            if let Some(seconds) = number.as_u64() {
                return Ok(seconds);
            }
            number
                .as_f64()
                .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
                .map(|seconds| seconds as u64)
                .ok_or_else(|| serde::de::Error::custom("invalid seconds value"))
        }
        other => Err(serde::de::Error::custom(format!(
            "expected seconds number, got {other}"
        ))),
    }
}

impl TeeClient {
    /// Create a TEE client for the given app domain.
    /// The domain is the HTTPS endpoint of the app (e.g., "myapp.enclava.dev").
    pub fn new(app_domain: &str) -> Self {
        Self::new_with_timeout(app_domain, std::time::Duration::from_secs(180))
    }

    /// Create a TEE client with a custom request timeout.
    pub fn new_with_timeout(app_domain: &str, timeout: std::time::Duration) -> Self {
        let accept_invalid_certs = accepts_invalid_tee_certs();
        let http = reqwest::Client::builder()
            .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
            .timeout(timeout)
            .danger_accept_invalid_certs(accept_invalid_certs)
            .https_only(true) // Enforce HTTPS
            .build()
            .expect("failed to build HTTP client");

        let base_url = if app_domain.starts_with("https://") || app_domain.starts_with("http://") {
            app_domain.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", app_domain.trim_end_matches('/'))
        };
        let confidential_base_url = if base_url.ends_with("/.well-known/confidential") {
            base_url
        } else {
            format!("{base_url}/.well-known/confidential")
        };

        Self {
            confidential_base_url,
            http,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.confidential_base_url, path)
    }

    async fn check_response(&self, resp: reqwest::Response) -> Result<reqwest::Response, TeeError> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            let status_code = status.as_u16();
            let message = resp
                .text()
                .await
                .unwrap_or_else(|_| format!("HTTP {status_code}"));
            Err(TeeError::Tee {
                status: status_code,
                message,
            })
        }
    }

    // --- Config operations (require API-issued JWT) ---

    /// Set a config key/value pair on the TEE's encrypted filesystem.
    pub async fn config_set(
        &self,
        key: &str,
        value: &str,
        config_token: &str,
    ) -> Result<(), TeeError> {
        let resp = self
            .http
            .put(self.url(&format!("/config/{key}")))
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {config_token}")).unwrap(),
            )
            .header(CONTENT_TYPE, "text/plain")
            .body(value.to_string())
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Delete a config key from the TEE's encrypted filesystem.
    pub async fn config_unset(&self, key: &str, config_token: &str) -> Result<(), TeeError> {
        let resp = self
            .http
            .delete(self.url(&format!("/config/{key}")))
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {config_token}")).unwrap(),
            )
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    // --- Status ---

    /// Get the TEE's ownership and unlock status.
    pub async fn status(&self) -> Result<TeeStatusResponse, TeeError> {
        let resp = self.http.get(self.url("/status")).send().await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Return whether the TEE status shows ownership has already been claimed.
    ///
    /// The claim endpoint can commit ownership and then close the connection
    /// before the client receives the response. Callers use this as an
    /// idempotence check after an indeterminate claim transport error.
    pub async fn claim_state_is_successful(&self) -> Result<bool, TeeError> {
        let resp = self.http.get(self.url("/status")).send().await?;
        let resp = self.check_response(resp).await?;
        let body = resp.json::<serde_json::Value>().await?;
        let state = body
            .get("ownership_state")
            .or_else(|| body.get("state"))
            .and_then(|value| value.as_str());
        let unlock_state = body.get("unlock_state").and_then(|value| value.as_str());

        Ok(matches!(state, Some("claimed" | "unlocked"))
            || matches!(unlock_state, Some("unlocked")))
    }

    // --- Ownership operations (direct to TEE, no API token) ---

    /// Request a bootstrap challenge for first-time ownership claim.
    pub async fn bootstrap_challenge(&self) -> Result<ChallengeResponse, TeeError> {
        let resp = self
            .http
            .post(self.url("/bootstrap/challenge"))
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Claim ownership of the app (first-time setup, password mode).
    pub async fn bootstrap_claim(
        &self,
        challenge_nonce: &str,
        bootstrap_pubkey: &str,
        signature: &str,
        password: &str,
    ) -> Result<ClaimResponse, TeeError> {
        let body = serde_json::json!({
            "challenge": challenge_nonce,
            "bootstrap_pubkey": bootstrap_pubkey,
            "signature": signature,
            "password": password,
        });
        let resp = self
            .http
            .post(self.url("/bootstrap/claim"))
            .json(&body)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Unlock storage with password (subsequent restarts, password mode).
    pub async fn unlock(&self, password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({ "password": password });
        let resp = self
            .http
            .post(self.url("/unlock"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Recover with BIP39 mnemonic and set a new password.
    pub async fn recover(&self, mnemonic: &str, new_password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({
            "mnemonic": mnemonic,
            "new_password": new_password,
        });
        let resp = self
            .http
            .post(self.url("/recover"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Change the unlock password.
    pub async fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), TeeError> {
        let body = serde_json::json!({
            "current_password": current_password,
            "new_password": new_password,
        });
        let resp = self
            .http
            .post(self.url("/change-password"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Enable auto-unlock (seal owner seed with VMPCK).
    pub async fn enable_auto_unlock(&self, password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({ "password": password });
        let resp = self
            .http
            .post(self.url("/enable-auto-unlock"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Disable auto-unlock (remove sealed seed).
    pub async fn disable_auto_unlock(&self, password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({ "password": password });
        let resp = self
            .http
            .post(self.url("/disable-auto-unlock"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{TeeClient, accepts_invalid_tee_certs};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn normalizes_plain_domain_to_confidential_base() {
        let tee = TeeClient::new("app.enclava.dev");
        assert_eq!(
            tee.url("/status"),
            "https://app.enclava.dev/.well-known/confidential/status"
        );
    }

    #[test]
    fn accepts_api_returned_confidential_base() {
        let tee = TeeClient::new("https://app.enclava.dev/.well-known/confidential");
        assert_eq!(
            tee.url("/bootstrap/challenge"),
            "https://app.enclava.dev/.well-known/confidential/bootstrap/challenge"
        );
    }

    #[test]
    fn challenge_response_accepts_live_proxy_shape() {
        let parsed: super::ChallengeResponse = serde_json::from_value(serde_json::json!({
            "challenge": "abc",
            "nonce": "abc",
            "expires_in_seconds": 300.0
        }))
        .expect("parse challenge");
        assert_eq!(parsed.nonce, "abc");
        assert_eq!(parsed.ttl_seconds, 300);
    }

    #[test]
    fn staging_tls_mode_accepts_invalid_tee_certs() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            std::env::remove_var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS");
        }
        assert!(accepts_invalid_tee_certs());
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
        }
    }

    #[test]
    fn default_tls_mode_requires_valid_tee_certs() {
        let _guard = env_lock();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
            std::env::remove_var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS");
        }
        assert!(!accepts_invalid_tee_certs());
    }
}
