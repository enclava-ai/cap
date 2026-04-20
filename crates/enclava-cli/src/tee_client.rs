use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};

/// Direct HTTPS client for the attestation proxy running inside a TEE.
/// All requests go to https://{app-domain}/.well-known/confidential/...
pub struct TeeClient {
    base_url: String,
    http: reqwest::Client,
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

impl TeeClient {
    /// Create a TEE client for the given app domain.
    /// The domain is the HTTPS endpoint of the app (e.g., "myapp.enclava.dev").
    pub fn new(app_domain: &str) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(false) // Require valid certificates
            .https_only(true) // Enforce HTTPS
            .build()
            .expect("failed to build HTTP client");

        let base_url = if app_domain.starts_with("https://") || app_domain.starts_with("http://") {
            app_domain.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", app_domain.trim_end_matches('/'))
        };

        Self { base_url, http }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/.well-known/confidential{}", self.base_url, path)
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
