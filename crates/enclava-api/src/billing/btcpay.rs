//! BTCPay Server client for Bitcoin invoice management.

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum BtcPayError {
    #[error("BTCPay API error: {0}")]
    Api(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvoiceRequest {
    pub amount: String,
    pub currency: String,
    pub metadata: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout: Option<CheckoutOptions>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckoutOptions {
    pub redirect_url: Option<String>,
    pub default_payment_method: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceResponse {
    pub id: String,
    pub status: String,
    pub checkout_link: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookPayload {
    pub invoice_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub metadata: Option<serde_json::Value>,
}

/// BTCPay Server API client.
pub struct BtcPayClient {
    client: Client,
    base_url: String,
    api_key: String,
    store_id: String,
}

impl BtcPayClient {
    pub fn new(base_url: &str, api_key: &str, store_id: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            store_id: store_id.to_string(),
        }
    }

    /// Create a new invoice for a subscription payment.
    pub async fn create_invoice(
        &self,
        amount_sats: u64,
        org_id: &str,
        tier: &str,
        description: &str,
    ) -> Result<InvoiceResponse, BtcPayError> {
        let url = format!("{}/api/v1/stores/{}/invoices", self.base_url, self.store_id);

        let body = CreateInvoiceRequest {
            amount: amount_sats.to_string(),
            currency: "SATS".to_string(),
            metadata: serde_json::json!({
                "org_id": org_id,
                "tier": tier,
                "description": description,
            }),
            checkout: Some(CheckoutOptions {
                redirect_url: None,
                default_payment_method: Some("BTC-LightningNetwork".to_string()),
            }),
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("token {}", self.api_key))
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(BtcPayError::Api(format!("status {}: {}", status, text)));
        }

        let invoice: InvoiceResponse = response.json().await?;
        Ok(invoice)
    }

    /// Get an existing invoice by ID.
    pub async fn get_invoice(&self, invoice_id: &str) -> Result<InvoiceResponse, BtcPayError> {
        let url = format!(
            "{}/api/v1/stores/{}/invoices/{}",
            self.base_url, self.store_id, invoice_id
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("token {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(BtcPayError::Api(format!("status {}: {}", status, text)));
        }

        let invoice: InvoiceResponse = response.json().await?;
        Ok(invoice)
    }
}
