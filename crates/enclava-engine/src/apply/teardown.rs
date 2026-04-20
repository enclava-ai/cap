use std::time::Duration;

use super::engine::ApplyError;

/// Build the teardown URL for the attestation proxy.
pub fn build_teardown_url(domain: &str) -> String {
    let domain = domain.trim_end_matches('/');
    format!("https://{domain}/.well-known/confidential/teardown")
}

/// Notify the attestation proxy to self-cleanup before teardown.
///
/// Sends POST to `/.well-known/confidential/teardown` on the app's domain.
/// The proxy uses its workload-authenticated credentials to DELETE its own
/// owner ciphertext from KBS.
///
/// This is a best-effort operation: if the proxy is unreachable (pod already
/// crashed, network issue), we log a warning and continue with cleanup.
/// Orphaned ciphertext is inert -- the policy binding is removed in a later step.
///
/// `api_token` is an API-issued JWT that authenticates the teardown request.
pub async fn notify_teardown_proxy(
    domain: &str,
    api_token: &str,
    timeout_duration: Duration,
) -> Result<(), ApplyError> {
    let url = build_teardown_url(domain);

    let client = reqwest::Client::builder()
        .timeout(timeout_duration)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| ApplyError::TeardownProxyFailed(e.to_string()))?;

    tracing::info!(url = %url, "sending teardown notification to attestation proxy");

    match client.post(&url).bearer_auth(api_token).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                tracing::info!(
                    url = %url,
                    status = %resp.status(),
                    "teardown proxy notification succeeded"
                );
                Ok(())
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    url = %url,
                    status = %status,
                    body = %body,
                    "teardown proxy returned non-success status -- continuing cleanup"
                );
                // Non-success is not fatal -- continue with cleanup
                Ok(())
            }
        }
        Err(e) => {
            if e.is_timeout() {
                tracing::warn!(
                    url = %url,
                    "teardown proxy timed out after {:?} -- continuing cleanup",
                    timeout_duration
                );
            } else if e.is_connect() {
                tracing::warn!(
                    url = %url,
                    "teardown proxy unreachable (connection failed) -- continuing cleanup"
                );
            } else {
                tracing::warn!(
                    url = %url,
                    error = %e,
                    "teardown proxy notification failed -- continuing cleanup"
                );
            }
            // All errors are non-fatal for teardown
            Ok(())
        }
    }
}
