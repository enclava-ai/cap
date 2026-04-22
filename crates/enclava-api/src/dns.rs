use reqwest::StatusCode;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub cloudflare_api_token: String,
    pub cloudflare_zone_id: Option<String>,
    pub cloudflare_zone_name: String,
    pub target: String,
    pub required: bool,
}

impl DnsConfig {
    pub fn record_type(&self) -> &'static str {
        if self.target.contains(':') {
            "AAAA"
        } else {
            "A"
        }
    }

    pub fn manages_hostname(&self, hostname: &str) -> bool {
        let zone = self
            .cloudflare_zone_name
            .trim_start_matches('.')
            .to_lowercase();
        let hostname = hostname.trim_end_matches('.').to_lowercase();
        hostname == zone || hostname.ends_with(&format!(".{zone}"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS management is required but not configured")]
    NotConfigured,
    #[error("hostname '{0}' is outside managed Cloudflare zone")]
    OutsideManagedZone(String),
    #[error("Cloudflare API error: {0}")]
    Cloudflare(String),
    #[error("Cloudflare request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, Deserialize)]
struct CloudflareList<T> {
    success: bool,
    result: Vec<T>,
    errors: Vec<CloudflareApiError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareSingle<T> {
    success: bool,
    result: Option<T>,
    errors: Vec<CloudflareApiError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareApiError {
    code: Option<i64>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareRecord {
    id: String,
}

fn cloudflare_error(errors: &[CloudflareApiError]) -> String {
    if errors.is_empty() {
        return "unknown error".to_string();
    }

    errors
        .iter()
        .map(|e| match e.code {
            Some(code) => format!("{code}: {}", e.message),
            None => e.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn resolve_zone_id(client: &reqwest::Client, config: &DnsConfig) -> Result<String, DnsError> {
    if let Some(zone_id) = config.cloudflare_zone_id.as_ref() {
        return Ok(zone_id.clone());
    }

    let response = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            config.cloudflare_zone_name
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(DnsError::Cloudflare(format!(
            "zone lookup returned HTTP {}",
            response.status()
        )));
    }

    let body: CloudflareList<CloudflareZone> = response.json().await?;
    if !body.success {
        return Err(DnsError::Cloudflare(cloudflare_error(&body.errors)));
    }

    body.result
        .into_iter()
        .next()
        .map(|zone| zone.id)
        .ok_or_else(|| {
            DnsError::Cloudflare(format!(
                "zone '{}' was not found",
                config.cloudflare_zone_name
            ))
        })
}

async fn find_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    hostname: &str,
) -> Result<Option<CloudflareRecord>, DnsError> {
    let record_type = config.record_type();
    let response = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={record_type}&name={hostname}&per_page=100"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(DnsError::Cloudflare(format!(
            "record lookup for '{hostname}' returned HTTP {}",
            response.status()
        )));
    }

    let body: CloudflareList<CloudflareRecord> = response.json().await?;
    if !body.success {
        return Err(DnsError::Cloudflare(cloudflare_error(&body.errors)));
    }

    Ok(body.result.into_iter().next())
}

async fn create_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    hostname: &str,
) -> Result<CloudflareRecord, DnsError> {
    let response = client
        .post(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .json(&serde_json::json!({
            "type": config.record_type(),
            "name": hostname,
            "content": config.target,
            "ttl": 300,
            "proxied": false,
        }))
        .send()
        .await?;

    let status = response.status();
    let body: CloudflareSingle<CloudflareRecord> = response.json().await?;
    if !status.is_success() || !body.success {
        return Err(DnsError::Cloudflare(format!(
            "create record for '{hostname}' failed: {}",
            cloudflare_error(&body.errors)
        )));
    }

    body.result
        .ok_or_else(|| DnsError::Cloudflare("create record response had no result".to_string()))
}

async fn update_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    record_id: &str,
    hostname: &str,
) -> Result<CloudflareRecord, DnsError> {
    let response = client
        .put(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .json(&serde_json::json!({
            "type": config.record_type(),
            "name": hostname,
            "content": config.target,
            "ttl": 300,
            "proxied": false,
        }))
        .send()
        .await?;

    let status = response.status();
    let body: CloudflareSingle<CloudflareRecord> = response.json().await?;
    if !status.is_success() || !body.success {
        return Err(DnsError::Cloudflare(format!(
            "update record for '{hostname}' failed: {}",
            cloudflare_error(&body.errors)
        )));
    }

    body.result
        .ok_or_else(|| DnsError::Cloudflare("update record response had no result".to_string()))
}

pub async fn ensure_dns_record(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&DnsConfig>,
    app_id: Uuid,
    hostname: &str,
    is_custom: bool,
) -> Result<(), DnsError> {
    let Some(config) = config else {
        return Ok(());
    };

    if !config.manages_hostname(hostname) {
        return Err(DnsError::OutsideManagedZone(hostname.to_string()));
    }

    let zone_id = resolve_zone_id(client, config).await?;
    let existing = find_record(client, config, &zone_id, hostname).await?;
    let record = match existing {
        Some(record) => update_record(client, config, &zone_id, &record.id, hostname).await?,
        None => create_record(client, config, &zone_id, hostname).await?,
    };

    sqlx::query(
        "INSERT INTO dns_records (id, app_id, hostname, zone_id, record_id, record_type, target, is_custom)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (hostname) DO UPDATE SET
             app_id = EXCLUDED.app_id,
             zone_id = EXCLUDED.zone_id,
             record_id = EXCLUDED.record_id,
             record_type = EXCLUDED.record_type,
             target = EXCLUDED.target,
             is_custom = EXCLUDED.is_custom,
             updated_at = now()",
    )
    .bind(Uuid::new_v4())
    .bind(app_id)
    .bind(hostname)
    .bind(&zone_id)
    .bind(&record.id)
    .bind(config.record_type())
    .bind(&config.target)
    .bind(is_custom)
    .execute(pool)
    .await?;

    tracing::info!(
        app_id = %app_id,
        hostname = %hostname,
        target = %config.target,
        record_id = %record.id,
        "DNS record ensured"
    );

    Ok(())
}

pub async fn delete_dns_record(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&DnsConfig>,
    app_id: Uuid,
    hostname: &str,
) -> Result<(), DnsError> {
    let Some(config) = config else {
        return Ok(());
    };

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT zone_id, record_id FROM dns_records WHERE app_id = $1 AND hostname = $2",
    )
    .bind(app_id)
    .bind(hostname)
    .fetch_optional(pool)
    .await?;

    let Some((zone_id, record_id)) = row else {
        return Ok(());
    };

    let response = client
        .delete(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .send()
        .await?;

    if response.status() != StatusCode::NOT_FOUND {
        let status = response.status();
        let body: CloudflareSingle<serde_json::Value> = response.json().await?;
        if !status.is_success() || !body.success {
            return Err(DnsError::Cloudflare(format!(
                "delete record for '{hostname}' failed: {}",
                cloudflare_error(&body.errors)
            )));
        }
    }

    sqlx::query("DELETE FROM dns_records WHERE app_id = $1 AND hostname = $2")
        .bind(app_id)
        .bind(hostname)
        .execute(pool)
        .await?;

    tracing::info!(
        app_id = %app_id,
        hostname = %hostname,
        record_id = %record_id,
        "DNS record deleted"
    );

    Ok(())
}

pub async fn delete_all_dns_records_for_app(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&DnsConfig>,
    app_id: Uuid,
) -> Result<(), DnsError> {
    let hostnames: Vec<String> =
        sqlx::query_scalar("SELECT hostname FROM dns_records WHERE app_id = $1 ORDER BY hostname")
            .bind(app_id)
            .fetch_all(pool)
            .await?;

    for hostname in hostnames {
        delete_dns_record(pool, client, config, app_id, &hostname).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DnsConfig;

    fn config() -> DnsConfig {
        DnsConfig {
            cloudflare_api_token: "token".to_string(),
            cloudflare_zone_id: None,
            cloudflare_zone_name: "enclava.dev".to_string(),
            target: "95.217.56.248".to_string(),
            required: true,
        }
    }

    #[test]
    fn record_type_uses_a_for_ipv4() {
        assert_eq!(config().record_type(), "A");
    }

    #[test]
    fn record_type_uses_aaaa_for_ipv6() {
        let mut config = config();
        config.target = "2001:db8::1".to_string();
        assert_eq!(config.record_type(), "AAAA");
    }

    #[test]
    fn manages_only_configured_zone() {
        let config = config();
        assert!(config.manages_hostname("app.enclava.dev"));
        assert!(config.manages_hostname("enclava.dev"));
        assert!(!config.manages_hostname("app.example.com"));
    }
}
