use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::models::App;
use crate::state::AppState;

/// Helper function for consistent internal server error responses
fn internal_server_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "internal server error"})),
    )
}

fn dns_error_response(error: crate::dns::DnsError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &error {
        crate::dns::DnsError::OutsideManagedZone(_) => StatusCode::BAD_REQUEST,
        crate::dns::DnsError::NotConfigured => StatusCode::INTERNAL_SERVER_ERROR,
        crate::dns::DnsError::Cloudflare(_)
        | crate::dns::DnsError::Http(_)
        | crate::dns::DnsError::Db(_) => StatusCode::BAD_GATEWAY,
    };

    (
        status,
        Json(serde_json::json!({"error": error.to_string()})),
    )
}

async fn delete_tenant_namespace(namespace: &str) -> Result<(), kube::Error> {
    let client = kube::Client::try_default().await?;
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);
    match api
        .delete(namespace, &kube::api::DeleteParams::default())
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
        Err(e) => Err(e),
    }
}

/// Comprehensive app name validation
fn validate_app_name(name: &str) -> Result<(), String> {
    // Length limits
    if name.len() < 1 || name.len() > 63 {
        return Err("app name must be between 1 and 63 characters".to_string());
    }

    // Reserved names (Kubernetes system names)
    let reserved = [
        "kubernetes",
        "kube",
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "default",
        "kube-service-account",
        "kube-root-ca",
        "config",
        "health",
        "status",
        "metrics",
        "prometheus",
        "grafana",
    ];
    if reserved.contains(&name) {
        return Err(format!("'{}' is a reserved name", name));
    }

    // Character validation (Kubernetes DNS-1123 subdomain)
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(
            "app name must contain only lowercase letters, digits, and hyphens".to_string(),
        );
    }

    // Must start and end with alphanumeric
    if !name.chars().next().unwrap().is_ascii_alphanumeric()
        || !name.chars().last().unwrap().is_ascii_alphanumeric()
    {
        return Err("app name must start and end with a letter or digit".to_string());
    }

    // No consecutive hyphens
    if name.contains("--") {
        return Err("app name cannot contain consecutive hyphens".to_string());
    }

    // No leading/trailing hyphens (already covered by alphanumeric check)
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    #[serde(default = "default_unlock_mode")]
    pub unlock_mode: String,
    /// For password-mode: hex SHA256 of the user's bootstrap claim public key.
    /// Required when unlock_mode is "password".
    #[serde(default)]
    pub bootstrap_pubkey_hash: Option<String>,
}

fn default_unlock_mode() -> String {
    "auto".to_string()
}

#[derive(Debug, Serialize)]
pub struct AppResponse {
    pub id: Uuid,
    pub name: String,
    pub namespace: String,
    pub instance_id: String,
    pub domain: String,
    pub custom_domain: Option<String>,
    pub unlock_mode: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<App> for AppResponse {
    fn from(a: App) -> Self {
        Self {
            id: a.id,
            name: a.name,
            namespace: a.namespace,
            instance_id: a.instance_id,
            domain: a.domain,
            custom_domain: a.custom_domain,
            unlock_mode: format!("{:?}", a.unlock_mode).to_lowercase(),
            status: format!("{:?}", a.status).to_lowercase(),
            created_at: a.created_at,
        }
    }
}

/// Derive identity fields per OID-1 and OID-6.
fn derive_identity(
    org_name: &str,
    app_id: Uuid,
    app_name: &str,
    unlock_mode: &str,
    user_pubkey_hash: Option<&str>,
) -> Result<(String, String, String, String, String, String), String> {
    let tenant_id = org_name.to_string();
    let app_id_short = &app_id.to_string()[..8];
    let instance_id = format!("{}-{}", tenant_id, app_id_short);
    let namespace = format!("cap-{}-{}", org_name, app_name);
    let service_account = format!("cap-{}-sa", app_name);

    let bootstrap_owner_pubkey_hash = match unlock_mode {
        "password" => {
            let hash =
                user_pubkey_hash.ok_or("bootstrap_pubkey_hash required for password mode")?;
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("bootstrap_pubkey_hash must be 64 hex characters".to_string());
            }
            hash.to_lowercase()
        }
        "auto" => {
            // Platform generates Ed25519 keypair for auto-unlock apps
            let keypair = SigningKey::generate(&mut OsRng);
            let pubkey_bytes = keypair.verifying_key().to_bytes();
            let hash = Sha256::digest(pubkey_bytes);
            hex::encode(hash)
        }
        _ => return Err(format!("invalid unlock_mode: {}", unlock_mode)),
    };

    let identity_hash = enclava_common::crypto::compute_identity_hash(
        &tenant_id,
        &instance_id,
        &bootstrap_owner_pubkey_hash,
    );

    Ok((
        tenant_id,
        instance_id,
        namespace,
        service_account,
        bootstrap_owner_pubkey_hash,
        identity_hash,
    ))
}

/// POST /apps -- create a new app.
pub async fn create_app(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<AppResponse>), (StatusCode, Json<serde_json::Value>)> {
    // Validate name with comprehensive checks
    validate_app_name(&body.name).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
    })?;

    // Enforce tier app limit (API-18)
    let org: crate::models::Organization =
        sqlx::query_as("SELECT * FROM organizations WHERE id = $1")
            .bind(auth.org_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| internal_server_error())?;

    let tier_str = format!("{:?}", org.tier).to_lowercase();
    let limits = crate::routes::billing::tier_limits(&tier_str).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "unknown tier"})),
    ))?;

    let app_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apps WHERE org_id = $1")
        .bind(auth.org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    if app_count >= limits.max_apps as i64 {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!("tier '{}' allows max {} apps, you have {}", tier_str, limits.max_apps, app_count)
            })),
        ));
    }

    let app_id = Uuid::new_v4();
    let (tenant_id, instance_id, namespace, service_account, pubkey_hash, identity_hash) =
        derive_identity(
            &auth.org_name,
            app_id,
            &body.name,
            &body.unlock_mode,
            body.bootstrap_pubkey_hash.as_deref(),
        )
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
        })?;

    let domain = format!("{}.{}", body.name, state.platform_domain);

    let result = sqlx::query(
        "INSERT INTO apps (id, org_id, name, namespace, instance_id, tenant_id,
         service_account, bootstrap_owner_pubkey_hash, tenant_instance_identity_hash,
         unlock_mode, domain)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum, $11)",
    )
    .bind(app_id)
    .bind(auth.org_id)
    .bind(&body.name)
    .bind(&namespace)
    .bind(&instance_id)
    .bind(&tenant_id)
    .bind(&service_account)
    .bind(&pubkey_hash)
    .bind(&identity_hash)
    .bind(&body.unlock_mode)
    .bind(&domain)
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "app name already taken in this org"})),
            ));
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("database error: {}", e)})),
        ));
    }

    // Insert default resources
    sqlx::query("INSERT INTO app_resources (app_id) VALUES ($1)")
        .bind(app_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    if let Err(e) = crate::dns::ensure_dns_record(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app_id,
        &domain,
        false,
    )
    .await
    {
        let _ = sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(app_id)
            .execute(&state.db)
            .await;
        return Err(dns_error_response(e));
    }

    // Audit
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail) VALUES ($1, $2, $3, 'app.create', $4)",
    )
    .bind(auth.org_id)
    .bind(app_id)
    .bind(auth.user_id)
    .bind(serde_json::json!({"name": &body.name, "unlock_mode": &body.unlock_mode}))
    .execute(&state.db)
    .await;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    Ok((StatusCode::CREATED, Json(app.into())))
}

/// GET /apps -- list apps in the current org.
pub async fn list_apps(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<AppResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let apps: Vec<App> = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 ORDER BY name")
        .bind(auth.org_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    Ok(Json(apps.into_iter().map(Into::into).collect()))
}

/// GET /apps/{name} -- app details.
pub async fn get_app(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<AppResponse>, (StatusCode, Json<serde_json::Value>)> {
    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    Ok(Json(app.into()))
}

/// DELETE /apps/{name} -- ordered teardown.
pub async fn delete_app(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    // Mark as deleting
    sqlx::query("UPDATE apps SET status = 'deleting', updated_at = now() WHERE id = $1")
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    crate::dns::delete_all_dns_records_for_app(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app.id,
    )
    .await
    .map_err(dns_error_response)?;

    delete_tenant_namespace(&app.namespace).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("failed to delete tenant namespace: {}", e)})),
        )
    })?;

    crate::kbs::soft_delete_owner_binding(&state.db, app.id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("failed to remove KBS owner binding: {}", e)})),
            )
        })?;
    crate::kbs::reconcile_policy(&state.db, state.kbs_policy.as_ref())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(
                    serde_json::json!({"error": format!("failed to reconcile KBS policy: {}", e)}),
                ),
            )
        })?;

    sqlx::query("DELETE FROM apps WHERE id = $1")
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    // Audit
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action) VALUES ($1, $2, $3, 'app.delete')",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await;

    Ok(StatusCode::NO_CONTENT)
}
