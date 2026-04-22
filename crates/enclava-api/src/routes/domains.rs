use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthContext;
use crate::models::App;
use crate::state::AppState;

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

#[derive(Debug, Deserialize)]
pub struct SetDomainRequest {
    pub domain: String,
}

#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub platform_domain: String,
    pub custom_domain: Option<String>,
    pub dns_instructions: Option<String>,
}

/// PUT /apps/{name}/domain -- set custom domain.
pub async fn set_domain(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<SetDomainRequest>,
) -> Result<Json<DomainResponse>, (StatusCode, Json<serde_json::Value>)> {
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

    if body.domain.is_empty() || !body.domain.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid domain"})),
        ));
    }

    crate::dns::ensure_dns_record(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app.id,
        &body.domain,
        true,
    )
    .await
    .map_err(dns_error_response)?;

    sqlx::query("UPDATE apps SET custom_domain = $1, updated_at = now() WHERE id = $2")
        .bind(&body.domain)
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    if let Some(previous) = app.custom_domain.as_ref().filter(|d| *d != &body.domain) {
        crate::dns::delete_dns_record(
            &state.db,
            &state.http_client,
            state.dns.as_ref(),
            app.id,
            previous,
        )
        .await
        .map_err(dns_error_response)?;
    }

    Ok(Json(DomainResponse {
        platform_domain: app.domain,
        custom_domain: Some(body.domain),
        dns_instructions: Some(
            "DNS is managed by CAP; tenant TLS remains workload-owned".to_string(),
        ),
    }))
}

/// GET /apps/{name}/domain -- domain + DNS instructions.
pub async fn get_domain(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<DomainResponse>, (StatusCode, Json<serde_json::Value>)> {
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

    let dns_instructions = app
        .custom_domain
        .as_ref()
        .map(|_| "DNS is managed by CAP; tenant TLS remains workload-owned".to_string());

    Ok(Json(DomainResponse {
        platform_domain: app.domain,
        custom_domain: app.custom_domain,
        dns_instructions,
    }))
}

/// DELETE /apps/{name}/domain -- remove custom domain.
pub async fn remove_domain(
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

    if let Some(custom_domain) = app.custom_domain.as_ref() {
        crate::dns::delete_dns_record(
            &state.db,
            &state.http_client,
            state.dns.as_ref(),
            app.id,
            custom_domain,
        )
        .await
        .map_err(dns_error_response)?;
    }

    sqlx::query("UPDATE apps SET custom_domain = NULL, updated_at = now() WHERE id = $1")
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}
