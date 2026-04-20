//! Status and logs proxied from K8s / TEE.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;

use crate::auth::middleware::AuthContext;
use crate::models::App;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct AppStatusResponse {
    pub app_name: String,
    pub status: String,
    pub domain: String,
    pub unlock_mode: String,
    pub pod_status: Option<String>,
    pub tee_status: Option<String>,
    pub storage_status: Option<String>,
}

/// GET /apps/{name}/status -- live status (pod, TEE, unlock).
pub async fn app_status(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<AppStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
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

    let domain = app.custom_domain.as_deref().unwrap_or(&app.domain);
    let tee_status_url = format!("https://{}/.well-known/confidential/status", domain);

    let (pod_status, tee_status, storage_status) =
        match state.http_client.get(&tee_status_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    (
                        body.get("pod_status")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        body.get("tee_status")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        body.get("storage_status")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    )
                } else {
                    (None, None, None)
                }
            }
            _ => (None, None, None),
        };

    Ok(Json(AppStatusResponse {
        app_name: app.name,
        status: format!("{:?}", app.status).to_lowercase(),
        domain: domain.to_string(),
        unlock_mode: format!("{:?}", app.unlock_mode).to_lowercase(),
        pod_status,
        tee_status,
        storage_status,
    }))
}

#[derive(Debug, Serialize)]
pub struct LogLine {
    pub timestamp: String,
    pub container: String,
    pub message: String,
}

/// GET /apps/{name}/logs -- proxied container logs.
pub async fn app_logs(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<Vec<LogLine>>, (StatusCode, Json<serde_json::Value>)> {
    let _app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
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

    // TODO: proxy via kube-rs pod log API (Plan 3 integration)
    Ok(Json(vec![]))
}
