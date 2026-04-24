//! Unlock metadata routes.
//!
//! The actual unlock happens CLI -> TEE direct. These routes provide metadata.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::models::{App, UnlockMode};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct UnlockStatusResponse {
    pub unlock_mode: String,
    pub tee_url: String,
    pub ownership_state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUnlockModeRequest {
    pub mode: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateUnlockModeResponse {
    pub app_name: String,
    pub unlock_mode: String,
    pub deployment_id: Option<Uuid>,
    pub status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedUnlockMode {
    Auto,
    Password,
}

impl RequestedUnlockMode {
    fn parse(mode: &str) -> Result<Self, String> {
        match mode {
            "auto" | "auto-unlock" => Ok(Self::Auto),
            "password" => Ok(Self::Password),
            _ => Err(format!(
                "invalid unlock mode '{mode}': expected 'password' or 'auto-unlock'"
            )),
        }
    }

    fn db_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Password => "password",
        }
    }

    fn api_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Password => "password",
        }
    }
}

fn current_mode(app: &App) -> RequestedUnlockMode {
    match app.unlock_mode {
        UnlockMode::Auto => RequestedUnlockMode::Auto,
        UnlockMode::Password => RequestedUnlockMode::Password,
    }
}

fn validate_transition(current: RequestedUnlockMode, requested: RequestedUnlockMode) -> bool {
    current == requested
        || matches!(
            (current, requested),
            (RequestedUnlockMode::Password, RequestedUnlockMode::Auto)
                | (RequestedUnlockMode::Auto, RequestedUnlockMode::Password)
        )
}

/// GET /apps/{name}/unlock/status -- ownership state (queried from TEE).
pub async fn unlock_status(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<UnlockStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
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
    let tee_url = format!("https://{}/.well-known/confidential", domain);

    let status_url = format!("https://{}/.well-known/confidential/status", domain);
    let ownership_state = match state.tee_http_client.get(&status_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            resp.json::<serde_json::Value>().await.ok().and_then(|v| {
                v.get("ownership_state")
                    .or_else(|| v.get("state"))
                    .and_then(|s| s.as_str())
                    .map(String::from)
            })
        }
        _ => None,
    };

    Ok(Json(UnlockStatusResponse {
        unlock_mode: format!("{:?}", app.unlock_mode).to_lowercase(),
        tee_url,
        ownership_state,
    }))
}

#[derive(Debug, Serialize)]
pub struct UnlockEndpointResponse {
    pub tee_url: String,
    pub unlock_endpoint: String,
    pub claim_endpoint: String,
}

/// GET /apps/{name}/unlock/endpoint -- returns TEE URLs for direct unlock/claim.
pub async fn unlock_endpoint(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<UnlockEndpointResponse>, (StatusCode, Json<serde_json::Value>)> {
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
    let base = format!("https://{}/.well-known/confidential", domain);

    Ok(Json(UnlockEndpointResponse {
        tee_url: base.clone(),
        unlock_endpoint: format!("{}/unlock", base),
        claim_endpoint: format!("{}/bootstrap/claim", base),
    }))
}

/// PUT /apps/{name}/unlock/mode -- update CAP-owned unlock mode and re-apply manifests.
///
/// The owner password must never pass through this route. The CLI calls the
/// tenant TEE endpoint first to create/remove the sealed seed, then calls this
/// route with only the desired CAP deployment mode.
pub async fn update_unlock_mode(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<UpdateUnlockModeRequest>,
) -> Result<Json<UpdateUnlockModeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let requested = RequestedUnlockMode::parse(&body.mode).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
    })?;

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

    let current = current_mode(&app);
    if !validate_transition(current, requested) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "invalid unlock mode transition"})),
        ));
    }

    if current == requested {
        return Ok(Json(UpdateUnlockModeResponse {
            app_name: app.name,
            unlock_mode: requested.api_value().to_string(),
            deployment_id: None,
            status: "unchanged".to_string(),
        }));
    }

    sqlx::query("UPDATE apps SET unlock_mode = $1::unlock_enum, updated_at = now() WHERE id = $2")
        .bind(requested.db_value())
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    let updated_app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    let image_digest: Option<String> = sqlx::query_scalar(
        "SELECT image_digest FROM app_containers WHERE app_id = $1 AND is_primary = true LIMIT 1",
    )
    .bind(app.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?
    .flatten();

    let deploy_id = Uuid::new_v4();
    let spec_snapshot = serde_json::json!({
        "app_name": updated_app.name,
        "namespace": updated_app.namespace,
        "instance_id": updated_app.instance_id,
        "unlock_mode": requested.api_value(),
        "transition": {
            "from": current.api_value(),
            "to": requested.api_value(),
        }
    });

    sqlx::query(
        "INSERT INTO deployments (id, app_id, trigger, spec_snapshot, image_digest)
         VALUES ($1, $2, 'api', $3, $4)",
    )
    .bind(deploy_id)
    .bind(app.id)
    .bind(&spec_snapshot)
    .bind(&image_digest)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail)
         VALUES ($1, $2, $3, 'app.unlock_mode.update', $4)",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "from": current.api_value(),
        "to": requested.api_value(),
        "deployment_id": deploy_id,
    }))
    .execute(&state.db)
    .await;

    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let db = state.db.clone();
    let attestation = state.attestation.clone();
    let kbs_policy = state.kbs_policy.clone();
    let api_url = state.api_url.clone();
    let apply_app = updated_app.clone();
    let apply_permits = state.deployment_apply_permits.clone();
    tokio::spawn(async move {
        let _apply_permit = match apply_permits.acquire_owned().await {
            Ok(permit) => permit,
            Err(e) => {
                let error_message = format!("deployment apply limiter closed: {}", e);
                let _ = crate::deploy::set_deployment_status(
                    &db,
                    deploy_id,
                    "failed",
                    None,
                    Some(&error_message),
                    true,
                )
                .await;
                let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
                tracing::error!(
                    app_id = %apply_app.id,
                    deployment_id = %deploy_id,
                    error = %error_message,
                    "failed to acquire unlock-mode apply permit"
                );
                return;
            }
        };

        if let Err(e) = crate::deploy::apply_deployment_manifests(
            db.clone(),
            apply_app.clone(),
            deploy_id,
            attestation,
            kbs_policy,
            api_signing_pubkey,
            api_url,
        )
        .await
        {
            let error_message = e.to_string();
            let _ = crate::deploy::set_deployment_status(
                &db,
                deploy_id,
                "failed",
                None,
                Some(&error_message),
                true,
            )
            .await;
            let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
            tracing::error!(
                app_id = %apply_app.id,
                deployment_id = %deploy_id,
                error = %error_message,
                "failed to apply unlock-mode manifests"
            );
        }
    });

    Ok(Json(UpdateUnlockModeResponse {
        app_name: updated_app.name,
        unlock_mode: requested.api_value().to_string(),
        deployment_id: Some(deploy_id),
        status: "deploying".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{RequestedUnlockMode, validate_transition};

    #[test]
    fn parses_public_unlock_mode_names() {
        assert_eq!(
            RequestedUnlockMode::parse("auto-unlock").unwrap(),
            RequestedUnlockMode::Auto
        );
        assert_eq!(
            RequestedUnlockMode::parse("auto").unwrap(),
            RequestedUnlockMode::Auto
        );
        assert_eq!(
            RequestedUnlockMode::parse("password").unwrap(),
            RequestedUnlockMode::Password
        );
        assert!(RequestedUnlockMode::parse("manual").is_err());
    }

    #[test]
    fn permits_only_supported_unlock_mode_transitions() {
        assert!(validate_transition(
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Auto
        ));
        assert!(validate_transition(
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password
        ));
        assert!(validate_transition(
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Auto
        ));
        assert!(validate_transition(
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Password
        ));
    }
}
