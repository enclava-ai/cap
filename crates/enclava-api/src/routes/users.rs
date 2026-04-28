use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterPublicKeyRequest {
    pub public_key: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterPublicKeyResponse {
    pub id: Uuid,
    pub public_key: String,
}

pub async fn register_public_key(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<RegisterPublicKeyRequest>,
) -> Result<(StatusCode, Json<RegisterPublicKeyResponse>), (StatusCode, Json<serde_json::Value>)> {
    let pubkey = decode_hex32(&body.public_key)?;
    let id = Uuid::new_v4();
    let row: (Uuid, Vec<u8>) = sqlx::query_as(
        "INSERT INTO user_signing_keys (id, user_id, pubkey)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, pubkey) WHERE revoked_at IS NULL
         DO UPDATE SET pubkey = EXCLUDED.pubkey
         RETURNING id, pubkey",
    )
    .bind(id)
    .bind(auth.user_id)
    .bind(pubkey.to_vec())
    .fetch_one(&state.db)
    .await
    .map_err(|_| db_error())?;

    let _ = sqlx::query(
        "INSERT INTO audit_log (user_id, action, detail)
         VALUES ($1, 'user.public_key.register', $2)",
    )
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "key_id": row.0,
        "label": body.label,
        "public_key": hex::encode(&row.1),
    }))
    .execute(&state.db)
    .await;

    Ok((
        StatusCode::OK,
        Json(RegisterPublicKeyResponse {
            id: row.0,
            public_key: hex::encode(row.1),
        }),
    ))
}

fn decode_hex32(value: &str) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    let bytes = hex::decode(value.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "public_key must be lowercase hex"})),
        )
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "public_key must decode to 32 bytes",
                "got": bytes.len()
            })),
        )
    })
}

fn db_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "database error"})),
    )
}
