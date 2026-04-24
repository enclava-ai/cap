use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use std::{
    env,
    io::Write,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct WriterState {
    repository_root: Arc<PathBuf>,
    token: Option<Arc<String>>,
}

#[derive(Debug, Serialize)]
struct ResourceResponse {
    repository: String,
    resource: String,
    tag: String,
    status: &'static str,
}

#[derive(Debug)]
enum WriterError {
    Unauthorized,
    InvalidPath(String),
    Io(std::io::Error),
}

impl IntoResponse for WriterError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response(),
            Self::InvalidPath(message) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": message})),
            )
                .into_response(),
            Self::Io(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": err.to_string()})),
            )
                .into_response(),
        }
    }
}

impl From<std::io::Error> for WriterError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kbs_resource_writer=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let bind_addr =
        env::var("KBS_RESOURCE_WRITER_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let repository_root =
        PathBuf::from(env::var("KBS_REPOSITORY_ROOT").unwrap_or_else(|_| "/repository".into()));
    let token = env::var("KBS_RESOURCE_WRITER_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
        .map(Arc::new);

    if token.is_none() {
        tracing::warn!(
            "KBS_RESOURCE_WRITER_TOKEN is unset; rely on network policy or local-only binding"
        );
    }

    let state = WriterState {
        repository_root: Arc::new(repository_root),
        token,
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/resources/{repository}/{resource}/{tag}",
            put(ensure_resource).delete(delete_resource),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("KBS resource writer listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ensure_resource(
    State(state): State<WriterState>,
    headers: HeaderMap,
    Path((repository, resource, tag)): Path<(String, String, String)>,
) -> Result<Json<ResourceResponse>, WriterError> {
    authorize(&state, &headers)?;
    validate_resource_path(&repository, &resource, &tag)?;

    let resource_dir = state.repository_root.join(&resource);
    let resource_path = resource_dir.join(&tag);
    if non_empty_file_exists(&resource_path)? {
        return Ok(Json(ResourceResponse {
            repository,
            resource,
            tag,
            status: "exists",
        }));
    }

    std::fs::create_dir_all(&resource_dir)?;
    let mut seed_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut seed_bytes);
    let seed = hex::encode(seed_bytes);
    let temp_path = resource_dir.join(format!(".{tag}.{}.tmp", OsRng.next_u64()));

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(seed.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    std::fs::rename(&temp_path, &resource_path)?;
    sync_dir(&resource_dir)?;

    tracing::info!(repository, resource, tag, "created KBS resource");
    Ok(Json(ResourceResponse {
        repository,
        resource,
        tag,
        status: "created",
    }))
}

async fn delete_resource(
    State(state): State<WriterState>,
    headers: HeaderMap,
    Path((repository, resource, tag)): Path<(String, String, String)>,
) -> Result<Json<ResourceResponse>, WriterError> {
    authorize(&state, &headers)?;
    validate_resource_path(&repository, &resource, &tag)?;

    let resource_dir = state.repository_root.join(&resource);
    let resource_path = resource_dir.join(&tag);
    match std::fs::remove_file(&resource_path) {
        Ok(()) => {
            let _ = std::fs::remove_dir(&resource_dir);
            tracing::info!(repository, resource, tag, "deleted KBS resource");
            Ok(Json(ResourceResponse {
                repository,
                resource,
                tag,
                status: "deleted",
            }))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Json(ResourceResponse {
            repository,
            resource,
            tag,
            status: "absent",
        })),
        Err(err) => Err(err.into()),
    }
}

fn authorize(state: &WriterState, headers: &HeaderMap) -> Result<(), WriterError> {
    let Some(expected) = &state.token else {
        return Ok(());
    };

    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let explicit = headers
        .get("x-kbs-resource-writer-token")
        .and_then(|value| value.to_str().ok());

    if bearer == Some(expected.as_str()) || explicit == Some(expected.as_str()) {
        return Ok(());
    }

    Err(WriterError::Unauthorized)
}

fn validate_resource_path(repository: &str, resource: &str, tag: &str) -> Result<(), WriterError> {
    if repository != "default" {
        return Err(WriterError::InvalidPath(
            "only the default repository is writable".to_string(),
        ));
    }
    if tag != "workload-secret-seed" {
        return Err(WriterError::InvalidPath(
            "only workload-secret-seed is writable".to_string(),
        ));
    }
    if resource.len() > 253
        || !resource.starts_with("cap-")
        || !resource.ends_with("-tls")
        || resource.starts_with('.')
        || !resource
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(WriterError::InvalidPath(
            "resource must be a CAP-managed TLS resource name".to_string(),
        ));
    }
    Ok(())
}

fn non_empty_file_exists(path: &FsPath) -> Result<bool, WriterError> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && metadata.len() > 0),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn sync_dir(path: &FsPath) -> Result<(), WriterError> {
    let dir = std::fs::File::open(path)?;
    dir.sync_all()?;
    Ok(())
}
