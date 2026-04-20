use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use enclava_api::{auth::jwt, build_router, state::AppState};

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn read_key_file(path: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read key file {}: {}", path, e))
}

fn load_signing_key() -> anyhow::Result<SigningKey> {
    if let Ok(path) = std::env::var("API_SIGNING_KEY_PATH") {
        let bytes = read_key_file(&path)?;
        return SigningKey::from_pkcs8_der(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PATH PKCS#8 key: {}", e));
    }

    if let Ok(b64) = std::env::var("API_SIGNING_KEY_PKCS8_BASE64") {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PKCS8_BASE64: {}", e))?;
        return SigningKey::from_pkcs8_der(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PKCS8_BASE64 key: {}", e));
    }

    if env_flag("ALLOW_EPHEMERAL_KEYS") {
        tracing::warn!("ALLOW_EPHEMERAL_KEYS enabled: generating ephemeral API signing key");
        return Ok(SigningKey::generate(&mut OsRng));
    }

    anyhow::bail!(
        "missing API signing key: set API_SIGNING_KEY_PATH or API_SIGNING_KEY_PKCS8_BASE64"
    )
}

fn load_hmac_key() -> anyhow::Result<[u8; 32]> {
    if let Ok(path) = std::env::var("SESSION_HMAC_KEY_PATH") {
        let bytes = read_key_file(&path)?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }

        let text = std::str::from_utf8(&bytes)
            .map_err(|e| anyhow::anyhow!("SESSION_HMAC_KEY_PATH content is not UTF-8: {}", e))?;
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|e| {
                anyhow::anyhow!(
                    "SESSION_HMAC_KEY_PATH is neither raw 32 bytes nor base64: {}",
                    e
                )
            })?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "SESSION_HMAC_KEY_PATH must decode to exactly 32 bytes, got {}",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        return Ok(key);
    }

    if let Ok(b64) = std::env::var("SESSION_HMAC_KEY_BASE64") {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| anyhow::anyhow!("invalid SESSION_HMAC_KEY_BASE64: {}", e))?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "SESSION_HMAC_KEY_BASE64 must decode to exactly 32 bytes, got {}",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        return Ok(key);
    }

    if env_flag("ALLOW_EPHEMERAL_KEYS") {
        tracing::warn!("ALLOW_EPHEMERAL_KEYS enabled: generating ephemeral JWT HMAC key");
        return Ok(jwt::generate_hmac_key());
    }

    anyhow::bail!("missing session HMAC key: set SESSION_HMAC_KEY_PATH or SESSION_HMAC_KEY_BASE64")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclava_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let btcpay_url =
        std::env::var("BTCPAY_URL").unwrap_or_else(|_| "http://localhost:23001".to_string());
    let btcpay_api_key = std::env::var("BTCPAY_API_KEY").unwrap_or_default();
    let btcpay_webhook_secret = std::env::var("BTCPAY_WEBHOOK_SECRET").unwrap_or_default();
    let platform_domain =
        std::env::var("PLATFORM_DOMAIN").unwrap_or_else(|_| "enclava.dev".to_string());

    let pool = enclava_api::db::pool::create_pool(&database_url)
        .await
        .expect("failed to connect to database");

    enclava_api::db::pool::run_migrations(&pool)
        .await
        .expect("failed to run migrations");

    let signing_key = load_signing_key().expect("failed to load API signing key");
    tracing::info!(
        "API signing public key (base64): {}",
        enclava_api::auth::jwt::public_key_base64(&signing_key)
    );

    let hmac_key = load_hmac_key().expect("failed to load session HMAC key");
    tracing::info!("Loaded session HMAC key");

    let state = AppState {
        db: pool,
        signing_key: Arc::new(signing_key),
        hmac_key: Arc::new(hmac_key),
        api_url,
        btcpay_url,
        btcpay_api_key,
        platform_domain,
        http_client: reqwest::Client::new(),
        btcpay_webhook_secret,
    };

    let app = build_router(state);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind");
    tracing::info!("listening on {}", bind_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("server error");
}
