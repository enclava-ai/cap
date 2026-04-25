//! Integration tests for API routes using testcontainers.

use ed25519_dalek::SigningKey;
use enclava_api::{state::AppState, test_router};
use enclava_common::image::ImageRef;
use enclava_engine::types::AttestationConfig;
use rand::rngs::OsRng;
use sqlx::PgPool;
use std::sync::Arc;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("failed to connect to test db");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations failed");

    pool
}

async fn setup_test_state() -> (AppState, PgPool) {
    let pool = setup_test_db().await;
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let hmac_key = Arc::new([0u8; 32]); // Test HMAC key

    let state = AppState {
        db: pool.clone(),
        signing_key,
        hmac_key,
        api_url: "http://localhost:3000".to_string(),
        btcpay_url: "http://localhost:23001".to_string(),
        btcpay_api_key: "test-key".to_string(),
        platform_domain: "enclava.dev".to_string(),
        http_client: reqwest::Client::new(),
        tee_http_client: reqwest::Client::new(),
        btcpay_webhook_secret: "test-secret".to_string(),
        attestation: Some(AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-ai/attestation-proxy@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-ai/caddy-ingress@sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            acme_ca_url: enclava_engine::types::default_acme_ca_url(),
            cloudflare_token_secret: "cloudflare-api-token-enclava-dev".to_string(),
            cloudflare_api_token: Some("test-cloudflare-token".to_string()),
        }),
        dns: None,
        kbs_policy: None,
        deployment_apply_permits: Arc::new(tokio::sync::Semaphore::new(1)),
    };

    (state, pool)
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);

    let server = axum_test::TestServer::new(app);

    let response = server
        .get("/health")
        .add_header("x-forwarded-for", "127.0.0.1")
        .await;

    response.assert_status_ok();
    response.assert_text("ok");
}
