//! Integration tests for API routes using testcontainers.

use ed25519_dalek::SigningKey;
use enclava_api::{state::AppState, test_router};
use rand::rngs::OsRng;
use sqlx::PgPool;
use std::sync::Arc;

async fn setup_test_db() -> PgPool {
    let pool = sqlx::PgPool::connect("postgresql://test:test@localhost:5432/test")
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
        btcpay_webhook_secret: "test-secret".to_string(),
    };

    (state, pool)
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);

    let server = axum_test::TestServer::new(app);

    let response = server.get("/health").await;

    response.assert_status_ok();
    response.assert_text("ok");
}
