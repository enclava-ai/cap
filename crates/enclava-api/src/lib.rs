pub mod auth;
pub mod billing;
pub mod cosign;
pub mod db;
pub mod deploy;
pub mod dns;
pub mod edge;
pub mod kbs;
pub mod models;
pub mod registry;
pub mod routes;
pub mod state;

use axum::Router;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    // Unlock routes are metadata/control-plane helpers. The secret-bearing
    // claim/unlock requests go directly to the tenant TEE, so this API limiter
    // must tolerate several concurrent CLIs behind the same NAT.
    let unlock_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(120)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("unlock governor config");

    // General API rate limit: 100 requests per second per IP
    // SmartIpKeyExtractor checks x-forwarded-for, x-real-ip, forwarded headers, then peer IP
    let api_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(100)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("api governor config");

    // Auth routes (unauthenticated)
    let auth_routes = Router::new()
        .route("/auth/signup", axum::routing::post(routes::auth::signup))
        .route("/auth/login", axum::routing::post(routes::auth::login))
        .route(
            "/auth/api-keys",
            axum::routing::post(routes::auth::create_api_key_route),
        )
        .route(
            "/auth/api-keys/{id}",
            axum::routing::delete(routes::auth::revoke_api_key_route),
        );

    // Org routes (authenticated)
    let org_routes = Router::new()
        .route("/orgs", axum::routing::post(routes::orgs::create_org))
        .route("/orgs", axum::routing::get(routes::orgs::list_orgs))
        .route(
            "/orgs/{name}/invite",
            axum::routing::post(routes::orgs::invite_member),
        )
        .route(
            "/orgs/{name}/members",
            axum::routing::get(routes::orgs::list_members),
        )
        .route(
            "/orgs/{name}/members/{id}",
            axum::routing::delete(routes::orgs::remove_member),
        );

    // App routes (authenticated)
    let app_routes = Router::new()
        .route("/apps", axum::routing::post(routes::apps::create_app))
        .route("/apps", axum::routing::get(routes::apps::list_apps))
        .route("/apps/{name}", axum::routing::get(routes::apps::get_app))
        .route(
            "/apps/{name}",
            axum::routing::delete(routes::apps::delete_app),
        );

    // Deployment routes (authenticated)
    let deploy_routes = Router::new()
        .route(
            "/apps/{name}/deploy",
            axum::routing::post(routes::deployments::deploy),
        )
        .route(
            "/apps/{name}/deployments",
            axum::routing::get(routes::deployments::deployment_history),
        )
        .route(
            "/apps/{name}/rollback",
            axum::routing::post(routes::deployments::rollback),
        );

    // Config routes (authenticated)
    let config_routes = Router::new()
        .route(
            "/apps/{name}/config-token",
            axum::routing::post(routes::config::issue_config_token_route),
        )
        .route(
            "/apps/{name}/config",
            axum::routing::get(routes::config::list_config_keys),
        )
        .route(
            "/apps/{name}/config/sync",
            axum::routing::post(routes::config::config_sync),
        )
        .route(
            "/apps/{name}/config/{key}/meta",
            axum::routing::delete(routes::config::delete_config_meta),
        );

    // Domain routes (authenticated)
    let domain_routes = Router::new()
        .route(
            "/apps/{name}/domain",
            axum::routing::put(routes::domains::set_domain),
        )
        .route(
            "/apps/{name}/domain",
            axum::routing::get(routes::domains::get_domain),
        )
        .route(
            "/apps/{name}/domain",
            axum::routing::delete(routes::domains::remove_domain),
        );

    // Status routes (authenticated)
    let status_routes = Router::new()
        .route(
            "/apps/{name}/status",
            axum::routing::get(routes::status::app_status),
        )
        .route(
            "/apps/{name}/logs",
            axum::routing::get(routes::status::app_logs),
        );

    // Unlock routes (authenticated, rate-limited)
    let unlock_routes = Router::new()
        .route(
            "/apps/{name}/unlock/status",
            axum::routing::get(routes::unlock::unlock_status),
        )
        .route(
            "/apps/{name}/unlock/endpoint",
            axum::routing::get(routes::unlock::unlock_endpoint),
        )
        .route(
            "/apps/{name}/unlock/mode",
            axum::routing::put(routes::unlock::update_unlock_mode),
        )
        .layer(GovernorLayer::new(unlock_governor_conf));

    // Billing routes
    let billing_routes = Router::new()
        .route(
            "/billing/tiers",
            axum::routing::get(routes::billing::list_tiers),
        )
        .route(
            "/billing/upgrade",
            axum::routing::post(routes::billing::upgrade_tier),
        )
        .route(
            "/billing/status",
            axum::routing::get(routes::billing::subscription_status),
        )
        .route(
            "/billing/renew",
            axum::routing::post(routes::billing::renew_subscription),
        )
        .route(
            "/billing/webhook",
            axum::routing::post(routes::billing::btcpay_webhook),
        );

    // Health check (unauthenticated)
    let health = Router::new().route("/health", axum::routing::get(|| async { "ok" }));

    Router::new()
        .merge(health)
        .merge(auth_routes)
        .merge(org_routes)
        .merge(app_routes)
        .merge(deploy_routes)
        .merge(config_routes)
        .merge(domain_routes)
        .merge(status_routes)
        .merge(unlock_routes)
        .merge(billing_routes)
        .layer(GovernorLayer::new(api_governor_conf))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

/// Expose build_router for testing.
#[doc(hidden)]
pub fn test_router(state: AppState) -> Router {
    build_router(state)
}
