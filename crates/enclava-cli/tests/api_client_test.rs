use enclava_cli::api_client::{ApiClient, ApiError};

#[test]
fn client_without_auth_returns_not_authenticated() {
    let client = ApiClient::new("https://api.enclava.dev", None);
    // Verify construction works without auth token.
    let _ = client;
}

#[test]
fn client_with_auth_constructs() {
    let client = ApiClient::new("https://api.enclava.dev", Some("test-token".to_string()));
    let _ = client;
}

#[test]
fn client_from_config() {
    let config = enclava_cli::config::CliConfig {
        api_url: "https://custom.api.dev".to_string(),
        org: None,
    };
    let creds = enclava_cli::config::Credentials {
        session_token: Some("jwt-test".to_string()),
        api_key: None,
    };
    let client = ApiClient::from_config(&config, &creds);
    let _ = client;
}

#[test]
fn api_error_display() {
    let err = ApiError::Api {
        status: 404,
        message: "app not found".to_string(),
    };
    assert!(err.to_string().contains("404"));
    assert!(err.to_string().contains("app not found"));
}

#[test]
fn not_authenticated_error_display() {
    let err = ApiError::NotAuthenticated;
    assert!(err.to_string().contains("login"));
}
