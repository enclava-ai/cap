use enclava_engine::testutil::sample_app;

#[test]
fn sample_app_has_digest_pinned_image() {
    let app = sample_app();
    let container = &app.containers[0];
    container
        .image
        .require_digest()
        .expect("primary container must be digest-pinned");
}

#[test]
fn sample_app_serializes_to_json() {
    let app = sample_app();
    let json = serde_json::to_string_pretty(&app).unwrap();
    assert!(json.contains("test-app"));
    assert!(json.contains("cap-test-org-test-app"));
}

#[test]
fn owner_resource_path_uses_namespace_and_app_name() {
    let app = sample_app();
    assert_eq!(
        app.owner_resource_path(),
        "default/cap-test-org-test-app-test-app-owner"
    );
}

#[test]
fn primary_domain_returns_platform_domain() {
    let app = sample_app();
    assert_eq!(app.primary_domain(), "test-app.enclava.dev");
}

#[test]
fn primary_domain_prefers_custom() {
    let mut app = sample_app();
    app.domain.custom_domain = Some("app.example.com".to_string());
    assert_eq!(app.primary_domain(), "app.example.com");
}

#[test]
fn all_apps_have_identity_fields() {
    // OID-1: identity fields are non-optional for ALL apps
    let app = enclava_engine::testutil::sample_app();
    assert!(!app.bootstrap_owner_pubkey_hash.is_empty());
    assert!(!app.tenant_instance_identity_hash.is_empty());
    assert_eq!(app.tenant_instance_identity_hash.len(), 64);

    let pwd = enclava_engine::testutil::sample_password_app();
    assert!(!pwd.bootstrap_owner_pubkey_hash.is_empty());
    assert!(!pwd.tenant_instance_identity_hash.is_empty());
    assert_eq!(pwd.tenant_instance_identity_hash.len(), 64);
}
