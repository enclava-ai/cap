use enclava_engine::manifest::service_account::generate_service_account;
use enclava_engine::testutil::sample_app;

#[test]
fn service_account_has_correct_name() {
    let app = sample_app();
    let sa = generate_service_account(&app);
    assert_eq!(sa.metadata.name.as_deref(), Some("cap-test-app-sa"));
}

#[test]
fn service_account_has_correct_namespace() {
    let app = sample_app();
    let sa = generate_service_account(&app);
    assert_eq!(
        sa.metadata.namespace.as_deref(),
        Some("cap-test-org-test-app")
    );
}

#[test]
fn service_account_has_managed_by_label() {
    let app = sample_app();
    let sa = generate_service_account(&app);
    let labels = sa.metadata.labels.as_ref().unwrap();
    assert_eq!(
        labels.get("app.kubernetes.io/managed-by"),
        Some(&"enclava-platform".to_string())
    );
}
