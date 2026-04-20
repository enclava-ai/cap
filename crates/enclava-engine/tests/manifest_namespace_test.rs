use enclava_engine::manifest::namespace::generate_namespace;
use enclava_engine::testutil::sample_app;

#[test]
fn namespace_has_correct_name() {
    let app = sample_app();
    let ns = generate_namespace(&app);
    assert_eq!(ns.metadata.name.as_deref(), Some("cap-test-org-test-app"));
}

#[test]
fn namespace_has_pod_security_labels() {
    let app = sample_app();
    let ns = generate_namespace(&app);
    let labels = ns.metadata.labels.as_ref().expect("labels must be set");
    assert_eq!(
        labels.get("pod-security.kubernetes.io/enforce"),
        Some(&"privileged".to_string())
    );
    assert_eq!(
        labels.get("pod-security.kubernetes.io/audit"),
        Some(&"privileged".to_string())
    );
    assert_eq!(
        labels.get("pod-security.kubernetes.io/warn"),
        Some(&"privileged".to_string())
    );
}

#[test]
fn namespace_has_managed_by_label() {
    let app = sample_app();
    let ns = generate_namespace(&app);
    let labels = ns.metadata.labels.as_ref().unwrap();
    assert_eq!(
        labels.get("app.kubernetes.io/managed-by"),
        Some(&"enclava-platform".to_string())
    );
}

#[test]
fn namespace_serializes_to_yaml() {
    let app = sample_app();
    let ns = generate_namespace(&app);
    let yaml = serde_yaml::to_string(&ns).unwrap();
    assert!(yaml.contains("cap-test-org-test-app"));
    assert!(yaml.contains("pod-security.kubernetes.io/enforce"));
}
