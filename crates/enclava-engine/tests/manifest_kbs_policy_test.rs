use enclava_engine::manifest::kbs_policy::{
    generate_kbs_policy_rego, generate_owner_binding_entry, generate_tls_binding_entry,
};
use enclava_engine::testutil::sample_app;

#[test]
fn owner_binding_key_uses_namespace_and_app_name_owner() {
    let app = sample_app();
    let (key, _val) = generate_owner_binding_entry(&app);
    assert_eq!(key, "cap-test-org-test-app-test-app-owner");
}

#[test]
fn owner_binding_has_allowed_tags() {
    let app = sample_app();
    let (_key, val) = generate_owner_binding_entry(&app);
    let tags = val["allowed_tags"].as_array().unwrap();
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&serde_json::json!("seed-encrypted")));
    assert!(tags.contains(&serde_json::json!("seed-sealed")));
}

#[test]
fn owner_binding_has_namespace() {
    let app = sample_app();
    let (_key, val) = generate_owner_binding_entry(&app);
    let ns = val["allowed_namespaces"].as_array().unwrap();
    assert_eq!(ns[0], "cap-test-org-test-app");
}

#[test]
fn owner_binding_has_service_account() {
    let app = sample_app();
    let (_key, val) = generate_owner_binding_entry(&app);
    let sa = val["allowed_service_accounts"].as_array().unwrap();
    assert_eq!(sa[0], "cap-test-app-sa");
}

#[test]
fn owner_binding_has_identity_hash() {
    let app = sample_app();
    let (_key, val) = generate_owner_binding_entry(&app);
    let hashes = val["allowed_identity_hashes"].as_array().unwrap();
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0], app.tenant_instance_identity_hash);
}

#[test]
fn owner_binding_has_repository() {
    let app = sample_app();
    let (_key, val) = generate_owner_binding_entry(&app);
    assert_eq!(val["repository"], "default");
}

#[test]
fn tls_binding_key_uses_namespace_and_app_name_tls() {
    let app = sample_app();
    let (key, _val) = generate_tls_binding_entry(&app);
    assert_eq!(key, "cap-test-org-test-app-test-app-tls");
}

#[test]
fn tls_binding_has_workload_secret_seed_tag() {
    let app = sample_app();
    let (_key, val) = generate_tls_binding_entry(&app);
    assert_eq!(val["repository"], "default");
    assert_eq!(val["tag"], "workload-secret-seed");
}

#[test]
fn tls_binding_has_namespace_service_account_and_identity_hash() {
    let app = sample_app();
    let (_key, val) = generate_tls_binding_entry(&app);
    assert_eq!(val["allowed_namespaces"][0], "cap-test-org-test-app");
    assert_eq!(val["allowed_service_accounts"][0], "cap-test-app-sa");
    assert_eq!(
        val["allowed_identity_hashes"][0],
        app.tenant_instance_identity_hash
    );
}

#[test]
fn full_policy_contains_package_declaration() {
    let app = sample_app();
    let apps = vec![&app];
    let rego = generate_kbs_policy_rego(&apps, "");
    assert!(rego.contains("package policy"));
    assert!(rego.contains("import rego.v1"));
    assert!(rego.contains("default allow := false"));
}

#[test]
fn full_policy_contains_owner_bindings() {
    let app = sample_app();
    let apps = vec![&app];
    let rego = generate_kbs_policy_rego(&apps, "");
    assert!(rego.contains("owner_resource_bindings"));
    assert!(rego.contains("cap-test-org-test-app-test-app-owner"));
    assert!(rego.contains("seed-encrypted"));
    assert!(rego.contains("seed-sealed"));
}

#[test]
fn full_policy_contains_tls_resource_bindings() {
    let app = sample_app();
    let apps = vec![&app];
    let rego = generate_kbs_policy_rego(&apps, "");
    assert!(rego.contains("resource_bindings"));
    assert!(rego.contains("cap-test-org-test-app-test-app-tls"));
    assert!(rego.contains("\"tag\": \"workload-secret-seed\""));
}

#[test]
fn full_policy_with_legacy_bindings() {
    let app = sample_app();
    let apps = vec![&app];
    let legacy = r#"  "legacy-resource": {
    "repository": "default",
    "tag": "workload-secret-seed",
    "allowed_namespaces": ["legacy-ns"]
  }"#;
    let rego = generate_kbs_policy_rego(&apps, legacy);
    assert!(rego.contains("resource_bindings"));
    assert!(rego.contains("legacy-resource"));
    assert!(rego.contains("owner_resource_bindings"));
    assert!(rego.contains("cap-test-org-test-app-test-app-owner"));
}

#[test]
fn full_policy_without_legacy_bindings_has_empty_resource_bindings() {
    let app = sample_app();
    let apps = vec![&app];
    let rego = generate_kbs_policy_rego(&apps, "");
    assert!(rego.contains("resource_bindings := {"));
    assert!(rego.contains("cap-test-org-test-app-test-app-tls"));
}

#[test]
fn multiple_apps_produce_multiple_bindings() {
    let app1 = sample_app();
    let mut app2 = sample_app();
    app2.name = "test-app-2".to_string();
    app2.namespace = "cap-test-org-test-app-2".to_string();
    app2.instance_id = "test-org-b2c3d4e5".to_string();
    app2.tenant_instance_identity_hash = enclava_common::crypto::compute_identity_hash(
        &app2.tenant_id,
        &app2.instance_id,
        &app2.bootstrap_owner_pubkey_hash,
    );
    let apps = vec![&app1, &app2];
    let rego = generate_kbs_policy_rego(&apps, "");
    assert!(rego.contains("cap-test-org-test-app-test-app-owner"));
    assert!(rego.contains("cap-test-org-test-app-2-test-app-2-owner"));
}
