use enclava_engine::manifest::bootstrap::{BOOTSTRAP_SCRIPT, generate_bootstrap_configmap};
use enclava_engine::testutil::sample_app;

#[test]
fn bootstrap_script_is_non_empty() {
    assert!(!BOOTSTRAP_SCRIPT.is_empty());
    assert!(BOOTSTRAP_SCRIPT.len() > 100);
}

#[test]
fn bootstrap_script_starts_with_shebang() {
    assert!(BOOTSTRAP_SCRIPT.starts_with("#!/bin/sh"));
}

#[test]
fn bootstrap_script_contains_ownership_bootstrap() {
    assert!(BOOTSTRAP_SCRIPT.contains("ownership_bootstrap"));
}

#[test]
fn bootstrap_script_contains_secure_pv_bootstrap() {
    assert!(BOOTSTRAP_SCRIPT.contains("secure_pv_bootstrap"));
}

#[test]
fn bootstrap_configmap_name() {
    let app = sample_app();
    let cm = generate_bootstrap_configmap(&app);
    assert_eq!(
        cm.metadata.name.as_deref(),
        Some("secure-pv-bootstrap-script")
    );
}

#[test]
fn bootstrap_configmap_namespace() {
    let app = sample_app();
    let cm = generate_bootstrap_configmap(&app);
    assert_eq!(
        cm.metadata.namespace.as_deref(),
        Some("cap-test-org-test-app")
    );
}

#[test]
fn bootstrap_configmap_has_script_data() {
    let app = sample_app();
    let cm = generate_bootstrap_configmap(&app);
    let data = cm.data.as_ref().unwrap();
    assert!(data.contains_key("bootstrap.sh"));
    let script = data.get("bootstrap.sh").unwrap();
    assert!(script.starts_with("#!/bin/sh"));
}
