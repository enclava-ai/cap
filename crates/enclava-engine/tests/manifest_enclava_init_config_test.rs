//! enclava-init ConfigMap (Phase 5).

use enclava_engine::manifest::enclava_init_config::generate_enclava_init_configmap;
use enclava_engine::testutil::sample_app;

#[test]
fn cm_name_is_per_app() {
    let cm = generate_enclava_init_configmap(&sample_app());
    assert_eq!(cm.metadata.name.as_deref(), Some("test-app-enclava-init"));
}

#[test]
fn config_toml_has_both_volume_blocks() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    assert!(toml_text.contains("[state]"));
    assert!(toml_text.contains("[tls-state]"));
    assert!(toml_text.contains("state-root = \"/state\""));
    assert!(toml_text.contains("mount-path = \"/state\""));
    assert!(toml_text.contains("mount-path = \"/state/tls-state\""));
    assert!(toml_text.contains("hkdf-info = \"state-luks-key\""));
    assert!(toml_text.contains("hkdf-info = \"tls-state-luks-key\""));
}

#[test]
fn config_toml_has_required_unlock_inputs() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    assert!(toml_text.contains("argon2-salt-hex = \""));
    assert!(toml_text.contains("kbs-url = \"http://127.0.0.1:8081/cdh/resource\""));
    assert!(
        toml_text.contains("kbs-resource-path = \"default/cap-test-org-test-app-test-app-owner\"")
    );
    assert!(!toml_text.contains("workload-secret-seed"));
}

#[test]
fn config_toml_parses() {
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    let _: toml::Value = toml::from_str(toml_text).expect("config.toml must parse");
}

#[test]
fn config_toml_defaults_trustee_policy_read_to_false() {
    // Phase 3 patches haven't shipped; verification stays SKIPPED until then.
    let cm = generate_enclava_init_configmap(&sample_app());
    let toml_text = cm.data.as_ref().unwrap().get("config.toml").unwrap();
    assert!(toml_text.contains("trustee-policy-read-available = false"));
}
