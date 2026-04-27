use enclava_engine::manifest::cc_init_data::{build_toml, encode_cc_init_data, sha256_hex};
use enclava_engine::testutil::sample_app;

#[test]
fn toml_contains_policy_rego() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("package agent_policy"));
    assert!(toml.contains("AllowRequestsFailingPolicy"));
}

#[test]
fn toml_contains_image_digest() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains(
        "ghcr.io/test/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    ));
}

#[test]
fn toml_contains_namespace() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("cap-test-org-test-app"));
}

#[test]
fn toml_contains_service_account() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("cap-test-app-sa"));
}

#[test]
fn toml_contains_policy_instance_annotation() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("\"tenant.flowforge.sh/instance\":\"test-app\""));
}

#[test]
fn toml_contains_aa_toml() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("[token_configs]"));
    assert!(toml.contains("[token_configs.kbs]"));
    assert!(toml.contains("http://kbs-service.trustee-operator-system.svc.cluster.local:8080"));
}

#[test]
fn toml_contains_cdh_toml() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("[kbc]"));
    assert!(toml.contains("cc_kbc"));
}

#[test]
fn toml_contains_identity_toml() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("identity.toml"));
    assert!(toml.contains(&format!("tenant_id = \"{}\"", app.namespace)));
    assert!(toml.contains(&format!("instance_id = \"{}\"", app.name)));
    assert!(toml.contains(&format!(
        "owner_resource_type = \"{}\"",
        app.owner_resource_type()
    )));
    assert!(toml.contains(&format!(
        "bootstrap_owner_pubkey_hash = \"{}\"",
        app.bootstrap_owner_pubkey_hash
    )));
    assert!(toml.contains(&format!(
        "tenant_instance_identity_hash = \"{}\"",
        app.tenant_instance_identity_hash
    )));
}

#[test]
fn sha256_hex_is_64_lowercase_hex() {
    let app = sample_app();
    let toml = build_toml(&app);
    let hash = sha256_hex(&toml);
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hash, hash.to_lowercase());
}

#[test]
fn sha256_hex_is_deterministic() {
    let app = sample_app();
    let toml = build_toml(&app);
    let h1 = sha256_hex(&toml);
    let h2 = sha256_hex(&toml);
    assert_eq!(h1, h2);
}

#[test]
fn encode_produces_valid_base64() {
    let app = sample_app();
    let toml = build_toml(&app);
    let encoded = encode_cc_init_data(&toml);
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("must be valid base64");
    // Decoded is gzip data -- first two bytes are the gzip magic number
    assert_eq!(decoded[0], 0x1f);
    assert_eq!(decoded[1], 0x8b);
}

#[test]
fn encode_roundtrips_through_gzip() {
    let app = sample_app();
    let toml = build_toml(&app);
    let encoded = encode_cc_init_data(&toml);

    use base64::Engine;
    use std::io::Read;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .unwrap();
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();

    assert_eq!(decompressed, toml);
}

#[test]
fn encode_gzip_has_zero_mtime() {
    // gzip header: magic(2) + method(1) + flags(1) + mtime(4) + ...
    // mtime is at bytes 4-7 and must be all zeros.
    let app = sample_app();
    let toml = build_toml(&app);
    let encoded = encode_cc_init_data(&toml);

    use base64::Engine;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .unwrap();
    assert_eq!(compressed[4], 0, "mtime byte 0 must be zero");
    assert_eq!(compressed[5], 0, "mtime byte 1 must be zero");
    assert_eq!(compressed[6], 0, "mtime byte 2 must be zero");
    assert_eq!(compressed[7], 0, "mtime byte 3 must be zero");
}

#[test]
fn toml_structure_matches_python_template() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.starts_with("version = \"0.1.0\"\nalgorithm = \"sha256\""));
}

#[test]
fn toml_binds_runtime_class() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("runtime_class = \"kata-qemu-snp\""));
}

#[test]
fn toml_binds_sidecar_digests() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("[data.sidecar_digests]"));
    assert!(toml.contains("attestation_proxy = \"sha256:1111"));
    assert!(toml.contains("caddy_ingress = \"sha256:2222"));
}

#[test]
fn verify_runtime_class_binding_passes_for_default_render() {
    use enclava_engine::manifest::cc_init_data::verify_runtime_class_binding;
    let app = sample_app();
    let manifests = enclava_engine::manifest::generate_all_manifests(&app);
    verify_runtime_class_binding(&manifests.statefulset).expect("default app must bind runtime class");
}
