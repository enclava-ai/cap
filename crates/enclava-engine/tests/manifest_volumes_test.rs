use enclava_engine::manifest::volumes::{build_volume_claim_templates, build_volumes};
use enclava_engine::testutil::sample_app;

// === Volumes tests ===

#[test]
fn volumes_has_ownership_signal() {
    let app = sample_app();
    let vols = build_volumes(&app);
    let os = vols.iter().find(|v| v.name == "ownership-signal").unwrap();
    let ed = os.empty_dir.as_ref().unwrap();
    assert_eq!(ed.medium.as_deref(), Some("Memory"));
    assert_eq!(ed.size_limit.as_ref().unwrap().0, "1Mi");
}

#[test]
fn volumes_has_secure_pv_bootstrap() {
    let app = sample_app();
    let vols = build_volumes(&app);
    let v = vols
        .iter()
        .find(|v| v.name == "secure-pv-bootstrap")
        .unwrap();
    let cm = v.config_map.as_ref().unwrap();
    assert_eq!(cm.name, "secure-pv-bootstrap-script");
}

#[test]
fn volumes_has_startup() {
    let app = sample_app();
    let vols = build_volumes(&app);
    let v = vols.iter().find(|v| v.name == "startup").unwrap();
    let cm = v.config_map.as_ref().unwrap();
    assert_eq!(cm.name, "test-app-startup");
}

#[test]
fn volumes_has_tenant_ingress_caddyfile() {
    let app = sample_app();
    let vols = build_volumes(&app);
    let v = vols
        .iter()
        .find(|v| v.name == "tenant-ingress-caddyfile")
        .unwrap();
    let cm = v.config_map.as_ref().unwrap();
    assert_eq!(cm.name, "test-app-tenant-ingress");
}

#[test]
fn volumes_has_tls_cloudflare_token() {
    let app = sample_app();
    let vols = build_volumes(&app);
    let v = vols
        .iter()
        .find(|v| v.name == "tls-cloudflare-token")
        .unwrap();
    let sec = v.secret.as_ref().unwrap();
    assert_eq!(
        sec.secret_name.as_deref(),
        Some("cloudflare-api-token-enclava-dev")
    );
}

#[test]
fn volumes_has_logs() {
    let app = sample_app();
    let vols = build_volumes(&app);
    assert!(vols.iter().any(|v| v.name == "logs"));
}

// === VolumeClaimTemplate tests ===

#[test]
fn vcts_has_state() {
    let app = sample_app();
    let vcts = build_volume_claim_templates(&app);
    let state = vcts
        .iter()
        .find(|v| v.metadata.name.as_deref() == Some("state"))
        .unwrap();
    let spec = state.spec.as_ref().unwrap();
    assert_eq!(spec.volume_mode.as_deref(), Some("Block"));
    assert_eq!(spec.storage_class_name.as_deref(), Some("longhorn-wait"));
    let storage = spec
        .resources
        .as_ref()
        .unwrap()
        .requests
        .as_ref()
        .unwrap()
        .get("storage")
        .unwrap();
    assert_eq!(storage.0, "10Gi");
}

#[test]
fn vcts_has_tls_state() {
    let app = sample_app();
    let vcts = build_volume_claim_templates(&app);
    let tls = vcts
        .iter()
        .find(|v| v.metadata.name.as_deref() == Some("tls-state"))
        .unwrap();
    let spec = tls.spec.as_ref().unwrap();
    assert_eq!(spec.volume_mode.as_deref(), Some("Block"));
    let storage = spec
        .resources
        .as_ref()
        .unwrap()
        .requests
        .as_ref()
        .unwrap()
        .get("storage")
        .unwrap();
    assert_eq!(storage.0, "2Gi");
}

#[test]
fn vcts_use_read_write_once() {
    let app = sample_app();
    let vcts = build_volume_claim_templates(&app);
    for vct in &vcts {
        let modes = vct.spec.as_ref().unwrap().access_modes.as_ref().unwrap();
        assert_eq!(modes, &["ReadWriteOnce"]);
    }
}
