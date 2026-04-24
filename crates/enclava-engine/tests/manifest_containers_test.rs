use enclava_engine::manifest::containers::{
    build_app_container, build_attestation_proxy_container, build_caddy_container,
};
use enclava_engine::testutil::sample_app;

// === App container tests ===

#[test]
fn app_container_name() {
    let app = sample_app();
    let c = build_app_container(&app);
    assert_eq!(c.name, "web");
}

#[test]
fn app_container_image() {
    let app = sample_app();
    let c = build_app_container(&app);
    assert!(
        c.image
            .as_ref()
            .unwrap()
            .contains("ghcr.io/test/app@sha256:")
    );
}

#[test]
fn app_container_has_bootstrap_command() {
    let app = sample_app();
    let c = build_app_container(&app);
    let cmd = c.command.as_ref().unwrap();
    assert_eq!(cmd[0], "/bin/sh");
    assert!(cmd.iter().any(|s| s.contains("bootstrap.sh")));
}

#[test]
fn app_container_has_cryptsetup_device_env() {
    let app = sample_app();
    let c = build_app_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "CRYPTSETUP_DEVICE").unwrap();
    assert_eq!(found.value.as_deref(), Some("/dev/csi0"));
}

#[test]
fn app_container_has_ownership_slot_env() {
    let app = sample_app();
    let c = build_app_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "OWNERSHIP_SLOT").unwrap();
    assert_eq!(found.value.as_deref(), Some("app-data"));
}

#[test]
fn app_container_has_storage_ownership_mode() {
    let app = sample_app();
    let c = build_app_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env
        .iter()
        .find(|e| e.name == "STORAGE_OWNERSHIP_MODE")
        .unwrap();
    assert_eq!(found.value.as_deref(), Some("auto-unlock"));
}

#[test]
fn app_container_privileged_security_context() {
    let app = sample_app();
    let c = build_app_container(&app);
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(true));
    assert_eq!(sc.run_as_user, Some(0));
}

#[test]
fn app_container_has_volume_device() {
    let app = sample_app();
    let c = build_app_container(&app);
    let vd = c.volume_devices.as_ref().unwrap();
    let state = vd.iter().find(|d| d.name == "state").unwrap();
    assert_eq!(state.device_path, "/dev/csi0");
}

#[test]
fn app_container_has_volume_mounts() {
    let app = sample_app();
    let c = build_app_container(&app);
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().any(|m| m.name == "secure-pv-bootstrap"));
    assert!(vm.iter().any(|m| m.name == "startup"));
    assert!(vm.iter().any(|m| m.name == "ownership-signal"));
}

// === Attestation proxy container tests ===

#[test]
fn proxy_container_name() {
    let app = sample_app();
    let c = build_attestation_proxy_container(&app);
    assert_eq!(c.name, "attestation-proxy");
}

#[test]
fn proxy_container_image() {
    let app = sample_app();
    let c = build_attestation_proxy_container(&app);
    assert!(
        c.image
            .as_ref()
            .unwrap()
            .contains("attestation-proxy@sha256:")
    );
}

#[test]
fn proxy_container_port_8081() {
    let app = sample_app();
    let c = build_attestation_proxy_container(&app);
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 8081));
}

#[test]
fn proxy_container_has_instance_id_env() {
    let app = sample_app();
    let c = build_attestation_proxy_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "INSTANCE_ID").unwrap();
    assert_eq!(
        found.value.as_deref(),
        Some("cap-test-org-test-app-test-app")
    );
}

#[test]
fn proxy_container_has_owner_ciphertext_backend() {
    let app = sample_app();
    let c = build_attestation_proxy_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env
        .iter()
        .find(|e| e.name == "OWNER_CIPHERTEXT_BACKEND")
        .unwrap();
    assert_eq!(found.value.as_deref(), Some("kbs-resource"));
}

#[test]
fn proxy_container_has_sev_sealing_permissions() {
    let app = sample_app();
    let c = build_attestation_proxy_container(&app);
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.run_as_non_root, Some(false));
    assert_eq!(sc.run_as_user, Some(0));
    assert_eq!(sc.run_as_group, Some(0));
    assert_eq!(sc.read_only_root_filesystem, Some(true));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert_eq!(caps.add.as_deref(), Some(&["MKNOD".to_string()][..]));
}

#[test]
fn proxy_container_has_ownership_signal_mount() {
    let app = sample_app();
    let c = build_attestation_proxy_container(&app);
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().any(|m| m.name == "ownership-signal"));
}

// === Caddy container tests ===

#[test]
fn caddy_container_name() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    assert_eq!(c.name, "tenant-ingress");
}

#[test]
fn caddy_container_image() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    assert!(c.image.as_ref().unwrap().contains("caddy-ingress@sha256:"));
}

#[test]
fn caddy_container_port_443() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 443));
}

#[test]
fn caddy_container_has_cryptsetup_device_csi1() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "CRYPTSETUP_DEVICE").unwrap();
    assert_eq!(found.value.as_deref(), Some("/dev/csi1"));
}

#[test]
fn caddy_container_has_tls_data_ownership_slot() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "OWNERSHIP_SLOT").unwrap();
    assert_eq!(found.value.as_deref(), Some("tls-data"));
}

#[test]
fn caddy_container_has_reset_on_key_mismatch() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env
        .iter()
        .find(|e| e.name == "SECURE_PV_RESET_ON_KEY_MISMATCH")
        .unwrap();
    assert_eq!(found.value.as_deref(), Some("false"));
}

#[test]
fn caddy_container_uses_kbs_tls_seed_path() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "KBS_RESOURCE_PATH").unwrap();
    assert_eq!(
        found.value.as_deref(),
        Some("default/cap-test-org-test-app-test-app-tls/workload-secret-seed")
    );
}

#[test]
fn caddy_container_does_not_use_owner_unlock_mode() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let env = c.env.as_ref().unwrap();
    let found = env
        .iter()
        .find(|e| e.name == "STORAGE_OWNERSHIP_MODE")
        .unwrap();
    assert_eq!(found.value.as_deref(), Some("kbs-resource"));
}

#[test]
fn caddy_container_runs_inside_persistent_tls_volume() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let command = c.command.as_ref().unwrap().join("\n");
    assert!(!command.contains("/tmp/caddy-bootstrap"));
    assert!(!command.contains("caddy run --config /etc/caddy/Caddyfile &"));
    assert!(command.contains(
        "exec /bin/sh /secure-pv/bootstrap.sh -- caddy run --config /etc/caddy/Caddyfile"
    ));
}

#[test]
fn caddy_container_privileged_security() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(true));
}

#[test]
fn caddy_container_has_volume_device_tls() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let vd = c.volume_devices.as_ref().unwrap();
    let tls = vd.iter().find(|d| d.name == "tls-state").unwrap();
    assert_eq!(tls.device_path, "/dev/csi1");
}

#[test]
fn caddy_container_has_required_volume_mounts() {
    let app = sample_app();
    let c = build_caddy_container(&app);
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().any(|m| m.name == "secure-pv-bootstrap"));
    assert!(vm.iter().any(|m| m.name == "tenant-ingress-caddyfile"));
    assert!(vm.iter().any(|m| m.name == "tls-cloudflare-token"));
    assert!(vm.iter().any(|m| m.name == "ownership-signal"));
}
