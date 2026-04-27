//! Container shape tests. Phase 5 default (no `LEGACY_BOOTSTRAP_SCRIPT`):
//! enclava-init opens LUKS in an initContainer; app and caddy are unprivileged
//! and read seeds from `/state/{app,caddy}/seed`. The tls-state volume is
//! mounted as a filesystem at `/state/tls-state`.

use enclava_engine::manifest::containers::{
    build_app_container, build_attestation_proxy_container, build_caddy_container,
    build_enclava_init_container,
};
use enclava_engine::testutil::sample_app;

// === App container (Phase 5 default) ===

#[test]
fn app_container_name() {
    let c = build_app_container(&sample_app());
    assert_eq!(c.name, "web");
}

#[test]
fn app_container_is_not_privileged() {
    let c = build_app_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(false));
    assert_eq!(sc.allow_privilege_escalation, Some(false));
    assert_eq!(sc.run_as_non_root, Some(true));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert!(caps.add.as_deref().map(|v| v.is_empty()).unwrap_or(true));
}

#[test]
fn app_container_does_not_use_sh_c() {
    let c = build_app_container(&sample_app());
    if let Some(cmd) = c.command.as_ref() {
        assert!(!cmd.iter().any(|s| s == "-c"));
        assert!(!cmd.iter().any(|s| s.contains("bootstrap.sh")));
    }
}

#[test]
fn app_container_reads_seed_from_state_app() {
    let c = build_app_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "APP_SEED_PATH").unwrap();
    assert_eq!(found.value.as_deref(), Some("/state/app/seed"));
}

#[test]
fn app_container_mounts_state_filesystem() {
    let c = build_app_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm.iter().find(|m| m.name == "state").unwrap();
    assert_eq!(m.mount_path, "/state");
    assert!(c.volume_devices.is_none());
}

// === Attestation proxy ===

#[test]
fn proxy_container_name_and_port() {
    let c = build_attestation_proxy_container(&sample_app());
    assert_eq!(c.name, "attestation-proxy");
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 8081));
}

#[test]
fn proxy_container_is_non_root() {
    let c = build_attestation_proxy_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.run_as_non_root, Some(true));
    assert_eq!(sc.run_as_user, Some(65532));
    assert_eq!(sc.read_only_root_filesystem, Some(true));
}

#[test]
fn proxy_container_mounts_unlock_socket() {
    let c = build_attestation_proxy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm.iter().find(|m| m.name == "unlock-socket").unwrap();
    assert_eq!(m.mount_path, "/run/enclava");
}

// === Caddy ===

#[test]
fn caddy_container_name_and_port() {
    let c = build_caddy_container(&sample_app());
    assert_eq!(c.name, "tenant-ingress");
    let ports = c.ports.as_ref().unwrap();
    assert!(ports.iter().any(|p| p.container_port == 443));
}

#[test]
fn caddy_container_is_unprivileged_with_only_net_bind() {
    let c = build_caddy_container(&sample_app());
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(false));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert_eq!(
        caps.add.as_deref(),
        Some(&["NET_BIND_SERVICE".to_string()][..])
    );
}

#[test]
fn caddy_container_command_is_argv_not_shell() {
    let c = build_caddy_container(&sample_app());
    let cmd = c.command.as_ref().unwrap();
    assert_eq!(cmd, &vec!["caddy".to_string()]);
    let args = c.args.as_ref().unwrap();
    assert_eq!(
        args,
        &vec![
            "run".to_string(),
            "--config".to_string(),
            "/etc/caddy/Caddyfile".to_string(),
        ]
    );
}

#[test]
fn caddy_container_has_no_cf_api_token_env() {
    // DNS-01 / Cloudflare path is gone; CF_API_TOKEN must not be set anywhere.
    let c = build_caddy_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    assert!(env.iter().all(|e| e.name != "CF_API_TOKEN"));
    if let Some(cmd) = c.command.as_ref() {
        for s in cmd {
            assert!(!s.contains("CF_API_TOKEN"));
        }
    }
}

#[test]
fn caddy_container_does_not_mount_cloudflare_token() {
    let c = build_caddy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().all(|m| m.name != "tls-cloudflare-token"));
}

#[test]
fn caddy_container_mounts_tls_state_filesystem() {
    let c = build_caddy_container(&sample_app());
    let vm = c.volume_mounts.as_ref().unwrap();
    let m = vm.iter().find(|m| m.name == "tls-state").unwrap();
    assert_eq!(m.mount_path, "/state/tls-state");
    assert!(c.volume_devices.is_none());
}

#[test]
fn caddy_container_reads_seed_from_state_caddy() {
    let c = build_caddy_container(&sample_app());
    let env = c.env.as_ref().unwrap();
    let found = env.iter().find(|e| e.name == "CADDY_SEED_PATH").unwrap();
    assert_eq!(found.value.as_deref(), Some("/state/caddy/seed"));
}

// === enclava-init initContainer ===

#[test]
fn enclava_init_container_drops_caps_and_keeps_only_sys_admin() {
    let c = build_enclava_init_container(&sample_app());
    assert_eq!(c.name, "enclava-init");
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.privileged, Some(false));
    assert_eq!(sc.allow_privilege_escalation, Some(false));
    let caps = sc.capabilities.as_ref().unwrap();
    assert_eq!(caps.drop.as_deref(), Some(&["ALL".to_string()][..]));
    assert_eq!(caps.add.as_deref(), Some(&["SYS_ADMIN".to_string()][..]));
}

#[test]
fn enclava_init_container_mounts_both_luks_devices_and_unlock_socket() {
    let c = build_enclava_init_container(&sample_app());
    let vd = c.volume_devices.as_ref().unwrap();
    assert!(vd.iter().any(|d| d.name == "state"));
    assert!(vd.iter().any(|d| d.name == "tls-state"));
    let vm = c.volume_mounts.as_ref().unwrap();
    assert!(vm.iter().any(|m| m.name == "unlock-socket"));
    assert!(vm.iter().any(|m| m.name == "enclava-init-config"));
}
