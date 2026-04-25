//! Container builders for the three containers in a confidential workload pod:
//! app (user), attestation-proxy (sidecar), caddy tenant-ingress (sidecar).

use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, EnvVar, SecurityContext, VolumeDevice, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

use crate::types::ConfidentialApp;
use enclava_common::types::UnlockMode;

/// Map UnlockMode to the STORAGE_OWNERSHIP_MODE env var value.
fn ownership_mode_str(mode: UnlockMode) -> &'static str {
    match mode {
        UnlockMode::Auto => "auto-unlock",
        UnlockMode::Password => "password",
    }
}

/// Build a simple EnvVar with a string value.
fn env(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value: Some(value.to_string()),
        ..Default::default()
    }
}

/// Build an EnvVar from a field ref (e.g., metadata.name).
fn env_field_ref(name: &str, field_path: &str) -> EnvVar {
    use k8s_openapi::api::core::v1::{EnvVarSource, ObjectFieldSelector};
    EnvVar {
        name: name.to_string(),
        value_from: Some(EnvVarSource {
            field_ref: Some(ObjectFieldSelector {
                field_path: field_path.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build the app container (user's primary container with bootstrap.sh entrypoint).
///
/// Security: privileged=true, SYS_ADMIN cap, runAsUser=0.
/// This is required for LUKS open/format/mount operations.
pub fn build_app_container(app: &ConfidentialApp) -> Container {
    let primary = app
        .primary_container()
        .expect("app must have a primary container");

    let app_port = primary.port.unwrap_or(8080);
    let mode = ownership_mode_str(app.unlock_mode);

    // Build bind-mount spec from storage_paths
    let bind_mounts_str = primary
        .storage_paths
        .iter()
        .map(|path| {
            let subdir = path.trim_start_matches('/').replace('/', "-");
            format!("{}/{}:{}", app.storage.app_data.mount_path, subdir, path)
        })
        .collect::<Vec<_>>()
        .join(",");

    let env_vars = vec![
        env("CRYPTSETUP_DEVICE", &app.storage.app_data.device_path),
        env("VOLUME_MOUNT_POINT", &app.storage.app_data.mount_path),
        env("SECURE_PV_ALLOW_RUNTIME_INSTALL", "false"),
        env("SECURE_PV_STRIP_RUNTIME_CAPS", "true"),
        env("SECURE_PV_LUKS_INTEGRITY", "hmac-sha256"),
        env("SECURE_PV_BIND_MOUNTS", &bind_mounts_str),
        env("SECURE_PV_EXEC_AS", "10001:10001"),
        env("SECURE_PV_CHOWN_RECURSIVE", "true"),
        env("WORKLOAD_SECRET_SOURCE", "kbs"),
        env(
            "WORKLOAD_SECRET_PATH",
            "/run/secure-pv/workload-secret-seed",
        ),
        env("KBS_CDH_ENDPOINT", "http://127.0.0.1:8081/cdh/resource"),
        env_field_ref("LUKS_MAPPING_NAME", "metadata.name"),
        env("ENCLAVA_SECURE_PV_BOOTSTRAP", "1"),
        env("SECURE_PV_RESET_ON_KEY_MISMATCH", "false"),
        env("STORAGE_OWNERSHIP_MODE", mode),
        env("OWNERSHIP_SLOT", "app-data"),
        env("OWNERSHIP_MOUNT_PATH", "/run/ownership-signal"),
        env("SKIP_ATTESTATION_CHECK", "true"),
        env("KBS_FETCH_RETRIES", "120"),
        env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
        env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
        env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "8"),
    ];

    // Build the bootstrap command. If the user has a custom command, append it.
    let user_cmd = if let Some(ref cmd) = primary.command {
        cmd.join(" ")
    } else {
        "/bin/sh -c 'exec /usr/local/bin/app'".to_string()
    };

    Container {
        name: primary.name.clone(),
        image: Some(primary.image.digest_ref()),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("/secure-pv/bootstrap.sh -- {user_cmd}"),
        ]),
        env: Some(env_vars),
        ports: Some(vec![ContainerPort {
            container_port: app_port as i32,
            ..Default::default()
        }]),
        volume_devices: Some(vec![VolumeDevice {
            name: "state".to_string(),
            device_path: "/dev/csi0".to_string(),
        }]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "secure-pv-bootstrap".to_string(),
                mount_path: "/secure-pv".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "startup".to_string(),
                mount_path: "/startup".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "ownership-signal".to_string(),
                mount_path: "/run/ownership-signal".to_string(),
                ..Default::default()
            },
        ]),
        security_context: Some(SecurityContext {
            privileged: Some(true),
            allow_privilege_escalation: Some(true),
            run_as_user: Some(0),
            run_as_group: Some(0),
            run_as_non_root: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: Some(vec!["SYS_ADMIN".to_string()]),
            }),
            ..Default::default()
        }),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("512Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("250m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity(app.resources.memory.clone()));
                m.insert("cpu".to_string(), Quantity(app.resources.cpu.clone()));
                m
            }),
            ..Default::default()
        }),
        liveness_probe: Some(k8s_openapi::api::core::v1::Probe {
            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                path: Some("/health".to_string()),
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                    app_port as i32,
                ),
                ..Default::default()
            }),
            initial_delay_seconds: Some(480),
            period_seconds: Some(15),
            ..Default::default()
        }),
        startup_probe: Some(k8s_openapi::api::core::v1::Probe {
            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                path: Some("/health".to_string()),
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                    app_port as i32,
                ),
                ..Default::default()
            }),
            period_seconds: Some(10),
            failure_threshold: Some(60),
            ..Default::default()
        }),
        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                path: Some("/health".to_string()),
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                    app_port as i32,
                ),
                ..Default::default()
            }),
            initial_delay_seconds: Some(180),
            period_seconds: Some(10),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build the attestation proxy sidecar container.
///
/// Security: non-root (65532), readOnlyRootFilesystem, drop ALL caps.
pub fn build_attestation_proxy_container(app: &ConfidentialApp) -> Container {
    let primary = app
        .primary_container()
        .expect("app must have a primary container");

    let mode = ownership_mode_str(app.unlock_mode);

    let env_vars = vec![
        env("ATTESTATION_WORKLOAD_CONTAINER", &primary.name),
        env_field_ref("ATTESTATION_POD_NAME", "metadata.name"),
        env_field_ref("ATTESTATION_POD_NAMESPACE", "metadata.namespace"),
        env("ATTESTATION_PROFILE", "coco-sev-snp"),
        env("ATTESTATION_RUNTIME_CLASS", "kata-qemu-snp"),
        env("ATTESTATION_WORKLOAD_IMAGE", &primary.image.digest_ref()),
        env("STORAGE_OWNERSHIP_MODE", mode),
        env("INSTANCE_ID", &app.owner_instance_id()),
        env("OWNER_CIPHERTEXT_BACKEND", "kbs-resource"),
        env("OWNER_SEED_HANDOFF_SLOTS", "app-data"),
        env("OWNERSHIP_MOUNT_PATH", "/run/ownership-signal"),
        env("KBS_RESOURCE_CACHE_SECONDS", "300"),
        env("KBS_RESOURCE_FAILURE_CACHE_SECONDS", "30"),
        env("KBS_FETCH_RETRIES", "120"),
        env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
        env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
        env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "10"),
    ];

    Container {
        name: "attestation-proxy".to_string(),
        image: Some(app.attestation.proxy_image.digest_ref()),
        command: Some(vec!["/attestation-proxy".to_string()]),
        ports: Some(vec![ContainerPort {
            container_port: 8081,
            name: Some("attestation".to_string()),
            ..Default::default()
        }]),
        env: Some(env_vars),
        volume_mounts: Some(vec![VolumeMount {
            name: "ownership-signal".to_string(),
            mount_path: "/run/ownership-signal".to_string(),
            ..Default::default()
        }]),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            run_as_non_root: Some(false),
            run_as_user: Some(0),
            run_as_group: Some(0),
            capabilities: Some(Capabilities {
                add: Some(vec!["MKNOD".to_string()]),
                drop: Some(vec!["ALL".to_string()]),
            }),
            ..Default::default()
        }),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("128Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("100m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("256Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("500m".to_string()));
                m
            }),
            ..Default::default()
        }),
        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                path: Some("/health".to_string()),
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8081),
                ..Default::default()
            }),
            initial_delay_seconds: Some(10),
            period_seconds: Some(10),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Build the caddy tenant-ingress sidecar container.
///
/// Handles TLS termination inside the TEE. Has its own LUKS volume for cert storage.
/// Security: privileged=true, SYS_ADMIN + NET_BIND_SERVICE caps (for port 443 and LUKS).
pub fn build_caddy_container(app: &ConfidentialApp) -> Container {
    let env_vars = vec![
        env_field_ref("POD_NAME", "metadata.name"),
        env_field_ref("POD_NAMESPACE", "metadata.namespace"),
        env("CRYPTSETUP_DEVICE", &app.storage.tls_data.device_path),
        env("VOLUME_MOUNT_POINT", &app.storage.tls_data.mount_path),
        env("SECURE_PV_ALLOW_RUNTIME_INSTALL", "false"),
        env("SECURE_PV_STRIP_RUNTIME_CAPS", "false"),
        env("SECURE_PV_LUKS_INTEGRITY", "hmac-sha256"),
        env("WORKLOAD_SECRET_SOURCE", "kbs"),
        env("WORKLOAD_SECRET_PATH", "/run/secure-pv/tls-secret-seed"),
        env("KBS_RESOURCE_PATH", &app.tls_resource_path()),
        env("KBS_CDH_ENDPOINT", "http://127.0.0.1:8081/cdh/resource"),
        env_field_ref("LUKS_MAPPING_NAME", "metadata.name"),
        env("ENCLAVA_SECURE_PV_BOOTSTRAP", "1"),
        env("FLOWFORGE_SECURE_PV_BOOTSTRAP", "1"),
        env("SECURE_PV_RESET_ON_KEY_MISMATCH", "false"),
        env("STORAGE_OWNERSHIP_MODE", "kbs-resource"),
        env("OWNERSHIP_SLOT", "tls-data"),
        env("XDG_DATA_HOME", "/tls-data/caddy"),
        env("KBS_FETCH_RETRIES", "120"),
        env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
        env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
    ];

    Container {
        name: "tenant-ingress".to_string(),
        image: Some(app.attestation.caddy_image.digest_ref()),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "LUKS_MAPPING_NAME=\"${LUKS_MAPPING_NAME}-tls\"\n\
             export LUKS_MAPPING_NAME\n\
             export CF_API_TOKEN=$(cat /run/secrets/cloudflare/token)\n\
             caddy validate --config /etc/caddy/Caddyfile\n\
             exec /bin/sh /secure-pv/bootstrap.sh -- caddy run --config /etc/caddy/Caddyfile"
                .to_string(),
        ]),
        ports: Some(vec![ContainerPort {
            container_port: 443,
            name: Some("https".to_string()),
            ..Default::default()
        }]),
        env: Some(env_vars),
        volume_devices: Some(vec![VolumeDevice {
            name: "tls-state".to_string(),
            device_path: "/dev/csi1".to_string(),
        }]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "secure-pv-bootstrap".to_string(),
                mount_path: "/secure-pv".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "tenant-ingress-caddyfile".to_string(),
                mount_path: "/etc/caddy".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "tls-cloudflare-token".to_string(),
                mount_path: "/run/secrets/cloudflare".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "ownership-signal".to_string(),
                mount_path: "/run/ownership-signal".to_string(),
                ..Default::default()
            },
        ]),
        security_context: Some(SecurityContext {
            privileged: Some(true),
            allow_privilege_escalation: Some(true),
            run_as_user: Some(0),
            run_as_group: Some(0),
            run_as_non_root: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: Some(vec![
                    "SYS_ADMIN".to_string(),
                    "NET_BIND_SERVICE".to_string(),
                ]),
            }),
            ..Default::default()
        }),
        resources: Some(k8s_openapi::api::core::v1::ResourceRequirements {
            requests: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("128Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("100m".to_string()));
                m
            }),
            limits: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("memory".to_string(), Quantity("256Mi".to_string()));
                m.insert("cpu".to_string(), Quantity("500m".to_string()));
                m
            }),
            ..Default::default()
        }),
        readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
            tcp_socket: Some(k8s_openapi::api::core::v1::TCPSocketAction {
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(443),
                ..Default::default()
            }),
            initial_delay_seconds: Some(180),
            period_seconds: Some(15),
            ..Default::default()
        }),
        ..Default::default()
    }
}
