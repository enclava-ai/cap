use std::sync::OnceLock;

use chrono::Utc;
use enclava_engine::types::ConfidentialApp;
use k8s_openapi::api::{
    apps::v1::DaemonSet,
    core::v1::{ConfigMap, Service},
};
use kube::{
    Api, Client,
    api::{Patch, PatchParams},
};
use serde_json::json;
use tokio::sync::Mutex;

static HAPROXY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, thiserror::Error)]
pub enum EdgeRouteError {
    #[error("Kubernetes client error: {0}")]
    Kube(#[from] kube::Error),
    #[error("haproxy ConfigMap {namespace}/{name} is missing data key 'haproxy.cfg'")]
    MissingConfig { namespace: String, name: String },
}

#[derive(Clone, Debug)]
pub struct EdgeRouteConfig {
    pub namespace: String,
    pub configmap_name: String,
    pub daemonset_name: String,
}

impl EdgeRouteConfig {
    pub fn from_env() -> Self {
        Self {
            namespace: std::env::var("TENANT_HAPROXY_NAMESPACE")
                .unwrap_or_else(|_| "tenant-envoy".to_string()),
            configmap_name: std::env::var("TENANT_HAPROXY_CONFIGMAP")
                .unwrap_or_else(|_| "haproxy-tenant".to_string()),
            daemonset_name: std::env::var("TENANT_HAPROXY_DAEMONSET")
                .unwrap_or_else(|_| "haproxy-tenant".to_string()),
        }
    }
}

pub async fn ensure_haproxy_route(
    config: &EdgeRouteConfig,
    app: &ConfidentialApp,
) -> Result<(), EdgeRouteError> {
    let backend_target = resolve_service_backend(app).await?;
    mutate_haproxy_config(config, |current| {
        let backend_name = backend_name(app);
        render_route(current, &backend_name, app, &backend_target)
    })
    .await?;

    tracing::info!(
        host = %app.primary_domain(),
        backend = %backend_target,
        "ensured tenant HAProxy SNI route"
    );

    Ok(())
}

pub async fn remove_haproxy_route(
    config: &EdgeRouteConfig,
    app_name: &str,
    domain: &str,
) -> Result<(), EdgeRouteError> {
    let backend_name = backend_name_for_app_name(app_name);
    let changed = mutate_haproxy_config(config, |current| {
        remove_route(current, &backend_name, domain)
    })
    .await?;

    if changed {
        tracing::info!(host = %domain, backend = %backend_name, "removed tenant HAProxy SNI route");
    }

    Ok(())
}

async fn mutate_haproxy_config<F>(
    config: &EdgeRouteConfig,
    mutate: F,
) -> Result<bool, EdgeRouteError>
where
    F: FnOnce(&str) -> String,
{
    let lock = HAPROXY_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;

    let client = Client::try_default().await?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let cm = cm_api.get(&config.configmap_name).await?;
    let current = cm
        .data
        .as_ref()
        .and_then(|data| data.get("haproxy.cfg"))
        .ok_or_else(|| EdgeRouteError::MissingConfig {
            namespace: config.namespace.clone(),
            name: config.configmap_name.clone(),
        })?;

    let updated = mutate(current);
    if updated == *current {
        return Ok(false);
    }

    let patch = json!({
        "data": {
            "haproxy.cfg": updated,
        }
    });
    cm_api
        .patch(
            &config.configmap_name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;

    let ds_api: Api<DaemonSet> = Api::namespaced(client, &config.namespace);
    let restart_patch = json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "cap.enclava.dev/haproxy-restarted-at": Utc::now().to_rfc3339(),
                    }
                }
            }
        }
    });
    ds_api
        .patch(
            &config.daemonset_name,
            &PatchParams::default(),
            &Patch::Merge(&restart_patch),
        )
        .await?;

    Ok(true)
}

fn backend_name(app: &ConfidentialApp) -> String {
    backend_name_for_app_name(&app.name)
}

fn backend_name_for_app_name(app_name: &str) -> String {
    format!("be_cap_{}_sni_route", sanitize_backend_token(app_name))
}

fn sanitize_backend_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

async fn resolve_service_backend(app: &ConfidentialApp) -> Result<String, EdgeRouteError> {
    let client = Client::try_default().await?;
    let service_api: Api<Service> = Api::namespaced(client, &app.namespace);
    let service = service_api.get(&app.name).await?;
    let cluster_ip = service
        .spec
        .and_then(|spec| spec.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None")
        .unwrap_or_else(|| format!("{}.{}.svc.cluster.local", app.name, app.namespace));

    Ok(format!("{cluster_ip}:443"))
}

fn render_route(
    config: &str,
    backend_name: &str,
    app: &ConfidentialApp,
    backend_target: &str,
) -> String {
    let host = app.primary_domain();
    let config = remove_route(config, backend_name, host);
    let use_backend = format!("  use_backend {backend_name} if {{ req.ssl_sni -i {host} }}");
    let server = format!("  server tenant {backend_target} check");
    let backend = format!(
        "backend {backend_name}\n  # Generated from CAP caddy-sni-route ConfigMap.\n  # TLS termination remains inside the confidential workload.\n{server}\n"
    );

    let mut out = config;
    if !out.lines().any(|line| line.trim() == use_backend.trim())
        && let Some(index) = out.find("  default_backend be_reject")
    {
        out.insert_str(index, &format!("{use_backend}\n"));
    }

    if !out
        .lines()
        .any(|line| line.trim() == format!("backend {backend_name}"))
    {
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&backend);
    }

    out
}

fn remove_route(config: &str, backend_name: &str, domain: &str) -> String {
    let use_backend = format!("use_backend {backend_name} if {{ req.ssl_sni -i {domain} }}");
    let mut out = Vec::new();
    let mut skipping_backend = false;

    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed == use_backend {
            continue;
        }
        if trimmed == format!("backend {backend_name}") {
            skipping_backend = true;
            continue;
        }
        if skipping_backend {
            if trimmed.starts_with("backend ") {
                skipping_backend = false;
            } else {
                continue;
            }
        }
        out.push(line);
    }

    let mut rendered = out.join("\n");
    if config.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_common::{
        image::ImageRef,
        types::{ResourceLimits, UnlockMode},
    };
    use enclava_engine::types::{AttestationConfig, Container, DomainSpec, StorageSpec};
    use std::collections::HashMap;
    use uuid::Uuid;

    fn app() -> ConfidentialApp {
        ConfidentialApp {
            app_id: Uuid::nil(),
            name: "test-app".to_string(),
            namespace: "cap-test-app".to_string(),
            instance_id: "cap-test-app-test-app".to_string(),
            tenant_id: "cap-test".to_string(),
            bootstrap_owner_pubkey_hash: "pubkeyhash".to_string(),
            tenant_instance_identity_hash: "hash".to_string(),
            service_account: "test-app".to_string(),
            containers: vec![Container {
                name: "web".to_string(),
                image: ImageRef::parse("ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
                port: Some(8080),
                command: None,
                env: HashMap::new(),
                storage_paths: vec!["/data".to_string()],
                is_primary: true,
            }],
            storage: StorageSpec::new("1Gi", "1Gi"),
            unlock_mode: UnlockMode::Password,
            domain: DomainSpec {
                platform_domain: "test-app.enclava.dev".to_string(),
                custom_domain: None,
            },
            api_signing_pubkey: "pubkey".to_string(),
            api_url: "https://cap.example".to_string(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse("ghcr.io/example/proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
                caddy_image: ImageRef::parse("ghcr.io/example/caddy@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").unwrap(),
                acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                cloudflare_token_secret: "cloudflare-token".to_string(),
                cloudflare_api_token: None,
            },
        }
    }

    #[test]
    fn adds_route_before_default_backend_and_backend_block() {
        let cfg =
            "frontend fe_443\n  bind :443\n  default_backend be_reject\n\nbackend be_reject\n";
        let rendered = render_route(cfg, "be_cap_test_app_sni_route", &app(), "10.43.1.2:443");
        assert!(
            rendered
                .find("use_backend be_cap_test_app_sni_route")
                .unwrap()
                < rendered.find("default_backend be_reject").unwrap()
        );
        assert!(rendered.contains("backend be_cap_test_app_sni_route"));
        assert!(rendered.contains("server tenant 10.43.1.2:443 check"));
    }

    #[test]
    fn route_render_is_idempotent() {
        let cfg =
            "frontend fe_443\n  bind :443\n  default_backend be_reject\n\nbackend be_reject\n";
        let once = render_route(cfg, "be_cap_test_app_sni_route", &app(), "10.43.1.2:443");
        let twice = render_route(&once, "be_cap_test_app_sni_route", &app(), "10.43.1.2:443");
        assert_eq!(once, twice);
    }

    #[test]
    fn route_render_updates_existing_backend_target() {
        let cfg = "frontend fe_443\n  bind :443\n  use_backend be_cap_test_app_sni_route if { req.ssl_sni -i test-app.enclava.dev }\n  default_backend be_reject\n\nbackend be_cap_test_app_sni_route\n  # Generated from CAP caddy-sni-route ConfigMap.\n  # TLS termination remains inside the confidential workload.\n  server tenant test-app.cap-test-app.svc.cluster.local:443 check init-addr none\n\nbackend be_reject\n";
        let rendered = render_route(cfg, "be_cap_test_app_sni_route", &app(), "10.43.1.2:443");
        assert!(rendered.contains("server tenant 10.43.1.2:443 check"));
        assert!(!rendered.contains("test-app.cap-test-app.svc.cluster.local:443"));
    }

    #[test]
    fn remove_route_removes_use_backend_and_backend_block() {
        let cfg = "frontend fe_443\n  bind :443\n  use_backend be_cap_test_app_sni_route if { req.ssl_sni -i test-app.enclava.dev }\n  default_backend be_reject\n\nbackend be_cap_test_app_sni_route\n  # Generated from CAP caddy-sni-route ConfigMap.\n  # TLS termination remains inside the confidential workload.\n  server tenant test-app.cap-test-app.svc.cluster.local:443 check init-addr none\n\nbackend be_reject\n";
        let rendered = remove_route(cfg, "be_cap_test_app_sni_route", "test-app.enclava.dev");
        assert!(!rendered.contains("be_cap_test_app_sni_route"));
        assert!(rendered.contains("default_backend be_reject"));
        assert!(rendered.contains("backend be_reject"));
    }
}
