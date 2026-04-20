//! Ingress ConfigMap: Caddyfile rendering with CAP routes.
//!
//! Generates the tenant-ingress ConfigMap containing a Caddyfile that:
//! - Terminates TLS inside the TEE via Cloudflare DNS-01 ACME
//! - Routes attestation + ownership endpoints to the proxy (8081)
//! - Routes /.well-known/confidential/* to the proxy (CAP-specific)
//! - Routes everything else to the app container

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

/// Generate the tenant-ingress ConfigMap with the rendered Caddyfile.
pub fn generate_ingress_configmap(app: &ConfidentialApp) -> ConfigMap {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("app".to_string(), app.name.clone());

    let caddyfile = render_caddyfile(app);

    let mut data = BTreeMap::new();
    data.insert("Caddyfile".to_string(), caddyfile);

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(format!("{}-tenant-ingress", app.name)),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Render the Caddyfile for a confidential app.
///
/// Extended from the live template at components/templates/confidential-workload/
/// tenant-ingress-configmap.yaml to include CAP-specific /.well-known/confidential/* routes.
fn render_caddyfile(app: &ConfidentialApp) -> String {
    let domain = app.primary_domain();
    let app_port = app.primary_container().and_then(|c| c.port).unwrap_or(8080);

    format!(
        r#"{{
  email infra@enclava.dev
  storage file_system /tls-data/caddy
  acme_ca https://acme-v02.api.letsencrypt.org/directory
}}
{domain} {{
  tls {{
    dns cloudflare {{env.CF_API_TOKEN}}
    resolvers 10.43.0.10
  }}
  @attestation-proxy path /v1/attestation /v1/attestation/* /unlock
  handle @attestation-proxy {{
    reverse_proxy 127.0.0.1:8081
  }}
  @confidential path /.well-known/confidential/*
  handle @confidential {{
    reverse_proxy 127.0.0.1:8081
  }}
  handle /health {{
    reverse_proxy 127.0.0.1:{app_port}
  }}
  handle {{
    reverse_proxy 127.0.0.1:{app_port}
  }}
}}
"#,
        domain = domain,
        app_port = app_port,
    )
}
