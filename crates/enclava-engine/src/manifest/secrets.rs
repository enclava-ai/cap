//! Tenant Secret resources.

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

pub fn generate_cloudflare_token_secret(app: &ConfidentialApp) -> Option<Secret> {
    let token = app.attestation.cloudflare_api_token.as_ref()?;

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );

    let mut string_data = BTreeMap::new();
    string_data.insert("api-token".to_string(), token.clone());

    Some(Secret {
        metadata: ObjectMeta {
            name: Some(app.attestation.cloudflare_token_secret.clone()),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        string_data: Some(string_data),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    })
}
