use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

/// Generate a Namespace resource with pod-security labels.
///
/// Matches the live shape at enclava-tenant-manifests/infra/namespace.yaml.
/// CoCo workloads require privileged pod-security because the app container
/// runs as root with SYS_ADMIN for LUKS operations.
pub fn generate_namespace(app: &ConfidentialApp) -> Namespace {
    let mut labels = BTreeMap::new();
    labels.insert(
        "pod-security.kubernetes.io/enforce".to_string(),
        "privileged".to_string(),
    );
    labels.insert(
        "pod-security.kubernetes.io/audit".to_string(),
        "privileged".to_string(),
    );
    labels.insert(
        "pod-security.kubernetes.io/warn".to_string(),
        "privileged".to_string(),
    );
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("enclava.dev/tenant".to_string(), app.tenant_id.clone());

    Namespace {
        metadata: ObjectMeta {
            name: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        ..Default::default()
    }
}
