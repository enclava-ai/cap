//! Bootstrap ConfigMap: wraps the static LUKS bootstrap script.
//!
//! The bootstrap.sh script is ~641 lines and is identical across all apps.
//! App-specific behavior is controlled via environment variables on the containers.
//! This module embeds the script at compile time via include_str!.

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

/// The LUKS bootstrap script, embedded at compile time.
/// Source: enclava-tenant-manifests/components/templates/confidential-workload/
///         secure-pv-bootstrap-configmap.yaml (the data.bootstrap.sh field).
pub const BOOTSTRAP_SCRIPT: &str = include_str!("bootstrap_script.sh");

/// Generate the bootstrap ConfigMap containing the LUKS init script.
pub fn generate_bootstrap_configmap(app: &ConfidentialApp) -> ConfigMap {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );

    let mut data = BTreeMap::new();
    data.insert("bootstrap.sh".to_string(), BOOTSTRAP_SCRIPT.to_string());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some("secure-pv-bootstrap-script".to_string()),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}
