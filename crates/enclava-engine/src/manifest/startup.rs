//! Startup ConfigMap referenced by app containers that do not provide argv.

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

const DEFAULT_STARTUP_SCRIPT: &str = r#"#!/bin/sh
set -eu

if [ -x /usr/local/bin/app ]; then
  exec /usr/local/bin/app
fi

exec /bin/sh
"#;

pub fn generate_startup_configmap(app: &ConfidentialApp) -> ConfigMap {
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), app.name.clone());
    labels.insert("app.kubernetes.io/name".to_string(), app.name.clone());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );

    let mut data = BTreeMap::new();
    data.insert("startup.sh".to_string(), DEFAULT_STARTUP_SCRIPT.to_string());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(format!("{}-startup", app.name)),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}
