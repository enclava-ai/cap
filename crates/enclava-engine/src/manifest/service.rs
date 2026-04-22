use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

/// Generate a Service with HTTPS (443) and attestation (8081) ports.
///
/// Matches the live shape at components/templates/confidential-workload/service.yaml.
pub fn generate_service(app: &ConfidentialApp) -> Service {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("app".to_string(), app.name.clone());

    let mut selector = BTreeMap::new();
    selector.insert("app".to_string(), app.name.clone());

    Service {
        metadata: ObjectMeta {
            name: Some(app.name.clone()),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            // The owner bootstrap API lives in the attestation-proxy sidecar and
            // must be reachable before the workload app has unlocked storage and
            // passed its own readiness checks.
            publish_not_ready_addresses: Some(true),
            ports: Some(vec![
                ServicePort {
                    name: Some("https".to_string()),
                    port: 443,
                    target_port: Some(IntOrString::Int(443)),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("attestation".to_string()),
                    port: 8081,
                    target_port: Some(IntOrString::Int(8081)),
                    ..Default::default()
                },
            ]),
            selector: Some(selector),
            ..Default::default()
        }),
        ..Default::default()
    }
}
