use k8s_openapi::api::core::v1::ResourceQuota;
use k8s_openapi::api::core::v1::ResourceQuotaSpec;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

/// Generate a ResourceQuota matching the live shape at
/// enclava-tenant-manifests/infra/resource-quota.yaml.
///
/// Includes the full resource set: CPU, memory, storage, PVCs, pods, services,
/// load balancers (0), node ports (0), secrets, configmaps.
pub fn generate_resource_quota(app: &ConfidentialApp) -> ResourceQuota {
    let mut hard = BTreeMap::new();

    // CPU
    hard.insert(
        "requests.cpu".to_string(),
        Quantity(app.resources.cpu.clone()),
    );
    hard.insert(
        "limits.cpu".to_string(),
        Quantity(format_doubled_cpu(&app.resources.cpu)),
    );

    // Memory
    hard.insert(
        "requests.memory".to_string(),
        Quantity(app.resources.memory.clone()),
    );
    hard.insert(
        "limits.memory".to_string(),
        Quantity(format_doubled_memory(&app.resources.memory)),
    );

    // Storage: sum of app-data + tls-data, plus headroom
    hard.insert(
        "requests.storage".to_string(),
        Quantity(app.storage.app_data.size.clone()),
    );
    hard.insert(
        "persistentvolumeclaims".to_string(),
        Quantity("5".to_string()),
    );

    // Pod and service limits
    hard.insert("pods".to_string(), Quantity("20".to_string()));
    hard.insert("services".to_string(), Quantity("20".to_string()));
    hard.insert(
        "services.loadbalancers".to_string(),
        Quantity("0".to_string()),
    );
    hard.insert("services.nodeports".to_string(), Quantity("0".to_string()));

    // Secrets and ConfigMaps
    hard.insert("secrets".to_string(), Quantity("50".to_string()));
    hard.insert("configmaps".to_string(), Quantity("50".to_string()));

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );

    ResourceQuota {
        metadata: ObjectMeta {
            name: Some("tenant-quota".to_string()),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ResourceQuotaSpec {
            hard: Some(hard),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Double the CPU string for limits (e.g., "1" -> "2", "4" -> "8").
fn format_doubled_cpu(cpu: &str) -> String {
    if let Ok(n) = cpu.parse::<f64>() {
        let doubled = n * 2.0;
        if doubled == doubled.floor() {
            format!("{}", doubled as i64)
        } else {
            format!("{doubled}")
        }
    } else {
        cpu.to_string()
    }
}

/// Double the memory string for limits (e.g., "1Gi" -> "2Gi", "512Mi" -> "1024Mi").
fn format_doubled_memory(mem: &str) -> String {
    let (num_str, suffix) = split_quantity(mem);
    if let Ok(n) = num_str.parse::<f64>() {
        let doubled = n * 2.0;
        if doubled == doubled.floor() {
            format!("{}{suffix}", doubled as i64)
        } else {
            format!("{doubled}{suffix}")
        }
    } else {
        mem.to_string()
    }
}

/// Split a quantity like "10Gi" into ("10", "Gi").
fn split_quantity(q: &str) -> (&str, &str) {
    let pos = q
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(q.len());
    (&q[..pos], &q[pos..])
}
