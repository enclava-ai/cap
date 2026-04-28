use enclava_engine::manifest::cc_init_data::compute_cc_init_data;
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::manifest::kbs_policy::{generate_kbs_policy_rego, generate_tls_binding_entry};
use enclava_engine::testutil::sample_app;
use serde_json::{Value, json};

const SNAPSHOT: &str = include_str!("fixtures/phase12_manifest_security_snapshot.json");
const SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/phase12_manifest_security_snapshot.json"
);

#[test]
fn phase12_manifest_security_snapshot_matches() {
    let actual = serde_json::to_string_pretty(&phase12_snapshot()).unwrap();
    assert_snapshot_eq(SNAPSHOT, &actual);
}

fn phase12_snapshot() -> Value {
    let app = sample_app();
    let manifests = generate_all_manifests(&app);
    let pod = manifests
        .statefulset
        .spec
        .as_ref()
        .unwrap()
        .template
        .spec
        .as_ref()
        .unwrap();

    let rendered_manifests = serde_json::to_string(&json!({
        "service_account": &manifests.service_account,
        "network_policy": &manifests.network_policy,
        "ingress_configmap": &manifests.ingress_configmap,
        "enclava_init_configmap": &manifests.enclava_init_configmap,
        "statefulset": &manifests.statefulset,
    }))
    .unwrap();

    let volumes: Vec<String> = pod
        .volumes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|volume| volume.name.clone())
        .collect();
    let cloudflare_volumes: Vec<String> = volumes
        .iter()
        .filter(|name| name.contains("cloudflare"))
        .cloned()
        .collect();

    let app_container_name = app.primary_container().unwrap().name.as_str();
    let workload_security: Vec<Value> = pod
        .containers
        .iter()
        .filter(|container| {
            container.name == app_container_name || container.name == "tenant-ingress"
        })
        .map(|container| {
            let sc = container.security_context.as_ref().unwrap();
            json!({
                "allowPrivilegeEscalation": sc.allow_privilege_escalation,
                "container": container.name,
                "privileged": sc.privileged,
                "runAsNonRoot": sc.run_as_non_root,
            })
        })
        .collect();

    let egress = manifests.network_policy["spec"]["egress"]
        .as_array()
        .expect("egress array");
    let fqdns: Vec<String> = egress
        .iter()
        .filter_map(|rule| rule["toFQDNs"][0]["matchName"].as_str())
        .map(str::to_string)
        .collect();
    let user_fqdn_rules: Vec<String> = fqdns
        .iter()
        .filter(|fqdn| !fqdn.ends_with("letsencrypt.org"))
        .cloned()
        .collect();

    let (_encoded_init_data, init_data_hash) = compute_cc_init_data(&app);
    let (tls_binding_key, tls_binding) = generate_tls_binding_entry(&app);
    let kbs_rego = generate_kbs_policy_rego(&[&app], "");

    json!({
        "cloudflare": {
            "containsCloudflareApiTokenEnv": rendered_manifests.contains("CF_API_TOKEN"),
            "containsTenantCloudflareSecretName": rendered_manifests.contains("cloudflare-api-token"),
            "secretGenerated": false,
            "volumeNames": cloudflare_volumes,
        },
        "egress": {
            "containsToEntities": egress.iter().any(|rule| rule.get("toEntities").is_some()),
            "containsWorld": value_contains_string(&manifests.network_policy, "world"),
            "fqdnRules": fqdns,
            "ruleCount": egress.len(),
            "userFqdnRules": user_fqdn_rules,
        },
        "kbs": {
            "regoContainsDefaultDeny": kbs_rego.contains("default allow := false"),
            "regoContainsInitDataHash": kbs_rego.contains(&init_data_hash),
            "tlsBinding": {
                "allowedImages": tls_binding["allowed_images"].clone(),
                "allowedInitDataHashes": tls_binding["allowed_init_data_hashes"].clone(),
                "key": tls_binding_key,
            },
        },
        "serviceAccount": {
            "automountServiceAccountToken": manifests.service_account.automount_service_account_token,
            "name": manifests.service_account.metadata.name.as_deref(),
        },
        "workloadSecurity": workload_security,
    })
}

fn value_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(s) => s == needle,
        Value::Array(values) => values.iter().any(|v| value_contains_string(v, needle)),
        Value::Object(map) => map.values().any(|v| value_contains_string(v, needle)),
        _ => false,
    }
}

fn assert_snapshot_eq(expected: &str, actual: &str) {
    if std::env::var_os("UPDATE_PHASE12_SNAPSHOT").is_some() {
        std::fs::write(SNAPSHOT_PATH, format!("{actual}\n")).unwrap();
        return;
    }

    let expected = expected.trim_end();
    let actual = actual.trim_end();
    if expected == actual {
        return;
    }

    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    let max = expected_lines.len().max(actual_lines.len());
    for idx in 0..max {
        let expected_line = expected_lines.get(idx).copied().unwrap_or("<missing>");
        let actual_line = actual_lines.get(idx).copied().unwrap_or("<missing>");
        if expected_line != actual_line {
            panic!(
                "Phase 12 manifest snapshot mismatch at line {}:\nexpected: {}\nactual:   {}\n\nSet UPDATE_PHASE12_SNAPSHOT=1 to refresh {}",
                idx + 1,
                expected_line,
                actual_line,
                SNAPSHOT_PATH
            );
        }
    }
}
