//! KBS owner_resource_bindings Rego generation.
//!
//! CAP generates `owner_resource_bindings` for each app. Legacy `resource_bindings`
//! are imported as frozen entries per OID-5.

use serde_json::{Value, json};

use crate::types::ConfidentialApp;

/// Generate the owner_resource_bindings map entry for a single app.
/// Returns (key, value) where key is "{instance_id}-owner".
pub fn generate_owner_binding_entry(app: &ConfidentialApp) -> (String, Value) {
    let key = format!("{}-owner", app.instance_id);
    let value = json!({
        "repository": "default",
        "allowed_tags": ["seed-encrypted", "seed-sealed"],
        "allowed_namespaces": [&app.namespace],
        "allowed_service_accounts": [&app.service_account],
        "allowed_identity_hashes": [&app.tenant_instance_identity_hash]
    });
    (key, value)
}

/// Generate the complete KBS resource-policy.rego.
///
/// - `apps`: all CAP-managed apps that need owner_resource_bindings
/// - `legacy_resource_bindings_body`: the inner body of the frozen legacy resource_bindings
///   map (the content between the outer braces). Pass empty string if no legacy bindings.
///
/// The output includes the full Rego file: package, imports, resource_bindings (frozen legacy),
/// owner_resource_bindings (CAP-generated), and all the evaluation rules from the live policy.
pub fn generate_kbs_policy_rego(
    apps: &[&ConfidentialApp],
    legacy_resource_bindings_body: &str,
) -> String {
    let mut rego = String::new();

    // Header
    rego.push_str("package policy\n\nimport rego.v1\n\ndefault allow := false\n\n");

    // Legacy resource_bindings (frozen per OID-5)
    if legacy_resource_bindings_body.trim().is_empty() {
        rego.push_str("resource_bindings := {}\n\n");
    } else {
        rego.push_str("resource_bindings := {\n");
        rego.push_str(legacy_resource_bindings_body);
        rego.push_str("\n}\n\n");
    }

    // CAP owner_resource_bindings
    rego.push_str("owner_resource_bindings := {\n");
    let entries: Vec<String> = apps
        .iter()
        .map(|app| {
            let (key, _val) = generate_owner_binding_entry(app);
            format!(
                "  \"{key}\": {{\n\
                 {indent}\"repository\": \"default\",\n\
                 {indent}\"allowed_tags\": [\"seed-encrypted\", \"seed-sealed\"],\n\
                 {indent}\"allowed_namespaces\": [\"{namespace}\"],\n\
                 {indent}\"allowed_service_accounts\": [\"{sa}\"],\n\
                 {indent}\"allowed_identity_hashes\": [\"{hash}\"]\n\
                 {indent2}}}",
                key = key,
                indent = "    ",
                indent2 = "  ",
                namespace = app.namespace,
                sa = app.service_account,
                hash = app.tenant_instance_identity_hash,
            )
        })
        .collect();
    rego.push_str(&entries.join(",\n"));
    rego.push_str("\n}\n");

    rego
}
