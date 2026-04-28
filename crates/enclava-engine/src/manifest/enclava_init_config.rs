//! ConfigMap that backs `/etc/enclava-init/config.toml` for the enclava-init
//! initContainer (Phase 5). Generated alongside the StatefulSet so the init
//! container has all the per-app knobs it needs (LUKS device paths, mapping
//! names, mount points, KBS resource path, in-TEE verification toggles).

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;
use enclava_common::canonical::ce_v1_hash;
use enclava_common::types::UnlockMode;

const LOCAL_CDH_RESOURCE_URL: &str = "http://127.0.0.1:8081/cdh/resource";
const APP_UID: u32 = 10001;
const APP_GID: u32 = 10001;
const CADDY_UID: u32 = 10002;
const CADDY_GID: u32 = 10002;

pub fn configmap_name(app_name: &str) -> String {
    format!("{app_name}-enclava-init")
}

pub fn generate_enclava_init_configmap(app: &ConfidentialApp) -> ConfigMap {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );
    labels.insert("app".to_string(), app.name.clone());

    let mut data = BTreeMap::new();
    data.insert("config.toml".to_string(), render_config_toml(app));

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(configmap_name(&app.name)),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

fn render_config_toml(app: &ConfidentialApp) -> String {
    let mode = match app.unlock_mode {
        UnlockMode::Auto => "autounlock",
        UnlockMode::Password => "password",
    };
    let mut out = String::new();
    out.push_str(&format!("mode = \"{mode}\"\n"));
    out.push_str("state-root = \"/state\"\n");
    out.push_str(&format!("app-uid = {APP_UID}\n"));
    out.push_str(&format!("app-gid = {APP_GID}\n"));
    out.push_str(&format!("caddy-uid = {CADDY_UID}\n"));
    out.push_str(&format!("caddy-gid = {CADDY_GID}\n"));
    out.push_str(&format!("argon2-salt-hex = \"{}\"\n", argon2_salt_hex(app)));
    out.push_str("\n[state]\n");
    out.push_str(&format!(
        "device = \"{}\"\n",
        app.storage.app_data.device_path
    ));
    out.push_str("mapping-name = \"cap-state\"\n");
    out.push_str("mount-path = \"/state\"\n");
    out.push_str("hkdf-info = \"state-luks-key\"\n");
    out.push_str("\n[tls-state]\n");
    out.push_str(&format!(
        "device = \"{}\"\n",
        app.storage.tls_data.device_path
    ));
    out.push_str("mapping-name = \"cap-tls-state\"\n");
    out.push_str("mount-path = \"/state/tls-state\"\n");
    out.push_str("hkdf-info = \"tls-state-luks-key\"\n");

    if app.unlock_mode == UnlockMode::Auto {
        out.push('\n');
        out.push_str(&format!("kbs-url = \"{LOCAL_CDH_RESOURCE_URL}\"\n"));
        out.push_str(&format!(
            "kbs-resource-path = \"{}\"\n",
            app.owner_resource_path()
        ));
    }

    out.push_str("\n# Phase 3 Trustee patches not yet deployed; in-TEE verification\n");
    out.push_str("# stays SKIPPED with a loud error log until this flips true.\n");
    out.push_str("trustee-policy-read-available = false\n");

    if let Some(primary) = app.primary_container() {
        for path in &primary.storage_paths {
            out.push_str("\n[[app-bind-mounts]]\n");
            out.push_str(&format!(
                "subdir = {}\n",
                toml_string(&storage_subdir(path))
            ));
            out.push_str(&format!("mount-path = {}\n", toml_string(path)));
        }
    }

    out
}

fn argon2_salt_hex(app: &ConfidentialApp) -> String {
    hex::encode(ce_v1_hash(&[
        ("purpose", b"enclava-init-argon2-salt-v1"),
        ("app_id", app.app_id.as_bytes().as_slice()),
        ("namespace", app.namespace.as_bytes()),
        (
            "identity_hash",
            app.tenant_instance_identity_hash.as_bytes(),
        ),
    ]))
}

fn storage_subdir(path: &str) -> String {
    path.trim_start_matches('/').replace('/', "-")
}

fn toml_string(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization is infallible")
}
