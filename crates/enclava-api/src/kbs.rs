use chrono::{DateTime, Utc};
use json_patch::{AddOperation, PatchOperation};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams};
use kube::core::{ApiResource, DynamicObject, GroupVersionKind};
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::BTreeMap;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use enclava_engine::types::ConfidentialApp;

#[derive(Debug, Clone)]
pub struct KbsPolicyConfig {
    pub namespace: String,
    pub configmap_name: String,
    pub policy_key: String,
    pub deployment_name: String,
    pub kbs_config_name: String,
    pub resource_writer_url: Option<String>,
    pub resource_writer_token: Option<String>,
    pub required: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum KbsPolicyError {
    #[error("KBS policy management is required but not configured")]
    NotConfigured,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("resource-policy ConfigMap is missing data key '{0}'")]
    MissingPolicyKey(String),
    #[error("resource-policy.rego does not contain an owner_resource_bindings block")]
    MissingOwnerBindingsBlock,
    #[error("resource-policy.rego does not contain a resource_bindings block")]
    MissingResourceBindingsBlock,
    #[error("KbsConfig spec.kbsSecretResources is not a list")]
    InvalidKbsConfig,
    #[error("Trustee deployment does not contain a kbs container")]
    MissingKbsContainer,
    #[error("Trustee deployment rollout timed out")]
    RolloutTimedOut,
    #[error("KBS resource writer error: {0}")]
    ResourceWriterHttp(#[from] reqwest::Error),
    #[error("KBS resource writer returned {status}: {body}")]
    ResourceWriterStatus {
        status: reqwest::StatusCode,
        body: String,
    },
}

#[derive(Debug, Clone, Deserialize, sqlx::FromRow)]
struct KbsOwnerBinding {
    binding_key: String,
    repository: String,
    allowed_tags: Vec<String>,
    namespace: String,
    service_account: String,
    tenant_instance_identity_hash: String,
}

#[derive(Debug, Clone, Deserialize, sqlx::FromRow)]
struct KbsTlsBinding {
    binding_key: String,
    repository: String,
    tag: String,
    namespace: String,
    service_account: String,
    tenant_instance_identity_hash: String,
}

pub async fn ensure_owner_binding(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    app: &ConfidentialApp,
) -> Result<(), KbsPolicyError> {
    if config.is_none() {
        return Ok(());
    }

    let binding_key = app.owner_resource_type();
    sqlx::query(
        "INSERT INTO kbs_owner_bindings (
            app_id, binding_key, repository, allowed_tags, namespace, service_account,
            tenant_instance_identity_hash, deleted_at
         )
         VALUES ($1, $2, 'default', ARRAY['seed-encrypted', 'seed-sealed'], $3, $4, $5, NULL)
         ON CONFLICT (app_id) DO UPDATE
         SET binding_key = EXCLUDED.binding_key,
             repository = EXCLUDED.repository,
             allowed_tags = EXCLUDED.allowed_tags,
             namespace = EXCLUDED.namespace,
             service_account = EXCLUDED.service_account,
             tenant_instance_identity_hash = EXCLUDED.tenant_instance_identity_hash,
             deleted_at = NULL,
             updated_at = now()",
    )
    .bind(app.app_id)
    .bind(&binding_key)
    .bind(&app.namespace)
    .bind(&app.service_account)
    .bind(&app.tenant_instance_identity_hash)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn ensure_tls_binding(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    app: &ConfidentialApp,
) -> Result<(), KbsPolicyError> {
    let Some(config) = config else {
        return Ok(());
    };

    let binding_key = app.tls_resource_type();
    sqlx::query(
        "INSERT INTO kbs_tls_bindings (
            app_id, binding_key, repository, tag, namespace, service_account,
            tenant_instance_identity_hash, deleted_at
         )
         VALUES ($1, $2, 'default', 'workload-secret-seed', $3, $4, $5, NULL)
         ON CONFLICT (app_id) DO UPDATE
         SET binding_key = EXCLUDED.binding_key,
             repository = EXCLUDED.repository,
             tag = EXCLUDED.tag,
             namespace = EXCLUDED.namespace,
             service_account = EXCLUDED.service_account,
             tenant_instance_identity_hash = EXCLUDED.tenant_instance_identity_hash,
             deleted_at = NULL,
             updated_at = now()",
    )
    .bind(app.app_id)
    .bind(&binding_key)
    .bind(&app.namespace)
    .bind(&app.service_account)
    .bind(&app.tenant_instance_identity_hash)
    .execute(db)
    .await?;

    ensure_tls_seed_resource(config, &binding_key).await?;
    Ok(())
}

pub async fn soft_delete_owner_binding(db: &PgPool, app_id: Uuid) -> Result<(), KbsPolicyError> {
    sqlx::query(
        "UPDATE kbs_owner_bindings
         SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
         WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn soft_delete_tls_binding(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
    app_id: Uuid,
) -> Result<(), KbsPolicyError> {
    let binding_key = sqlx::query_scalar::<_, String>(
        "SELECT binding_key
         FROM kbs_tls_bindings
         WHERE app_id = $1 AND deleted_at IS NULL",
    )
    .bind(app_id)
    .fetch_optional(db)
    .await?;

    sqlx::query(
        "UPDATE kbs_tls_bindings
         SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
         WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(db)
    .await?;

    if let (Some(config), Some(binding_key)) = (config, binding_key) {
        delete_tls_seed_resource(config, &binding_key).await?;
    }

    Ok(())
}

pub async fn reconcile_policy(
    db: &PgPool,
    config: Option<&KbsPolicyConfig>,
) -> Result<(), KbsPolicyError> {
    let Some(config) = config else {
        return Ok(());
    };

    let bindings: Vec<KbsOwnerBinding> = sqlx::query_as(
        "SELECT binding_key, repository, allowed_tags, namespace, service_account,
                tenant_instance_identity_hash
         FROM kbs_owner_bindings
         WHERE deleted_at IS NULL
         ORDER BY binding_key",
    )
    .fetch_all(db)
    .await?;
    let tls_bindings: Vec<KbsTlsBinding> = sqlx::query_as(
        "SELECT binding_key, repository, tag, namespace, service_account,
                tenant_instance_identity_hash
         FROM kbs_tls_bindings
         WHERE deleted_at IS NULL
         ORDER BY binding_key",
    )
    .fetch_all(db)
    .await?;

    let client = kube::Client::try_default().await?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let cm = cm_api.get(&config.configmap_name).await?;
    let mut data = cm.data.unwrap_or_default();
    let current_policy = data
        .get(&config.policy_key)
        .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
    let next_policy = replace_tls_resource_bindings_block(current_policy, &tls_bindings)?;
    let next_policy = replace_owner_bindings_block(&next_policy, &bindings)?;

    if next_policy != *current_policy {
        data.insert(config.policy_key.clone(), next_policy);
        let patch = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": config.configmap_name,
                "namespace": config.namespace,
            },
            "data": data,
        });
        let pp = PatchParams::apply("enclava-platform").force();
        cm_api
            .patch(&config.configmap_name, &pp, &Patch::Apply(&patch))
            .await?;
        restart_trustee_deployment(client, config).await?;
    }

    Ok(())
}

async fn ensure_tls_seed_resource(
    config: &KbsPolicyConfig,
    resource_name: &str,
) -> Result<(), KbsPolicyError> {
    if let Some(writer_url) = &config.resource_writer_url {
        ensure_tls_seed_repository_resource(config, writer_url, resource_name).await?;
        return Ok(());
    }

    let client = kube::Client::try_default().await?;
    ensure_tls_seed_secret(client.clone(), config, resource_name).await?;
    ensure_kbs_config_secret_resource(client.clone(), config, resource_name).await?;
    ensure_trustee_secret_resource_mount(client, config, resource_name).await?;
    Ok(())
}

async fn ensure_tls_seed_repository_resource(
    config: &KbsPolicyConfig,
    writer_url: &str,
    resource_name: &str,
) -> Result<(), KbsPolicyError> {
    let base = writer_url.trim_end_matches('/');
    let url = format!("{base}/resources/default/{resource_name}/workload-secret-seed");
    let client = reqwest::Client::new();
    let mut request = client.put(url);
    if let Some(token) = &config.resource_writer_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(KbsPolicyError::ResourceWriterStatus { status, body })
}

async fn delete_tls_seed_resource(
    config: &KbsPolicyConfig,
    resource_name: &str,
) -> Result<(), KbsPolicyError> {
    let Some(writer_url) = &config.resource_writer_url else {
        return Ok(());
    };

    let base = writer_url.trim_end_matches('/');
    let url = format!("{base}/resources/default/{resource_name}/workload-secret-seed");
    let client = reqwest::Client::new();
    let mut request = client.delete(url);
    if let Some(token) = &config.resource_writer_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(KbsPolicyError::ResourceWriterStatus { status, body })
}

async fn ensure_tls_seed_secret(
    client: kube::Client,
    config: &KbsPolicyConfig,
    resource_name: &str,
) -> Result<(), KbsPolicyError> {
    let secrets: Api<Secret> = Api::namespaced(client, &config.namespace);
    match secrets.get(resource_name).await {
        Ok(existing) => {
            let has_seed = existing
                .data
                .as_ref()
                .and_then(|data| data.get("workload-secret-seed"))
                .map(|value| !value.0.is_empty())
                .unwrap_or(false);
            if has_seed {
                return Ok(());
            }
        }
        Err(kube::Error::Api(err)) if err.code == 404 => {}
        Err(err) => return Err(err.into()),
    }

    let mut seed_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
    let seed = hex::encode(seed_bytes);
    let mut string_data = BTreeMap::new();
    string_data.insert("workload-secret-seed".to_string(), seed);
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(resource_name.to_string()),
            namespace: Some(config.namespace.clone()),
            ..Default::default()
        },
        string_data: Some(string_data),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    };
    let pp = PatchParams::apply("enclava-platform").force();
    secrets
        .patch(resource_name, &pp, &Patch::Apply(&secret))
        .await?;
    Ok(())
}

async fn ensure_kbs_config_secret_resource(
    client: kube::Client,
    config: &KbsPolicyConfig,
    resource_name: &str,
) -> Result<(), KbsPolicyError> {
    let gvk = GroupVersionKind::gvk("confidentialcontainers.org", "v1alpha1", "KbsConfig");
    let ar = ApiResource::from_gvk(&gvk);
    let api: Api<DynamicObject> = Api::namespaced_with(client, &config.namespace, &ar);
    let current = api.get(&config.kbs_config_name).await?;
    let Some(items) = current
        .data
        .get("spec")
        .and_then(|spec| spec.get("kbsSecretResources"))
        .and_then(Value::as_array)
    else {
        return Err(KbsPolicyError::InvalidKbsConfig);
    };
    let mut resources: Vec<String> = items
        .iter()
        .filter_map(|item| item.as_str().map(ToString::to_string))
        .collect();
    if resources.iter().any(|item| item == resource_name) {
        return Ok(());
    }
    resources.push(resource_name.to_string());

    let patch = serde_json::json!({
        "apiVersion": "confidentialcontainers.org/v1alpha1",
        "kind": "KbsConfig",
        "metadata": {
            "name": config.kbs_config_name,
            "namespace": config.namespace,
        },
        "spec": {
            "kbsSecretResources": resources,
        }
    });
    let pp = PatchParams::apply("enclava-platform").force();
    api.patch(&config.kbs_config_name, &pp, &Patch::Apply(&patch))
        .await?;
    restart_trustee_deployment(kube::Client::try_default().await?, config).await?;
    Ok(())
}

async fn ensure_trustee_secret_resource_mount(
    client: kube::Client,
    config: &KbsPolicyConfig,
    resource_name: &str,
) -> Result<(), KbsPolicyError> {
    let deploy_api: Api<Deployment> = Api::namespaced(client, &config.namespace);
    let deployment = deploy_api.get(&config.deployment_name).await?;
    let spec = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref());
    let kbs_container_index = spec
        .and_then(|spec| {
            spec.containers
                .iter()
                .position(|container| container.name == "kbs")
        })
        .ok_or(KbsPolicyError::MissingKbsContainer)?;
    let volume_name = kbs_secret_volume_name(resource_name);
    let volume_present = spec
        .and_then(|spec| spec.volumes.as_ref())
        .map(|volumes| volumes.iter().any(|volume| volume.name == volume_name))
        .unwrap_or(false);
    let mount_present = spec
        .and_then(|spec| {
            spec.containers
                .iter()
                .find(|container| container.name == "kbs")
        })
        .and_then(|container| container.volume_mounts.as_ref())
        .map(|mounts| mounts.iter().any(|mount| mount.name == volume_name))
        .unwrap_or(false);

    if volume_present && mount_present {
        return Ok(());
    }

    let mount_path = format!("/opt/confidential-containers/kbs/repository/default/{resource_name}");
    let mut ops = Vec::new();
    if !volume_present {
        ops.push(add_patch_op(
            "/spec/template/spec/volumes/-",
            serde_json::json!({
                "name": volume_name,
                "secret": {
                    "secretName": resource_name
                }
            }),
        ));
    }
    if !mount_present {
        ops.push(add_patch_op(
            &format!("/spec/template/spec/containers/{kbs_container_index}/volumeMounts/-"),
            serde_json::json!({
                "name": volume_name,
                "mountPath": mount_path,
                "readOnly": true
            }),
        ));
    }

    let pp = PatchParams::default();
    deploy_api
        .patch(
            &config.deployment_name,
            &pp,
            &Patch::<()>::Json(json_patch::Patch(ops)),
        )
        .await?;
    wait_for_deployment_ready(&deploy_api, &config.deployment_name).await?;
    Ok(())
}

fn add_patch_op(path: &str, value: Value) -> PatchOperation {
    PatchOperation::Add(AddOperation {
        path: json_patch::jsonptr::PointerBuf::parse(path)
            .expect("JSON patch paths are hard-coded and valid"),
        value,
    })
}

fn kbs_secret_volume_name(resource_name: &str) -> String {
    let mut safe: String = resource_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    safe = safe.trim_matches('-').to_string();
    if safe.is_empty() {
        safe = "resource".to_string();
    }

    let digest = hex::encode(Sha256::digest(resource_name.as_bytes()));
    let prefix_len = 63 - "kbs-tls-".len() - 1 - 12;
    let prefix: String = safe.chars().take(prefix_len).collect();
    format!("kbs-tls-{prefix}-{}", &digest[..12])
}

async fn restart_trustee_deployment(
    client: kube::Client,
    config: &KbsPolicyConfig,
) -> Result<(), KbsPolicyError> {
    let deploy_api: Api<Deployment> = Api::namespaced(client, &config.namespace);
    let restarted_at: DateTime<Utc> = Utc::now();
    let patch = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": config.deployment_name,
            "namespace": config.namespace,
        },
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "enclava.dev/cap-policy-restarted-at": restarted_at.to_rfc3339()
                    }
                }
            }
        }
    });
    let pp = PatchParams::apply("enclava-platform").force();
    deploy_api
        .patch(&config.deployment_name, &pp, &Patch::Apply(&patch))
        .await?;
    wait_for_deployment_ready(&deploy_api, &config.deployment_name).await?;
    Ok(())
}

async fn wait_for_deployment_ready(
    deploy_api: &Api<Deployment>,
    name: &str,
) -> Result<(), KbsPolicyError> {
    let start = Instant::now();
    let timeout = Duration::from_secs(180);

    loop {
        let deployment = deploy_api.get(name).await?;
        let spec_replicas = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.replicas)
            .unwrap_or(1);
        let status = deployment.status.as_ref();
        let observed = status.and_then(|s| s.observed_generation).unwrap_or(0);
        let generation = deployment.metadata.generation.unwrap_or(0);
        let updated = status.and_then(|s| s.updated_replicas).unwrap_or(0);
        let available = status.and_then(|s| s.available_replicas).unwrap_or(0);

        if observed >= generation && updated >= spec_replicas && available >= spec_replicas {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(KbsPolicyError::RolloutTimedOut);
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn replace_tls_resource_bindings_block(
    policy: &str,
    bindings: &[KbsTlsBinding],
) -> Result<String, KbsPolicyError> {
    let marker = "resource_bindings := {";
    let cap_begin = "# BEGIN CAP MANAGED TLS RESOURCE BINDINGS";
    let cap_end = "# END CAP MANAGED TLS RESOURCE BINDINGS";
    let start = policy
        .find(marker)
        .ok_or(KbsPolicyError::MissingResourceBindingsBlock)?;
    replace_bindings_block(
        policy,
        marker,
        start,
        cap_begin,
        cap_end,
        &render_cap_tls_resource_bindings_section(bindings),
    )
}

fn replace_owner_bindings_block(
    policy: &str,
    bindings: &[KbsOwnerBinding],
) -> Result<String, KbsPolicyError> {
    let marker = "owner_resource_bindings := {";
    let cap_begin = "# BEGIN CAP MANAGED OWNER BINDINGS";
    let cap_end = "# END CAP MANAGED OWNER BINDINGS";
    let start = policy
        .find(marker)
        .ok_or(KbsPolicyError::MissingOwnerBindingsBlock)?;
    replace_bindings_block(
        policy,
        marker,
        start,
        cap_begin,
        cap_end,
        &render_cap_owner_bindings_section(bindings),
    )
}

fn replace_bindings_block(
    policy: &str,
    marker: &str,
    start: usize,
    cap_begin: &str,
    cap_end: &str,
    cap_section: &str,
) -> Result<String, KbsPolicyError> {
    let open_brace = start + marker.len() - 1;
    let mut depth = 0i32;
    let mut end = None;

    for (offset, ch) in policy[open_brace..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(open_brace + offset + ch.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }

    let Some(end) = end else {
        return Err(if marker == "resource_bindings := {" {
            KbsPolicyError::MissingResourceBindingsBlock
        } else {
            KbsPolicyError::MissingOwnerBindingsBlock
        });
    };

    let block_body_start = open_brace + 1;
    let block_body_end = end - 1;
    let block_body = &policy[block_body_start..block_body_end];

    if let (Some(begin_rel), Some(end_rel)) = (block_body.find(cap_begin), block_body.find(cap_end))
    {
        let begin = block_body_start + begin_rel;
        let end_marker_end = block_body_start + end_rel + cap_end.len();
        let line_end = policy[end_marker_end..]
            .find('\n')
            .map(|offset| end_marker_end + offset)
            .unwrap_or(end_marker_end);

        let mut next = String::with_capacity(policy.len() + cap_section.len());
        next.push_str(&policy[..begin]);
        next.push_str(cap_section.trim_start_matches(','));
        next.push_str(&policy[line_end..]);
        return Ok(next);
    }

    let section = if block_body.trim().is_empty() {
        cap_section.trim_start_matches(',').to_string()
    } else {
        cap_section.to_string()
    };
    let mut next = String::with_capacity(policy.len() + section.len());
    next.push_str(&policy[..block_body_end]);
    next.push_str(&section);
    next.push_str(&policy[block_body_end..]);
    Ok(next)
}

fn render_cap_tls_resource_bindings_section(bindings: &[KbsTlsBinding]) -> String {
    let mut out = String::new();
    out.push(',');
    out.push_str("\n  # BEGIN CAP MANAGED TLS RESOURCE BINDINGS\n");
    let entries: Vec<String> = bindings
        .iter()
        .map(|binding| {
            format!(
                "  {key}: {{\n    \"repository\": {repo},\n    \"tag\": {tag},\n    \"allowed_images\": [],\n    \"allowed_image_tag_prefixes\": [],\n    \"allowed_init_data_hashes\": [],\n    \"allowed_namespaces\": [{namespace}],\n    \"allowed_service_accounts\": [{service_account}],\n    \"allowed_identity_hashes\": [{identity_hash}]\n  }}",
                key = json_string(&binding.binding_key),
                repo = json_string(&binding.repository),
                tag = json_string(&binding.tag),
                namespace = json_string(&binding.namespace),
                service_account = json_string(&binding.service_account),
                identity_hash = json_string(&binding.tenant_instance_identity_hash),
            )
        })
        .collect();
    out.push_str(&entries.join(",\n"));
    if !entries.is_empty() {
        out.push('\n');
    }
    out.push_str("  # END CAP MANAGED TLS RESOURCE BINDINGS\n");
    out
}

fn render_cap_owner_bindings_section(bindings: &[KbsOwnerBinding]) -> String {
    let mut out = String::new();
    out.push(',');
    out.push_str("\n  # BEGIN CAP MANAGED OWNER BINDINGS\n");
    let entries: Vec<String> = bindings
        .iter()
        .map(|binding| {
            format!(
                "  {key}: {{\n    \"repository\": {repo},\n    \"allowed_tags\": {tags},\n    \"allowed_namespaces\": [{namespace}],\n    \"allowed_service_accounts\": [{service_account}],\n    \"allowed_identity_hashes\": [{identity_hash}]\n  }}",
                key = json_string(&binding.binding_key),
                repo = json_string(&binding.repository),
                tags = json_string_array(&binding.allowed_tags),
                namespace = json_string(&binding.namespace),
                service_account = json_string(&binding.service_account),
                identity_hash = json_string(&binding.tenant_instance_identity_hash),
            )
        })
        .collect();
    out.push_str(&entries.join(",\n"));
    if !entries.is_empty() {
        out.push('\n');
    }
    out.push_str("  # END CAP MANAGED OWNER BINDINGS\n");
    out
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization is infallible")
}

fn json_string_array(values: &[String]) -> String {
    serde_json::to_string(values).expect("string array serialization is infallible")
}

pub fn config_from_env() -> Option<KbsPolicyConfig> {
    let required = std::env::var("KBS_POLICY_MANAGEMENT_REQUIRED")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let enabled = required
        || std::env::var("KBS_POLICY_MANAGEMENT_ENABLED")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

    if !enabled {
        return None;
    }

    Some(KbsPolicyConfig {
        namespace: std::env::var("KBS_POLICY_NAMESPACE")
            .unwrap_or_else(|_| "trustee-operator-system".to_string()),
        configmap_name: std::env::var("KBS_POLICY_CONFIGMAP")
            .unwrap_or_else(|_| "resource-policy".to_string()),
        policy_key: std::env::var("KBS_POLICY_KEY").unwrap_or_else(|_| "policy.rego".to_string()),
        deployment_name: std::env::var("KBS_POLICY_DEPLOYMENT")
            .unwrap_or_else(|_| "trustee-deployment".to_string()),
        kbs_config_name: std::env::var("KBS_POLICY_KBSCONFIG")
            .unwrap_or_else(|_| "kbsconfig-sample".to_string()),
        resource_writer_url: std::env::var("KBS_RESOURCE_WRITER_URL")
            .ok()
            .filter(|url| !url.trim().is_empty()),
        resource_writer_token: std::env::var("KBS_RESOURCE_WRITER_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty()),
        required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(key: &str) -> KbsOwnerBinding {
        KbsOwnerBinding {
            binding_key: key.to_string(),
            repository: "default".to_string(),
            allowed_tags: vec!["seed-encrypted".to_string(), "seed-sealed".to_string()],
            namespace: "cap-test".to_string(),
            service_account: "cap-test-sa".to_string(),
            tenant_instance_identity_hash: "abc123".to_string(),
        }
    }

    fn config() -> KbsPolicyConfig {
        KbsPolicyConfig {
            namespace: "trustee-operator-system".to_string(),
            configmap_name: "resource-policy".to_string(),
            policy_key: "policy.rego".to_string(),
            deployment_name: "trustee-deployment".to_string(),
            kbs_config_name: "kbsconfig-sample".to_string(),
            resource_writer_url: None,
            resource_writer_token: None,
            required: true,
        }
    }

    fn tls_binding(key: &str) -> KbsTlsBinding {
        KbsTlsBinding {
            binding_key: key.to_string(),
            repository: "default".to_string(),
            tag: "workload-secret-seed".to_string(),
            namespace: "cap-test".to_string(),
            service_account: "cap-test-sa".to_string(),
            tenant_instance_identity_hash: "abc123".to_string(),
        }
    }

    #[test]
    fn replaces_only_owner_bindings_block() {
        let policy = r#"package policy

resource_bindings := {
  "legacy": {"repository": "default"}
}

owner_resource_bindings := {
  "old-owner": {
    "repository": "default"
  }
}

allow if {
  binding := owner_resource_bindings["x"]
}
"#;

        let next = replace_owner_bindings_block(policy, &[binding("new-owner")]).unwrap();
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("\"old-owner\""));
        assert!(next.contains("\"new-owner\""));
        assert!(next.contains("BEGIN CAP MANAGED OWNER BINDINGS"));
        assert!(next.contains("allow if"));
    }

    #[test]
    fn replaces_existing_cap_managed_section() {
        let policy = r#"owner_resource_bindings := {
  "legacy-owner": {
    "repository": "default"
  },
  # BEGIN CAP MANAGED OWNER BINDINGS
  "old-cap-owner": {
    "repository": "default"
  }
  # END CAP MANAGED OWNER BINDINGS
}
"#;

        let next = replace_owner_bindings_block(policy, &[binding("new-cap-owner")]).unwrap();
        assert!(next.contains("\"legacy-owner\""));
        assert!(next.contains("\"new-cap-owner\""));
        assert!(!next.contains("\"old-cap-owner\""));
    }

    #[test]
    fn renders_empty_cap_section() {
        assert_eq!(
            render_cap_owner_bindings_section(&[]),
            ",\n  # BEGIN CAP MANAGED OWNER BINDINGS\n  # END CAP MANAGED OWNER BINDINGS\n"
        );
    }

    #[test]
    fn replaces_tls_resource_bindings_block() {
        let policy = r#"package policy

resource_bindings := {
  "legacy": {"repository": "default"}
}

owner_resource_bindings := {}
"#;

        let next = replace_tls_resource_bindings_block(policy, &[tls_binding("cap-test-app-tls")])
            .unwrap();
        assert!(next.contains("\"legacy\""));
        assert!(next.contains("\"cap-test-app-tls\""));
        assert!(next.contains("BEGIN CAP MANAGED TLS RESOURCE BINDINGS"));
        assert!(next.contains("owner_resource_bindings := {}"));
    }

    #[test]
    fn kbs_secret_volume_name_is_dns_label_sized() {
        let name = kbs_secret_volume_name(
            "cap-very-long-org-name-with-many-segments-and-a-long-app-name-tls",
        );
        assert!(name.len() <= 63);
        assert!(name.starts_with("kbs-tls-"));
        assert!(
            name.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        );
    }

    #[test]
    fn config_can_select_resource_writer() {
        let mut cfg = config();
        cfg.resource_writer_url = Some("http://writer".to_string());
        cfg.resource_writer_token = Some("token".to_string());
        assert_eq!(cfg.resource_writer_url.as_deref(), Some("http://writer"));
        assert_eq!(cfg.resource_writer_token.as_deref(), Some("token"));
    }
}
