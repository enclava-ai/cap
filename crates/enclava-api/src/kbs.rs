use chrono::{DateTime, Utc};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams};
use serde::Deserialize;
use sqlx::PgPool;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use enclava_engine::types::ConfidentialApp;

#[derive(Debug, Clone)]
pub struct KbsPolicyConfig {
    pub namespace: String,
    pub configmap_name: String,
    pub policy_key: String,
    pub deployment_name: String,
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
    #[error("Trustee deployment rollout timed out")]
    RolloutTimedOut,
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

    let client = kube::Client::try_default().await?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let cm = cm_api.get(&config.configmap_name).await?;
    let mut data = cm.data.unwrap_or_default();
    let current_policy = data
        .get(&config.policy_key)
        .ok_or_else(|| KbsPolicyError::MissingPolicyKey(config.policy_key.clone()))?;
    let next_policy = replace_owner_bindings_block(current_policy, &bindings)?;

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
        return Err(KbsPolicyError::MissingOwnerBindingsBlock);
    };

    let block_body_start = open_brace + 1;
    let block_body_end = end - 1;
    let block_body = &policy[block_body_start..block_body_end];
    let cap_section = render_cap_owner_bindings_section(bindings, !block_body.trim().is_empty());

    if let (Some(begin_rel), Some(end_rel)) = (block_body.find(cap_begin), block_body.find(cap_end))
    {
        let begin = block_body_start + begin_rel;
        let end_marker_end = block_body_start + end_rel + cap_end.len();
        let line_end = policy[end_marker_end..]
            .find('\n')
            .map(|offset| end_marker_end + offset)
            .unwrap_or(end_marker_end);

        let mut next = String::with_capacity(policy.len() + bindings.len() * 256);
        next.push_str(&policy[..begin]);
        next.push_str(cap_section.trim_start_matches(','));
        next.push_str(&policy[line_end..]);
        return Ok(next);
    }

    let mut next = String::with_capacity(policy.len() + bindings.len() * 256);
    next.push_str(&policy[..block_body_end]);
    next.push_str(&cap_section);
    next.push_str(&policy[block_body_end..]);
    Ok(next)
}

fn render_cap_owner_bindings_section(
    bindings: &[KbsOwnerBinding],
    needs_leading_comma: bool,
) -> String {
    let mut out = String::new();
    if needs_leading_comma {
        out.push(',');
    }
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
            render_cap_owner_bindings_section(&[], false),
            "\n  # BEGIN CAP MANAGED OWNER BINDINGS\n  # END CAP MANAGED OWNER BINDINGS\n"
        );
    }
}
