use k8s_openapi::api::apps::v1::StatefulSet;
use kube::api::Api;

use crate::manifest::GeneratedManifests;
use crate::types::ConfidentialApp;

use super::engine::{ApplyEngine, ApplyError};
use super::orchestrator::{MANIFEST_HASH_ANNOTATION, manifest_hash};

/// Result of a drift check.
#[derive(Debug, Clone)]
pub struct DriftResult {
    /// Whether drift was detected (desired != live).
    pub has_drift: bool,
    /// The desired manifest hash (computed from current ConfidentialApp spec).
    pub desired_hash: String,
    /// The live manifest hash (from StatefulSet annotation). None if not deployed.
    pub live_hash: Option<String>,
}

impl DriftResult {
    /// Compare two hashes.
    pub fn compare(desired: &str, live: &str) -> Self {
        Self {
            has_drift: desired != live,
            desired_hash: desired.to_string(),
            live_hash: Some(live.to_string()),
        }
    }

    /// Live resource is missing (not deployed).
    pub fn missing(desired: &str) -> Self {
        Self {
            has_drift: true,
            desired_hash: desired.to_string(),
            live_hash: None,
        }
    }
}

/// Check whether the live cluster state matches the desired manifests.
///
/// Compares the SHA256 manifest hash stored on the StatefulSet's annotation
/// (written by `apply_all`) against the hash of the current desired manifests.
///
/// This is a lightweight operation: one GET on the StatefulSet plus a local
/// hash computation. No full manifest diff.
///
/// Returns `DriftResult` indicating whether re-apply is needed.
pub async fn check_drift(
    engine: &ApplyEngine,
    app: &ConfidentialApp,
    manifests: &GeneratedManifests,
) -> Result<DriftResult, ApplyError> {
    let desired = manifest_hash(manifests);

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), &app.namespace);

    match api.get(&app.name).await {
        Ok(sts) => {
            let live = sts
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(MANIFEST_HASH_ANNOTATION))
                .cloned();

            match live {
                Some(live_hash) => {
                    let result = DriftResult::compare(&desired, &live_hash);
                    if result.has_drift {
                        tracing::info!(
                            app = %app.name,
                            namespace = %app.namespace,
                            desired = %desired,
                            live = %live_hash,
                            "drift detected -- manifest hashes differ"
                        );
                    } else {
                        tracing::debug!(
                            app = %app.name,
                            namespace = %app.namespace,
                            hash = %desired,
                            "no drift -- manifests match"
                        );
                    }
                    Ok(result)
                }
                None => {
                    tracing::info!(
                        app = %app.name,
                        namespace = %app.namespace,
                        "drift detected -- StatefulSet missing manifest hash annotation"
                    );
                    Ok(DriftResult::missing(&desired))
                }
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            tracing::info!(
                app = %app.name,
                namespace = %app.namespace,
                "drift detected -- StatefulSet not found"
            );
            Ok(DriftResult::missing(&desired))
        }
        Err(e) => Err(e.into()),
    }
}

/// Drift check is advisory only (Phase 11). Auto-revert is removed: the
/// manifest hash annotation is operator-writable and an attacker with cluster
/// access could roll back to a "clean" hash to suppress detection. Until an
/// attested controller can sign + verify desired state we do not act on
/// drift, only log it. Operators investigate manually.
pub async fn check_and_reconcile(
    engine: &ApplyEngine,
    app: &ConfidentialApp,
    manifests: &GeneratedManifests,
) -> Result<DriftResult, ApplyError> {
    let result = check_drift(engine, app, manifests).await?;

    if result.has_drift {
        tracing::warn!(
            app = %app.name,
            namespace = %app.namespace,
            desired = %result.desired_hash,
            live = ?result.live_hash,
            "drift detected (advisory) -- manifest-hash annotation is operator-writable; \
             auto-revert disabled until an attested controller can verify desired state"
        );
    }

    Ok(result)
}
