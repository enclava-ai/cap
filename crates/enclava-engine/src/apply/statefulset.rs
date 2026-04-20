use k8s_openapi::api::apps::v1::StatefulSet;
use kube::api::{Api, Patch, PatchParams};

use super::engine::{ApplyEngine, ApplyError};

/// Apply a StatefulSet via server-side apply.
///
/// Applied after namespace and all supporting resources (SA, ConfigMaps, Service)
/// are in place, because the StatefulSet references them.
pub async fn apply_statefulset(
    engine: &ApplyEngine,
    namespace: &str,
    statefulset: &StatefulSet,
) -> Result<StatefulSet, ApplyError> {
    let name = statefulset.metadata.name.as_deref().unwrap_or("<unnamed>");

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    let pp = PatchParams::apply(&engine.config().field_manager).force();

    let patched = api.patch(name, &pp, &Patch::Apply(statefulset)).await?;

    tracing::info!(
        namespace = %namespace,
        statefulset = %name,
        "StatefulSet applied via SSA"
    );

    Ok(patched)
}
