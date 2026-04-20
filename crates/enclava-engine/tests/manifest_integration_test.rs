use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::manifest::kbs_policy::generate_kbs_policy_rego;
use enclava_engine::testutil::sample_app;

#[test]
fn generate_all_manifests_returns_all_resources() {
    let app = sample_app();
    let m = generate_all_manifests(&app);

    // Namespace
    assert_eq!(
        m.namespace.metadata.name.as_deref(),
        Some("cap-test-org-test-app")
    );

    // ServiceAccount
    assert_eq!(
        m.service_account.metadata.name.as_deref(),
        Some("cap-test-app-sa")
    );

    // NetworkPolicy (CiliumNetworkPolicy CRD)
    assert_eq!(m.network_policy["kind"], "CiliumNetworkPolicy");
    assert_eq!(
        m.network_policy["metadata"]["namespace"],
        "cap-test-org-test-app"
    );

    // ResourceQuota
    assert_eq!(
        m.resource_quota.metadata.name.as_deref(),
        Some("tenant-quota")
    );

    // Service
    assert_eq!(m.service.metadata.name.as_deref(), Some("test-app"));

    // Bootstrap ConfigMap
    assert_eq!(
        m.bootstrap_configmap.metadata.name.as_deref(),
        Some("secure-pv-bootstrap-script")
    );

    // Ingress ConfigMap
    assert_eq!(
        m.ingress_configmap.metadata.name.as_deref(),
        Some("test-app-tenant-ingress")
    );

    // StatefulSet
    assert_eq!(m.statefulset.metadata.name.as_deref(), Some("test-app"));
    let containers = &m
        .statefulset
        .spec
        .as_ref()
        .unwrap()
        .template
        .spec
        .as_ref()
        .unwrap()
        .containers;
    assert_eq!(containers.len(), 3);

    // KBS owner binding
    let (key, value) = &m.kbs_owner_binding;
    assert!(key.ends_with("-owner"));
    assert!(value.get("allowed_identity_hashes").is_some());
}

#[test]
fn all_namespaced_resources_share_namespace() {
    let app = sample_app();
    let m = generate_all_manifests(&app);
    let ns = "cap-test-org-test-app";

    assert_eq!(m.namespace.metadata.name.as_deref(), Some(ns));
    assert_eq!(m.service_account.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.resource_quota.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.service.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(
        m.bootstrap_configmap.metadata.namespace.as_deref(),
        Some(ns)
    );
    assert_eq!(m.ingress_configmap.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.statefulset.metadata.namespace.as_deref(), Some(ns));
    assert_eq!(m.network_policy["metadata"]["namespace"].as_str(), Some(ns));
}

#[test]
fn all_managed_resources_have_managed_by_label() {
    let app = sample_app();
    let m = generate_all_manifests(&app);
    let managed_by = "enclava-platform";

    // Namespace
    let ns_labels = m.namespace.metadata.labels.as_ref().unwrap();
    assert_eq!(
        ns_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // ServiceAccount
    let sa_labels = m.service_account.metadata.labels.as_ref().unwrap();
    assert_eq!(
        sa_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // ResourceQuota
    let rq_labels = m.resource_quota.metadata.labels.as_ref().unwrap();
    assert_eq!(
        rq_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // Service
    let svc_labels = m.service.metadata.labels.as_ref().unwrap();
    assert_eq!(
        svc_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // StatefulSet
    let sts_labels = m.statefulset.metadata.labels.as_ref().unwrap();
    assert_eq!(
        sts_labels
            .get("app.kubernetes.io/managed-by")
            .map(|s| s.as_str()),
        Some(managed_by)
    );

    // CiliumNetworkPolicy
    assert_eq!(
        m.network_policy["metadata"]["labels"]["app.kubernetes.io/managed-by"].as_str(),
        Some(managed_by)
    );
}

#[test]
fn kbs_policy_rego_integrates_with_owner_binding() {
    let app = sample_app();
    let m = generate_all_manifests(&app);

    let rego = generate_kbs_policy_rego(&[&app], "");
    let (key, _) = &m.kbs_owner_binding;
    assert!(rego.contains("owner_resource_bindings"));
    assert!(rego.contains(key));
}

#[test]
fn manifests_serialize_to_yaml() {
    let app = sample_app();
    let m = generate_all_manifests(&app);

    // Each k8s-openapi type must round-trip through serde_yaml
    let ns_yaml = serde_yaml::to_string(&m.namespace).unwrap();
    assert!(ns_yaml.contains("cap-test-org-test-app"));

    let sa_yaml = serde_yaml::to_string(&m.service_account).unwrap();
    assert!(sa_yaml.contains("cap-test-app-sa"));

    let rq_yaml = serde_yaml::to_string(&m.resource_quota).unwrap();
    assert!(rq_yaml.contains("tenant-quota"));

    let svc_yaml = serde_yaml::to_string(&m.service).unwrap();
    assert!(svc_yaml.contains("test-app"));

    let sts_yaml = serde_yaml::to_string(&m.statefulset).unwrap();
    assert!(sts_yaml.contains("kata-qemu-snp"));

    let cm_yaml = serde_yaml::to_string(&m.bootstrap_configmap).unwrap();
    assert!(cm_yaml.contains("secure-pv-bootstrap-script"));

    let ingress_yaml = serde_yaml::to_string(&m.ingress_configmap).unwrap();
    assert!(ingress_yaml.contains("test-app-tenant-ingress"));

    // CiliumNetworkPolicy is Value, uses serde_json for serialization
    let np_yaml = serde_yaml::to_string(&m.network_policy).unwrap();
    assert!(np_yaml.contains("CiliumNetworkPolicy"));
}
