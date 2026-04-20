use enclava_engine::manifest::network_policy::generate_network_policy;
use enclava_engine::testutil::sample_app;

#[test]
fn network_policy_api_version() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    assert_eq!(val["apiVersion"], "cilium.io/v2");
    assert_eq!(val["kind"], "CiliumNetworkPolicy");
}

#[test]
fn network_policy_namespace() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    assert_eq!(val["metadata"]["namespace"], "cap-test-org-test-app");
}

#[test]
fn network_policy_ingress_allows_same_namespace() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let ingress = &val["spec"]["ingress"];
    let from = &ingress[0]["fromEndpoints"];
    assert_eq!(
        from[0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "cap-test-org-test-app"
    );
}

#[test]
fn network_policy_ingress_allows_envoy_gateway() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let from = &val["spec"]["ingress"][0]["fromEndpoints"];
    assert_eq!(
        from[1]["matchLabels"]["io.kubernetes.pod.namespace"],
        "tenant-envoy"
    );
    assert_eq!(from[1]["matchLabels"]["app.kubernetes.io/name"], "envoy");
}

#[test]
fn network_policy_egress_has_dns() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    let dns_endpoints = &egress[0]["toEndpoints"][0]["matchLabels"];
    assert_eq!(dns_endpoints["io.kubernetes.pod.namespace"], "kube-system");
    assert_eq!(dns_endpoints["k8s-app"], "kube-dns");
    let dns_ports = &egress[0]["toPorts"][0]["ports"];
    assert_eq!(dns_ports[0]["port"], "53");
    assert_eq!(dns_ports[0]["protocol"], "UDP");
    assert_eq!(dns_ports[1]["port"], "53");
    assert_eq!(dns_ports[1]["protocol"], "TCP");
}

#[test]
fn network_policy_egress_has_same_namespace() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    assert_eq!(
        egress[1]["toEndpoints"][0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "cap-test-org-test-app"
    );
}

#[test]
fn network_policy_egress_has_kbs() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    assert_eq!(
        egress[2]["toEndpoints"][0]["matchLabels"]["io.kubernetes.pod.namespace"],
        "trustee-operator-system"
    );
    assert_eq!(egress[2]["toPorts"][0]["ports"][0]["port"], "8080");
}

#[test]
fn network_policy_egress_has_kbs_service() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    assert_eq!(
        egress[3]["toServices"][0]["k8sService"]["namespace"],
        "trustee-operator-system"
    );
    assert_eq!(
        egress[3]["toServices"][0]["k8sService"]["serviceName"],
        "kbs-service"
    );
}

#[test]
fn network_policy_egress_has_world_http_https() {
    let app = sample_app();
    let val = generate_network_policy(&app);
    let egress = &val["spec"]["egress"];
    assert_eq!(egress[4]["toEntities"][0], "world");
    let ports = &egress[4]["toPorts"][0]["ports"];
    assert_eq!(ports[0]["port"], "80");
    assert_eq!(ports[0]["protocol"], "TCP");
    assert_eq!(ports[1]["port"], "443");
    assert_eq!(ports[1]["protocol"], "TCP");
}
