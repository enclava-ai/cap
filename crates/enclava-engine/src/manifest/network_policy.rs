use serde_json::{Value, json};

use crate::types::{ConfidentialApp, EgressRule};

/// Platform-default FQDN egress allowlist.
///
/// Hardcoded so the operator cannot quietly drop these. Caddy needs ACME
/// reachability to issue and renew TLS certs for tenant ingress.
const PLATFORM_DEFAULT_FQDNS: &[&str] = &[
    "acme-v02.api.letsencrypt.org",
    "acme-staging-v02.api.letsencrypt.org",
];

/// Generate a CiliumNetworkPolicy (cilium.io/v2 CRD).
///
/// Default: no egress to `world`. The previous policy allowed unrestricted
/// HTTP/HTTPS egress to the internet, which let a compromised workload
/// exfiltrate plaintext to any host. Phase 11: per-app FQDN allowlist instead.
///
/// Each `EgressRule` becomes a Cilium `toFQDNs` rule scoped to the listed ports.
/// The platform-default allowlist (DNS, KBS, ACME) is always present; per-app
/// `egress_allowlist` adds on top.
pub fn generate_network_policy(app: &ConfidentialApp) -> Value {
    let mut egress = vec![
        // Rule: DNS to kube-dns
        json!({
            "toEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": "kube-system",
                        "k8s-app": "kube-dns"
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        { "port": "53", "protocol": "UDP" },
                        { "port": "53", "protocol": "TCP" }
                    ]
                }
            ]
        }),
        // Rule: same namespace
        json!({
            "toEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": &app.namespace
                    }
                }
            ]
        }),
        // Rule: KBS endpoint (direct pod access)
        json!({
            "toEndpoints": [
                {
                    "matchLabels": {
                        "io.kubernetes.pod.namespace": "trustee-operator-system"
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        { "port": "8080", "protocol": "TCP" }
                    ]
                }
            ]
        }),
        // Rule: KBS service (service routing)
        json!({
            "toServices": [
                {
                    "k8sService": {
                        "namespace": "trustee-operator-system",
                        "serviceName": "kbs-service"
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        { "port": "8080", "protocol": "TCP" }
                    ]
                }
            ]
        }),
    ];

    for fqdn in PLATFORM_DEFAULT_FQDNS {
        egress.push(json!({
            "toFQDNs": [{ "matchName": fqdn }],
            "toPorts": [{ "ports": [{ "port": "443", "protocol": "TCP" }] }],
        }));
    }

    for rule in &app.egress_allowlist {
        egress.push(egress_rule_value(rule));
    }

    json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": "tenant-isolation",
            "namespace": app.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "enclava-platform"
            }
        },
        "spec": {
            "description": "Strict network isolation for confidential workload",
            "endpointSelector": {},
            "ingress": [
                {
                    "fromEndpoints": [
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": &app.namespace
                            }
                        },
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": "tenant-envoy",
                                "app.kubernetes.io/name": "envoy"
                            }
                        }
                    ]
                }
            ],
            "egress": egress,
        }
    })
}

fn egress_rule_value(rule: &EgressRule) -> Value {
    let ports: Vec<Value> = rule
        .ports
        .iter()
        .map(|p| json!({ "port": p.to_string(), "protocol": "TCP" }))
        .collect();
    json!({
        "toFQDNs": [{ "matchName": rule.host }],
        "toPorts": [{ "ports": ports }],
    })
}
