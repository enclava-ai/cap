use serde_json::{Value, json};

use crate::types::ConfidentialApp;

/// Generate a CiliumNetworkPolicy (cilium.io/v2 CRD).
///
/// Matches the live shape at enclava-tenant-manifests/infra/network-policy.yaml.
/// Uses serde_json::Value because CiliumNetworkPolicy is a CRD not in k8s-openapi.
///
/// Rules:
/// - Ingress: same namespace + envoy gateway namespace
/// - Egress: DNS (kube-system:53), same namespace, KBS (trustee-operator-system:8080),
///   KBS service, world (80/443)
pub fn generate_network_policy(app: &ConfidentialApp) -> Value {
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
            "egress": [
                // Rule 0: DNS
                {
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
                },
                // Rule 1: same namespace
                {
                    "toEndpoints": [
                        {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": &app.namespace
                            }
                        }
                    ]
                },
                // Rule 2: KBS endpoint (direct pod access)
                {
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
                },
                // Rule 3: KBS service (service routing)
                {
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
                },
                // Rule 4: world HTTP/HTTPS
                {
                    "toEntities": ["world"],
                    "toPorts": [
                        {
                            "ports": [
                                { "port": "80", "protocol": "TCP" },
                                { "port": "443", "protocol": "TCP" }
                            ]
                        }
                    ]
                }
            ]
        }
    })
}
