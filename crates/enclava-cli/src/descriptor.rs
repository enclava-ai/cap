//! Customer-signed deployment descriptor (Phase 7 — D10 / D11 rev14).
//!
//! Descriptor types and CE-v1 canonicalisation live in `enclava-common` so the
//! CLI signer, signing service, and in-TEE verifier share one byte layout.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
pub use enclava_common::descriptor::{
    Capabilities, DeploymentDescriptor, EnvVar, Mount, OciRuntimeSpec, Port, Resources,
    SecurityContext, Sidecars, SignerIdentity, canonical_oci_spec_bytes,
    canonical_sidecar_map_bytes, canonical_signer_bytes, descriptor_canonical_bytes,
    descriptor_core_canonical_bytes, descriptor_core_hash,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::UserSigningKey;

#[derive(Debug, Error)]
pub enum DescriptorError {
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("home directory not available")]
    NoHome,
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentDescriptorEnvelope {
    pub descriptor: DeploymentDescriptor,
    #[serde(with = "hex_sig")]
    pub signature: Signature,
    pub signing_key_id: String,
    #[serde(with = "hex_pubkey")]
    pub signing_pubkey: VerifyingKey,
}

mod hex_sig {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("len != 64"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

mod hex_pubkey {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(k: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(k.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("len != 32"))?;
        VerifyingKey::from_bytes(&arr).map_err(D::Error::custom)
    }
}

pub fn sign(
    deployer: &UserSigningKey,
    descriptor: DeploymentDescriptor,
    signing_key_id: String,
) -> DeploymentDescriptorEnvelope {
    let bytes = descriptor_canonical_bytes(&descriptor);
    let signature = deployer.sign(&bytes);
    DeploymentDescriptorEnvelope {
        descriptor,
        signature,
        signing_key_id,
        signing_pubkey: deployer.public,
    }
}

pub fn verify<'e>(
    envelope: &'e DeploymentDescriptorEnvelope,
    expected_pubkey: &VerifyingKey,
) -> Result<&'e DeploymentDescriptor, DescriptorError> {
    if envelope.signing_pubkey.to_bytes() != expected_pubkey.to_bytes() {
        return Err(DescriptorError::Verify(
            "signing pubkey mismatch".to_string(),
        ));
    }
    let bytes = descriptor_canonical_bytes(&envelope.descriptor);
    expected_pubkey
        .verify(&bytes, &envelope.signature)
        .map_err(|e| DescriptorError::Verify(e.to_string()))?;
    Ok(&envelope.descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn fixed_descriptor() -> DeploymentDescriptor {
        DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "abcd1234".to_string(),
            app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "demo".to_string(),
            deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap(),
            nonce: [7; 32],
            app_domain: "demo.abcd1234.enclava.dev".to_string(),
            tee_domain: "demo.abcd1234.tee.enclava.dev".to_string(),
            custom_domains: vec!["app.example.com".to_string()],
            namespace: "cap-abcd1234-demo".to_string(),
            service_account: "cap-demo-sa".to_string(),
            identity_hash: [9; 32],
            image_digest: "sha256:aaaa".to_string(),
            signer_identity: SignerIdentity {
                subject: "https://github.com/x/y/.github/workflows/build.yml".to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/app".to_string()],
                args: vec!["--serve".to_string()],
                env: vec![
                    EnvVar {
                        name: "B".to_string(),
                        value: "2".to_string(),
                    },
                    EnvVar {
                        name: "A".to_string(),
                        value: "1".to_string(),
                    },
                ],
                ports: vec![Port {
                    container_port: 3000,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest: "sha256:1111".to_string(),
                caddy_digest: "sha256:2222".to_string(),
            },
            expected_firmware_measurement: [3; 32],
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-abcd1234-demo-tls-owner".to_string(),
            policy_template_id: "kbs-release-policy-v3".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "platform-2026.04".to_string(),
            expected_cc_init_data_hash: [5; 32],
            expected_kbs_policy_hash: [6; 32],
        }
    }

    #[test]
    fn signing_round_trips() {
        let key = UserSigningKey::generate(Uuid::new_v4());
        let env = sign(&key, fixed_descriptor(), "key-1".to_string());
        verify(&env, &key.public).unwrap();
    }

    #[test]
    fn descriptor_core_excludes_chain_anchors() {
        let mut d = fixed_descriptor();
        let h1 = descriptor_core_hash(&d);
        d.expected_cc_init_data_hash = [0xFF; 32];
        d.expected_kbs_policy_hash = [0xFE; 32];
        let h2 = descriptor_core_hash(&d);
        assert_eq!(h1, h2, "core hash must NOT include expected_*_hash fields");
    }

    #[test]
    fn full_signature_changes_when_chain_anchor_changes() {
        let mut d_a = fixed_descriptor();
        let mut d_b = d_a.clone();
        d_b.expected_cc_init_data_hash = [0xFF; 32];
        assert_ne!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b)
        );
        d_a.expected_cc_init_data_hash = [0xFF; 32];
        assert_eq!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b)
        );
    }

    #[test]
    fn env_canonicalization_is_name_sorted() {
        let oci_a = OciRuntimeSpec {
            command: vec![],
            args: vec![],
            env: vec![
                EnvVar {
                    name: "B".into(),
                    value: "2".into(),
                },
                EnvVar {
                    name: "A".into(),
                    value: "1".into(),
                },
            ],
            ports: vec![],
            mounts: vec![],
            capabilities: Capabilities::default(),
            security_context: SecurityContext::default(),
            resources: Resources::default(),
        };
        let oci_b = OciRuntimeSpec {
            command: vec![],
            args: vec![],
            env: vec![
                EnvVar {
                    name: "A".into(),
                    value: "1".into(),
                },
                EnvVar {
                    name: "B".into(),
                    value: "2".into(),
                },
            ],
            ports: vec![],
            mounts: vec![],
            capabilities: Capabilities::default(),
            security_context: SecurityContext::default(),
            resources: Resources::default(),
        };
        assert_eq!(
            canonical_oci_spec_bytes(&oci_a),
            canonical_oci_spec_bytes(&oci_b),
            "env must canonicalize regardless of input order"
        );
    }

    #[test]
    fn json_round_trip_preserves_canonical_hash() {
        let d = fixed_descriptor();
        let h1 = descriptor_core_hash(&d);
        let json = serde_json::to_string(&d).unwrap();
        let d2: DeploymentDescriptor = serde_json::from_str(&json).unwrap();
        let h2 = descriptor_core_hash(&d2);
        assert_eq!(h1, h2);
    }
}
