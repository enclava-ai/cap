//! Customer-signed deployment descriptor (Phase 7 — D10 / D11 rev14).
//!
//! The descriptor is the trust anchor: every Rego field, every cc_init_data
//! claim, and every attestation expectation derives from values the customer
//! signed. CE-v1 canonicalisation lives in `enclava_common::canonical`; this
//! module orders the records exactly as D11 specifies.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

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
pub struct SignerIdentity {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub container_port: u32,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    pub source: String,
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityContext {
    pub run_as_user: u32,
    pub run_as_group: u32,
    pub read_only_root_fs: bool,
    pub allow_privilege_escalation: bool,
    pub privileged: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resources {
    #[serde(default)]
    pub requests: Vec<EnvVar>,
    #[serde(default)]
    pub limits: Vec<EnvVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRuntimeSpec {
    pub command: Vec<String>,
    pub args: Vec<String>,
    /// Sorted by name; canonical ordering. Enforced at sign time.
    pub env: Vec<EnvVar>,
    pub ports: Vec<Port>,
    pub mounts: Vec<Mount>,
    pub capabilities: Capabilities,
    pub security_context: SecurityContext,
    pub resources: Resources,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecars {
    pub attestation_proxy_digest: String,
    pub caddy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentDescriptor {
    pub schema_version: String,
    pub org_id: Uuid,
    pub org_slug: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub deploy_id: Uuid,
    pub created_at: DateTime<Utc>,
    #[serde(with = "hex_bytes32")]
    pub nonce: [u8; 32],

    pub app_domain: String,
    pub tee_domain: String,
    #[serde(default)]
    pub custom_domains: Vec<String>,

    pub namespace: String,
    pub service_account: String,
    #[serde(with = "hex_bytes32")]
    pub identity_hash: [u8; 32],

    pub image_digest: String,
    pub signer_identity: SignerIdentity,
    pub oci_runtime_spec: OciRuntimeSpec,
    pub sidecars: Sidecars,

    #[serde(with = "hex_bytes32")]
    pub expected_firmware_measurement: [u8; 32],
    pub expected_runtime_class: String,
    pub kbs_resource_path: String,

    pub policy_template_id: String,
    #[serde(with = "hex_bytes32")]
    pub policy_template_sha256: [u8; 32],
    pub platform_release_version: String,

    /// rev11: forward-chain anchors. Excluded from descriptor_core_canonical_bytes.
    #[serde(with = "hex_bytes32")]
    pub expected_cc_init_data_hash: [u8; 32],
    #[serde(with = "hex_bytes32")]
    pub expected_kbs_policy_hash: [u8; 32],
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

mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 32"))
    }
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
        let arr: [u8; 64] = bytes.try_into().map_err(|_| D::Error::custom("len != 64"))?;
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
        let arr: [u8; 32] = bytes.try_into().map_err(|_| D::Error::custom("len != 32"))?;
        VerifyingKey::from_bytes(&arr).map_err(D::Error::custom)
    }
}

// --- sub-canonicalisations (D11) ---

pub fn canonical_signer_bytes(s: &SignerIdentity) -> [u8; 32] {
    ce_v1_hash(&[
        ("subject", s.subject.as_bytes()),
        ("issuer", s.issuer.as_bytes()),
    ])
}

pub fn canonical_sidecar_map_bytes(s: &Sidecars) -> [u8; 32] {
    // Sorted lexicographically by sidecar name.
    ce_v1_hash(&[
        ("attestation_proxy", s.attestation_proxy_digest.as_bytes()),
        ("caddy", s.caddy_digest.as_bytes()),
    ])
}

fn canonical_string_list_bytes(items: &[String]) -> [u8; 32] {
    let records: Vec<(String, Vec<u8>)> = items
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("i{i}"), v.as_bytes().to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_env_bytes(env: &[EnvVar]) -> [u8; 32] {
    // sorted by name
    let mut sorted: Vec<&EnvVar> = env.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let records: Vec<(String, Vec<u8>)> = sorted
        .iter()
        .map(|e| (e.name.clone(), e.value.as_bytes().to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_ports_bytes(ports: &[Port]) -> [u8; 32] {
    let parts: Vec<(String, Vec<u8>)> = ports
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut v = Vec::with_capacity(4 + p.protocol.len());
            v.extend_from_slice(&p.container_port.to_be_bytes());
            v.extend_from_slice(p.protocol.as_bytes());
            (format!("p{i}"), v)
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_mounts_bytes(mounts: &[Mount]) -> [u8; 32] {
    let parts: Vec<(String, [u8; 32])> = mounts
        .iter()
        .enumerate()
        .map(|(i, m)| {
            (
                format!("m{i}"),
                ce_v1_hash(&[
                    ("source", m.source.as_bytes()),
                    ("destination", m.destination.as_bytes()),
                    ("type", m.mount_type.as_bytes()),
                    ("options", &canonical_string_list_bytes(&m.options)),
                ]),
            )
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_secctx_bytes(s: &SecurityContext) -> [u8; 32] {
    let user = s.run_as_user.to_be_bytes();
    let group = s.run_as_group.to_be_bytes();
    let bits = [
        s.read_only_root_fs as u8,
        s.allow_privilege_escalation as u8,
        s.privileged as u8,
    ];
    ce_v1_hash(&[
        ("run_as_user", &user),
        ("run_as_group", &group),
        ("flags", &bits),
    ])
}

fn canonical_resources_bytes(r: &Resources) -> [u8; 32] {
    ce_v1_hash(&[
        ("requests", &canonical_env_bytes(&r.requests)),
        ("limits", &canonical_env_bytes(&r.limits)),
    ])
}

pub fn canonical_oci_spec_bytes(o: &OciRuntimeSpec) -> [u8; 32] {
    ce_v1_hash(&[
        ("command", &canonical_string_list_bytes(&o.command)),
        ("args", &canonical_string_list_bytes(&o.args)),
        ("env", &canonical_env_bytes(&o.env)),
        ("ports", &canonical_ports_bytes(&o.ports)),
        ("mounts", &canonical_mounts_bytes(&o.mounts)),
        (
            "capabilities_add",
            &canonical_string_list_bytes(&o.capabilities.add),
        ),
        (
            "capabilities_drop",
            &canonical_string_list_bytes(&o.capabilities.drop),
        ),
        ("security_context", &canonical_secctx_bytes(&o.security_context)),
        ("resources", &canonical_resources_bytes(&o.resources)),
    ])
}

// --- top-level canonical bytes ---

fn descriptor_records<'a>(
    d: &'a DeploymentDescriptor,
    purpose: &'a [u8],
    include_chain_anchors: bool,
    sub: &'a DescriptorSubHashes,
) -> Vec<(&'a str, &'a [u8])> {
    let mut r: Vec<(&str, &[u8])> = vec![
        ("purpose", purpose),
        ("schema_version", d.schema_version.as_bytes()),
        ("org_id", d.org_id.as_bytes().as_slice()),
        ("org_slug", d.org_slug.as_bytes()),
        ("app_id", d.app_id.as_bytes().as_slice()),
        ("app_name", d.app_name.as_bytes()),
        ("deploy_id", d.deploy_id.as_bytes().as_slice()),
        ("created_at", sub.created_at.as_bytes()),
        ("nonce", &d.nonce),
        ("app_domain", d.app_domain.as_bytes()),
        ("tee_domain", d.tee_domain.as_bytes()),
        ("custom_domains", &sub.custom_domains_hash),
        ("namespace", d.namespace.as_bytes()),
        ("service_account", d.service_account.as_bytes()),
        ("identity_hash", &d.identity_hash),
        ("image_digest", d.image_digest.as_bytes()),
        ("signer_identity", &sub.signer_hash),
        ("oci_runtime_spec", &sub.oci_hash),
        ("sidecars", &sub.sidecar_hash),
        (
            "expected_firmware_measurement",
            &d.expected_firmware_measurement,
        ),
        ("expected_runtime_class", d.expected_runtime_class.as_bytes()),
        ("kbs_resource_path", d.kbs_resource_path.as_bytes()),
        ("policy_template_id", d.policy_template_id.as_bytes()),
        ("policy_template_sha256", &d.policy_template_sha256),
        (
            "platform_release_version",
            d.platform_release_version.as_bytes(),
        ),
    ];
    if include_chain_anchors {
        r.push(("expected_cc_init_data_hash", &d.expected_cc_init_data_hash));
        r.push(("expected_kbs_policy_hash", &d.expected_kbs_policy_hash));
    }
    r
}

struct DescriptorSubHashes {
    created_at: String,
    custom_domains_hash: [u8; 32],
    signer_hash: [u8; 32],
    oci_hash: [u8; 32],
    sidecar_hash: [u8; 32],
}

fn sub_hashes(d: &DeploymentDescriptor) -> DescriptorSubHashes {
    DescriptorSubHashes {
        created_at: d.created_at.to_rfc3339(),
        custom_domains_hash: canonical_string_list_bytes(&d.custom_domains),
        signer_hash: canonical_signer_bytes(&d.signer_identity),
        oci_hash: canonical_oci_spec_bytes(&d.oci_runtime_spec),
        sidecar_hash: canonical_sidecar_map_bytes(&d.sidecars),
    }
}

/// CE-v1 raw bytes over the full descriptor, signed by the deployer's Ed25519
/// key. This is the input to `Signer::sign` (NOT a hash; PureEd25519 hashes
/// internally).
pub fn descriptor_canonical_bytes(d: &DeploymentDescriptor) -> Vec<u8> {
    let sub = sub_hashes(d);
    let records = descriptor_records(d, b"enclava-deployment-descriptor-v1", true, &sub);
    ce_v1_bytes(&records)
}

/// CE-v1 32-byte hash over the cycle-free subset (excludes both
/// `expected_*_hash` fields). Embedded in cc_init_data as
/// `descriptor_core_hash`. Domain-separated by purpose label `-core-v1`.
pub fn descriptor_core_canonical_bytes(d: &DeploymentDescriptor) -> Vec<u8> {
    let sub = sub_hashes(d);
    let records = descriptor_records(d, b"enclava-deployment-descriptor-core-v1", false, &sub);
    ce_v1_bytes(&records)
}

pub fn descriptor_core_hash(d: &DeploymentDescriptor) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(descriptor_core_canonical_bytes(d)).into()
}

// --- sign / verify ---

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
        return Err(DescriptorError::Verify("signing pubkey mismatch".to_string()));
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
    use chrono::TimeZone;

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
        let key = UserSigningKey::generate(Uuid::new_v4());
        let env_a = sign(&key, fixed_descriptor(), "k".to_string());

        let mut d_b = fixed_descriptor();
        d_b.expected_cc_init_data_hash = [0xFF; 32];
        let env_b = sign(&key, d_b, "k".to_string());

        assert_ne!(env_a.signature.to_bytes(), env_b.signature.to_bytes());
    }

    #[test]
    fn env_canonicalization_is_name_sorted() {
        let oci_a = canonical_oci_spec_bytes(&OciRuntimeSpec {
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
        });
        let oci_b = canonical_oci_spec_bytes(&OciRuntimeSpec {
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
        });
        assert_eq!(oci_a, oci_b, "env must canonicalize regardless of input order");
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
