//! In-TEE Trustee policy verification chain (rev13/rev14, plan ~lines 811-833).
//!
//! Runs entirely inside the SEV-SNP TEE before any seed material is released.
//! Six steps; failure on any one refuses the seed write.
//!
//! Network fetch of the policy envelope from `GET /resource-policy/<id>/body`
//! and the workload-attested artifact bundle from `GET
//! /api/v1/workload/artifacts` is gated behind `Config.trustee_policy_read_available`.
//! The flag defaults FALSE; while it's false the verifier emits a loud
//! `tracing::error!` saying the Phase 3 Trustee patch hasn't shipped yet,
//! and `verify_chain_or_skip` returns Ok(false) so the caller knows the
//! release happened without policy verification. We do NOT fall back to a
//! local descriptor file the way the earlier prototype did — that would be
//! pretending to verify something we didn't.
//!
//! Descriptor hashing uses `enclava_common::descriptor`, the same module the
//! CLI signer uses, so signer + verifier agree byte-for-byte across crates.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::ce_v1_bytes;
#[cfg(test)]
use enclava_common::canonical::ce_v1_hash;
use enclava_common::descriptor::{
    DeploymentDescriptor, descriptor_canonical_bytes, descriptor_core_hash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::errors::{InitError, Result};

/// Envelope of the active Trustee policy as fetched from
/// `GET /resource-policy/<id>/body` (rev9 finding #2 — Phase 3 endpoint).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEnvelope {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    /// Detached Ed25519 signature over the CE-v1 raw bytes of (purpose,
    /// canonical_policy_metadata_hash, sha256(rego_text)). rev13 finding #5.
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMetadata {
    pub app_id: String,
    pub deploy_id: String,
    pub descriptor_core_hash: String,
    pub descriptor_signing_pubkey: String,
    pub platform_release_version: String,
    pub policy_template_id: String,
    pub policy_template_sha256: String,
    pub signed_at: String,
    pub key_id: String,
}

/// Bundle returned by `GET /api/v1/workload/artifacts` (rev14 finding #2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactsBundle {
    pub descriptor_payload: serde_json::Value,
    #[serde(with = "hex::serde")]
    pub descriptor_signature: [u8; 64],
    pub descriptor_signing_key_id: String,
    pub org_keyring_payload: serde_json::Value,
    #[serde(with = "hex::serde")]
    pub org_keyring_signature: [u8; 64],
    pub signed_policy_artifact: PolicyEnvelope,
}

#[derive(Debug, Clone)]
pub struct CcInitDataClaims {
    pub descriptor_core_hash: [u8; 32],
    pub descriptor_signing_pubkey: [u8; 32],
    pub org_keyring_fingerprint: [u8; 32],
}

pub struct VerifyInputs<'a> {
    pub policy_envelope: &'a PolicyEnvelope,
    pub artifacts: &'a ArtifactsBundle,
    pub cc_init_data_claims: &'a CcInitDataClaims,
    pub local_cc_init_data_toml: &'a [u8],
    pub platform_trustee_policy_pubkey: &'a VerifyingKey,
    pub signing_service_pubkey: &'a VerifyingKey,
}

/// Run all six in-TEE verification steps. Returns Ok(()) only if every step
/// passes; any mismatch returns `InitError::TrusteePolicy(<step>)`.
pub fn verify_chain(inputs: &VerifyInputs<'_>) -> Result<()> {
    if inputs.platform_trustee_policy_pubkey.to_bytes() != inputs.signing_service_pubkey.to_bytes()
    {
        return Err(InitError::TrusteePolicy(
            "policy verification pubkey mismatch".into(),
        ));
    }

    if inputs.policy_envelope != &inputs.artifacts.signed_policy_artifact {
        return Err(InitError::TrusteePolicy(
            "active Trustee policy does not match workload artifact bundle".into(),
        ));
    }

    verify_policy_envelope_signature(
        inputs.policy_envelope,
        inputs.platform_trustee_policy_pubkey,
    )?;

    let core_hash = compute_descriptor_core_hash(&inputs.artifacts.descriptor_payload)?;
    if core_hash != inputs.cc_init_data_claims.descriptor_core_hash {
        return Err(InitError::TrusteePolicy(
            "step 1: descriptor_core_hash mismatch".into(),
        ));
    }

    verify_descriptor_full_signature(
        inputs.artifacts,
        &inputs.cc_init_data_claims.descriptor_signing_pubkey,
    )?;

    let descriptor = &inputs.artifacts.descriptor_payload;
    let expected_cc_init_data_hash = descriptor
        .get("expected_cc_init_data_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            InitError::TrusteePolicy("descriptor missing expected_cc_init_data_hash".into())
        })?;
    let local_hash = sha256_hex(inputs.local_cc_init_data_toml);
    if !ct_eq_hex(expected_cc_init_data_hash, &local_hash) {
        return Err(InitError::TrusteePolicy(
            "step 3: forward-chain expected_cc_init_data_hash mismatch".into(),
        ));
    }

    verify_keyring(
        inputs.artifacts,
        &inputs.cc_init_data_claims.org_keyring_fingerprint,
    )?;

    if !is_descriptor_signing_pubkey_in_keyring(
        &inputs.artifacts.org_keyring_payload,
        &inputs.cc_init_data_claims.descriptor_signing_pubkey,
    ) {
        return Err(InitError::TrusteePolicy(
            "step 4: descriptor_signing_pubkey not a deployer member of keyring".into(),
        ));
    }

    verify_signed_policy_artifact_metadata(
        inputs.policy_envelope,
        inputs.artifacts,
        inputs.cc_init_data_claims,
    )?;

    let expected_kbs_policy_hash = descriptor
        .get("expected_kbs_policy_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            InitError::TrusteePolicy("descriptor missing expected_kbs_policy_hash".into())
        })?;
    let actual_rego_hash = sha256_hex(inputs.policy_envelope.rego_text.as_bytes());
    if !ct_eq_hex(expected_kbs_policy_hash, &actual_rego_hash) {
        return Err(InitError::TrusteePolicy(
            "step 6: rego_text hash != descriptor.expected_kbs_policy_hash".into(),
        ));
    }

    Ok(())
}

/// Returns true if the chain ran end-to-end, false if it was skipped because
/// the Phase 3 Trustee patch is not yet deployed. False return is logged as
/// an error so production deployments cannot quietly run without verification.
pub fn verify_chain_or_skip(inputs: Option<&VerifyInputs<'_>>) -> Result<bool> {
    match inputs {
        Some(i) => {
            verify_chain(i)?;
            Ok(true)
        }
        None => {
            tracing::error!(
                "Phase 3 Trustee patch not yet deployed; in-TEE policy verification SKIPPED"
            );
            Ok(false)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactFetcher {
    pub workload_artifacts_url: String,
    pub trustee_policy_url: String,
    pub kbs_attestation_token: String,
    pub timeout: Duration,
}

impl ArtifactFetcher {
    pub fn fetch(&self) -> Result<(ArtifactsBundle, PolicyEnvelope)> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| InitError::Kbs(format!("client build: {e}")))?;
        let bundle: ArtifactsBundle = client
            .get(&self.workload_artifacts_url)
            .header(
                "Authorization",
                format!("Attestation {}", self.kbs_attestation_token),
            )
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json())
            .map_err(|e| InitError::Kbs(format!("fetch artifacts: {e}")))?;
        let policy: PolicyEnvelope = client
            .get(&self.trustee_policy_url)
            .header(
                "Authorization",
                format!("Attestation {}", self.kbs_attestation_token),
            )
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json())
            .map_err(|e| InitError::Kbs(format!("fetch policy: {e}")))?;
        Ok((bundle, policy))
    }
}

pub fn resolve_kbs_attestation_token(
    env_token: Option<&str>,
    token_url: &str,
    timeout: Duration,
) -> Result<String> {
    if let Some(token) = env_token.map(str::trim).filter(|token| !token.is_empty()) {
        return Ok(token.to_string());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| InitError::Kbs(format!("token client build: {e}")))?;
    let payload: serde_json::Value = client
        .get(token_url)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .map_err(|e| InitError::Kbs(format!("fetch KBS attestation token: {e}")))?;
    parse_kbs_attestation_token_payload(&payload)
}

fn parse_kbs_attestation_token_payload(payload: &serde_json::Value) -> Result<String> {
    let token = payload
        .get("token")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| InitError::Kbs("KBS attestation token response missing token".into()))?;
    Ok(token.to_string())
}

fn verify_policy_envelope_signature(env: &PolicyEnvelope, pk: &VerifyingKey) -> Result<()> {
    let msg = ce_v1_policy_envelope_message(env)?;
    let sig = Signature::from_bytes(&env.signature);
    pk.verify(&msg, &sig)
        .map_err(|e| InitError::TrusteePolicy(format!("policy envelope sig: {e}")))
}

fn verify_descriptor_full_signature(
    artifacts: &ArtifactsBundle,
    descriptor_signing_pubkey: &[u8; 32],
) -> Result<()> {
    let pk = VerifyingKey::from_bytes(descriptor_signing_pubkey)
        .map_err(|e| InitError::TrusteePolicy(format!("descriptor pubkey: {e}")))?;
    let msg = ce_v1_descriptor_full_message(&artifacts.descriptor_payload)?;
    let sig = Signature::from_bytes(&artifacts.descriptor_signature);
    pk.verify(&msg, &sig)
        .map_err(|e| InitError::TrusteePolicy(format!("descriptor sig: {e}")))
}

fn verify_keyring(artifacts: &ArtifactsBundle, expected_fingerprint: &[u8; 32]) -> Result<()> {
    let bytes = ce_v1_keyring_bytes(&artifacts.org_keyring_payload)?;
    let fp = sha256_bytes(&bytes);
    if &fp != expected_fingerprint {
        return Err(InitError::TrusteePolicy(
            "step 4a: keyring fingerprint != cc_init_data.org_keyring_fingerprint".into(),
        ));
    }
    Ok(())
}

fn is_descriptor_signing_pubkey_in_keyring(keyring: &serde_json::Value, pubkey: &[u8; 32]) -> bool {
    let Some(members) = keyring.get("members").and_then(|m| m.as_array()) else {
        return false;
    };
    let pubkey_hex = hex::encode(pubkey);
    members.iter().any(|m| {
        let pk = m.get("pubkey").and_then(|p| p.as_str()).unwrap_or("");
        let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
        ct_eq_hex(pk, &pubkey_hex) && (role == "deployer" || role == "owner")
    })
}

fn verify_signed_policy_artifact_metadata(
    env: &PolicyEnvelope,
    artifacts: &ArtifactsBundle,
    cc: &CcInitDataClaims,
) -> Result<()> {
    let descriptor = &artifacts.descriptor_payload;
    let m = &env.metadata;

    let want_app = descriptor
        .get("app_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_deploy = descriptor
        .get("deploy_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_release = descriptor
        .get("platform_release_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_template_id = descriptor
        .get("policy_template_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_template_sha = descriptor
        .get("policy_template_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if m.app_id != want_app {
        return Err(InitError::TrusteePolicy("step 5: app_id mismatch".into()));
    }
    if m.deploy_id != want_deploy {
        return Err(InitError::TrusteePolicy(
            "step 5: deploy_id mismatch".into(),
        ));
    }
    if m.descriptor_core_hash != hex::encode(cc.descriptor_core_hash) {
        return Err(InitError::TrusteePolicy(
            "step 5: descriptor_core_hash mismatch".into(),
        ));
    }
    if m.descriptor_signing_pubkey != hex::encode(cc.descriptor_signing_pubkey) {
        return Err(InitError::TrusteePolicy(
            "step 5: descriptor_signing_pubkey mismatch".into(),
        ));
    }
    if m.platform_release_version != want_release {
        return Err(InitError::TrusteePolicy(
            "step 5: platform_release_version mismatch".into(),
        ));
    }
    if m.policy_template_id != want_template_id {
        return Err(InitError::TrusteePolicy(
            "step 5: policy_template_id mismatch".into(),
        ));
    }
    if m.policy_template_sha256 != want_template_sha {
        return Err(InitError::TrusteePolicy(
            "step 5: policy_template_sha256 mismatch".into(),
        ));
    }
    Ok(())
}

fn compute_descriptor_core_hash(descriptor: &serde_json::Value) -> Result<[u8; 32]> {
    let d = parse_descriptor(descriptor)?;
    Ok(descriptor_core_hash(&d))
}

fn ce_v1_descriptor_full_message(descriptor: &serde_json::Value) -> Result<Vec<u8>> {
    let d = parse_descriptor(descriptor)?;
    Ok(descriptor_canonical_bytes(&d))
}

fn parse_descriptor(descriptor: &serde_json::Value) -> Result<DeploymentDescriptor> {
    serde_json::from_value(descriptor.clone())
        .map_err(|e| InitError::TrusteePolicy(format!("descriptor schema: {e}")))
}

fn ce_v1_policy_envelope_message(env: &PolicyEnvelope) -> Result<Vec<u8>> {
    let metadata_value =
        serde_json::to_value(&env.metadata).map_err(|e| InitError::Serde(e.to_string()))?;
    let metadata_obj = metadata_value
        .as_object()
        .cloned()
        .ok_or_else(|| InitError::Serde("metadata not an object".into()))?;
    let metadata_bytes = encode_json_object_ce_v1("enclava-policy-metadata-v1", &metadata_obj);
    let metadata_hash: [u8; 32] = Sha256::digest(&metadata_bytes).into();
    let rego_hash: [u8; 32] = Sha256::digest(env.rego_text.as_bytes()).into();
    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", metadata_hash.as_slice()),
        ("rego_sha256", rego_hash.as_slice()),
    ]))
}

fn ce_v1_keyring_bytes(keyring: &serde_json::Value) -> Result<Vec<u8>> {
    let obj = keyring
        .as_object()
        .cloned()
        .ok_or_else(|| InitError::TrusteePolicy("keyring not an object".into()))?;
    Ok(encode_json_object_ce_v1("enclava-org-keyring-v1", &obj))
}

/// Encode a JSON object as CE-v1 records: one `purpose` record then one
/// record per top-level field in lexicographic order. Each value is the
/// minified JSON encoding of the field. Cross-crate parity with the
/// signing service is asserted via the byte-parity tests below.
fn encode_json_object_ce_v1(
    purpose: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Vec<u8> {
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    let mut owned: Vec<(String, Vec<u8>)> = Vec::with_capacity(keys.len() + 1);
    owned.push(("purpose".to_string(), purpose.as_bytes().to_vec()));
    for k in keys {
        let v_json = serde_json::to_vec(&obj[k]).expect("value is serializable");
        owned.push((k.clone(), v_json));
    }
    let records: Vec<(&str, &[u8])> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
    ce_v1_bytes(&records)
}

fn sha256_bytes(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(sha256_bytes(b))
}

fn ct_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn metadata_for(rego: &str) -> PolicyMetadata {
        PolicyMetadata {
            app_id: "a".into(),
            deploy_id: "d".into(),
            descriptor_core_hash: "00".repeat(32),
            descriptor_signing_pubkey: "00".repeat(32),
            platform_release_version: "v1".into(),
            policy_template_id: "tmpl".into(),
            policy_template_sha256: hex::encode(Sha256::digest(rego.as_bytes())),
            signed_at: "2026-01-01T00:00:00Z".into(),
            key_id: "k1".into(),
        }
    }

    fn mk_envelope(sk: &SigningKey, metadata: PolicyMetadata, rego: &str) -> PolicyEnvelope {
        let mut env = PolicyEnvelope {
            metadata,
            rego_text: rego.to_string(),
            signature: [0u8; 64],
        };
        let msg = ce_v1_policy_envelope_message(&env).unwrap();
        env.signature = sk.sign(&msg).to_bytes();
        env
    }

    fn descriptor_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": "v1",
            "org_id": "11111111-1111-1111-1111-111111111111",
            "org_slug": "abcd1234",
            "app_id": "22222222-2222-2222-2222-222222222222",
            "app_name": "demo",
            "deploy_id": "33333333-3333-3333-3333-333333333333",
            "created_at": "2026-04-01T12:00:00Z",
            "nonce": "07".repeat(32),
            "app_domain": "demo.abcd1234.enclava.dev",
            "tee_domain": "demo.abcd1234.tee.enclava.dev",
            "custom_domains": ["app.example.com"],
            "namespace": "cap-abcd1234-demo",
            "service_account": "cap-demo-sa",
            "identity_hash": "09".repeat(32),
            "image_digest": "sha256:aaaa",
            "signer_identity": {
                "subject": "https://github.com/x/y/.github/workflows/build.yml",
                "issuer": "https://token.actions.githubusercontent.com"
            },
            "oci_runtime_spec": {
                "command": ["/app"],
                "args": ["--serve"],
                "env": [
                    {"name": "A", "value": "1"},
                    {"name": "B", "value": "2"}
                ],
                "ports": [{"container_port": 3000, "protocol": "TCP"}],
                "mounts": [],
                "capabilities": {"add": [], "drop": []},
                "security_context": {
                    "run_as_user": 0,
                    "run_as_group": 0,
                    "read_only_root_fs": false,
                    "allow_privilege_escalation": false,
                    "privileged": false
                },
                "resources": {"requests": [], "limits": []}
            },
            "sidecars": {
                "attestation_proxy_digest": "sha256:1111",
                "caddy_digest": "sha256:2222"
            },
            "expected_firmware_measurement": "03".repeat(32),
            "expected_runtime_class": "kata-qemu-snp",
            "kbs_resource_path": "default/cap-abcd1234-demo-owner",
            "policy_template_id": "tmpl-default",
            "policy_template_sha256": "04".repeat(32),
            "platform_release_version": "v1.2.3",
            "expected_cc_init_data_hash": "05".repeat(32),
            "expected_kbs_policy_hash": "06".repeat(32)
        })
    }

    #[test]
    fn ce_v1_byte_parity_with_enclava_common() {
        let bytes = ce_v1_bytes(&[("purpose", b"test"), ("k", b"v")]);
        let hash = ce_v1_hash(&[("purpose", b"test"), ("k", b"v")]);
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn policy_envelope_signature_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let env = mk_envelope(&sk, metadata_for("package x\n"), "package x\n");
        verify_policy_envelope_signature(&env, &pk).unwrap();
    }

    #[test]
    fn policy_envelope_tampered_rego_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let mut env = mk_envelope(&sk, metadata_for("package x\n"), "package x\n");
        env.rego_text = "package y\n".into();
        assert!(verify_policy_envelope_signature(&env, &pk).is_err());
    }

    #[test]
    fn descriptor_core_hash_excludes_expected_fields() {
        let v1 = descriptor_json();
        let mut v2 = v1.clone();
        v2["expected_cc_init_data_hash"] = serde_json::Value::String("aa".repeat(32));
        v2["expected_kbs_policy_hash"] = serde_json::Value::String("bb".repeat(32));
        let h1 = compute_descriptor_core_hash(&v1).unwrap();
        let h2 = compute_descriptor_core_hash(&v2).unwrap();
        assert_eq!(h1, h2);
    }

    fn build_inputs(
        descriptor: &serde_json::Value,
        keyring: serde_json::Value,
        rego: &str,
        signing_sk: &SigningKey,
        descriptor_sk: &SigningKey,
        cc_init_toml: &[u8],
    ) -> (
        ArtifactsBundle,
        PolicyEnvelope,
        CcInitDataClaims,
        VerifyingKey,
        VerifyingKey,
    ) {
        let core_hash = compute_descriptor_core_hash(descriptor).unwrap();
        let pubkey_bytes = descriptor_sk.verifying_key().to_bytes();
        let local_hash_hex = hex::encode(Sha256::digest(cc_init_toml));
        let mut descriptor = descriptor.clone();
        descriptor["expected_cc_init_data_hash"] = serde_json::Value::String(local_hash_hex);
        descriptor["expected_kbs_policy_hash"] =
            serde_json::Value::String(hex::encode(Sha256::digest(rego.as_bytes())));

        let descriptor_msg = ce_v1_descriptor_full_message(&descriptor).unwrap();
        let descriptor_sig = descriptor_sk.sign(&descriptor_msg).to_bytes();

        let keyring_bytes = ce_v1_keyring_bytes(&keyring).unwrap();
        let keyring_fp: [u8; 32] = Sha256::digest(&keyring_bytes).into();

        let mut metadata = metadata_for(rego);
        metadata.app_id = descriptor.get("app_id").unwrap().as_str().unwrap().into();
        metadata.deploy_id = descriptor
            .get("deploy_id")
            .unwrap()
            .as_str()
            .unwrap()
            .into();
        metadata.descriptor_core_hash = hex::encode(core_hash);
        metadata.descriptor_signing_pubkey = hex::encode(pubkey_bytes);
        metadata.platform_release_version = descriptor
            .get("platform_release_version")
            .unwrap()
            .as_str()
            .unwrap()
            .into();
        metadata.policy_template_id = descriptor
            .get("policy_template_id")
            .unwrap()
            .as_str()
            .unwrap()
            .into();
        metadata.policy_template_sha256 = descriptor
            .get("policy_template_sha256")
            .unwrap()
            .as_str()
            .unwrap()
            .into();

        let env = mk_envelope(signing_sk, metadata, rego);

        let bundle = ArtifactsBundle {
            descriptor_payload: descriptor,
            descriptor_signature: descriptor_sig,
            descriptor_signing_key_id: "deployer-1".into(),
            org_keyring_payload: keyring,
            org_keyring_signature: [0u8; 64],
            signed_policy_artifact: env.clone(),
        };
        let cc = CcInitDataClaims {
            descriptor_core_hash: core_hash,
            descriptor_signing_pubkey: pubkey_bytes,
            org_keyring_fingerprint: keyring_fp,
        };
        (
            bundle,
            env,
            cc,
            signing_sk.verifying_key(),
            descriptor_sk.verifying_key(),
        )
    }

    #[test]
    fn end_to_end_chain_passes_for_valid_inputs() {
        let signing = SigningKey::generate(&mut OsRng);
        let deployer = SigningKey::generate(&mut OsRng);
        let descriptor = descriptor_json();
        let keyring = serde_json::json!({
            "members": [
                {"pubkey": hex::encode(deployer.verifying_key().to_bytes()), "role": "deployer"}
            ]
        });
        let rego = "package enclava\ndefault allow := false\n";
        let cc_toml = b"placeholder cc_init_data";
        let (bundle, env, cc, signer_pk, _) =
            build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);

        let inputs = VerifyInputs {
            policy_envelope: &env,
            artifacts: &bundle,
            cc_init_data_claims: &cc,
            local_cc_init_data_toml: cc_toml,
            platform_trustee_policy_pubkey: &signer_pk,
            signing_service_pubkey: &signer_pk,
        };
        verify_chain(&inputs).expect("chain should pass");
    }

    #[test]
    fn end_to_end_chain_rejects_tampered_descriptor() {
        let signing = SigningKey::generate(&mut OsRng);
        let deployer = SigningKey::generate(&mut OsRng);
        let descriptor = descriptor_json();
        let keyring = serde_json::json!({
            "members": [
                {"pubkey": hex::encode(deployer.verifying_key().to_bytes()), "role": "deployer"}
            ]
        });
        let rego = "package enclava\ndefault allow := false\n";
        let cc_toml = b"placeholder cc_init_data";
        let (mut bundle, env, cc, signer_pk, _) =
            build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);

        bundle.descriptor_payload["app_name"] = serde_json::Value::String("evil".into());

        let inputs = VerifyInputs {
            policy_envelope: &env,
            artifacts: &bundle,
            cc_init_data_claims: &cc,
            local_cc_init_data_toml: cc_toml,
            platform_trustee_policy_pubkey: &signer_pk,
            signing_service_pubkey: &signer_pk,
        };
        let err = verify_chain(&inputs).unwrap_err();
        match err {
            InitError::TrusteePolicy(s) => {
                assert!(s.starts_with("step 1") || s.contains("descriptor sig"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn end_to_end_chain_rejects_wrong_keyring_fingerprint() {
        let signing = SigningKey::generate(&mut OsRng);
        let deployer = SigningKey::generate(&mut OsRng);
        let descriptor = descriptor_json();
        let keyring = serde_json::json!({
            "members": [
                {"pubkey": hex::encode(deployer.verifying_key().to_bytes()), "role": "deployer"}
            ]
        });
        let rego = "package enclava\n";
        let cc_toml = b"x";
        let (bundle, env, mut cc, signer_pk, _) =
            build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);
        cc.org_keyring_fingerprint = [0xFFu8; 32];

        let inputs = VerifyInputs {
            policy_envelope: &env,
            artifacts: &bundle,
            cc_init_data_claims: &cc,
            local_cc_init_data_toml: cc_toml,
            platform_trustee_policy_pubkey: &signer_pk,
            signing_service_pubkey: &signer_pk,
        };
        let err = verify_chain(&inputs).unwrap_err();
        assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("step 4a")));
    }

    #[test]
    fn end_to_end_chain_rejects_rego_mismatch() {
        let signing = SigningKey::generate(&mut OsRng);
        let deployer = SigningKey::generate(&mut OsRng);
        let descriptor = descriptor_json();
        let keyring = serde_json::json!({
            "members": [
                {"pubkey": hex::encode(deployer.verifying_key().to_bytes()), "role": "deployer"}
            ]
        });
        let rego = "package enclava\n";
        let cc_toml = b"x";
        let (mut bundle, mut env, cc, signer_pk, _) =
            build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);

        // Point expected_kbs_policy_hash at one rego, but ship a different one.
        env.rego_text = "package different\n".into();
        // Re-sign the (now-different) envelope so we don't fail at step "envelope sig"
        // and instead reach step 6.
        let new_msg = ce_v1_policy_envelope_message(&env).unwrap();
        env.signature = signing.sign(&new_msg).to_bytes();
        bundle.signed_policy_artifact = env.clone();

        let inputs = VerifyInputs {
            policy_envelope: &env,
            artifacts: &bundle,
            cc_init_data_claims: &cc,
            local_cc_init_data_toml: cc_toml,
            platform_trustee_policy_pubkey: &signer_pk,
            signing_service_pubkey: &signer_pk,
        };
        let err = verify_chain(&inputs).unwrap_err();
        assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("step 6")));
    }

    #[test]
    fn end_to_end_chain_rejects_active_policy_not_in_artifact_bundle() {
        let signing = SigningKey::generate(&mut OsRng);
        let deployer = SigningKey::generate(&mut OsRng);
        let descriptor = descriptor_json();
        let keyring = serde_json::json!({
            "members": [
                {"pubkey": hex::encode(deployer.verifying_key().to_bytes()), "role": "deployer"}
            ]
        });
        let rego = "package enclava\n";
        let cc_toml = b"x";
        let (bundle, mut env, cc, signer_pk, _) =
            build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);
        env.metadata.key_id = "different-active-policy".into();
        let new_msg = ce_v1_policy_envelope_message(&env).unwrap();
        env.signature = signing.sign(&new_msg).to_bytes();

        let inputs = VerifyInputs {
            policy_envelope: &env,
            artifacts: &bundle,
            cc_init_data_claims: &cc,
            local_cc_init_data_toml: cc_toml,
            platform_trustee_policy_pubkey: &signer_pk,
            signing_service_pubkey: &signer_pk,
        };
        let err = verify_chain(&inputs).unwrap_err();
        assert!(
            matches!(err, InitError::TrusteePolicy(s) if s.contains("does not match workload artifact"))
        );
    }

    #[test]
    fn end_to_end_chain_rejects_policy_pubkey_mismatch() {
        let signing = SigningKey::generate(&mut OsRng);
        let other_signer = SigningKey::generate(&mut OsRng);
        let deployer = SigningKey::generate(&mut OsRng);
        let descriptor = descriptor_json();
        let keyring = serde_json::json!({
            "members": [
                {"pubkey": hex::encode(deployer.verifying_key().to_bytes()), "role": "deployer"}
            ]
        });
        let rego = "package enclava\n";
        let cc_toml = b"x";
        let (bundle, env, cc, signer_pk, _) =
            build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);
        let other_pk = other_signer.verifying_key();

        let inputs = VerifyInputs {
            policy_envelope: &env,
            artifacts: &bundle,
            cc_init_data_claims: &cc,
            local_cc_init_data_toml: cc_toml,
            platform_trustee_policy_pubkey: &signer_pk,
            signing_service_pubkey: &other_pk,
        };
        let err = verify_chain(&inputs).unwrap_err();
        assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("pubkey mismatch")));
    }

    #[test]
    fn skipped_chain_logs_and_returns_false() {
        let result = verify_chain_or_skip(None).unwrap();
        assert!(!result);
    }

    #[test]
    fn resolve_kbs_attestation_token_prefers_env_token() {
        let token = resolve_kbs_attestation_token(
            Some("  env-token  "),
            "http://127.0.0.1:1/unused",
            Duration::from_millis(1),
        )
        .unwrap();
        assert_eq!(token, "env-token");
    }

    #[test]
    fn parse_kbs_attestation_token_payload_rejects_missing_token() {
        let err = parse_kbs_attestation_token_payload(&serde_json::json!({})).unwrap_err();
        assert!(matches!(err, InitError::Kbs(msg) if msg.contains("missing token")));
    }

    #[test]
    fn parse_kbs_attestation_token_payload_accepts_token() {
        let token =
            parse_kbs_attestation_token_payload(&serde_json::json!({ "token": "abc.def.ghi" }))
                .unwrap();
        assert_eq!(token, "abc.def.ghi");
    }
}
