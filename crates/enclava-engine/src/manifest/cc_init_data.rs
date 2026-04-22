//! cc_init_data generation: TOML + gzip + base64.
//!
//! Ports the Python implementation at platform_api/manifests/init_data.py.
//! The output must be byte-for-byte compatible for cc_init_data annotations.
//! The SHA256 hash is computed on the uncompressed TOML string.

use sha2::{Digest, Sha256};
use std::io::Write;

use crate::types::ConfidentialApp;

const KBS_URL: &str = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";

/// Build the cc_init_data TOML string for a ConfidentialApp.
///
/// The TOML structure matches the Python template in init_data.py exactly.
/// It contains:
/// - policy.rego: agent policy with image digest and namespace
/// - aa.toml: attestation agent config pointing to KBS
/// - cdh.toml: confidential data hub config pointing to KBS
/// - identity.toml: tenant/instance identity for ownership binding
pub fn build_toml(app: &ConfidentialApp) -> String {
    let primary = app
        .primary_container()
        .expect("app must have a primary container");
    let image_digest = primary.image.digest_ref();

    let identity_toml = build_identity_toml(
        &app.namespace,
        &app.name,
        &app.owner_resource_type(),
        &app.bootstrap_owner_pubkey_hash,
        &app.tenant_instance_identity_hash,
    );

    // This format matches init_data.py _TOML_TEMPLATE exactly.
    // Whitespace and quoting must be identical for hash compatibility.
    let mut toml = String::new();
    toml.push_str("version = \"0.1.0\"\nalgorithm = \"sha256\"\n");
    toml.push('\n');
    toml.push_str("[data]\n");

    // policy.rego
    toml.push_str("\"policy.rego\" = '''\n");
    toml.push_str("package agent_policy\n");
    toml.push('\n');
    toml.push_str("default AllowRequestsFailingPolicy := true\n");
    toml.push('\n');
    toml.push_str(&format!(
        "policy_data := {{\"containers\":[{{\"OCI\":{{\"Annotations\":{{\"io.kubernetes.cri.image-name\":\"{image_digest}\",\"io.kubernetes.pod.namespace\":\"{namespace}\",\"io.kubernetes.pod.service-account.name\":\"{service_account}\",\"tenant.flowforge.sh/instance\":\"{instance}\"}}}},\"image_name\":\"{image_digest}\"}}]}}\n",
        image_digest = image_digest,
        namespace = app.namespace,
        service_account = app.service_account,
        instance = app.name,
    ));
    toml.push_str("'''\n");
    toml.push('\n');

    // aa.toml
    toml.push_str("\"aa.toml\" = '''\n");
    toml.push_str("[token_configs]\n");
    toml.push_str("[token_configs.kbs]\n");
    toml.push_str(&format!("url = \"{KBS_URL}\"\n"));
    toml.push_str("'''\n");
    toml.push('\n');

    // cdh.toml
    toml.push_str("\"cdh.toml\" = '''\n");
    toml.push_str("[kbc]\n");
    toml.push_str("name = \"cc_kbc\"\n");
    toml.push_str(&format!("url = \"{KBS_URL}\"\n"));
    toml.push_str("'''\n");

    // identity.toml (always present per OID-1)
    toml.push('\n');
    toml.push_str("\"identity.toml\" = '''\n");
    toml.push_str(&identity_toml);
    toml.push_str("'''\n");

    toml
}

/// Build the identity.toml content.
fn build_identity_toml(
    tenant_id: &str,
    instance_id: &str,
    owner_resource_type: &str,
    bootstrap_owner_pubkey_hash: &str,
    identity_hash: &str,
) -> String {
    format!(
        "tenant_id = \"{tenant_id}\"\n\
         instance_id = \"{instance_id}\"\n\
         owner_resource_type = \"{owner_resource_type}\"\n\
         bootstrap_owner_pubkey_hash = \"{bootstrap_owner_pubkey_hash}\"\n\
         tenant_instance_identity_hash = \"{identity_hash}\"\n"
    )
}

/// Compute SHA256 hex digest of the TOML string.
/// This hash is used in the `storage.enclava.dev/secure-pv-init-data-sha256` annotation.
pub fn sha256_hex(toml: &str) -> String {
    let hash = Sha256::digest(toml.as_bytes());
    hex::encode(hash)
}

/// gzip compress (mtime=0) then base64 encode the TOML string.
/// Matches the Python `gzip.compress(data, mtime=0)` + `base64.b64encode()`.
pub fn encode_cc_init_data(toml: &str) -> String {
    let header = flate2::GzBuilder::new().mtime(0);
    let mut encoder = header.write(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(toml.as_bytes())
        .expect("gzip write failed");
    let compressed = encoder.finish().expect("gzip finish failed");

    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&compressed)
}

/// Convenience: build TOML, compute hash, and encode in one call.
/// Returns (encoded_base64, sha256_hash).
pub fn compute_cc_init_data(app: &ConfidentialApp) -> (String, String) {
    let toml = build_toml(app);
    let hash = sha256_hex(&toml);
    let encoded = encode_cc_init_data(&toml);
    (encoded, hash)
}
