use sha2::{Digest, Sha256};

/// Compute stable tenant instance identity hash.
///
/// Identity hash = lowercase hex SHA256("{tenant_id}:{instance_id}:{pubkey_hash}")
///
/// Byte-for-byte identical to the Python implementation in
/// `platform_api/manifests/init_data.py:compute_identity_hash`.
pub fn compute_identity_hash(
    tenant_id: &str,
    instance_id: &str,
    bootstrap_owner_pubkey_hash: &str,
) -> String {
    let input = format!("{tenant_id}:{instance_id}:{bootstrap_owner_pubkey_hash}");
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}
