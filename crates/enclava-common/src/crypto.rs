use crate::canonical::ce_v1_hash;

/// Compute stable tenant instance identity hash using CE-v1 (D11 / Phase 1).
///
/// The previous implementation used colon-concatenated SHA-256, which was
/// vulnerable to length-shift / boundary-confusion attacks. CE-v1 enforces
/// length-prefixed TLV records with a versioned domain-separation label,
/// so a variable-length field cannot shift boundaries to forge a collision.
///
/// `bootstrap_owner_pubkey_hash` is the hex-encoded SHA-256 of the owner's
/// raw Ed25519 public key (preserved from the previous signature so all
/// existing callers compile unchanged).
pub fn compute_identity_hash(
    tenant_id: &str,
    instance_id: &str,
    bootstrap_owner_pubkey_hash: &str,
) -> String {
    let hash = ce_v1_hash(&[
        ("purpose", b"enclava-identity-v1"),
        ("tenant_id", tenant_id.as_bytes()),
        ("instance_id", instance_id.as_bytes()),
        ("bootstrap_owner_pubkey", bootstrap_owner_pubkey_hash.as_bytes()),
    ]);
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_hash_is_lowercase_hex_64_chars() {
        let hash = compute_identity_hash("t", "i", "p");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash, hash.to_lowercase());
    }

    #[test]
    fn identity_hash_deterministic() {
        let a = compute_identity_hash("x", "y", "z");
        let b = compute_identity_hash("x", "y", "z");
        assert_eq!(a, b);
    }

    #[test]
    fn identity_hash_sensitive_to_all_inputs() {
        let base = compute_identity_hash("t", "i", "p");
        assert_ne!(base, compute_identity_hash("T", "i", "p"));
        assert_ne!(base, compute_identity_hash("t", "I", "p"));
        assert_ne!(base, compute_identity_hash("t", "i", "P"));
    }

    #[test]
    fn identity_hash_resists_boundary_collision() {
        // The colon-concatenated implementation was vulnerable: the inputs
        // ("a","bc","x") and ("ab","c","x") produced different — but only
        // because of the colon delimiter; without delimiters, "abcx" would
        // collide. CE-v1 length-prefixes every record so even adversarially
        // chosen splits produce different bytes.
        let a = compute_identity_hash("a", "bc", "x");
        let b = compute_identity_hash("ab", "c", "x");
        assert_ne!(a, b);
    }
}
