//! Cross-crate sanity check that the CE-v1 identity hash is callable from
//! consumers. Per-record property tests live alongside the implementation
//! in `crates/enclava-common/src/crypto.rs`.

use enclava_common::canonical::ce_v1_hash;
use enclava_common::crypto::compute_identity_hash;

#[test]
fn identity_hash_matches_explicit_ce_v1_construction() {
    let hash = compute_identity_hash("tenant-1", "instance-a", "aabbccdd");
    let expected = hex::encode(ce_v1_hash(&[
        ("purpose", b"enclava-identity-v1"),
        ("tenant_id", b"tenant-1"),
        ("instance_id", b"instance-a"),
        ("bootstrap_owner_pubkey", b"aabbccdd"),
    ]));
    assert_eq!(hash, expected);
}

#[test]
fn identity_hash_is_lowercase_hex_64_chars() {
    let hash = compute_identity_hash("t", "i", "p");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hash, hash.to_lowercase());
}

#[test]
fn identity_hash_resists_boundary_collision() {
    // Plain concat ("a"+"bc"+"x" vs "ab"+"c"+"x") would collide on
    // the unprefixed bytes "abcx". CE-v1's length-prefixed records prevent it.
    let a = compute_identity_hash("a", "bc", "x");
    let b = compute_identity_hash("ab", "c", "x");
    assert_ne!(a, b);
}
