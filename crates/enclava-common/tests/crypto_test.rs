use enclava_common::crypto::compute_identity_hash;

#[test]
fn identity_hash_matches_python_implementation() {
    // Verified: python3 -c "import hashlib; print(hashlib.sha256(b'tenant-1:instance-a:aabbccdd').hexdigest())"
    let hash = compute_identity_hash("tenant-1", "instance-a", "aabbccdd");
    assert_eq!(
        hash,
        "61d6db7a790e5aec89d6ff87bd1ac02868cb5725bf9be8eea71c522d8f5e3c26"
    );
}

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
