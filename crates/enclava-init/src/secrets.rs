//! Secret newtype wrappers. Every type here zeroes its bytes on drop so we
//! never leak owner-seed / wrap-key / password material into freed heap pages
//! that the host could later inspect.

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OwnerSeed(pub [u8; 32]);

impl OwnerSeed {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WrapKey(pub [u8; 32]);

impl WrapKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Password(pub Vec<u8>);

impl Password {
    pub fn from_plaintext(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedSeed(pub [u8; 32]);

impl DerivedSeed {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_seed_zeroize_wires_up() {
        let mut seed = OwnerSeed([0xAAu8; 32]);
        seed.zeroize();
        assert_eq!(seed.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn password_zeroize_wires_up() {
        let mut p = Password(vec![0x42u8; 16]);
        p.zeroize();
        assert!(p.as_bytes().is_empty());
    }

    #[test]
    fn wrap_key_zeroize_wires_up() {
        let mut k = WrapKey([0xFFu8; 32]);
        k.zeroize();
        assert_eq!(k.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn derived_seed_zeroize_wires_up() {
        let mut s = DerivedSeed([0x11u8; 32]);
        s.zeroize();
        assert_eq!(s.as_bytes(), &[0u8; 32]);
    }
}
