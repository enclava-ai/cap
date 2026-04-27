use rand::RngCore;

pub const ORG_SLUG_LEN: usize = 8;

/// Generate a fresh 8-char lowercase-hex `cust_slug`.
///
/// Random per call; the database's UNIQUE constraint plus a callside retry
/// on `unique_violation` is the collision-resolution path. With a 32-bit
/// space the birthday bound is ~65k orgs before collisions become likely,
/// so a small retry cap (e.g. 5) is sufficient for the platform's foreseeable
/// scale.
pub fn generate_org_slug() -> String {
    let mut bytes = [0u8; ORG_SLUG_LEN / 2];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_eight_lowercase_hex() {
        for _ in 0..32 {
            let s = generate_org_slug();
            assert_eq!(s.len(), ORG_SLUG_LEN);
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "non-hex slug: {s}",
            );
        }
    }

    #[test]
    fn slug_passes_org_slug_validator() {
        for _ in 0..32 {
            let s = generate_org_slug();
            assert!(crate::validate::validate_org_slug(&s).is_ok());
        }
    }
}
