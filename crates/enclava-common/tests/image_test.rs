use enclava_common::image::ImageRef;

#[test]
fn parse_digest_ref() {
    let img = ImageRef::parse(
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    )
    .unwrap();
    assert_eq!(img.registry(), "ghcr.io");
    assert_eq!(img.repository(), "user/app");
    assert_eq!(
        img.digest(),
        "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    );
    assert!(img.tag().is_none());
    assert!(img.has_digest());
}

#[test]
fn parse_tag_ref() {
    let img = ImageRef::parse("ghcr.io/user/app:latest").unwrap();
    assert_eq!(img.tag(), Some("latest"));
    assert!(!img.has_digest());
}

#[test]
fn parse_bare_image() {
    let img = ImageRef::parse("ubuntu:latest").unwrap();
    assert_eq!(img.registry(), "docker.io");
    assert_eq!(img.repository(), "library/ubuntu");
    assert_eq!(img.tag(), Some("latest"));
}

#[test]
fn digest_ref_string() {
    let img = ImageRef::parse(
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    )
    .unwrap();
    assert_eq!(
        img.digest_ref(),
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    );
}

#[test]
fn require_digest_rejects_tag_only() {
    let img = ImageRef::parse("ghcr.io/user/app:latest").unwrap();
    let err = img.require_digest().unwrap_err();
    assert!(err.to_string().contains("digest"));
}

#[test]
fn require_digest_accepts_pinned() {
    let img = ImageRef::parse(
        "ghcr.io/user/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    )
    .unwrap();
    img.require_digest().unwrap(); // should not panic
}
