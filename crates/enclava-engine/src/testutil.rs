//! Test fixtures for enclava-engine. Only available with the `testutil` feature.

use crate::types::*;
use enclava_common::image::ImageRef;
use enclava_common::types::{ResourceLimits, UnlockMode};
use std::collections::HashMap;
use uuid::Uuid;

/// The pubkey hash used in all test fixtures.
pub const TEST_PUBKEY_HASH: &str =
    "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";

/// A minimal valid ConfidentialApp for testing (auto-unlock mode).
pub fn sample_app() -> ConfidentialApp {
    let tenant_id = "test-org".to_string();
    let instance_id = "test-org-a1b2c3d4".to_string();
    let identity_hash =
        enclava_common::crypto::compute_identity_hash(&tenant_id, &instance_id, TEST_PUBKEY_HASH);

    ConfidentialApp {
        app_id: Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap(),
        name: "test-app".to_string(),
        namespace: "cap-test-org-test-app".to_string(),
        instance_id,
        tenant_id,
        bootstrap_owner_pubkey_hash: TEST_PUBKEY_HASH.to_string(),
        tenant_instance_identity_hash: identity_hash,
        service_account: "cap-test-app-sa".to_string(),
        containers: vec![Container {
            name: "web".to_string(),
            image: ImageRef::parse(
                "ghcr.io/test/app@sha256:\
                 abcd1234abcd1234abcd1234abcd1234\
                 abcd1234abcd1234abcd1234abcd1234",
            )
            .unwrap(),
            port: Some(3000),
            command: None,
            env: HashMap::new(),
            storage_paths: vec!["/app/data".to_string()],
            is_primary: true,
        }],
        storage: StorageSpec::new("10Gi", "2Gi"),
        unlock_mode: UnlockMode::Auto,
        domain: DomainSpec {
            platform_domain: "test-app.abcd1234.enclava.dev".to_string(),
            tee_domain: "test-app.abcd1234.tee.enclava.dev".to_string(),
            custom_domain: None,
        },
        api_signing_pubkey: "test-pubkey-placeholder".to_string(),
        api_url: "https://api.enclava.dev".to_string(),
        resources: ResourceLimits::default(),
        attestation: AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-ai/attestation-proxy@sha256:\
                 1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-ai/caddy-ingress@sha256:\
                 2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            acme_ca_url: default_acme_ca_url(),
            cloudflare_token_secret: "cloudflare-api-token-enclava-dev".to_string(),
            cloudflare_api_token: Some("test-cloudflare-token".to_string()),
        },
        egress_allowlist: Vec::new(),
    }
}

/// A password-mode app with identity fields populated.
pub fn sample_password_app() -> ConfidentialApp {
    let mut app = sample_app();
    app.unlock_mode = UnlockMode::Password;
    app
}
