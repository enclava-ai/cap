//! Phase 4 Caddyfile adversarial input tests.
//!
//! Confirms the structured Caddyfile builder rejects every known injection
//! vector before any output is rendered.

use enclava_engine::manifest::ingress::{IngressRenderError, render_caddyfile};
use enclava_engine::testutil::sample_app;

#[test]
fn render_succeeds_on_validated_inputs() {
    let app = sample_app();
    let out = render_caddyfile(&app).expect("validated inputs render");
    assert!(out.contains("test-app.abcd1234.enclava.dev"));
    assert!(!out.contains("\n\n\n"));
}

#[test]
fn render_rejects_injection_in_acme_url() {
    let cases = [
        "https://example.com\nimport other.conf",
        "https://example.com }\nadmin off",
        "https://example.com `whoami`",
        "https://example.com;rm -rf /",
        "https://example.com\"injected\"",
        "https://example.com'injected'",
        "https://exámple.com",
        "http://example.com",
        "ftp://example.com",
    ];
    for bad in cases {
        let mut app = sample_app();
        app.attestation.acme_ca_url = bad.to_string();
        match render_caddyfile(&app) {
            Err(IngressRenderError::InvalidAcmeUrl(_)) => {}
            Err(IngressRenderError::InvalidHostname(_)) => {}
            Err(other) => panic!("unexpected error variant for {bad:?}: {other:?}"),
            Ok(out) => panic!("expected rejection for {bad:?}, got rendered:\n{out}"),
        }
    }
}

#[test]
fn render_rejects_injection_via_custom_domain() {
    let cases = [
        "host}\n  acl evil",
        "host;",
        "host`",
        "host\0",
        "host\n",
        "host'evil'",
        "host\"evil\"",
        "host{evil}",
    ];
    for bad in cases {
        let mut app = sample_app();
        app.domain.custom_domain = Some(bad.to_string());
        // primary_domain prefers custom — so it's now the value being
        // validated by the renderer.
        assert!(
            render_caddyfile(&app).is_err(),
            "expected rejection for {bad:?}"
        );
    }
}
