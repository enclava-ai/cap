//! Cosign signature verification with per-app Fulcio identity policies.
//!
//! Verification model:
//! - Each app pins a `VerificationPolicy` (Fulcio URL/email identity, or a
//!   raw public key for advanced offline-signing users).
//! - The customer signs their own image — typically inside their own
//!   GitHub Actions runner via cosign keyless — and we verify the resulting
//!   signature against the app's pinned policy.
//! - Rekor inclusion is required: the trust root carries Rekor pubkeys, so
//!   `trusted_signature_layers` only returns layers whose Rekor bundle
//!   verifies. Signatures without Rekor evidence yield zero trusted layers
//!   and we reject.
//!
//! Trust root pinning:
//! - In production we pin to a TUF metadata snapshot bundled with the CAP
//!   release. Set `SIGSTORE_TUF_ROOT_PATH` to a trusted_root.json file
//!   shipped with the release artifact. Without that env var, the verifier
//!   falls back to the Sigstore Public Good Instance via TUF, which performs
//!   a network fetch — acceptable in dev, refused in production deployments
//!   by the surrounding ops policy.
//! - Refresh process: build a new CAP release with an updated bundled
//!   trusted_root.json fetched from the official Sigstore TUF repo, signed
//!   into the release artifact like any other dependency.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sigstore::cosign::CosignCapabilities;
use sigstore::cosign::verification_constraint::{
    CertSubjectEmailVerifier, CertSubjectUrlVerifier, PublicKeyVerifier, VerificationConstraintVec,
    cert_subject_email_verifier::StringVerifier,
};
use sigstore::cosign::{ClientBuilder, verify_constraints};
use sigstore::crypto::SigningScheme;
use sigstore::registry::{Auth, ClientConfig, ClientProtocol, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;

use crate::registry::registry_base_url;

#[derive(Debug, thiserror::Error)]
pub enum CosignError {
    #[error("cosign verification failed: {0}")]
    VerificationFailed(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("image is not signed: {0}")]
    NotSigned(String),
    #[error("signer policy is not configured for this app")]
    PolicyNotConfigured,
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("trust root error: {0}")]
    TrustRoot(String),
}

/// Per-app verification policy.
///
/// `FulcioUrlIdentity` matches GitHub Actions OIDC subjects, which are URL-
/// shaped (e.g. `https://github.com/<org>/<repo>/.github/workflows/...`).
/// `FulcioEmailIdentity` is for OIDC issuers using email subjects (Google,
/// generic OIDC). `PublicKey` is for advanced users who sign offline.
#[derive(Debug, Clone)]
pub enum VerificationPolicy {
    FulcioUrlIdentity {
        fulcio_subject_url: String,
        fulcio_issuer: String,
    },
    FulcioEmailIdentity {
        email: String,
        fulcio_issuer: String,
    },
    PublicKey {
        pem: String,
    },
}

/// Result of a successful verification, recorded for audit/deployment.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedSignature {
    pub digest: String,
    pub signer_subject: Option<String>,
    pub signer_issuer: Option<String>,
    pub verified_at: DateTime<Utc>,
    pub rekor_log_index: Option<i64>,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn looks_like_not_signed_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("manifest unknown")
        || lower.contains("name unknown")
        || lower.contains("not found")
        || lower.contains("404")
}

/// Convert a digest like "sha256:abcdef..." to the cosign tag format "sha256-abcdef..."
fn digest_to_cosign_tag(digest: &str, suffix: &str) -> String {
    let tag = digest.replace(':', "-");
    format!("{}.{}", tag, suffix)
}

/// Parse an image reference into (registry, repository) components.
fn parse_image_parts(image_ref: &str) -> Result<(String, String), CosignError> {
    let base = image_ref
        .split('@')
        .next()
        .unwrap_or(image_ref)
        .split(':')
        .next()
        .unwrap_or(image_ref);

    let parts: Vec<&str> = base.splitn(3, '/').collect();
    match parts.len() {
        1 => Ok(("docker.io".to_string(), format!("library/{}", parts[0]))),
        2 => {
            if parts[0].contains('.') || parts[0].contains(':') {
                Ok((parts[0].to_string(), parts[1].to_string()))
            } else {
                Ok((
                    "docker.io".to_string(),
                    format!("{}/{}", parts[0], parts[1]),
                ))
            }
        }
        3 => Ok((parts[0].to_string(), format!("{}/{}", parts[1], parts[2]))),
        _ => Err(CosignError::VerificationFailed(format!(
            "cannot parse image reference: {}",
            image_ref
        ))),
    }
}

/// Build a sigstore trust root, preferring a bundled TUF snapshot when
/// `SIGSTORE_TUF_ROOT_PATH` is set.
async fn load_trust_root() -> Result<Arc<SigstoreTrustRoot>, CosignError> {
    if let Ok(path) = std::env::var("SIGSTORE_TUF_ROOT_PATH") {
        let data = std::fs::read(&path).map_err(|e| {
            CosignError::TrustRoot(format!(
                "failed to read SIGSTORE_TUF_ROOT_PATH {}: {}",
                path, e
            ))
        })?;
        let root = SigstoreTrustRoot::from_trusted_root_json_unchecked(&data).map_err(|e| {
            CosignError::TrustRoot(format!("invalid bundled trusted_root.json: {}", e))
        })?;
        return Ok(Arc::new(root));
    }

    let root = SigstoreTrustRoot::new(None)
        .await
        .map_err(|e| CosignError::TrustRoot(format!("sigstore TUF fetch failed: {}", e)))?;
    Ok(Arc::new(root))
}

fn build_constraints(
    policy: &VerificationPolicy,
) -> Result<VerificationConstraintVec, CosignError> {
    let constraints: VerificationConstraintVec = match policy {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url,
            fulcio_issuer,
        } => {
            if fulcio_subject_url.is_empty() || fulcio_issuer.is_empty() {
                return Err(CosignError::InvalidPolicy(
                    "fulcio subject and issuer must be non-empty".to_string(),
                ));
            }
            vec![Box::new(CertSubjectUrlVerifier {
                url: fulcio_subject_url.clone(),
                issuer: fulcio_issuer.clone(),
            })]
        }
        VerificationPolicy::FulcioEmailIdentity {
            email,
            fulcio_issuer,
        } => {
            if email.is_empty() || fulcio_issuer.is_empty() {
                return Err(CosignError::InvalidPolicy(
                    "fulcio email and issuer must be non-empty".to_string(),
                ));
            }
            vec![Box::new(CertSubjectEmailVerifier {
                email: StringVerifier::ExactMatch(email.clone()),
                issuer: Some(StringVerifier::ExactMatch(fulcio_issuer.clone())),
            })]
        }
        VerificationPolicy::PublicKey { pem } => {
            let verifier =
                PublicKeyVerifier::new(pem.as_bytes(), &SigningScheme::default()).map_err(
                    |e| CosignError::InvalidPolicy(format!("invalid public key PEM: {}", e)),
                )?;
            vec![Box::new(verifier)]
        }
    };
    Ok(constraints)
}

/// Verify that a cosign signature exists for the given image digest and
/// satisfies the app's pinned verification policy.
pub async fn verify_image(
    image_ref: &str,
    image_digest: &str,
    policy: &VerificationPolicy,
) -> Result<VerifiedSignature, CosignError> {
    let trust_root = load_trust_root().await?;

    let image: OciReference = image_ref
        .parse()
        .map_err(|e| CosignError::VerificationFailed(format!("invalid image reference: {}", e)))?;

    let mut oci_client_config = ClientConfig::default();
    if env_flag("COSIGN_ALLOW_HTTP_REGISTRY") {
        oci_client_config.protocol = ClientProtocol::Http;
    }

    let mut cosign_client = ClientBuilder::default()
        .with_oci_client_config(oci_client_config)
        .with_trust_repository(trust_root.as_ref())
        .map_err(|e| CosignError::TrustRoot(format!("trust repository setup failed: {}", e)))?
        .build()
        .map_err(|e| {
            CosignError::VerificationFailed(format!("failed to initialize sigstore client: {}", e))
        })?;

    let auth = Auth::Anonymous;
    let (cosign_signature_image, source_image_digest) = cosign_client
        .triangulate(&image, &auth)
        .await
        .map_err(|e| {
            CosignError::VerificationFailed(format!("failed to triangulate signature image: {}", e))
        })?;

    if source_image_digest != image_digest {
        return Err(CosignError::VerificationFailed(format!(
            "image digest mismatch: resolved {}, expected {}",
            source_image_digest, image_digest
        )));
    }

    let trusted_layers = cosign_client
        .trusted_signature_layers(&auth, &source_image_digest, &cosign_signature_image)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if looks_like_not_signed_error(&msg) {
                CosignError::NotSigned(format!("no cosign signature found for {}", image_digest))
            } else {
                CosignError::VerificationFailed(format!(
                    "failed to fetch/verify signature layers: {}",
                    msg
                ))
            }
        })?;

    if trusted_layers.is_empty() {
        return Err(CosignError::NotSigned(format!(
            "no Rekor-attested signature layers for {}",
            image_digest
        )));
    }

    let constraints = build_constraints(policy)?;
    verify_constraints(&trusted_layers, constraints.iter()).map_err(|e| {
        CosignError::VerificationFailed(format!(
            "signature did not satisfy app's verification policy: {}",
            e
        ))
    })?;

    let (signer_subject, signer_issuer, rekor_log_index) =
        extract_signer_metadata(&trusted_layers, policy);

    Ok(VerifiedSignature {
        digest: image_digest.to_string(),
        signer_subject,
        signer_issuer,
        verified_at: Utc::now(),
        rekor_log_index,
    })
}

fn extract_signer_metadata(
    layers: &[sigstore::cosign::SignatureLayer],
    policy: &VerificationPolicy,
) -> (Option<String>, Option<String>, Option<i64>) {
    use sigstore::cosign::signature_layers::CertificateSubject;

    let layer = layers.iter().find(|l| l.certificate_signature.is_some());
    let mut subject: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut rekor_index: Option<i64> = None;

    if let Some(layer) = layer
        && let Some(cert) = &layer.certificate_signature
    {
        subject = match &cert.subject {
            CertificateSubject::Email(e) => Some(e.clone()),
            CertificateSubject::Uri(u) => Some(u.clone()),
        };
        issuer = cert.issuer.clone();
    }

    if let Some(layer) = layers.iter().find(|l| l.bundle.is_some())
        && let Some(bundle) = &layer.bundle
    {
        rekor_index = Some(bundle.payload.log_index);
    }

    if subject.is_none() {
        match policy {
            VerificationPolicy::FulcioUrlIdentity {
                fulcio_subject_url,
                fulcio_issuer,
            } => {
                subject = Some(fulcio_subject_url.clone());
                issuer = Some(fulcio_issuer.clone());
            }
            VerificationPolicy::FulcioEmailIdentity {
                email,
                fulcio_issuer,
            } => {
                subject = Some(email.clone());
                issuer = Some(fulcio_issuer.clone());
            }
            VerificationPolicy::PublicKey { .. } => {}
        }
    }

    (subject, issuer, rekor_index)
}

/// Fetch provenance attestation and SBOM from OCI registry attestation tags.
pub async fn fetch_attestations(
    client: &reqwest::Client,
    image_ref: &str,
    digest: &str,
) -> Result<(Option<serde_json::Value>, Option<serde_json::Value>), CosignError> {
    let (registry, repository) = parse_image_parts(image_ref)?;
    let base_url = registry_base_url(&registry)
        .map_err(|e| CosignError::VerificationFailed(format!("unsupported registry: {}", e)))?;

    let provenance = fetch_attestation_tag(client, &base_url, &repository, digest, "att").await?;
    let sbom = fetch_attestation_tag(client, &base_url, &repository, digest, "sbom").await?;

    Ok((provenance, sbom))
}

async fn fetch_attestation_tag(
    client: &reqwest::Client,
    base_url: &str,
    repository: &str,
    digest: &str,
    suffix: &str,
) -> Result<Option<serde_json::Value>, CosignError> {
    let tag = digest_to_cosign_tag(digest, suffix);
    let url = format!("{}/v2/{}/manifests/{}", base_url, repository, tag);

    let response = client
        .get(&url)
        .header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !response.status().is_success() {
        tracing::warn!(
            "registry returned {} when fetching {}.{} attestation",
            response.status(),
            digest,
            suffix
        );
        return Ok(None);
    }

    let body = response.text().await?;
    match serde_json::from_str(&body) {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            tracing::warn!("failed to parse {} attestation as JSON: {}", suffix, e);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url_policy() -> VerificationPolicy {
        VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url:
                "https://github.com/example/repo/.github/workflows/build.yml@refs/heads/main"
                    .to_string(),
            fulcio_issuer: "https://token.actions.githubusercontent.com".to_string(),
        }
    }

    #[test]
    fn build_constraints_url_policy_ok() {
        let c = build_constraints(&url_policy()).expect("constraints build");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn build_constraints_email_policy_ok() {
        let policy = VerificationPolicy::FulcioEmailIdentity {
            email: "ci@example.com".to_string(),
            fulcio_issuer: "https://accounts.google.com".to_string(),
        };
        let c = build_constraints(&policy).expect("constraints build");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn build_constraints_rejects_empty_url_subject() {
        let policy = VerificationPolicy::FulcioUrlIdentity {
            fulcio_subject_url: String::new(),
            fulcio_issuer: "https://token.actions.githubusercontent.com".to_string(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn build_constraints_rejects_empty_email_issuer() {
        let policy = VerificationPolicy::FulcioEmailIdentity {
            email: "ci@example.com".to_string(),
            fulcio_issuer: String::new(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn build_constraints_rejects_invalid_public_key() {
        let policy = VerificationPolicy::PublicKey {
            pem: "not a real PEM".to_string(),
        };
        assert!(matches!(
            build_constraints(&policy),
            Err(CosignError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn parse_image_parts_handles_common_shapes() {
        assert_eq!(
            parse_image_parts("nginx").unwrap(),
            ("docker.io".to_string(), "library/nginx".to_string())
        );
        assert_eq!(
            parse_image_parts("ghcr.io/org/repo:v1").unwrap(),
            ("ghcr.io".to_string(), "org/repo".to_string())
        );
        assert_eq!(
            parse_image_parts("user/repo:tag").unwrap(),
            ("docker.io".to_string(), "user/repo".to_string())
        );
    }
}
