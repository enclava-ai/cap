//! Cosign signature verification for container images.
//!
//! Verifies image signatures against a configured cosign public key and
//! fetches optional attestation tags from the OCI registry.

use reqwest::Client;
use sigstore::cosign::verification_constraint::{PublicKeyVerifier, VerificationConstraintVec};
use sigstore::cosign::{CosignCapabilities, verify_constraints};
use sigstore::registry::{Auth, ClientConfig, ClientProtocol, OciReference};

use crate::registry::registry_base_url;

#[derive(Debug, thiserror::Error)]
pub enum CosignError {
    #[error("cosign verification failed: {0}")]
    VerificationFailed(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("image is not signed: {0}")]
    NotSigned(String),
}

/// Convert a digest like "sha256:abcdef..." to the cosign tag format "sha256-abcdef..."
fn digest_to_cosign_tag(digest: &str, suffix: &str) -> String {
    let tag = digest.replace(':', "-");
    format!("{}.{}", tag, suffix)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn load_cosign_public_key() -> Result<Vec<u8>, CosignError> {
    if let Ok(path) = std::env::var("COSIGN_PUBLIC_KEY_PATH") {
        return std::fs::read(&path).map_err(|e| {
            CosignError::VerificationFailed(format!(
                "failed to read COSIGN_PUBLIC_KEY_PATH {}: {}",
                path, e
            ))
        });
    }

    if let Ok(pem) = std::env::var("COSIGN_PUBLIC_KEY_PEM") {
        return Ok(pem.into_bytes());
    }

    Err(CosignError::VerificationFailed(
        "missing cosign key: set COSIGN_PUBLIC_KEY_PATH or COSIGN_PUBLIC_KEY_PEM".to_string(),
    ))
}

fn looks_like_not_signed_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("manifest unknown")
        || lower.contains("name unknown")
        || lower.contains("not found")
        || lower.contains("404")
}

/// Parse an image reference into (registry, repository) components.
/// Handles docker.io shorthand and standard registry/repo formats.
fn parse_image_parts(image_ref: &str) -> Result<(String, String), CosignError> {
    // Strip any tag or digest suffix to get the base reference
    let base = image_ref
        .split('@')
        .next()
        .unwrap_or(image_ref)
        .split(':')
        .next()
        .unwrap_or(image_ref);

    let parts: Vec<&str> = base.splitn(3, '/').collect();
    match parts.len() {
        1 => {
            // e.g. "nginx" -> docker.io/library/nginx
            Ok(("docker.io".to_string(), format!("library/{}", parts[0])))
        }
        2 => {
            // Could be "user/repo" (docker.io) or "ghcr.io/repo"
            if parts[0].contains('.') || parts[0].contains(':') {
                Ok((parts[0].to_string(), parts[1].to_string()))
            } else {
                Ok((
                    "docker.io".to_string(),
                    format!("{}/{}", parts[0], parts[1]),
                ))
            }
        }
        3 => {
            // e.g. "ghcr.io/org/repo"
            Ok((parts[0].to_string(), format!("{}/{}", parts[1], parts[2])))
        }
        _ => Err(CosignError::VerificationFailed(format!(
            "cannot parse image reference: {}",
            image_ref
        ))),
    }
}

/// Verify that a cosign signature exists for the given image digest.
///
/// Checks for the cosign signature tag at the OCI registry:
/// `{digest_algo}-{digest_hex}.sig`
///
/// Returns `Ok(true)` when signature tag is found.
/// Returns `Err(CosignError::NotSigned)` when no signature exists.
pub async fn verify_image(
    _client: &Client,
    image_ref: &str,
    digest: &str,
) -> Result<bool, CosignError> {
    let public_key = load_cosign_public_key()?;
    let image: OciReference = image_ref
        .parse()
        .map_err(|e| CosignError::VerificationFailed(format!("invalid image reference: {}", e)))?;

    let mut oci_client_config = ClientConfig::default();
    if env_flag("COSIGN_ALLOW_HTTP_REGISTRY") {
        oci_client_config.protocol = ClientProtocol::Http;
    }

    let mut cosign_client = sigstore::cosign::ClientBuilder::default()
        .with_oci_client_config(oci_client_config)
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

    if source_image_digest != digest {
        return Err(CosignError::VerificationFailed(format!(
            "image digest mismatch: resolved {}, expected {}",
            source_image_digest, digest
        )));
    }

    let trusted_layers = cosign_client
        .trusted_signature_layers(&auth, &source_image_digest, &cosign_signature_image)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if looks_like_not_signed_error(&msg) {
                CosignError::NotSigned(format!("no cosign signature found for {}", digest))
            } else {
                CosignError::VerificationFailed(format!(
                    "failed to fetch/verify signature layers: {}",
                    msg
                ))
            }
        })?;

    if trusted_layers.is_empty() {
        return Err(CosignError::NotSigned(format!(
            "no trusted cosign signature layers for {}",
            digest
        )));
    }

    let public_key_verifier = PublicKeyVerifier::try_from(&public_key).map_err(|e| {
        CosignError::VerificationFailed(format!("invalid cosign public key: {}", e))
    })?;
    let constraints: VerificationConstraintVec = vec![Box::new(public_key_verifier)];

    verify_constraints(&trusted_layers, constraints.iter()).map_err(|e| {
        CosignError::VerificationFailed(format!(
            "cosign signature did not satisfy public key constraint: {}",
            e
        ))
    })?;

    Ok(true)
}

/// Fetch provenance attestation and SBOM from OCI registry attestation tags.
///
/// Checks for:
/// - Provenance attestation: `{digest_algo}-{digest_hex}.att`
/// - SBOM: `{digest_algo}-{digest_hex}.sbom`
///
/// Returns `(provenance_json, sbom_json)` -- `None` for each if not found.
pub async fn fetch_attestations(
    client: &Client,
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

/// Fetch a single attestation tag from the registry.
/// Returns None if the tag doesn't exist (404).
async fn fetch_attestation_tag(
    client: &Client,
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
        // Non-fatal: attestation tags are optional
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
