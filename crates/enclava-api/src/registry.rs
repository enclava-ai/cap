//! OCI registry client for resolving image tags to digests.
//!
//! Supports Docker Hub, GHCR, and any OCI-compliant registry.
//! Uses the distribution spec v2 manifest endpoint.

use reqwest::Client;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("failed to resolve image tag: {0}")]
    ResolveFailed(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("image not found: {0}")]
    NotFound(String),
    #[error("unsupported registry: {0}")]
    UnsupportedRegistry(String),
}

/// Resolve an image tag to a digest by querying the registry's manifest endpoint.
/// Returns the full digest string (e.g., "sha256:abcd...").
pub async fn resolve_tag_to_digest(
    client: &Client,
    registry: &str,
    repository: &str,
    tag: &str,
) -> Result<String, RegistryError> {
    let base_url = registry_base_url(registry)?;

    // HEAD request for the manifest, accepting OCI and Docker media types
    let url = format!("{}/v2/{}/manifests/{}", base_url, repository, tag);

    let response = client
        .head(&url)
        .header(
            "Accept",
            "application/vnd.oci.image.index.v1+json, \
             application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json, \
             application/vnd.docker.distribution.manifest.list.v2+json",
        )
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(RegistryError::NotFound(format!(
            "{}/{}:{}",
            registry, repository, tag
        )));
    }

    if !response.status().is_success() {
        return Err(RegistryError::ResolveFailed(format!(
            "registry returned status {}",
            response.status()
        )));
    }

    // The digest is in the Docker-Content-Digest header
    let digest = response
        .headers()
        .get("Docker-Content-Digest")
        .or_else(|| response.headers().get("docker-content-digest"))
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            RegistryError::ResolveFailed("no Docker-Content-Digest header in response".to_string())
        })?;

    Ok(digest.to_string())
}

/// Map registry hostname to base URL.
pub fn registry_base_url(registry: &str) -> Result<String, RegistryError> {
    match registry {
        "docker.io" => Ok("https://registry-1.docker.io".to_string()),
        "ghcr.io" => Ok("https://ghcr.io".to_string()),
        r if r.contains('.') => Ok(format!("https://{}", r)),
        _ => Err(RegistryError::UnsupportedRegistry(registry.to_string())),
    }
}

/// Parse a full image reference and resolve the tag to a digest.
/// If the image already has a digest, returns it as-is.
pub async fn resolve_image_digest(
    client: &Client,
    image_ref: &enclava_common::image::ImageRef,
) -> Result<String, RegistryError> {
    if image_ref.has_digest() {
        return Ok(image_ref.digest().to_string());
    }

    let tag = image_ref
        .tag()
        .ok_or_else(|| RegistryError::ResolveFailed("image has no tag or digest".to_string()))?;

    resolve_tag_to_digest(client, image_ref.registry(), image_ref.repository(), tag).await
}
