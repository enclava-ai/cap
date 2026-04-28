use enclava_common::image::ImageRef;
use enclava_common::types::{BootstrapPolicy, Durability, ResourceLimits, UnlockMode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Complete specification for a confidential application deployment.
/// This is the sole input to the engine's manifest generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialApp {
    /// Stable UUID, used in KBS paths.
    pub app_id: Uuid,
    /// Human-readable name (unique within org).
    pub name: String,
    /// Kubernetes namespace (immutable after create).
    pub namespace: String,
    /// Stable identity for key derivation (immutable).
    /// OID-6: instance_id = "{tenant_id}-{app_id_short}".
    pub instance_id: String,
    /// Org identifier for identity hash computation (immutable).
    /// OID-6: tenant_id = org name.
    pub tenant_id: String,
    /// Hex SHA256 of the claim public key. Present for ALL apps:
    /// - Auto-unlock: platform generates the keypair and holds the private key
    /// - Password: user generates the keypair and holds the private key
    pub bootstrap_owner_pubkey_hash: String,
    /// SHA256(tenant_id:instance_id:pubkey_hash). Present for ALL apps.
    /// Used as the identity binding in KBS owner_resource_bindings Rego.
    pub tenant_instance_identity_hash: String,
    /// Kubernetes ServiceAccount name for this app.
    pub service_account: String,
    /// Customer-controlled signer identity bound into KBS policy when present.
    pub signer_identity_subject: Option<String>,
    pub signer_identity_issuer: Option<String>,
    /// User's application containers.
    pub containers: Vec<Container>,
    /// Encrypted storage configuration (two volumes).
    pub storage: StorageSpec,
    /// How the app's storage is unlocked.
    pub unlock_mode: UnlockMode,
    /// Domain configuration.
    pub domain: DomainSpec,
    /// API's Ed25519 public key for config JWT verification (embedded in cc_init_data).
    pub api_signing_pubkey: String,
    /// API URL for config metadata sync.
    pub api_url: String,
    /// CPU and memory limits.
    pub resources: ResourceLimits,
    /// Attestation proxy and ingress sidecar configuration.
    pub attestation: AttestationConfig,
    /// Per-app world-egress allowlist (Phase 11). Default: empty -> no
    /// world-egress rules emitted. Each rule is rendered as a Cilium `toFQDNs`
    /// egress entry restricted to the listed TCP ports.
    #[serde(default)]
    pub egress_allowlist: Vec<EgressRule>,
}

/// One world-egress allowance. Hosts must validate as FQDNs (see
/// `enclava_common::validate::validate_fqdn`); ports are TCP only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRule {
    pub host: String,
    pub ports: Vec<u16>,
}

/// Attestation proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Attestation proxy image reference (digest-pinned).
    pub proxy_image: ImageRef,
    /// Caddy tenant-ingress image reference (digest-pinned).
    pub caddy_image: ImageRef,
    /// ACME directory URL used by tenant Caddy for DNS-01 issuance.
    #[serde(default = "default_acme_ca_url")]
    pub acme_ca_url: String,
    /// Cloudflare API token secret name for ACME DNS-01 challenge.
    pub cloudflare_token_secret: String,
    /// Cloudflare API token value copied into each tenant namespace for Caddy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare_api_token: Option<String>,
}

pub fn default_acme_ca_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

/// A user-defined container in the app pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    /// Container name (e.g., "web", "redis").
    pub name: String,
    /// OCI image reference. Must have digest for deployment (enforced at validation time).
    pub image: ImageRef,
    /// Port the container listens on.
    pub port: Option<u16>,
    /// Override command.
    pub command: Option<Vec<String>>,
    /// Non-secret environment variables.
    pub env: std::collections::HashMap<String, String>,
    /// Paths to bind-mount from the app-data LUKS volume.
    pub storage_paths: Vec<String>,
    /// Whether this is the primary container (gets domain routing).
    pub is_primary: bool,
}

/// Two-volume storage specification.
///
/// App data is owner-seed backed. TLS data keeps the legacy KBS seed model so
/// Caddy can start with persisted certificates before app-data is claimed or
/// unlocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSpec {
    pub app_data: VolumeSpec,
    pub tls_data: VolumeSpec,
}

impl StorageSpec {
    /// Create default storage spec with given sizes.
    pub fn new(app_data_size: &str, tls_data_size: &str) -> Self {
        Self {
            app_data: VolumeSpec {
                size: app_data_size.to_string(),
                device_path: "/dev/csi0".to_string(),
                mount_path: "/data".to_string(),
                durability: Durability::DurableState,
                bootstrap_policy: BootstrapPolicy::FirstBootOnly,
                bind_mounts: Vec::new(),
            },
            tls_data: VolumeSpec {
                size: tls_data_size.to_string(),
                device_path: "/dev/csi1".to_string(),
                mount_path: "/tls-data".to_string(),
                durability: Durability::DisposableState,
                bootstrap_policy: BootstrapPolicy::AllowReinit,
                bind_mounts: Vec::new(),
            },
        }
    }
}

/// Configuration for a single LUKS-encrypted block volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSpec {
    /// Volume size (e.g., "10Gi").
    pub size: String,
    /// Block device path inside the container (e.g., "/dev/csi0").
    pub device_path: String,
    /// Mount point for the decrypted filesystem (e.g., "/data").
    pub mount_path: String,
    /// Durability class.
    pub durability: Durability,
    /// Bootstrap policy for LUKS initialization.
    pub bootstrap_policy: BootstrapPolicy,
    /// Bind mounts from subdirectories to container paths.
    pub bind_mounts: Vec<BindMount>,
}

/// A bind mount from a LUKS volume subdirectory to a container path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMount {
    /// Source path within the LUKS volume (e.g., "/data/postgresql").
    pub source: String,
    /// Destination path in the container (e.g., "/var/lib/postgresql/data").
    pub destination: String,
}

/// Domain configuration for an app. Per D1 (two-hostname model) every app
/// has both a user-facing app hostname and a TEE-facing hostname.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSpec {
    /// App hostname `<app>.<orgSlug>.<platform_domain>`.
    pub platform_domain: String,
    /// TEE hostname `<app>.<orgSlug>.<tee_domain_suffix>`.
    #[serde(default)]
    pub tee_domain: String,
    /// Optional custom domain (e.g., "app.example.com").
    pub custom_domain: Option<String>,
}

impl ConfidentialApp {
    /// Returns the primary container (the one that gets domain routing).
    pub fn primary_container(&self) -> Option<&Container> {
        self.containers.iter().find(|c| c.is_primary)
    }

    /// Returns the app's primary domain (custom if set, platform otherwise).
    pub fn primary_domain(&self) -> &str {
        self.domain
            .custom_domain
            .as_deref()
            .unwrap_or(&self.domain.platform_domain)
    }

    /// KBS owner ciphertext path prefix for this app.
    /// E.g., "default/{namespace}-{name}-owner"
    pub fn owner_resource_path(&self) -> String {
        format!("default/{}", self.owner_resource_type())
    }

    /// Stable owner-resource instance name used by the attestation proxy.
    ///
    /// The live Trustee policy derives owner resource access from the attested
    /// Kubernetes namespace and the `tenant.flowforge.sh/instance` annotation,
    /// so CAP uses the namespace and app name for the KBS owner path.
    pub fn owner_instance_id(&self) -> String {
        format!("{}-{}", self.namespace, self.name)
    }

    /// KBS owner resource type for `owner_resource_bindings`.
    pub fn owner_resource_type(&self) -> String {
        format!("{}-owner", self.owner_instance_id())
    }

    /// KBS TLS resource path used by tenant-ingress Caddy.
    pub fn tls_resource_path(&self) -> String {
        format!("default/{}/workload-secret-seed", self.tls_resource_type())
    }

    /// KBS TLS resource type for generic `resource_bindings`.
    pub fn tls_resource_type(&self) -> String {
        format!("{}-tls", self.owner_instance_id())
    }
}
