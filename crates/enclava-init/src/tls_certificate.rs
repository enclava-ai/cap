//! Static TLS certificate provisioning through the workload-attested broker.
//!
//! Trust model (review fix on top of the retained-state validation):
//!
//! * Every chain — retained on disk or freshly returned by the broker — is
//!   validated with webpki [`EndEntityCert::verify_for_usage`] for
//!   `serverAuth` against the independently trusted public root store
//!   (`webpki-roots`, the Mozilla CA certificate programme). Only that store
//!   is trusted in production; there is no configuration switch that adds,
//!   downloads, or extends roots.
//! * Certificates carried inside a chain never extend the trust store: a
//!   trailing self-signed root, a root sent in the same broker response, or a
//!   leaf-only chain all fail closed unless the chain independently leads to
//!   a configured trust anchor. Signature linkage, issuer validity windows,
//!   CA basic constraints/path lengths, name constraints, and serverAuth EKU
//!   are all enforced by webpki during path building.
//! * The public store deliberately does not contain the Let's Encrypt
//!   *staging* roots, so staging-issued chains are rejected by default. A
//!   future staging deployment needs explicit, separately reviewed trust
//!   support; it is never inferred from URLs, chain contents, or broker
//!   responses (see `TLS_CERTIFICATE_VALIDATION.md`).
//!
//! Retained-state policy: reuse is only permitted when the retained
//! certificate and key are regular files and the full anchored validation
//! passes. Anything else — non-regular files, symlinks (including dangling
//! ones), unreadable state, malformed/expired/untrusted chains, key
//! mismatches — aborts provisioning without ordering a replacement
//! certificate and without replacing the retained private key. Only an
//! actually absent certificate (ENOENT) starts issuance; a certificate-less
//! retained key is reused for the new CSR so an interrupted first issuance
//! retries with the same key.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SigningKey};
use rustls_pki_types::{
    CertificateDer, ServerName, SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, KeyUsage};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::Config;
use crate::{trustee_verify, writes};

pub const CERT_RELATIVE_PATH: &str = "certificates/tls.crt";
pub const KEY_RELATIVE_PATH: &str = "certificates/tls.key";

/// Signature algorithms accepted during chain validation. Covers the
/// algorithm families used by public WebPKI issuers (and therefore by the
/// broker's ACME provider).
const SUPPORTED_SIG_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
];

/// Reuse clock tolerance for `notBefore`: broker-issued certificates can
/// carry an issuance timestamp slightly ahead of the workload clock. When a
/// chain is not valid yet by at most this much, path validation is retried
/// at the certificate's own `notBefore` time; expiry stays strict.
const NOT_BEFORE_TOLERANCE_SECS: u64 = 300;

/// Fixed message signed with the retained/generated TLS private key to prove
/// the certificate leaf was issued for exactly that key.
const TLS_KEY_BINDING_PROBE: &[u8] = b"enclava-init tls certificate key binding probe";

#[derive(Debug, Serialize)]
struct CertificateRequest<'a> {
    hostnames: &'a [String],
    csr_der_base64: String,
    cc_init_data_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CertificateResponse {
    certificate_chain_pem: String,
}

pub fn provision_static_tls_certificate(cfg: &Config, persistent_root: &Path) -> Result<()> {
    provision_with_trust_anchors(cfg, persistent_root, TLS_SERVER_ROOTS)
}

/// Same as [`provision_static_tls_certificate`], with the trust anchor set
/// injected by the in-module tests (synthetic independently trusted anchors).
/// Production callers reach this only through
/// [`provision_static_tls_certificate`], which always passes the public
/// `webpki-roots` store; there is no configuration path that alters anchors.
fn provision_with_trust_anchors(
    cfg: &Config,
    persistent_root: &Path,
    trust_anchors: &[TrustAnchor<'_>],
) -> Result<()> {
    let Some(broker_url) = cfg.tls_certificate_broker_url.as_deref() else {
        return Ok(());
    };
    if cfg.tls_certificate_hostnames.is_empty() {
        return Err(anyhow!(
            "tls-certificate-broker-url requires tls-certificate-hostnames"
        ));
    }

    let cert_path = cert_path(persistent_root);
    let key_path = key_path(persistent_root);
    if retained_path_is_regular_file(&cert_path)
        .with_context(|| format!("checking retained TLS certificate {}", cert_path.display()))?
    {
        // Fail closed on retained state: an incomplete, malformed, expired,
        // untrusted, or mismatched certificate never triggers a new broker
        // order and the retained private key is never replaced. An operator
        // must remove the stale certificate explicitly to force reissuance.
        if !retained_path_is_regular_file(&key_path)
            .with_context(|| format!("checking retained TLS private key {}", key_path.display()))?
        {
            return Err(anyhow!(
                "retained TLS certificate {} exists but private key {} is missing; \
                 refusing to order a replacement certificate or replace the private key",
                cert_path.display(),
                key_path.display()
            ));
        }
        validate_retained_tls_state(
            trust_anchors,
            &cfg.tls_certificate_hostnames,
            &cert_path,
            &key_path,
        )
        .context("validating retained static TLS certificate")?;
        tracing::info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "retained static TLS certificate validated; skipping issuance"
        );
        return Ok(());
    }

    let key_pair = load_or_generate_key(&key_path)?;
    let csr_der = build_csr_der(&cfg.tls_certificate_hostnames, &key_pair)?;
    let token = trustee_verify::resolve_kbs_attestation_token(
        std::env::var("KBS_ATTESTATION_TOKEN").ok().as_deref(),
        &cfg.kbs_attestation_token_url,
        Duration::from_secs(15),
    )
    .context("resolving KBS attestation token for TLS certificate broker")?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .context("building TLS certificate broker client")?;
    let request = CertificateRequest {
        hostnames: &cfg.tls_certificate_hostnames,
        csr_der_base64: base64::engine::general_purpose::STANDARD.encode(csr_der),
        cc_init_data_hash: local_cc_init_data_hash(cfg)?,
    };
    let response = client
        .post(broker_url)
        .header("Authorization", format!("Attestation {token}"))
        .json(&request)
        .send()
        .with_context(|| format!("requesting TLS certificate from {broker_url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "TLS certificate broker returned HTTP {status}: {body}"
        ));
    }
    let body: CertificateResponse = response
        .json()
        .context("decoding TLS certificate broker response")?;
    validate_certificate_chain(
        &body.certificate_chain_pem,
        &key_pair,
        &cfg.tls_certificate_hostnames,
        trust_anchors,
    )
    .context("validating TLS certificate broker response")?;
    writes::atomic_write(&cert_path, body.certificate_chain_pem.as_bytes(), 0o644)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    Ok(())
}

pub fn cert_path(persistent_root: &Path) -> PathBuf {
    persistent_root.join(CERT_RELATIVE_PATH)
}

pub fn key_path(persistent_root: &Path) -> PathBuf {
    persistent_root.join(KEY_RELATIVE_PATH)
}

/// Classify retained TLS state fail-closed: `Ok(true)` for a regular file,
/// `Ok(false)` only for a confirmed missing path (ENOENT). Directories,
/// symlinks (including dangling ones and links to regular files), other
/// non-regular inodes, and stat errors are hard errors — none of them may
/// silently start issuance or be overwritten.
fn retained_path_is_regular_file(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(anyhow!(
                    "{} is a symbolic link; refusing to use or replace it as retained TLS state",
                    path.display()
                ));
            }
            if !file_type.is_file() {
                return Err(anyhow!(
                    "{} is not a regular file; refusing to use or replace it as retained TLS state",
                    path.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow!("reading metadata of {}: {error}", path.display())),
    }
}

/// Validate retained TLS state read from the confidential encrypted volume.
fn validate_retained_tls_state(
    trust_anchors: &[TrustAnchor<'_>],
    hostnames: &[String],
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    let chain_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading retained TLS certificate {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading retained TLS private key {}", key_path.display()))?;
    let key_pair = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("parsing retained TLS private key {}", key_path.display()))?;
    validate_certificate_chain(&chain_pem, &key_pair, hostnames, trust_anchors)
}

/// Validate a PEM certificate chain against the retained private key, the
/// configured hostnames, and the given trust anchors.
///
/// Checks: PEM blocks are all certificates; the leaf is issued for exactly
/// the retained private key (signature probe verified with the leaf's public
/// key); the leaf covers every configured hostname; and the full chain is
/// anchored via webpki `verify_for_usage` for `serverAuth`, which enforces
/// per-certificate signature verification, issuer validity windows, CA basic
/// constraints and path lengths, name constraints, and serverAuth EKU.
/// Trust derives exclusively from `trust_anchors`; certificates inside the
/// chain (including any trailing self-signed root) never add trust.
fn validate_certificate_chain(
    chain_pem: &str,
    key_pair: &KeyPair,
    hostnames: &[String],
    trust_anchors: &[TrustAnchor<'_>],
) -> Result<()> {
    let pems = pem::parse_many(chain_pem).context("parsing TLS certificate chain PEM")?;
    if pems.is_empty() {
        return Err(anyhow!("TLS certificate chain contains no PEM blocks"));
    }
    for (index, block) in pems.iter().enumerate() {
        if block.tag() != "CERTIFICATE" {
            return Err(anyhow!(
                "unexpected PEM block {:?} at position {index} in TLS certificate chain",
                block.tag()
            ));
        }
    }
    let certs: Vec<CertificateDer<'static>> = pems
        .iter()
        .map(|block| CertificateDer::from(block.contents().to_vec()))
        .collect();
    let intermediates = &certs[1..];
    let leaf = &certs[0];

    let end_entity = EndEntityCert::try_from(leaf)
        .map_err(|error| anyhow!("parsing TLS leaf certificate: {error}"))?;

    // Leaf/key binding: a signature made with the retained private key must
    // verify under the leaf's public key.
    let signature = key_pair
        .sign(TLS_KEY_BINDING_PROBE)
        .map_err(|error| anyhow!("signing TLS key binding probe: {error}"))?;
    end_entity
        .verify_signature(
            verification_algorithm_for_key(key_pair)?,
            TLS_KEY_BINDING_PROBE,
            &signature,
        )
        .map_err(|_| {
            anyhow!("TLS certificate chain leaf does not match the retained TLS private key")
        })?;

    for hostname in hostnames {
        let server_name = ServerName::try_from(hostname.as_str())
            .with_context(|| format!("interpreting configured TLS hostname {hostname:?}"))?;
        end_entity
            .verify_is_valid_for_subject_name(&server_name)
            .with_context(|| {
                format!("TLS certificate does not cover configured hostname {hostname}")
            })?;
    }

    verify_anchored_path(&end_entity, intermediates, trust_anchors)
}

/// Anchored path validation with a bounded `notBefore` clock-skew retry.
fn verify_anchored_path(
    end_entity: &EndEntityCert<'_>,
    intermediates: &[CertificateDer<'static>],
    trust_anchors: &[TrustAnchor<'_>],
) -> Result<()> {
    let now = UnixTime::now();
    match end_entity.verify_for_usage(
        SUPPORTED_SIG_ALGS,
        trust_anchors,
        intermediates,
        now,
        KeyUsage::server_auth(),
        None,
        None,
    ) {
        Ok(_) => Ok(()),
        // Bounded clock-skew tolerance: if the chain becomes valid within
        // NOT_BEFORE_TOLERANCE_SECS, re-run validation at the certificate's
        // own notBefore time. Expiry remains strict at the current time.
        Err(webpki::Error::CertNotValidYet { not_before, .. })
            if now.as_secs().saturating_add(NOT_BEFORE_TOLERANCE_SECS) >= not_before.as_secs() =>
        {
            end_entity
                .verify_for_usage(
                    SUPPORTED_SIG_ALGS,
                    trust_anchors,
                    intermediates,
                    not_before,
                    KeyUsage::server_auth(),
                    None,
                    None,
                )
                .map(|_| ())
                .map_err(|_| {
                    anyhow!(
                        "TLS certificate is not valid before unix time {}",
                        not_before.as_secs()
                    )
                })
        }
        Err(webpki::Error::CertExpired { not_after, .. }) => Err(anyhow!(
            "TLS certificate chain expired at unix time {}",
            not_after.as_secs()
        )),
        Err(error) => Err(anyhow!(
            "anchored TLS certificate chain validation failed: {error}"
        )),
    }
}

/// Map the retained TLS key's signature algorithm to a webpki verification
/// algorithm for the key-binding probe. Only algorithms rcgen itself can
/// sign with are accepted; every other key family fails closed.
fn verification_algorithm_for_key(
    key_pair: &KeyPair,
) -> Result<&'static dyn SignatureVerificationAlgorithm> {
    let algorithm = key_pair.algorithm();
    if algorithm == &rcgen::PKCS_ED25519 {
        Ok(webpki::ring::ED25519)
    } else if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 {
        Ok(webpki::ring::ECDSA_P256_SHA256)
    } else if algorithm == &rcgen::PKCS_ECDSA_P384_SHA384 {
        Ok(webpki::ring::ECDSA_P384_SHA384)
    } else {
        Err(anyhow!(
            "unsupported TLS private key signature algorithm {algorithm:?}"
        ))
    }
}

fn load_or_generate_key(path: &Path) -> Result<KeyPair> {
    if retained_path_is_regular_file(path)
        .with_context(|| format!("checking TLS private key {}", path.display()))?
    {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("reading TLS private key {}", path.display()))?;
        return KeyPair::from_pem(&pem)
            .with_context(|| format!("parsing TLS private key {}", path.display()));
    }
    let key_pair = KeyPair::generate().context("generating TLS private key")?;
    writes::atomic_write(path, key_pair.serialize_pem().as_bytes(), 0o600)
        .with_context(|| format!("writing TLS private key {}", path.display()))?;
    Ok(key_pair)
}

fn build_csr_der(hostnames: &[String], key_pair: &KeyPair) -> Result<Vec<u8>> {
    let mut params =
        CertificateParams::new(hostnames.to_vec()).context("building TLS CSR parameters")?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(key_pair)
        .context("serializing TLS CSR")?;
    Ok(csr.der().as_ref().to_vec())
}

fn local_cc_init_data_hash(cfg: &Config) -> Result<Option<String>> {
    let Some(path) = cfg.cc_init_data_path.as_deref() else {
        return Ok(None);
    };
    let bytes = std::fs::read(path).with_context(|| format!("reading cc_init_data from {path}"))?;
    Ok(Some(hex::encode(Sha256::digest(&bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer};
    use tempfile::tempdir;

    const TEST_HOSTNAMES: &[&str] = &["app.example.test", "www.example.test"];

    struct TestRoot {
        params: CertificateParams,
        key: KeyPair,
        cert: rcgen::Certificate,
        der: CertificateDer<'static>,
    }

    impl TestRoot {
        fn anchor(&self) -> TrustAnchor<'_> {
            webpki::anchor_from_trusted_cert(&self.der)
                .expect("synthetic root parses as trust anchor")
        }
    }

    fn mint_root(name: &str) -> TestRoot {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());
        TestRoot {
            params,
            key,
            cert,
            der,
        }
    }

    struct TestChain {
        chain_pem: String,
        leaf_key_pem: String,
    }

    fn mint_leaf(
        issuer_params: &CertificateParams,
        issuer_key: &KeyPair,
        hostnames: &[&str],
        tweak_leaf: impl FnOnce(&mut CertificateParams),
    ) -> TestChain {
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params =
            CertificateParams::new(hostnames.iter().map(|h| h.to_string()).collect::<Vec<_>>())
                .unwrap();
        tweak_leaf(&mut leaf_params);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &Issuer::from_params(issuer_params, issuer_key))
            .unwrap();
        TestChain {
            chain_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }

    fn mint_test_chain(
        hostnames: &[&str],
        tweak_leaf: impl FnOnce(&mut CertificateParams),
    ) -> (TestRoot, TestChain) {
        let root = mint_root("Enclava Test Root CA");
        let chain = mint_leaf(&root.params, &root.key, hostnames, tweak_leaf);
        (root, chain)
    }

    fn broker_config(dir: &Path, hostnames: &[&str]) -> Config {
        let cfg_path = dir.join("config.toml");
        let hostnames_list = hostnames
            .iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            &cfg_path,
            format!(
                r#"
mode = "autounlock"
tls-certificate-broker-url = "http://127.0.0.1:9/"
tls-certificate-hostnames = [{hostnames_list}]

[state]
device = "/dev/csi0"
mapping-name = "cap-state"
mount-path = "/state/app-data"
hkdf-info = "state-luks-key"

[tls-state]
device = "/dev/csi1"
mapping-name = "cap-tls-state"
mount-path = "/state/tls-state"
hkdf-info = "tls-state-luks-key"
"#
            ),
        )
        .unwrap();
        Config::load(&cfg_path).unwrap()
    }

    fn write_retained_state(dir: &Path, chain_pem: &str, key_pem: &str) -> PathBuf {
        let persistent = dir.join("persistent");
        writes::atomic_write(&cert_path(&persistent), chain_pem.as_bytes(), 0o644).unwrap();
        writes::atomic_write(&key_path(&persistent), key_pem.as_bytes(), 0o600).unwrap();
        persistent
    }

    /// Full leaf -> (optional intermediate) -> root chain PEM, including the
    /// root itself, exactly like ACME providers deliver chains.
    fn full_chain_pem(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn certificate_paths_match_caddyfile_static_tls_paths() {
        let root = Path::new("/state/tls-state/tenant-ingress");
        assert_eq!(
            cert_path(root),
            PathBuf::from("/state/tls-state/tenant-ingress/certificates/tls.crt")
        );
        assert_eq!(
            key_path(root),
            PathBuf::from("/state/tls-state/tenant-ingress/certificates/tls.key")
        );
    }

    #[test]
    fn generated_key_is_persisted_and_reused_for_csrs() {
        let dir = tempdir().unwrap();
        let key_path = key_path(dir.path());
        let hosts = vec!["app.example.test".to_string()];

        let first_key = load_or_generate_key(&key_path).unwrap();
        let first_pem = std::fs::read_to_string(&key_path).unwrap();
        let first_csr = build_csr_der(&hosts, &first_key).unwrap();
        let second_key = load_or_generate_key(&key_path).unwrap();
        let second_pem = std::fs::read_to_string(&key_path).unwrap();
        let second_csr = build_csr_der(&hosts, &second_key).unwrap();

        assert!(KeyPair::from_pem(&first_pem).is_ok());
        assert_eq!(first_pem, second_pem);
        assert!(!first_csr.is_empty());
        assert!(!second_csr.is_empty());
    }

    #[test]
    fn local_cc_init_data_hash_reads_signed_runtime_toml() {
        let dir = tempdir().unwrap();
        let cc_path = dir.path().join("cc-init-data.toml");
        std::fs::write(&cc_path, b"descriptor_core_hash = \"abc\"\n").unwrap();
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            format!(
                r#"
mode = "autounlock"
cc-init-data-path = "{}"

[state]
device = "/dev/csi0"
mapping-name = "cap-state"
mount-path = "/state/app-data"
hkdf-info = "state-luks-key"

[tls-state]
device = "/dev/csi1"
mapping-name = "cap-tls-state"
mount-path = "/state/tls-state"
hkdf-info = "tls-state-luks-key"
"#,
                cc_path.display()
            ),
        )
        .unwrap();
        let cfg = Config::load(&cfg_path).unwrap();

        assert_eq!(
            local_cc_init_data_hash(&cfg).unwrap(),
            Some(hex::encode(Sha256::digest(
                b"descriptor_core_hash = \"abc\"\n"
            )))
        );
    }

    #[test]
    fn retained_valid_anchored_certificate_is_reused_repeatedly_without_broker_calls() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        // The broker URL points at an unroutable address: any broker contact
        // makes provisioning fail, so two clean runs prove zero broker calls.
        provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap();
        provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap();

        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_valid_chain_with_intermediate_and_root_validates_anchored() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &intermediate_cert.pem(), &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap();
    }

    #[test]
    fn retained_expired_certificate_fails_closed_without_reissue_or_key_replacement() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        });
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("expired"), "unexpected error: {message}");
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_not_yet_valid_certificate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.not_before = rcgen::date_time_ymd(3000, 1, 1);
        });
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed") || message.contains("not valid"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_key_mismatch_fails_closed_without_key_replacement() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let unrelated_key_pem = KeyPair::generate().unwrap().serialize_pem();
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &unrelated_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("does not match the retained TLS private key"),
            "unexpected error: {message}"
        );
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_hostname_mismatch_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), &["app.example.test"]);
        let (root, chain) = mint_test_chain(&["other.example.test"], |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("does not cover configured hostname app.example.test"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_leaf_only_chain_missing_intermediate_fails_closed() {
        // A lone leaf whose issuer (an intermediate) is not delivered cannot
        // reach a trust anchor on its own; the old adjacency loop accepted
        // leaf-only chains without any issuer verification.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let _intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        // Chain delivers the leaf only, without the issuing intermediate.
        let persistent = write_retained_state(dir.path(), &chain.chain_pem, &chain.leaf_key_pem);
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
    }

    #[test]
    fn retained_self_signed_leaf_chain_fails_closed() {
        // A self-signed leaf is its own issuer; without the issuing key being
        // a configured anchor this must fail closed.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, _) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];

        let self_signed_key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(
            TEST_HOSTNAMES
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let self_signed = params.self_signed(&self_signed_key).unwrap();
        let persistent = write_retained_state(
            dir.path(),
            &self_signed.pem(),
            &self_signed_key.serialize_pem(),
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_chain_from_untrusted_root_fails_closed() {
        // Chain is fully valid internally but rooted at a CA that is not in
        // the configured anchor set: no trust, no reuse.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (trusted_root, _) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let (untrusted_root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [trusted_root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &untrusted_root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
    }

    #[test]
    fn retained_chain_missing_its_intermediate_fails_closed() {
        // Leaf issued by an intermediate, chain carries the root but not the
        // intermediate: the gap must not be bridged by trusting the chain's
        // own last certificate.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let _intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        // Chain delivers leaf + root, skipping the issuing intermediate.
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_expired_intermediate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        intermediate_params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        let intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &intermediate_cert.pem(), &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("expired"), "unexpected error: {message}");
    }

    #[test]
    fn retained_wrong_eku_leaf_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        });
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn production_public_roots_reject_synthetic_and_staging_like_chains() {
        // The production entry has no anchor parameter: it always validates
        // against the public webpki-roots store. Any chain not leading to a
        // public root — including synthetic CAs and, by the same mechanism,
        // Let's Encrypt staging chains whose roots are absent from the
        // public store — is rejected by default.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (synthetic_root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let synthetic_chain = full_chain_pem(&[&chain.chain_pem, &synthetic_root.cert.pem()]);
        let persistent = write_retained_state(dir.path(), &synthetic_chain, &chain.leaf_key_pem);

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_certificate_without_private_key_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = dir.path().join("persistent");
        writes::atomic_write(
            &cert_path(&persistent),
            full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]).as_bytes(),
            0o644,
        )
        .unwrap();
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("private key") && message.contains("missing"),
            "unexpected error: {message}"
        );
        assert!(!key_path(&persistent).exists());
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
    }

    #[test]
    fn retained_malformed_certificate_chain_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, valid_chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let full = full_chain_pem(&[&valid_chain.chain_pem, &root.cert.pem()]);

        for malformed in [
            "not a pem certificate".to_string(),
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                base64::engine::general_purpose::STANDARD.encode(b"junk not der")
            ),
            String::new(),
            full[..full.find("-----END CERTIFICATE-----").unwrap()].to_string(),
        ] {
            let persistent =
                write_retained_state(dir.path(), &malformed, &valid_chain.leaf_key_pem);
            assert!(
                provision_with_trust_anchors(&cfg, &persistent, &anchors).is_err(),
                "expected failure for malformed chain: {malformed}"
            );
        }
    }

    #[test]
    fn directory_at_cert_path_never_reaches_broker() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(cert_path(&persistent)).unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("not a regular file"),
            "unexpected error: {message}"
        );
        // No issuance side effects: the key was never generated.
        assert!(!key_path(&persistent).exists());
    }

    #[test]
    fn dangling_symlink_at_cert_path_never_reaches_broker() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(cert_path(&persistent).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(
            persistent.join("does-not-exist.crt"),
            cert_path(&persistent),
        )
        .unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
        assert!(!key_path(&persistent).exists());
    }

    #[test]
    fn symlink_to_regular_certificate_is_rejected() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let real = dir.path().join("real.crt");
        std::fs::write(&real, full_chain_pem(&[&chain.chain_pem, &root.cert.pem()])).unwrap();
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(cert_path(&persistent).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, cert_path(&persistent)).unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
        assert!(!key_path(&persistent).exists());
    }

    #[test]
    fn directory_at_key_path_with_retained_certificate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        std::fs::remove_file(key_path(&persistent)).unwrap();
        std::fs::create_dir_all(key_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("not a regular file"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn dangling_symlink_at_key_path_with_retained_certificate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        std::fs::remove_file(key_path(&persistent)).unwrap();
        std::os::unix::fs::symlink(persistent.join("does-not-exist.key"), key_path(&persistent))
            .unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn missing_cert_with_retained_key_retries_issuance_with_same_key() {
        // Interrupted-initial-issuance semantics: only a genuinely missing
        // certificate (ENOENT) starts issuance, and the retained key is
        // reused for the new CSR. No KBS runs locally and the broker URL is
        // unroutable, so the issuance attempt surfaces at the attestation
        // token step — after the CSR was built from the retained key — and
        // the key file is provably unchanged.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let key_pem = KeyPair::generate().unwrap().serialize_pem();
        let persistent = dir.path().join("persistent");
        writes::atomic_write(&key_path(&persistent), key_pem.as_bytes(), 0o600).unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("KBS attestation token"),
            "unexpected error: {message}"
        );
        assert_eq!(
            std::fs::read_to_string(key_path(&persistent)).unwrap(),
            key_pem
        );
        assert!(!cert_path(&persistent).exists());
    }

    #[test]
    fn symlink_at_key_path_blocks_issuance_before_broker_contact() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(key_path(&persistent).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(persistent.join("does-not-exist.key"), key_path(&persistent))
            .unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
    }
}
