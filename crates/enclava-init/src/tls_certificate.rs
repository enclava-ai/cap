use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls_pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webpki::EndEntityCert;
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;

use crate::config::Config;
use crate::{trustee_verify, writes};

pub const CERT_RELATIVE_PATH: &str = "certificates/tls.crt";
pub const KEY_RELATIVE_PATH: &str = "certificates/tls.key";

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
    if cert_path.is_file() {
        // Fail closed on retained state: an incomplete, malformed, expired, or
        // mismatched certificate never triggers a new broker order and the
        // retained private key is never replaced. An operator must remove the
        // stale certificate explicitly to force reissuance.
        if !key_path.is_file() {
            return Err(anyhow!(
                "retained TLS certificate {} exists but private key {} is missing; \
                 refusing to order a replacement certificate or replace the private key",
                cert_path.display(),
                key_path.display()
            ));
        }
        validate_retained_tls_state(&cfg.tls_certificate_hostnames, &cert_path, &key_path)
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

/// Reuse clock tolerance for leaf `notBefore`: broker-issued certificates can
/// carry an issuance timestamp slightly ahead of the workload clock.
const NOT_BEFORE_TOLERANCE_SECS: i64 = 300;

/// Validate retained TLS state read from the confidential encrypted volume.
fn validate_retained_tls_state(
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
    validate_certificate_chain(&chain_pem, &key_pair, hostnames)
}

/// Validate a PEM certificate chain against the retained private key and the
/// configured hostnames: parseability, leaf/key match, leaf validity window,
/// leaf hostname coverage, and internal chain linkage.
///
/// Trust-anchor validation is deliberately not attempted: the broker contract
/// delivers only `certificate_chain_pem` with no pinned root, so a chain
/// vouching for its own last certificate proves nothing. Anchored validation
/// would require the broker (or config) to provide an out-of-band trusted
/// root; that contract change is tracked separately.
fn validate_certificate_chain(
    chain_pem: &str,
    key_pair: &KeyPair,
    hostnames: &[String],
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
    let certs: Vec<X509Certificate> = pems
        .iter()
        .enumerate()
        .map(|(index, block)| {
            parse_x509_certificate(block.contents())
                .map(|(_, cert)| cert)
                .with_context(|| format!("parsing TLS chain certificate #{index}"))
        })
        .collect::<Result<_>>()?;
    let leaf = &certs[0];

    if leaf
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        != key_pair.public_key_raw()
    {
        return Err(anyhow!(
            "TLS certificate chain leaf does not match the retained TLS private key"
        ));
    }

    let now = chrono::Utc::now().timestamp();
    let validity = leaf.tbs_certificate.validity();
    if now + NOT_BEFORE_TOLERANCE_SECS < validity.not_before.timestamp() {
        return Err(anyhow!(
            "TLS certificate is not valid before {}",
            validity.not_before
        ));
    }
    if now > validity.not_after.timestamp() {
        return Err(anyhow!("TLS certificate expired on {}", validity.not_after));
    }

    let leaf_der = CertificateDer::from(pems[0].contents().to_vec());
    let end_entity = EndEntityCert::try_from(&leaf_der)
        .context("parsing TLS leaf certificate for hostname validation")?;
    for hostname in hostnames {
        let server_name = ServerName::try_from(hostname.as_str())
            .with_context(|| format!("interpreting configured TLS hostname {hostname:?}"))?;
        end_entity
            .verify_is_valid_for_subject_name(&server_name)
            .with_context(|| {
                format!("TLS certificate does not cover configured hostname {hostname}")
            })?;
    }

    for (index, pair) in certs.windows(2).enumerate() {
        pair[0]
            .verify_signature(Some(&pair[1].tbs_certificate.subject_pki))
            .with_context(|| {
                format!(
                    "TLS chain certificate #{index} is not signed by the following \
                     certificate in the chain"
                )
            })?;
    }
    Ok(())
}

fn load_or_generate_key(path: &Path) -> Result<KeyPair> {
    if path.is_file() {
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
    use rcgen::{BasicConstraints, DnType, IsCa, Issuer};
    use tempfile::tempdir;

    const TEST_HOSTNAMES: &[&str] = &["app.example.test", "www.example.test"];

    struct TestChain {
        chain_pem: String,
        leaf_key_pem: String,
    }

    fn mint_test_chain(
        hostnames: &[&str],
        tweak_leaf: impl FnOnce(&mut CertificateParams),
    ) -> TestChain {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        let mut ca_name = DistinguishedName::new();
        ca_name.push(DnType::CommonName, "Enclava Test Root CA");
        ca_params.distinguished_name = ca_name;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params =
            CertificateParams::new(hostnames.iter().map(|h| h.to_string()).collect::<Vec<_>>())
                .unwrap();
        tweak_leaf(&mut leaf_params);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();

        TestChain {
            chain_pem: format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
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
    fn retained_valid_certificate_is_reused_repeatedly_without_broker_calls() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let chain = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let persistent = write_retained_state(dir.path(), &chain.chain_pem, &chain.leaf_key_pem);
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        // The broker URL points at an unroutable address: any broker contact
        // makes provisioning fail, so two clean runs prove zero broker calls.
        provision_static_tls_certificate(&cfg, &persistent).unwrap();
        provision_static_tls_certificate(&cfg, &persistent).unwrap();

        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_expired_certificate_fails_closed_without_reissue_or_key_replacement() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let chain = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        });
        let persistent = write_retained_state(dir.path(), &chain.chain_pem, &chain.leaf_key_pem);
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("expired"), "unexpected error: {message}");
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_not_yet_valid_certificate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let chain = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.not_before = rcgen::date_time_ymd(3000, 1, 1);
        });
        let persistent = write_retained_state(dir.path(), &chain.chain_pem, &chain.leaf_key_pem);

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("not valid before"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_key_mismatch_fails_closed_without_key_replacement() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let chain = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let unrelated_key_pem = KeyPair::generate().unwrap().serialize_pem();
        let persistent = write_retained_state(dir.path(), &chain.chain_pem, &unrelated_key_pem);
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
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
        let chain = mint_test_chain(&["other.example.test"], |_| {});
        let persistent = write_retained_state(dir.path(), &chain.chain_pem, &chain.leaf_key_pem);

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("does not cover configured hostname app.example.test"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_certificate_without_private_key_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let chain = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let persistent = dir.path().join("persistent");
        writes::atomic_write(&cert_path(&persistent), chain.chain_pem.as_bytes(), 0o644).unwrap();
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
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
        let valid_chain = mint_test_chain(TEST_HOSTNAMES, |_| {});

        for malformed in [
            "not a pem certificate".to_string(),
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                base64::engine::general_purpose::STANDARD.encode(b"junk not der")
            ),
            String::new(),
            valid_chain.chain_pem[..valid_chain
                .chain_pem
                .find("-----END CERTIFICATE-----")
                .unwrap()]
                .to_string(),
        ] {
            let persistent =
                write_retained_state(dir.path(), &malformed, &valid_chain.leaf_key_pem);
            assert!(
                provision_static_tls_certificate(&cfg, &persistent).is_err(),
                "expected failure for malformed chain: {malformed}"
            );
        }
    }

    #[test]
    fn retained_chain_with_missing_or_unrelated_issuer_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        // Leaf signed by one CA, but the chain carries an unrelated self-signed
        // CA in its place: the internal chain link must not verify.
        let signed = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let unrelated_ca_key = KeyPair::generate().unwrap();
        let mut unrelated_ca_params = CertificateParams::default();
        unrelated_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let unrelated_ca_cert = unrelated_ca_params.self_signed(&unrelated_ca_key).unwrap();
        let leaf_pem_end = signed.chain_pem.find("-----END CERTIFICATE-----").unwrap()
            + "-----END CERTIFICATE-----".len();
        let broken_chain = format!(
            "{}\n{}",
            &signed.chain_pem[..leaf_pem_end],
            unrelated_ca_cert.pem()
        );
        let persistent = write_retained_state(dir.path(), &broken_chain, &signed.leaf_key_pem);

        let error = provision_static_tls_certificate(&cfg, &persistent).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("is not signed by"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_chain_with_intermediate_is_validated_across_the_full_chain() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root_params, &root_key),
            )
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(
            TEST_HOSTNAMES
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let leaf_cert = leaf_params
            .signed_by(
                &leaf_key,
                &Issuer::from_params(&intermediate_params, &intermediate_key),
            )
            .unwrap();

        let chain_pem = format!(
            "{}{}{}",
            leaf_cert.pem(),
            intermediate_cert.pem(),
            root_cert.pem()
        );
        let persistent = write_retained_state(dir.path(), &chain_pem, &leaf_key.serialize_pem());

        provision_static_tls_certificate(&cfg, &persistent).unwrap();
    }
}
