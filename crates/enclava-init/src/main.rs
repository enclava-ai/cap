use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow};
use enclava_init::config::{Config, Mode, VolumeConfig};
use enclava_init::secrets::{DerivedSeed, OwnerSeed, Password};
use enclava_init::{kbs_fetch, luks, seeds, socket, trustee_verify, unlock, writes};

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .json()
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "enclava-init failed");
            eprintln!("enclava-init: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let cfg_path = std::env::var("ENCLAVA_INIT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/enclava-init/config.toml"));
    let cfg = Config::load(&cfg_path).with_context(|| format!("loading {}", cfg_path.display()))?;

    let owner = match cfg.mode {
        Mode::Password => acquire_owner_seed_password(&cfg)?,
        Mode::Autounlock => acquire_owner_seed_autounlock(&cfg)?,
    };

    // Derive per-volume LUKS keys and open both devices BEFORE running the
    // verification chain. If verification fails we still need LUKS open to
    // load anything from /state for diagnostics; we just refuse to write the
    // per-component seeds in that case.
    open_luks_volumes(&cfg, &owner)?;

    if !run_in_tee_verification(&cfg)? {
        // Skipped because Phase 3 Trustee patch isn't deployed yet. The
        // tracing::error above made this loud; we let the binary continue so
        // staged rollout can proceed, but we log a final warning.
        tracing::warn!(
            "seeds released without in-TEE Trustee policy verification (TRUSTEE_POLICY_READ_AVAILABLE=false)"
        );
    }

    write_per_component_seeds(&cfg, &owner)?;

    tracing::info!("enclava-init: seeds released");
    Ok(())
}

fn acquire_owner_seed_password(cfg: &Config) -> Result<OwnerSeed> {
    let salt_hex = cfg
        .argon2_salt_hex
        .as_deref()
        .ok_or_else(|| anyhow!("password mode requires argon2_salt_hex in config"))?;
    let salt = hex::decode(salt_hex).context("decoding argon2_salt_hex")?;

    let listener = socket::bind(Path::new(&cfg.unlock_socket))?;
    tracing::info!(socket = %cfg.unlock_socket, "awaiting password");

    loop {
        let now = unlock::now_secs();
        if let Err(e) = unlock::check_rate_limit(Path::new(&cfg.attempts_path), now) {
            return Err(anyhow!("rate limit: {e}"));
        }

        let (mut stream, _) = listener.accept()?;
        let pw_str = match socket::read_password_line(&mut stream) {
            Ok(s) => s,
            Err(e) => {
                let _ = socket::reply_err(&mut stream, &format!("read: {e}"));
                continue;
            }
        };
        let password = Password::from_plaintext(&pw_str);
        unlock::record_attempt(Path::new(&cfg.attempts_path), now)?;

        match unlock::derive_owner_seed(&password, &salt) {
            Ok(seed) => {
                socket::reply_ok(&mut stream).ok();
                return Ok(seed);
            }
            Err(e) => {
                socket::reply_err(&mut stream, &format!("derive: {e}")).ok();
            }
        }
    }
}

fn acquire_owner_seed_autounlock(cfg: &Config) -> Result<OwnerSeed> {
    let url = cfg
        .kbs_url
        .as_deref()
        .ok_or_else(|| anyhow!("autounlock mode requires kbs_url"))?;
    let path = cfg
        .kbs_resource_path
        .as_deref()
        .ok_or_else(|| anyhow!("autounlock mode requires kbs_resource_path"))?;
    let client = kbs_fetch::KbsClient::new(url.into(), path.into());
    let wrap = client
        .fetch_wrap_key()
        .with_context(|| "fetching wrap key from KBS")?;
    Ok(OwnerSeed(*wrap.as_bytes()))
}

fn open_luks_volumes(cfg: &Config, owner: &OwnerSeed) -> Result<()> {
    if dev_no_luks_override() {
        tracing::warn!("ENCLAVA_INIT_DEV_NO_LUKS=true — skipping luks open (debug builds only)");
        return Ok(());
    }
    open_one_volume(&cfg.state, owner)
        .with_context(|| format!("opening state volume {}", cfg.state.device))?;
    open_one_volume(&cfg.tls_state, owner)
        .with_context(|| format!("opening tls-state volume {}", cfg.tls_state.device))?;
    Ok(())
}

fn open_one_volume(vol: &VolumeConfig, owner: &OwnerSeed) -> Result<()> {
    let key = derive_volume_key(owner, &vol.hkdf_info)?;
    let device = Path::new(&vol.device);
    let opened = luks::format_if_unformatted_then_open(device, &vol.mapping_name, &key)?;
    luks::mount(&opened.mapper_path, Path::new(&vol.mount_path))?;
    tracing::info!(
        device = %vol.device,
        mapper = %opened.mapper_path.display(),
        mount = %vol.mount_path,
        "opened luks volume"
    );
    Ok(())
}

fn derive_volume_key(owner: &OwnerSeed, info: &str) -> Result<DerivedSeed> {
    let derived = seeds::derive(owner, info.as_bytes())?;
    Ok(derived)
}

fn run_in_tee_verification(cfg: &Config) -> Result<bool> {
    if !cfg.trustee_policy_read_available {
        return Ok(trustee_verify::verify_chain_or_skip(None)?);
    }

    let workload_url = cfg.workload_artifacts_url.as_deref().ok_or_else(|| {
        anyhow!("trustee_policy_read_available=true requires workload_artifacts_url")
    })?;
    let policy_url = cfg
        .trustee_policy_url
        .as_deref()
        .ok_or_else(|| anyhow!("trustee_policy_read_available=true requires trustee_policy_url"))?;
    let cc_path = cfg
        .cc_init_data_path
        .as_deref()
        .ok_or_else(|| anyhow!("verification requires cc_init_data_path"))?;
    let signer_pk_hex = cfg
        .platform_trustee_policy_pubkey_hex
        .as_deref()
        .ok_or_else(|| anyhow!("verification requires platform_trustee_policy_pubkey_hex"))?;
    let signing_pk_hex = cfg
        .signing_service_pubkey_hex
        .as_deref()
        .ok_or_else(|| anyhow!("verification requires signing_service_pubkey_hex"))?;

    let cc_bytes =
        std::fs::read(cc_path).with_context(|| format!("reading cc_init_data from {cc_path}"))?;
    let cc_claims = parse_cc_init_data_claims(&cc_bytes)?;
    let signer_pk = parse_pubkey(signer_pk_hex)?;
    let signing_pk = parse_pubkey(signing_pk_hex)?;

    let token = std::env::var("KBS_ATTESTATION_TOKEN").unwrap_or_default();
    let fetcher = trustee_verify::ArtifactFetcher {
        workload_artifacts_url: workload_url.into(),
        trustee_policy_url: policy_url.into(),
        kbs_attestation_token: token,
        timeout: std::time::Duration::from_secs(15),
    };
    let (bundle, envelope) = fetcher.fetch().context("fetching trustee artifacts")?;
    let inputs = trustee_verify::VerifyInputs {
        policy_envelope: &envelope,
        artifacts: &bundle,
        cc_init_data_claims: &cc_claims,
        local_cc_init_data_toml: &cc_bytes,
        platform_trustee_policy_pubkey: &signer_pk,
        signing_service_pubkey: &signing_pk,
    };
    trustee_verify::verify_chain_or_skip(Some(&inputs)).map_err(Into::into)
}

fn parse_pubkey(hex_str: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let raw = hex::decode(hex_str).context("decoding pubkey hex")?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&arr)?)
}

fn parse_cc_init_data_claims(toml_bytes: &[u8]) -> Result<trustee_verify::CcInitDataClaims> {
    let s = std::str::from_utf8(toml_bytes).context("cc_init_data not utf-8")?;
    let v: toml::Value = toml::from_str(s).context("cc_init_data parse")?;
    let data = v
        .get("data")
        .ok_or_else(|| anyhow!("cc_init_data missing [data] section"))?;
    let core_hash = read_hex32(data, "descriptor_core_hash")?;
    let signing_pk = read_hex32(data, "descriptor_signing_pubkey")?;
    let keyring_fp = read_hex32(data, "org_keyring_fingerprint")?;
    Ok(trustee_verify::CcInitDataClaims {
        descriptor_core_hash: core_hash,
        descriptor_signing_pubkey: signing_pk,
        org_keyring_fingerprint: keyring_fp,
    })
}

fn read_hex32(v: &toml::Value, key: &str) -> Result<[u8; 32]> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("cc_init_data.data.{key} missing or not string"))?;
    let raw = hex::decode(s).with_context(|| format!("decoding {key}"))?;
    raw.try_into().map_err(|_| anyhow!("{key} not 32 bytes"))
}

fn dev_no_luks_override() -> bool {
    cfg!(debug_assertions)
        && std::env::var("ENCLAVA_INIT_DEV_NO_LUKS")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false)
}

fn write_per_component_seeds(cfg: &Config, owner: &OwnerSeed) -> Result<()> {
    let caddy_seed = seeds::derive(owner, seeds::CADDY_INFO)?;
    let app_seed = seeds::derive(owner, seeds::APP_INFO)?;

    let caddy_path = Path::new(&cfg.state_root).join("caddy/seed");
    let app_path = Path::new(&cfg.state_root).join("app/seed");

    writes::atomic_write(&caddy_path, caddy_seed.as_bytes(), 0o600)?;
    writes::atomic_write(&app_path, app_seed.as_bytes(), 0o600)?;

    Ok(())
}
