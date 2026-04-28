use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use enclava_init::chown::{self, ExecIdentity, IdentityKind};
use enclava_init::config::{Config, Mode, VolumeConfig};
use enclava_init::secrets::{DerivedSeed, OwnerSeed, Password};
use enclava_init::{kbs_fetch, luks, seeds, socket, trustee_verify, unlock, writes};

const DEFAULT_READY_FILE: &str = "/run/enclava/init-ready";

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--probe-ready") {
        return if ready_file_exists(&ready_file_path()) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

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
    let stay_alive = stay_alive_enabled();
    let ready_file = ready_file_path();
    if stay_alive {
        clear_ready_file(&ready_file)
            .with_context(|| format!("clearing stale ready file {}", ready_file.display()))?;
        wait_for_container_start_sentinels()
            .context("waiting for workload containers to start before mounting LUKS")?;
    }

    let owner = match cfg.mode {
        Mode::Password => acquire_owner_seed_password(&cfg)?,
        Mode::Autounlock => acquire_owner_seed_autounlock(&cfg)?,
    };

    // Derive per-volume LUKS keys and open both devices BEFORE running the
    // verification chain. If verification fails we still need LUKS open to
    // load anything from /state for diagnostics; we just refuse to write the
    // per-component seeds in that case.
    open_luks_volumes(&cfg, &owner)?;
    prepare_mount_ownership(&cfg)?;

    if !run_in_tee_verification(&cfg)? {
        // Skipped because Phase 3 Trustee patch isn't deployed yet. The
        // tracing::error above made this loud; we let the binary continue so
        // staged rollout can proceed, but we log a final warning.
        tracing::warn!(
            "seeds released without in-TEE Trustee policy verification (TRUSTEE_POLICY_READ_AVAILABLE=false)"
        );
    }

    write_per_component_seeds(&cfg, &owner)?;

    if stay_alive {
        mark_ready_file(&ready_file)
            .with_context(|| format!("writing ready file {}", ready_file.display()))?;
        tracing::info!(
            ready_file = %ready_file.display(),
            "enclava-init: seeds released; keeping mounter sidecar alive"
        );
        stay_alive_forever();
    }

    tracing::info!("enclava-init: seeds released");
    Ok(())
}

fn stay_alive_enabled() -> bool {
    std::env::var("ENCLAVA_INIT_STAY_ALIVE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

fn ready_file_path() -> PathBuf {
    std::env::var("ENCLAVA_INIT_READY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_READY_FILE))
}

fn started_dir_path() -> PathBuf {
    std::env::var("ENCLAVA_INIT_STARTED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/enclava/containers"))
}

fn wait_for_container_start_sentinels() -> Result<()> {
    let names = std::env::var("ENCLAVA_INIT_WAIT_FOR_CONTAINERS").unwrap_or_default();
    let containers = names
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(validate_sentinel_name)
        .collect::<Result<Vec<_>>>()?;
    if containers.is_empty() {
        return Ok(());
    }

    let dir = started_dir_path();
    tracing::info!(
        dir = %dir.display(),
        containers = containers.join(","),
        "waiting for workload containers to start before opening LUKS"
    );
    loop {
        let missing = containers
            .iter()
            .filter(|name| !ready_file_exists(&dir.join(name.as_str())))
            .cloned()
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        tracing::debug!(
            missing = missing.join(","),
            "workload containers not started yet"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn validate_sentinel_name(name: &str) -> Result<String> {
    let path = Path::new(name);
    if path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
    {
        Ok(name.to_string())
    } else {
        Err(anyhow!("invalid container sentinel name: {name}"))
    }
}

fn clear_ready_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn mark_ready_file(path: &Path) -> Result<()> {
    writes::atomic_write(path, b"ready\n", 0o644).map_err(Into::into)
}

fn ready_file_exists(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

fn stay_alive_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
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

fn prepare_mount_ownership(cfg: &Config) -> Result<()> {
    let app_identity = numeric_identity(cfg.app_uid, cfg.app_gid);
    let caddy_identity = numeric_identity(cfg.caddy_uid, cfg.caddy_gid);

    let state_root = Path::new(&cfg.state.mount_path);
    let tls_state_root = Path::new(&cfg.tls_state.mount_path);
    std::fs::create_dir_all(state_root)
        .with_context(|| format!("creating {}", state_root.display()))?;
    std::fs::create_dir_all(tls_state_root)
        .with_context(|| format!("creating {}", tls_state_root.display()))?;

    chown::chown(state_root, app_identity)
        .with_context(|| format!("chown {}", state_root.display()))?;
    chown::chown_recursive(tls_state_root, caddy_identity)
        .with_context(|| format!("chown {}", tls_state_root.display()))?;

    let app_seed_dir = Path::new(&cfg.state_root).join("app");
    std::fs::create_dir_all(&app_seed_dir)
        .with_context(|| format!("creating {}", app_seed_dir.display()))?;
    chown::chown_recursive(&app_seed_dir, app_identity)
        .with_context(|| format!("chown {}", app_seed_dir.display()))?;

    let caddy_seed_dir = Path::new(&cfg.state_root).join("caddy");
    std::fs::create_dir_all(&caddy_seed_dir)
        .with_context(|| format!("creating {}", caddy_seed_dir.display()))?;
    chown::chown_recursive(&caddy_seed_dir, caddy_identity)
        .with_context(|| format!("chown {}", caddy_seed_dir.display()))?;

    for bind in &cfg.app_bind_mounts {
        let dir = app_bind_mount_dir(state_root, &bind.subdir)?;
        std::fs::create_dir_all(&dir).with_context(|| {
            format!(
                "creating app bind mount source {} for {}",
                dir.display(),
                bind.mount_path
            )
        })?;
        chown::chown_recursive(&dir, app_identity)
            .with_context(|| format!("chown {}", dir.display()))?;
    }

    Ok(())
}

fn app_bind_mount_dir(state_root: &Path, subdir: &str) -> Result<PathBuf> {
    if subdir.is_empty() {
        return Err(anyhow!("app bind mount subdir cannot be empty"));
    }
    let rel = Path::new(subdir);
    if rel.is_absolute() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(anyhow!("invalid app bind mount subdir: {subdir}"));
    }
    Ok(state_root.join(rel))
}

fn numeric_identity(uid: u32, gid: u32) -> ExecIdentity {
    ExecIdentity {
        uid,
        gid,
        kind: IdentityKind::Numeric,
    }
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

    let token = trustee_verify::resolve_kbs_attestation_token(
        std::env::var("KBS_ATTESTATION_TOKEN").ok().as_deref(),
        &cfg.kbs_attestation_token_url,
        std::time::Duration::from_secs(15),
    )
    .context("resolving KBS attestation token")?;
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
    chown::chown(&caddy_path, numeric_identity(cfg.caddy_uid, cfg.caddy_gid))
        .with_context(|| format!("chown {}", caddy_path.display()))?;
    chown::chown(&app_path, numeric_identity(cfg.app_uid, cfg.app_gid))
        .with_context(|| format!("chown {}", app_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ready_probe_reflects_ready_file_state() {
        let dir = tempdir().unwrap();
        let ready = dir.path().join("run/enclava/init-ready");

        assert!(!ready_file_exists(&ready));
        mark_ready_file(&ready).unwrap();
        assert!(ready_file_exists(&ready));
        clear_ready_file(&ready).unwrap();
        assert!(!ready_file_exists(&ready));
    }

    #[test]
    fn container_sentinel_names_are_single_path_components() {
        assert_eq!(validate_sentinel_name("web").unwrap(), "web");
        assert!(validate_sentinel_name("../web").is_err());
        assert!(validate_sentinel_name("web/sidecar").is_err());
    }
}
