use clap::Args;
use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Subcommand;
use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::*;
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::tee_client::TeeClient;

/// Resolve app name from --app flag or enclava.toml.
fn resolve_app_name(explicit: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(name.clone());
    }
    let config = AppConfig::find_and_load()?;
    Ok(config.app.name)
}

/// Build an authenticated API client from stored config/credentials.
fn build_api_client() -> Result<(ApiClient, CliPaths, config::CliConfig), Box<dyn std::error::Error>>
{
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok((api, paths, cli_config))
}

/// Parse KEY=VALUE pairs from --set flags.
fn parse_config_vars(vars: &[String]) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    vars.iter()
        .map(|v| {
            let (key, value) = v
                .split_once('=')
                .ok_or_else(|| format!("invalid config format '{v}': expected KEY=VALUE"))?;
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

#[derive(Args)]
pub struct CreateArgs {
    /// Container image to deploy (tag resolved to digest automatically)
    #[arg(long)]
    pub image: Option<String>,
    /// Cosign Fulcio identity subject for image-signature verification.
    /// Examples: GitHub Actions OIDC subject
    /// (`https://github.com/<org>/<repo>/.github/workflows/<wf>.yml@refs/heads/<branch>`),
    /// or a maintainer email tied to the keyless OIDC issuer.
    #[arg(long = "signer-subject")]
    pub signer_subject: Option<String>,
    /// Cosign Fulcio issuer URL for the signer identity. Defaults to
    /// the GitHub Actions OIDC issuer when omitted.
    #[arg(
        long = "signer-issuer",
        default_value = "https://token.actions.githubusercontent.com"
    )]
    pub signer_issuer: String,
}

pub async fn create(args: CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_config = AppConfig::find_and_load()?;
    let (api, paths, cli_config) = build_api_client()?;

    let bootstrap_key = if app_config.unlock.mode == "password" {
        let org = cli_config
            .org
            .as_deref()
            .ok_or("no active org -- run `enclava login` first")?;
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_hash = hex::encode(Sha256::digest(public_key));
        Some((
            org.to_string(),
            hex::encode(signing_key.to_bytes()),
            public_key_hash,
        ))
    } else {
        None
    };

    let services: Vec<ServiceSpec> = app_config
        .services
        .iter()
        .map(|(name, svc)| ServiceSpec {
            name: name.clone(),
            image: svc.image.clone(),
            port: svc.port,
            storage_paths: svc.storage_paths.clone().unwrap_or_default(),
        })
        .collect();

    let signer_identity_subject = args.signer_subject.clone();
    let signer_identity_issuer = signer_identity_subject
        .as_ref()
        .map(|_| args.signer_issuer.clone());

    let req = CreateAppRequest {
        name: app_config.app.name.clone(),
        port: app_config.app.port,
        image: args.image,
        unlock_mode: app_config.unlock.mode.clone(),
        bootstrap_pubkey_hash: bootstrap_key
            .as_ref()
            .map(|(_, _, public_key_hash)| public_key_hash.clone()),
        storage_size: app_config.storage.size.clone(),
        tls_storage_size: app_config.storage.tls_size.clone(),
        storage_paths: app_config.storage.paths.clone(),
        cpu: app_config.resources.cpu.clone(),
        memory: app_config.resources.memory.clone(),
        services,
        health_path: app_config.health.as_ref().map(|h| h.path.clone()),
        health_interval: app_config.health.as_ref().map(|h| h.interval),
        health_timeout: app_config.health.as_ref().map(|h| h.timeout),
        signer_identity_subject,
        signer_identity_issuer,
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    spinner.set_message("Creating app...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let resp = api.create_app(&req).await?;

    if let Some((org, private_key_hex, _)) = bootstrap_key {
        let key_path =
            config::save_bootstrap_key(&paths, &org, &app_config.app.name, &private_key_hex)?;
        println!("Bootstrap key saved: {}", key_path.display());
    }

    spinner.finish_with_message(format!("App '{}' created.", resp.name));
    println!();
    println!("  Domain:    {}", resp.domain);
    println!("  Namespace: {}", resp.namespace);
    println!("  Status:    {}", resp.status);
    println!("  Unlock:    {}", resp.unlock_mode);
    println!();
    println!("Next: run `enclava deploy --image <image>` to deploy.");
    if resp.unlock_mode == "password" {
        println!(
            "During deploy, you will be prompted for the initial storage password inside the TEE claim flow."
        );
    }

    Ok(())
}

#[derive(Args)]
pub struct DeployArgs {
    /// Container image to deploy (tag resolved to digest automatically)
    #[arg(long)]
    pub image: Option<String>,
    /// Set config key=value pairs delivered to TEE after boot
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub config_vars: Vec<String>,
}

pub async fn deploy(args: DeployArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = match AppConfig::find_and_load() {
        Ok(config) => config.app.name,
        Err(_) => {
            return Err("no enclava.toml found -- run `enclava init` or specify --app".into());
        }
    };

    let config_pairs = parse_config_vars(&args.config_vars)?;
    let (api, _paths, _cli_config) = build_api_client()?;
    let app = api.get_app(&app_name).await?;
    let is_password_mode = app.unlock_mode == "password";

    let req = DeployRequest {
        image: args.image.clone(),
    };

    // Phase 1: Deploy
    let pb = ProgressBar::new(5);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:30.cyan/blue}] {msg}")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_message("Deploying...");

    let resp = api.deploy(&app_name, &req).await?;
    pb.set_position(1);
    pb.set_message("Manifests applied");

    // Phase 2: Wait for TEE boot (poll status)
    pb.set_position(2);
    pb.set_message("Waiting for TEE boot...");

    let max_wait = Duration::from_secs(900);
    let poll_interval = Duration::from_secs(3);

    // Phase 3: First ownership claim for password-mode apps.
    //
    // On first boot the app container is intentionally unhealthy until the
    // owner claims storage, so waiting for app-level readiness deadlocks.
    // Instead, wait for the TEE bootstrap endpoint and claim directly.
    let needs_initial_claim = if is_password_mode {
        api.get_unlock_status(&app_name)
            .await
            .ok()
            .and_then(|status| status.ownership_state)
            .is_none_or(|state| state == "unclaimed")
    } else {
        false
    };

    if needs_initial_claim {
        pb.set_position(3);
        pb.set_message("Waiting for ownership claim endpoint...");
        if wait_for_bootstrap_endpoint(&api, &app_name, max_wait, poll_interval, &pb).await? {
            claim_initial_ownership(&api, &_paths, &_cli_config, &app_name).await?;
            pb.set_message("Ownership claimed");
        }
    } else {
        wait_for_deploy_runtime(&api, &app_name, max_wait, poll_interval, &pb).await?;
    }

    // Phase 4: Push config if --set was used
    if !config_pairs.is_empty() {
        pb.set_position(4);
        pb.set_message(format!("Setting {} config values...", config_pairs.len()));

        // Get config token from API
        let token_resp = api.get_config_token(&app_name).await?;
        let tee = TeeClient::new(&resp.app_domain);

        for (key, value) in &config_pairs {
            tee.config_set(key, value, &token_resp.token).await?;
        }
    }

    // Phase 4: Health check
    pb.set_position(5);
    pb.set_message("Waiting for health check...");

    let health_start = std::time::Instant::now();
    let health_timeout = Duration::from_secs(60);

    loop {
        if health_start.elapsed() > health_timeout {
            pb.finish_with_message("Deployed (health check timed out)");
            break;
        }

        match api.get_status(&app_name).await {
            Ok(status) if status.status == "running" => {
                pb.finish_with_message("Deployed and healthy");
                break;
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    println!();
    println!("  App:    {app_name}");
    println!("  URL:    https://{}", resp.app_domain);
    println!("  Deploy: {}", resp.deployment_id);
    if !config_pairs.is_empty() {
        println!("  Config: {} key(s) set", config_pairs.len());
    }

    Ok(())
}

async fn wait_for_bootstrap_endpoint(
    api: &ApiClient,
    app_name: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<bool, Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new_with_timeout(&endpoint.tee_url, Duration::from_secs(10));
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for ownership claim endpoint");
            return Err("deploy timed out waiting for TEE ownership claim endpoint".into());
        }

        match tee.bootstrap_challenge().await {
            Ok(_) => {
                pb.set_message("Ownership claim endpoint ready");
                return Ok(true);
            }
            Err(err) if tee.claim_state_is_successful().await.unwrap_or(false) => {
                pb.set_message("Ownership already claimed");
                let _ = err;
                return Ok(false);
            }
            Err(_) => {
                pb.set_message("Waiting for ownership claim endpoint...");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_deploy_runtime(
    api: &ApiClient,
    app_name: &str,
    max_wait: Duration,
    poll_interval: Duration,
    pb: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > max_wait {
            pb.abandon_with_message("Timeout waiting for TEE boot");
            return Err("deploy timed out waiting for TEE to boot".into());
        }

        match api.get_status(app_name).await {
            Ok(status) => {
                if matches!(status.status.as_str(), "running" | "locked") {
                    pb.set_position(3);
                    pb.set_message(match status.status.as_str() {
                        "locked" => "TEE running, storage locked",
                        _ => "TEE running, attestation complete",
                    });
                    return Ok(());
                }

                match status.pod_phase.as_deref() {
                    Some("Running") => {
                        pb.set_position(3);
                        pb.set_message("TEE running, attestation complete");
                        return Ok(());
                    }
                    Some(phase) => {
                        pb.set_message(format!("Pod: {phase}"));
                    }
                    None => {}
                }
            }
            Err(_) => {
                // Status endpoint may not be ready yet.
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn claim_initial_ownership(
    api: &ApiClient,
    paths: &CliPaths,
    cli_config: &config::CliConfig,
    app_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    let tee = TeeClient::new(&endpoint.tee_url);

    let challenge = tee.bootstrap_challenge().await?;

    let org = cli_config
        .org
        .as_deref()
        .ok_or("no active org -- run `enclava login` first")?;
    let key_path = paths.bootstrap_key_path(org, app_name);
    let private_key_hex = std::fs::read_to_string(&key_path).map_err(|e| {
        format!(
            "bootstrap key not found at {}: {e}. Was this app created with `enclava create`?",
            key_path.display()
        )
    })?;
    let private_key_bytes: [u8; 32] = hex::decode(private_key_hex.trim())
        .map_err(|e| format!("invalid bootstrap key format: {e}"))?
        .try_into()
        .map_err(|_| "bootstrap key must be 32 bytes (64 hex chars)")?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge.nonce.as_bytes())
        .map_err(|e| format!("invalid bootstrap challenge encoding: {e}"))?;
    let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&challenge_bytes).to_bytes());
    let bootstrap_pubkey = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());

    let password = dialoguer::Password::new()
        .with_prompt("Set initial storage password")
        .with_confirmation("Confirm initial storage password", "Passwords don't match")
        .interact()?;

    let result = match tee
        .bootstrap_claim(&challenge.nonce, &bootstrap_pubkey, &signature, &password)
        .await
    {
        Ok(result) => Some(result),
        Err(err) if tee.claim_state_is_successful().await.unwrap_or(false) => {
            eprintln!(
                "Claim response was interrupted after the TEE accepted ownership; continuing."
            );
            let _ = err;
            None
        }
        Err(err) => return Err(err.into()),
    };

    if let Some(mnemonic) = result.and_then(|result| result.mnemonic) {
        println!();
        println!("IMPORTANT: Save your recovery mnemonic. This is shown ONCE.");
        println!("{mnemonic}");
    }

    Ok(())
}

#[derive(Args)]
pub struct StatusArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

pub async fn status(args: StatusArgs) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let status = api.get_status(&app_name).await?;

    let status_colored = match status.status.as_str() {
        "running" => status.status.green().to_string(),
        "creating" | "deploying" => status.status.yellow().to_string(),
        "failed" | "stopped" => status.status.red().to_string(),
        _ => status.status.clone(),
    };

    println!("App:      {}", status.app_name);
    println!("Status:   {}", status_colored);
    println!("Domain:   https://{}", status.domain);
    if let Some(phase) = &status.pod_phase {
        println!("Pod:      {phase}");
    }
    if let Some(tee) = &status.tee_status {
        println!("TEE:      {tee}");
    }
    if let Some(unlock) = &status.unlock_status {
        println!("Unlock:   {unlock}");
    }
    if let Some(deployed) = &status.last_deployed {
        println!("Deployed: {deployed}");
    }

    Ok(())
}

#[derive(Args)]
pub struct LogsArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Follow log output
    #[arg(short, long)]
    pub follow: bool,
}

pub async fn logs(args: LogsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let resp = api.get_logs(&app_name, args.follow).await?;

    if args.follow {
        // Stream logs line by line
        use tokio::io::AsyncBufReadExt;
        let stream = resp.bytes_stream();
        let reader = tokio_util::io::StreamReader::new(
            stream.map(|result| result.map_err(std::io::Error::other)),
        );
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            println!("{line}");
        }
    } else {
        // Print all logs at once
        let body = resp.text().await?;
        print!("{body}");
    }

    Ok(())
}

#[derive(Args)]
pub struct RollbackArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Deployment ID to rollback to (defaults to previous)
    #[arg(long)]
    pub to: Option<String>,
}

pub async fn rollback(args: RollbackArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    let deployment_id = if let Some(id) = args.to.clone() {
        id
    } else {
        // Show recent deployments and let user pick
        let deployments = api.list_deployments(&app_name).await?;
        if deployments.len() < 2 {
            return Err("no previous deployment to roll back to".into());
        }

        println!("Recent deployments for {app_name}:");
        for (i, d) in deployments.iter().enumerate() {
            let marker = if i == 0 { " (current)" } else { "" };
            println!(
                "  {} | {} | {} | {}{}",
                &d.id[..8],
                d.status,
                d.image_digest.as_deref().unwrap_or("n/a"),
                d.created_at,
                marker,
            );
        }

        // Default to the immediately previous deployment
        let previous = &deployments[1];
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("Roll back to deployment {}?", &previous.id[..8]))
            .default(true)
            .interact()?;

        if !confirm {
            println!("Rollback cancelled.");
            return Ok(());
        }

        previous.id.clone()
    };

    let req = RollbackRequest {
        deployment_id: Some(deployment_id),
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    spinner.set_message(format!("Rolling back {app_name}..."));
    spinner.enable_steady_tick(Duration::from_millis(100));

    let resp = api.rollback(&app_name, &req).await?;

    spinner.finish_with_message(format!("Rolled back to deployment {}", resp.rolled_back_to));
    println!("New deployment: {}", resp.deployment_id);

    Ok(())
}

// ---- Signer identity (set / rotate) ----

#[derive(Subcommand)]
pub enum SignerCommand {
    /// Set the signer identity for an app that has none yet (initial set).
    /// No email confirmation token is required for the first set.
    Set {
        /// Cosign Fulcio identity subject. Examples:
        /// `https://github.com/<org>/<repo>/.github/workflows/deploy.yml@refs/heads/main`
        /// or an email.
        subject: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Cosign Fulcio issuer URL.
        #[arg(long, default_value = "https://token.actions.githubusercontent.com")]
        issuer: String,
    },
    /// Rotate an existing signer identity. Requires an email confirmation
    /// token tied to the requesting user's verified email.
    Rotate {
        /// New cosign Fulcio identity subject.
        subject: String,
        /// Email confirmation token issued by the platform.
        #[arg(long = "confirmation-token")]
        confirmation_token: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
        /// Cosign Fulcio issuer URL.
        #[arg(long, default_value = "https://token.actions.githubusercontent.com")]
        issuer: String,
    },
}

pub async fn signer(cmd: SignerCommand) -> Result<(), Box<dyn std::error::Error>> {
    let (api, _paths, _cli_config) = build_api_client()?;
    match cmd {
        SignerCommand::Set {
            subject,
            issuer,
            app,
        } => {
            let app_name = resolve_app_name(&app)?;
            let req = SetSignerRequest {
                subject: subject.clone(),
                issuer: issuer.clone(),
                email_confirmation_token: None,
            };
            let _ = api.set_signer(&app_name, &req).await?;
            println!("Signer identity set for {app_name}.");
            println!("  Subject: {subject}");
            println!("  Issuer:  {issuer}");
        }
        SignerCommand::Rotate {
            subject,
            issuer,
            confirmation_token,
            app,
        } => {
            let app_name = resolve_app_name(&app)?;
            let req = SetSignerRequest {
                subject: subject.clone(),
                issuer: issuer.clone(),
                email_confirmation_token: Some(confirmation_token),
            };
            let _ = api.set_signer(&app_name, &req).await?;
            println!("Signer identity rotated for {app_name}.");
            println!("  Subject: {subject}");
            println!("  Issuer:  {issuer}");
        }
    }
    Ok(())
}

#[derive(Args)]
pub struct DestroyArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
    /// Skip confirmation prompt
    #[arg(long)]
    pub force: bool,
}

pub async fn destroy(args: DestroyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths, _cli_config) = build_api_client()?;

    if !args.force {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!(
                "This will permanently destroy '{app_name}' and all its data. Continue?"
            ))
            .default(false)
            .interact()?;

        if !confirm {
            println!("Destroy cancelled.");
            return Ok(());
        }

        // Double confirmation: type the app name
        let typed_name: String = dialoguer::Input::new()
            .with_prompt(format!("Type '{app_name}' to confirm"))
            .interact_text()?;

        if typed_name != app_name {
            println!("Name did not match. Destroy cancelled.");
            return Ok(());
        }
    }

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.red} {msg}")
            .unwrap(),
    );
    spinner.set_message(format!("Destroying {app_name}..."));
    spinner.enable_steady_tick(Duration::from_millis(100));

    api.delete_app(&app_name).await?;

    spinner.finish_with_message(format!("App '{app_name}' destroyed."));

    Ok(())
}
