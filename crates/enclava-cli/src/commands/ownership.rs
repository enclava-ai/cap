use clap::{Args, Subcommand};
use dialoguer::{Input, Password};
use ed25519_dalek::{Signer, SigningKey};

use enclava_cli::api_client::ApiClient;
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};
use enclava_cli::tee_client::TeeClient;

#[derive(Args)]
pub struct ClaimArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

#[derive(Args)]
pub struct UnlockArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

#[derive(Args)]
pub struct RecoverArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

#[derive(Args)]
pub struct ChangePasswordArgs {
    /// App name (defaults to enclava.toml app.name)
    #[arg(long)]
    pub app: Option<String>,
}

#[derive(Subcommand)]
pub enum AutoUnlockCommand {
    /// Seal owner seed with VMPCK for automatic restart
    Enable {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
    /// Remove sealed seed, require password on restart
    Disable {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
}

/// Resolve app name from --app flag or enclava.toml.
fn resolve_app_name(explicit: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(name.clone());
    }
    let config = AppConfig::find_and_load()?;
    Ok(config.app.name)
}

/// Get the TEE URL for an app by querying the API.
async fn resolve_tee_url(
    api: &ApiClient,
    app_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let endpoint = api.get_unlock_endpoint(app_name).await?;
    Ok(endpoint.tee_url)
}

/// Build an authenticated API client from stored config/credentials.
fn build_api_client() -> Result<(ApiClient, CliPaths), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok((api, paths))
}

pub async fn claim(args: ClaimArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, paths) = build_api_client()?;
    let tee_url = resolve_tee_url(&api, &app_name).await?;
    let tee = TeeClient::new(&tee_url);

    println!("Claiming ownership of {app_name}...");

    // Step 1: Get challenge from TEE
    let challenge = tee.bootstrap_challenge().await?;
    println!("Challenge received (expires in {}s)", challenge.ttl_seconds);

    // Step 2: Load bootstrap keypair
    let cli_config = config::load_config(&paths)?;
    let org = cli_config
        .org
        .as_deref()
        .ok_or("no active org -- run `enclava login` first")?;
    let key_path = paths.bootstrap_key_path(org, &app_name);

    // Step 3: Sign challenge with Ed25519 bootstrap keypair
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

    // Sign the challenge nonce
    let signature_bytes = signing_key.sign(challenge.nonce.as_bytes());

    let bootstrap_pubkey = hex::encode(verifying_key.to_bytes());
    let signature = hex::encode(signature_bytes.to_bytes());

    // Step 4: Get password
    let password = Password::new()
        .with_prompt("Set unlock password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;

    // Step 5: Claim
    let result = tee
        .bootstrap_claim(&challenge.nonce, &bootstrap_pubkey, &signature, &password)
        .await?;

    println!("Ownership claimed.");

    if let Some(mnemonic) = &result.mnemonic {
        println!();
        println!("IMPORTANT: Save your recovery mnemonic. This is shown ONCE.");
        println!("If you lose your password, this is the only way to recover.");
        println!();
        println!("  {mnemonic}");
        println!();
    }

    Ok(())
}

pub async fn unlock(args: UnlockArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths) = build_api_client()?;
    let tee_url = resolve_tee_url(&api, &app_name).await?;
    let tee = TeeClient::new(&tee_url);

    let password = Password::new().with_prompt("Unlock password").interact()?;

    println!("Unlocking {app_name}...");
    tee.unlock(&password).await?;
    println!("Storage unlocked. App is starting.");
    Ok(())
}

pub async fn recover(args: RecoverArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths) = build_api_client()?;
    let tee_url = resolve_tee_url(&api, &app_name).await?;
    let tee = TeeClient::new(&tee_url);

    let mnemonic: String = Input::new()
        .with_prompt("Recovery mnemonic (BIP39)")
        .interact_text()?;

    let new_password = Password::new()
        .with_prompt("New unlock password")
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;

    println!("Recovering {app_name}...");
    tee.recover(&mnemonic, &new_password).await?;
    println!("Recovery complete. Use the new password to unlock.");
    Ok(())
}

pub async fn change_password(args: ChangePasswordArgs) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = resolve_app_name(&args.app)?;
    let (api, _paths) = build_api_client()?;
    let tee_url = resolve_tee_url(&api, &app_name).await?;
    let tee = TeeClient::new(&tee_url);

    let current = Password::new().with_prompt("Current password").interact()?;

    let new_password = Password::new()
        .with_prompt("New password")
        .with_confirmation("Confirm new password", "Passwords don't match")
        .interact()?;

    println!("Changing password for {app_name}...");
    tee.change_password(&current, &new_password).await?;
    println!("Password changed.");
    Ok(())
}

pub async fn auto_unlock(cmd: AutoUnlockCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AutoUnlockCommand::Enable { app } => {
            let app_name = resolve_app_name(&app)?;
            let (api, _paths) = build_api_client()?;
            let tee_url = resolve_tee_url(&api, &app_name).await?;
            let tee = TeeClient::new(&tee_url);

            let password = Password::new()
                .with_prompt("Unlock password (to authorize sealing)")
                .interact()?;

            println!("Enabling auto-unlock for {app_name}...");
            tee.enable_auto_unlock(&password).await?;
            println!("Auto-unlock enabled. Restarts no longer require a password.");
            Ok(())
        }
        AutoUnlockCommand::Disable { app } => {
            let app_name = resolve_app_name(&app)?;
            let (api, _paths) = build_api_client()?;
            let tee_url = resolve_tee_url(&api, &app_name).await?;
            let tee = TeeClient::new(&tee_url);

            let password = Password::new()
                .with_prompt("Unlock password (to authorize unsealing)")
                .interact()?;

            println!("Disabling auto-unlock for {app_name}...");
            tee.disable_auto_unlock(&password).await?;
            println!("Auto-unlock disabled. Restarts require the password.");
            Ok(())
        }
    }
}
