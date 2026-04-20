use clap::Args;
use dialoguer::{Input, Password, Select};

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::{LoginRequest, SignupRequest};
use enclava_cli::config::{self, CliPaths, Credentials};

#[derive(Args)]
pub struct LoginArgs {
    /// Authenticate with Nostr identity (NIP-98)
    #[arg(long)]
    pub nostr: bool,
    /// Authenticate with email + password
    #[arg(long)]
    pub email: bool,
}

pub async fn signup() -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;

    let methods = vec!["Email", "Nostr (npub)"];
    let selection = Select::new()
        .with_prompt("Sign up with")
        .items(&methods)
        .default(0)
        .interact()?;

    let req = match selection {
        0 => {
            let email: String = Input::new().with_prompt("Email").interact_text()?;
            let password = Password::new()
                .with_prompt("Password")
                .with_confirmation("Confirm password", "Passwords don't match")
                .interact()?;
            let display_name: String = Input::new()
                .with_prompt("Display name (optional)")
                .allow_empty(true)
                .interact_text()?;

            SignupRequest {
                provider: "email".to_string(),
                email: Some(email),
                password: Some(password),
                npub: None,
                display_name: if display_name.is_empty() {
                    None
                } else {
                    Some(display_name)
                },
            }
        }
        1 => {
            let npub: String = Input::new()
                .with_prompt("Nostr public key (npub1...)")
                .interact_text()?;

            SignupRequest {
                provider: "nostr".to_string(),
                email: None,
                password: None,
                npub: Some(npub),
                display_name: None,
            }
        }
        _ => unreachable!(),
    };

    let client = ApiClient::new(&cli_config.api_url, None);
    let resp = client.signup(&req).await?;

    // Save credentials
    let creds = Credentials {
        session_token: Some(resp.token),
        api_key: None,
    };
    config::save_credentials(&paths, &creds)?;

    // Save org
    let mut updated_config = cli_config;
    updated_config.org = Some(resp.org_name.clone());
    config::save_config(&paths, &updated_config)?;

    println!("Account created. Logged in as {}.", resp.org_name);
    Ok(())
}

pub async fn login(args: LoginArgs) -> Result<(), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;

    // Check for existing session
    let existing_creds = config::load_credentials(&paths)?;
    if existing_creds.session_token.is_some() {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Already logged in. Replace existing session?")
            .default(true)
            .interact()?;
        if !confirm {
            println!("Login cancelled.");
            return Ok(());
        }
    }

    let use_nostr = if args.nostr {
        true
    } else if args.email {
        false
    } else {
        let methods = vec!["Email", "Nostr (npub)"];
        let selection = Select::new()
            .with_prompt("Log in with")
            .items(&methods)
            .default(0)
            .interact()?;
        selection == 1
    };

    let req = if use_nostr {
        let npub: String = Input::new()
            .with_prompt("Nostr public key (npub1...)")
            .interact_text()?;
        let nsec_str: String = Password::new()
            .with_prompt("Nostr private key (nsec1...)")
            .interact()?;

        // Parse the secret key from nsec bech32
        let secret_key =
            nostr::SecretKey::parse(&nsec_str).map_err(|e| format!("invalid nsec key: {e}"))?;
        let keys = nostr::Keys::new(secret_key);

        // Verify the npub matches the nsec
        let expected_pubkey = keys.public_key();
        let provided_pubkey =
            nostr::PublicKey::parse(&npub).map_err(|e| format!("invalid npub: {e}"))?;
        if expected_pubkey != provided_pubkey {
            return Err("npub does not match nsec".into());
        }

        // Construct NIP-98 HTTP Auth event (kind 27235)
        let api_url = format!("{}/auth/login", cli_config.api_url);
        let event = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
            .tag(
                nostr::Tag::parse(["u".to_string(), api_url])
                    .map_err(|e| format!("tag error: {e}"))?,
            )
            .tag(
                nostr::Tag::parse(["method".to_string(), "POST".to_string()])
                    .map_err(|e| format!("tag error: {e}"))?,
            )
            .sign_with_keys(&keys)
            .map_err(|e| format!("failed to sign NIP-98 event: {e}"))?;

        let signed_event_json = nostr::JsonUtil::as_json(&event);

        LoginRequest {
            provider: "nostr".to_string(),
            email: None,
            password: None,
            npub: Some(npub),
            nostr_event: Some(signed_event_json),
        }
    } else {
        let email: String = Input::new().with_prompt("Email").interact_text()?;
        let password = Password::new().with_prompt("Password").interact()?;

        LoginRequest {
            provider: "email".to_string(),
            email: Some(email),
            password: Some(password),
            npub: None,
            nostr_event: None,
        }
    };

    let client = ApiClient::new(&cli_config.api_url, None);
    let resp = client.login(&req).await?;

    // Save credentials
    let creds = Credentials {
        session_token: Some(resp.token),
        api_key: None,
    };
    config::save_credentials(&paths, &creds)?;

    // Save org
    let mut updated_config = cli_config;
    updated_config.org = Some(resp.org_name.clone());
    config::save_config(&paths, &updated_config)?;

    println!("Logged in. Active org: {}", resp.org_name);
    Ok(())
}
