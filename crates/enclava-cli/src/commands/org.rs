use clap::Subcommand;

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::{CreateOrgRequest, InviteRequest};
use enclava_cli::config::{self, CliPaths};

#[derive(Subcommand)]
pub enum OrgCommand {
    /// Create a new organization
    Create {
        /// Organization name
        name: String,
    },
    /// Switch active organization
    Switch {
        /// Organization name to switch to
        name: String,
    },
    /// Invite a member to the current organization
    Invite {
        /// Email or Nostr npub of the person to invite
        identifier: String,
        /// Role to assign
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// List members of the current organization
    Members,
    /// Manage the org-signed keyring (Phase 7 D10)
    #[command(subcommand)]
    Keyring(KeyringCommand),
}

#[derive(Subcommand)]
pub enum KeyringCommand {
    /// Owner-only: create v1 keyring, sign with current key, upload (stub)
    Init {
        /// Org UUID
        org_id: String,
    },
    /// Owner-only: increment version, add member, sign, upload (stub)
    AddMember {
        org_id: String,
        user_id: String,
        /// Hex-encoded Ed25519 public key (32 bytes / 64 hex chars)
        pubkey: String,
        #[arg(long, default_value = "deployer")]
        role: String,
    },
    /// Member's first encounter: TOFU prompt, cache the owner pubkey
    Trust {
        org_id: String,
        /// Hex-encoded owner pubkey (32 bytes / 64 hex chars)
        owner_pubkey: String,
    },
}

fn build_api_client_with_paths()
-> Result<(ApiClient, CliPaths, config::CliConfig), Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    let api = ApiClient::from_config(&cli_config, &creds);
    Ok((api, paths, cli_config))
}

pub async fn run(cmd: OrgCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        OrgCommand::Create { name } => {
            let (api, paths, mut cli_config) = build_api_client_with_paths()?;

            let req = CreateOrgRequest { name: name.clone() };
            let resp = api.create_org(&req).await?;

            println!("Organization '{}' created.", resp.name);
            println!("Tier: {}", resp.tier);

            // Switch to the new org
            cli_config.org = Some(resp.name.clone());
            config::save_config(&paths, &cli_config)?;
            println!("Switched to org '{}'.", resp.name);
        }

        OrgCommand::Switch { name } => {
            let (api, paths, mut cli_config) = build_api_client_with_paths()?;

            // Verify the org exists and user is a member
            let orgs = api.list_orgs().await?;
            let found = orgs.iter().any(|o| o.name == name);
            if !found {
                return Err(format!(
                    "org '{name}' not found. Available orgs: {}",
                    orgs.iter()
                        .map(|o| o.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into());
            }

            cli_config.org = Some(name.clone());
            config::save_config(&paths, &cli_config)?;
            println!("Switched to org '{name}'.");
        }

        OrgCommand::Invite { identifier, role } => {
            let (api, _paths, cli_config) = build_api_client_with_paths()?;
            let org = cli_config
                .org
                .as_deref()
                .ok_or("no active org -- run `enclava org switch <name>`")?;

            let req = InviteRequest {
                identifier: identifier.clone(),
                role: role.clone(),
            };
            api.invite_member(org, &req).await?;
            println!("Invited {identifier} to {org} as {role}.");
        }

        OrgCommand::Keyring(sub) => return run_keyring(sub).await,

        OrgCommand::Members => {
            let (api, _paths, cli_config) = build_api_client_with_paths()?;
            let org = cli_config
                .org
                .as_deref()
                .ok_or("no active org -- run `enclava org switch <name>`")?;

            let members = api.list_members(org).await?;

            println!("Members of {org}:");
            for member in &members {
                let name = member.display_name.as_deref().unwrap_or(&member.user_id);
                println!("  {} ({})", name, member.role);
            }
        }
    }
    Ok(())
}

async fn run_keyring(cmd: KeyringCommand) -> Result<(), Box<dyn std::error::Error>> {
    use chrono::Utc;
    use ed25519_dalek::VerifyingKey;
    use enclava_cli::keyring::{
        Member, OrgKeyring, Role, fingerprint, sign_keyring, store_trusted_owner,
    };
    use enclava_cli::keys;
    use uuid::Uuid;

    fn parse_pubkey(hex_in: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
        let bytes = hex::decode(hex_in)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "pubkey must decode to 32 bytes")?;
        Ok(VerifyingKey::from_bytes(&arr)?)
    }

    fn parse_role(s: &str) -> Result<Role, Box<dyn std::error::Error>> {
        match s {
            "owner" => Ok(Role::Owner),
            "admin" => Ok(Role::Admin),
            "deployer" => Ok(Role::Deployer),
            other => Err(format!("unknown role `{other}`").into()),
        }
    }

    match cmd {
        KeyringCommand::Init { org_id } => {
            let org = Uuid::parse_str(&org_id)?;
            // TODO(phase-7-api): load the active user_id from creds; assumes a single
            // local user keypair until the user-keys API endpoint exists.
            let user_id = Uuid::new_v4();
            let key = keys::create_and_store(user_id)?;

            let keyring = OrgKeyring {
                org_id: org,
                version: 1,
                members: vec![Member {
                    user_id,
                    pubkey: key.public,
                    role: Role::Owner,
                    added_at: Utc::now(),
                }],
                updated_at: Utc::now(),
            };
            let env = sign_keyring(&key, keyring);
            store_trusted_owner(&org, &key.public)?;

            println!("Initialized keyring for {org}");
            println!("Owner pubkey fingerprint: {}", fingerprint(&key.public));
            println!("Signed envelope (TODO(phase-7-api): upload to platform):");
            println!("{}", serde_json::to_string_pretty(&env)?);
        }
        KeyringCommand::AddMember {
            org_id,
            user_id,
            pubkey,
            role,
        } => {
            let org = Uuid::parse_str(&org_id)?;
            let user = Uuid::parse_str(&user_id)?;
            let pk = parse_pubkey(&pubkey)?;
            let role = parse_role(&role)?;
            println!(
                "TODO(phase-7-api): fetch current keyring v_n for {org}, append member \
                 ({user}, {role:?}, {}), bump to v_{{n+1}}, sign with stored owner key, \
                 upload",
                fingerprint(&pk)
            );
        }
        KeyringCommand::Trust {
            org_id,
            owner_pubkey,
        } => {
            let org = Uuid::parse_str(&org_id)?;
            let pk = parse_pubkey(&owner_pubkey)?;

            println!(
                "About to TRUST owner pubkey for org {org}.\n  fingerprint: {}\n\
                 Verify this fingerprint with the org owner over an out-of-band channel.",
                fingerprint(&pk)
            );
            let confirm = dialoguer::Confirm::new()
                .with_prompt("Confirm trust on first use?")
                .default(false)
                .interact()?;
            if !confirm {
                return Err("trust declined".into());
            }
            store_trusted_owner(&org, &pk)?;
            println!("Owner pubkey cached at ~/.enclava/state/{org}/owner_pubkey");
        }
    }
    Ok(())
}
