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
