use clap::Subcommand;

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::SetDomainRequest;
use enclava_cli::app_config::AppConfig;
use enclava_cli::config::{self, CliPaths};

#[derive(Subcommand)]
pub enum DomainsCommand {
    /// Add a custom domain
    Add {
        /// Domain name (e.g., app.example.com)
        domain: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
    /// List domains for an app
    List {
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
    /// Remove a custom domain
    Remove {
        /// Domain name to remove
        domain: String,
        /// App name (defaults to enclava.toml app.name)
        #[arg(long)]
        app: Option<String>,
    },
}

fn resolve_app_name(explicit: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = explicit {
        return Ok(name.clone());
    }
    let config = AppConfig::find_and_load()?;
    Ok(config.app.name)
}

fn build_api_client() -> Result<ApiClient, Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    Ok(ApiClient::from_config(&cli_config, &creds))
}

pub async fn run(cmd: DomainsCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        DomainsCommand::Add { domain, app } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            let req = SetDomainRequest {
                domain: domain.clone(),
            };
            let resp = api.set_domain(&app_name, &req).await?;

            println!("Custom domain added: {domain}");
            println!();
            println!("Platform domain: {}", resp.platform_domain);
            if let Some(instructions) = &resp.dns_instructions {
                println!();
                println!("DNS setup required:");
                println!("{instructions}");
            }
        }

        DomainsCommand::List { app } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            let resp = api.get_domain(&app_name).await?;

            println!("Domains for {app_name}:");
            println!("  Platform: https://{}", resp.platform_domain);
            if let Some(custom) = &resp.custom_domain {
                println!("  Custom:   https://{custom}");
            }
        }

        DomainsCommand::Remove { domain, app } => {
            let app_name = resolve_app_name(&app)?;
            let api = build_api_client()?;

            api.delete_domain(&app_name).await?;
            println!("Custom domain '{domain}' removed from {app_name}.");
        }
    }
    Ok(())
}
