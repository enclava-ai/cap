use clap::Subcommand;

use enclava_cli::api_client::ApiClient;
use enclava_cli::api_types::InvoiceResponse;
use enclava_cli::config::{self, CliPaths};

#[derive(Subcommand)]
pub enum TierCommand {
    /// Upgrade to a higher tier (generates BTCPay invoice)
    Upgrade {
        /// Target tier name
        tier: String,
    },
    /// Renew current subscription (generates BTCPay invoice)
    Renew,
}

fn build_api_client() -> Result<ApiClient, Box<dyn std::error::Error>> {
    let paths = CliPaths::resolve()?;
    let cli_config = config::load_config(&paths)?;
    let creds = config::load_credentials(&paths)?;
    Ok(ApiClient::from_config(&cli_config, &creds))
}

fn display_invoice(invoice: &InvoiceResponse) {
    println!("Payment invoice created:");
    println!();
    println!("  Amount:  {} sats", invoice.amount_sats);
    println!("  Expires: {}", invoice.expires_at);
    println!();
    println!("  Pay here: {}", invoice.payment_url);
    if let Some(ln) = &invoice.lightning_invoice {
        println!();
        println!("  Lightning invoice:");
        println!("  {ln}");
    }
    println!();
    println!("Your tier will activate automatically once payment is confirmed.");
}

pub async fn run(cmd: TierCommand) -> Result<(), Box<dyn std::error::Error>> {
    let api = build_api_client()?;

    match cmd {
        TierCommand::Upgrade { tier } => {
            // Show current tier and target
            let billing = api.get_billing_status().await?;
            println!("Current tier: {}", billing.tier);
            println!("Upgrading to: {tier}");
            println!();

            // Show tier details
            let tiers = api.get_tiers().await?;
            if let Some(target) = tiers.iter().find(|t| t.name == tier) {
                println!("  {} tier:", target.name);
                println!("    Apps:    up to {}", target.max_apps);
                println!("    CPU:     up to {}", target.max_cpu);
                println!("    Memory:  up to {}", target.max_memory);
                println!("    Storage: up to {}", target.max_storage);
                println!("    Price:   {} sats/month", target.price_sats);
                println!();
            }

            let confirm = dialoguer::Confirm::new()
                .with_prompt("Generate payment invoice?")
                .default(true)
                .interact()?;

            if !confirm {
                println!("Upgrade cancelled.");
                return Ok(());
            }

            let invoice = api.upgrade_tier(&tier).await?;
            display_invoice(&invoice);
        }

        TierCommand::Renew => {
            let billing = api.get_billing_status().await?;
            println!("Current tier: {}", billing.tier);
            println!("Status: {}", billing.status);
            if let Some(end) = &billing.period_end {
                println!("Period ends: {end}");
            }
            println!();

            let invoice = api.renew().await?;
            display_invoice(&invoice);
        }
    }
    Ok(())
}
