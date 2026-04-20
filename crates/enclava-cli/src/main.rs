mod commands;

use clap::Parser;
use commands::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = commands::run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
