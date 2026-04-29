//! `enclava descriptor` — debug subcommand for Phase 7 deployment descriptor work.
//!
//! Prints the canonical hex (full descriptor and core subset) for a JSON
//! descriptor file. `enclava deploy` now generates and signs descriptors
//! automatically; this command remains useful for byte-layout debugging.

use clap::Subcommand;

use enclava_cli::descriptor::{
    DeploymentDescriptor, descriptor_canonical_bytes, descriptor_core_canonical_bytes,
    descriptor_core_hash,
};

#[derive(Subcommand)]
pub enum DescriptorCommand {
    /// Render the CE-v1 canonical bytes (and core hash) for a JSON descriptor.
    Render {
        /// Path to a JSON DeploymentDescriptor.
        path: std::path::PathBuf,
    },
}

pub async fn run(cmd: DescriptorCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        DescriptorCommand::Render { path } => {
            let json = std::fs::read_to_string(&path)?;
            let d: DeploymentDescriptor = serde_json::from_str(&json)?;
            let full = descriptor_canonical_bytes(&d);
            let core = descriptor_core_canonical_bytes(&d);
            let core_hash = descriptor_core_hash(&d);
            println!("descriptor_canonical_bytes ({} bytes):", full.len());
            println!("  {}", hex::encode(&full));
            println!("descriptor_core_canonical_bytes ({} bytes):", core.len());
            println!("  {}", hex::encode(&core));
            println!("descriptor_core_hash:");
            println!("  {}", hex::encode(core_hash));
        }
    }
    Ok(())
}
