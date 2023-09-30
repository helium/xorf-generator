use crate::{cmd::print_json, manifest::PublicKeyManifest};
use anyhow::{Context, Result};
use serde_json::json;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct Cmd {
    #[command(subcommand)]
    pub cmd: KeyCommand,
}

impl Cmd {
    pub fn run(&self) -> Result<()> {
        self.cmd.run()
    }
}

/// Commands on keypairs
#[derive(clap::Subcommand, Debug)]
pub enum KeyCommand {
    Info(Info),
}

impl KeyCommand {
    pub fn run(&self) -> Result<()> {
        match self {
            Self::Info(cmd) => cmd.run(),
        }
    }
}

/// Displays key information for a given keypair
#[derive(clap::Args, Debug)]
pub struct Info {
    /// File to read public key from
    #[arg(default_value = "public_key.json")]
    input: PathBuf,
}

impl Info {
    pub fn run(&self) -> Result<()> {
        let manifest = PublicKeyManifest::from_path(&self.input)
            .context(format!("reading public key {}", self.input.display()))?;
        print_manifest(&manifest)
    }
}

fn print_manifest(manifest: &PublicKeyManifest) -> Result<()> {
    let json = json!({
        "address": manifest.public_key()?.to_string(),
        "keys": manifest.public_keys.len(),
        "required": manifest.required,
    });
    print_json(&json)
}
