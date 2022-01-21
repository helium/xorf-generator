use crate::{cmd::print_json, manifest::PublicKeyManifest, Result};
use serde_json::json;
use std::path::PathBuf;
use structopt::StructOpt;

/// Commands on keypairs
#[derive(StructOpt, Debug)]
pub enum Cmd {
    Info(Info),
}

impl Cmd {
    pub fn run(&self) -> Result {
        match self {
            Self::Info(cmd) => cmd.run(),
        }
    }
}

/// Displays key information for a given keypair
#[derive(StructOpt, Debug)]
pub struct Info {
    /// File to read public key from
    input: PathBuf,
}

impl Info {
    pub fn run(&self) -> Result {
        let manifest = PublicKeyManifest::from_csv(&self.input)?;
        print_manifest(&manifest)
    }
}

fn print_manifest(manifest: &PublicKeyManifest) -> Result {
    let json = json!({
        "address": manifest.public_key()?.to_string(),
        "keys": manifest.public_keys.len(),
        "required": manifest.required,
    });
    print_json(&json)
}
