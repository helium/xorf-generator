use crate::{
    cmd::{open_output_file, print_json},
    Filter, Manifest, PublicKeyManifest, Result,
};
use anyhow::bail;
use helium_crypto::PublicKey;
use serde_json::json;
use std::{io::Write, path::PathBuf};
use structopt::StructOpt;

/// Commands on filters
#[derive(StructOpt, Debug)]
pub enum Cmd {
    Generate(Generate),
    Contains(Contains),
    Verify(Verify),
}

impl Cmd {
    pub fn run(&self) -> Result {
        match self {
            Self::Generate(cmd) => cmd.run(),
            Self::Contains(cmd) => cmd.run(),
            Self::Verify(cmd) => cmd.run(),
        }
    }
}

/// Check if a given filter file contains a given public key
#[derive(StructOpt, Debug)]
pub struct Contains {
    /// The input file to generate a filter for
    #[structopt(long, short, default_value = "filter.bin")]
    input: PathBuf,
    /// The public key to check
    key: PublicKey,
}

impl Contains {
    pub fn run(&self) -> Result {
        let filter = Filter::from_path(&self.input)?;
        let json = json!({
            "address":  self.key.to_string(),
            "in_filter": filter.contains(&self.key),
        });
        print_json(&json)
    }
}

/// Verifies a given filter against the given public key
#[derive(StructOpt, Debug)]
pub struct Verify {
    /// The input file to verify the signature for
    #[structopt(long, short, default_value = "filter.bin")]
    input: PathBuf,
    /// The public key to use for verification
    #[structopt(long, short, default_value = "public_key.json")]
    key: PathBuf,
}

impl Verify {
    pub fn run(&self) -> Result {
        let filter = Filter::from_path(&self.input)?;
        let key_manifest = PublicKeyManifest::from_path(&self.key)?;
        let key = key_manifest.public_key()?;
        let verified = filter.verify(&key).is_ok();
        print_verified(&key, verified)
    }
}

/// Generate a binary filter for the hotspots listed in the given file.
///
/// This converts a csv file of given hotspot public keys and generates a binary
/// xor filter (a binary fuse with 32 bit fingerprints to be precise). If a
/// manifest file is given on the command line the resulting binary is signed
/// and the signature included in the resulting output.
#[derive(Debug, StructOpt)]
pub struct Generate {
    /// The input csv file to generate a filter for
    #[structopt(long, short)]
    input: PathBuf,
    /// The public key file to use
    #[structopt(long, short, default_value = "public_key.json")]
    key: PathBuf,

    /// The file to write the resulting binary filter to
    #[structopt(long, short, default_value = "filter.bin")]
    output: PathBuf,

    /// The path for the signature manifet to use
    #[structopt(long, short, default_value = "manifest.json")]
    manifest: PathBuf,
}

impl Generate {
    pub fn run(&self) -> Result {
        let manifest = Manifest::from_path(&self.manifest)?;
        let key_manifest = PublicKeyManifest::from_path(&self.key)?;
        let key = key_manifest.public_key()?;

        let mut filter = Filter::from_csv(manifest.serial, &self.input)?;
        filter.signature = manifest.sign(&key_manifest)?;
        let filter_bytes = filter.to_bytes()?;
        let mut file = open_output_file(&self.output, false)?;
        file.write_all(&filter_bytes)?;

        let verified = filter.verify(&key).is_ok();
        let _ = print_verified(&key, verified);
        if !verified {
            bail!("Filter does not verify with key {}", key.to_string());
        }
        Ok(())
    }
}

fn print_verified(public_key: &PublicKey, verified: bool) -> Result {
    let json = json!({
        "address":  public_key.to_string(),
        "verified": verified,
    });
    print_json(&json)
}
