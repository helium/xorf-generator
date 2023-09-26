use crate::{
    cmd::{open_output_file, print_json},
    filter::Filter,
    manifest::{ManifestSignature, ManifestSignatureVerify},
    Descriptor, Manifest, PublicKeyManifest, Result,
};
use anyhow::bail;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use std::{io::Write, path::PathBuf};

#[derive(clap::Args, Debug)]
pub struct Cmd {
    #[command(subcommand)]
    pub cmd: ManifestCommand,
}

impl Cmd {
    pub fn run(&self) -> Result {
        self.cmd.run()
    }
}

/// Commands on manifests
#[derive(clap::Subcommand, Debug)]
pub enum ManifestCommand {
    Generate(Generate),
    Verify(Verify),
}

impl ManifestCommand {
    pub fn run(&self) -> Result {
        match self {
            Self::Generate(cmd) => cmd.run(),
            Self::Verify(cmd) => cmd.run(),
        }
    }
}

/// Generate a manifest for a given list of hotspots
///
/// This takes a a filename for a list of hotspots and generates a manifest file
/// that can be used to add signatures to as well as binary file which contains
/// the data of the filter to sign.
#[derive(Debug, clap::Args)]

pub struct Generate {
    /// The descriptor file to generate a manifest for
    #[arg(long, short, default_value = "descriptor.json")]
    input: PathBuf,

    /// The public key file to use
    #[arg(long, short, default_value = "public_key.json")]
    key: PathBuf,

    /// The file to write the resulting manifest file to
    #[arg(long, short, default_value = "manifest.json")]
    manifest: PathBuf,

    /// Whether to force overwrite an existing manifest file
    #[arg(long, short)]
    force: bool,

    /// The serial number for the filter
    #[arg(long, short)]
    serial: u32,
}

impl Generate {
    pub fn run(&self) -> Result {
        let descriptor = Descriptor::from_csv(&self.input)?;
        let filter = Filter::from_descriptor(self.serial, &descriptor)?;
        let filter_hash = filter.hash()?;
        let key_manifest = PublicKeyManifest::from_path(&self.key)?;
        let signatures = key_manifest
            .public_keys
            .iter()
            .map(ManifestSignature::from)
            .collect();

        let mut manifest_file = open_output_file(&self.manifest, !self.force)?;
        let manifest = Manifest {
            serial: self.serial,
            hash: STANDARD.encode(filter_hash),
            signatures,
        };
        serde_json::to_writer_pretty(&mut manifest_file, &manifest)?;
        Ok(())
    }
}

/// Verify the manifest for a given list of hotspots
///
/// This takes a a filename for a list of hotspots and a manifest file, and
/// generates the file to sign while verifying that the given manifest hash and
/// serial number is a match for the csv data.
#[derive(Debug, clap::Args)]

pub struct Verify {
    /// The descriptor file to verify the manifest and generate a filter for
    #[arg(long, short, default_value = "descriptor.json")]
    input: PathBuf,

    /// The manifest file to verify
    #[arg(long, short, default_value = "manifest.json")]
    manifest: PathBuf,

    /// The file to write the filter signing data to
    #[arg(long, short, default_value = "data.bin")]
    data: PathBuf,
}

impl Verify {
    pub fn run(&self) -> Result {
        let manifest = Manifest::from_path(&self.manifest)?;
        let manifest_hash = STANDARD.decode(&manifest.hash)?;

        let descriptor = Descriptor::from_csv(&self.input)?;
        let filter = Filter::from_descriptor(manifest.serial, &descriptor)?;
        let filter_hash = filter.hash()?;

        if manifest_hash != filter_hash {
            bail!(
                "manifest hash {} does not match filter hash {}",
                STANDARD.encode(manifest_hash),
                STANDARD.encode(filter_hash)
            )
        }

        let mut data_file = open_output_file(&self.data, false)?;
        let signing_bytes = filter.signing_bytes()?;
        data_file.write_all(&signing_bytes)?;

        let verified: Vec<ManifestSignatureVerify> = manifest
            .signatures
            .iter()
            .map(|signature| signature.verify(&signing_bytes))
            .collect();

        let json = json!({
            "signing_data": self.data,
            "hash": {
                "serial": manifest.serial,
                "hash": manifest.hash,
                "verified": true,
            },
            "signatures": verified,
        });
        print_json(&json)
    }
}
