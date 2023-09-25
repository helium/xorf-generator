use crate::{
    cmd::{open_output_file, print_json},
    filter::Filter,
    manifest::{ManifestSignature, ManifestSignatureVerify},
    Manifest, PublicKeyManifest, Result,
};
use anyhow::bail;
use serde_json::json;
use std::{io::Write, path::PathBuf};
use structopt::StructOpt;

/// Commands on manifests
#[derive(StructOpt, Debug)]
pub enum Cmd {
    Generate(Generate),
    Verify(Verify),
}

impl Cmd {
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
#[derive(Debug, StructOpt)]

pub struct Generate {
    /// The input csv file to generate a manifest for
    #[structopt(long, short)]
    input: PathBuf,

    /// The public key file to use
    #[structopt(long, short, default_value = "public_key.json")]
    key: PathBuf,

    /// The file to write the resulting manifest file to
    #[structopt(long, short, default_value = "manifest.json")]
    manifest: PathBuf,

    /// Whether to force overwrite an existing manifest file
    #[structopt(long, short)]
    force: bool,

    /// The serial number for the filter
    #[structopt(long, short)]
    serial: u32,
}

impl Generate {
    pub fn run(&self) -> Result {
        let filter = Filter::from_csv(self.serial, &self.input)?;
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
            hash: base64::encode(filter_hash),
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
#[derive(Debug, StructOpt)]

pub struct Verify {
    /// The input csv file to verify the manifest and generate a filter for
    #[structopt(long, short)]
    input: PathBuf,

    /// The manifest file to verify
    #[structopt(long, short, default_value = "manifest.json")]
    manifest: PathBuf,

    /// The file to write the filter signing data to
    #[structopt(long, short, default_value = "data.bin")]
    data: PathBuf,
}

impl Verify {
    pub fn run(&self) -> Result {
        let manifest = Manifest::from_path(&self.manifest)?;
        let manifest_hash = base64::decode(&manifest.hash)?;
        let filter = Filter::from_csv(manifest.serial, &self.input)?;
        let filter_hash = filter.hash()?;

        if manifest_hash != filter_hash {
            bail!(
                "manifest hash {} does not match filter hash {}",
                base64::encode(manifest_hash),
                base64::encode(filter_hash)
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
