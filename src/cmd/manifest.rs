use crate::{cmd::open_output_file, filter::Filter, Result};
use serde_json::json;
use std::{io::Write, path::PathBuf};
use structopt::StructOpt;

/// Commands on manifests
#[derive(StructOpt, Debug)]
pub enum Cmd {
    Generate(Generate),
}

impl Cmd {
    pub fn run(&self) -> Result {
        match self {
            Self::Generate(cmd) => cmd.run(),
        }
    }
}

/// Generate a manifest for a given list of hotspots
///
/// This takes a a filename for a list of hotspots and generates a manifest file
/// that can be used to add signatures to.
#[derive(Debug, StructOpt)]

pub struct Generate {
    /// The input file to generate a filter for
    #[structopt(long, short)]
    input: PathBuf,

    /// The file to write the resulting manifest file to
    #[structopt(long, short, default_value = "manifest.json")]
    manifest: PathBuf,

    /// The file to write the filter signing data bytes to
    #[structopt(long, short, default_value = "data.bin")]
    data: PathBuf,

    /// Whether to force overwrite an existing output file
    #[structopt(long, short)]
    force: bool,

    /// The serial number for the filter
    #[structopt(long, short)]
    serial: u32,
}

impl Generate {
    pub fn run(&self) -> Result {
        let filter = Filter::from_csv(self.serial, &self.input)?;
        let mut data_file = open_output_file(&self.data, !self.force)?;
        data_file.write_all(&filter.signing_bytes()?)?;

        let mut manifest_file = open_output_file(&self.manifest, !self.force)?;
        let json = json!({
            "data": self.data,
            "signatures": [],
        });
        serde_json::to_writer_pretty(&mut manifest_file, &json)?;
        Ok(())
    }
}
