use crate::cmd::open_output_file;
use anyhow::{Context, Result};
use std::{io::Write, path::PathBuf};
use xorf_generator::{Descriptor, Filter};

#[derive(clap::Args, Debug)]
pub struct Cmd {
    #[command(subcommand)]
    pub cmd: DataCommand,
}

impl Cmd {
    pub fn run(&self) -> Result<()> {
        self.cmd.run()
    }
}

/// Commands on binary data files
#[derive(clap::Subcommand, Debug)]
pub enum DataCommand {
    Generate(Generate),
}

impl DataCommand {
    pub fn run(&self) -> Result<()> {
        match self {
            Self::Generate(cmd) => cmd.run(),
        }
    }
}

/// Generate a descriptor file for the given csv file
#[derive(Debug, clap::Args)]
pub struct Generate {
    /// The input descriptor file to generate signing bytes for
    #[arg(default_value = "descriptor.bin.gz")]
    input: PathBuf,
    /// The file to write the resulting signing bytes to
    #[arg(default_value = "data.bin")]
    output: PathBuf,
    /// The serial number embedded in the signing bytes
    #[arg(long, short)]
    serial: u32,
}

impl Generate {
    pub fn run(&self) -> Result<()> {
        let mut data_file = open_output_file(&self.output, false)?;
        let descriptor = Descriptor::from_path(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;
        let filter = Filter::from_descriptor(self.serial, &descriptor)?;
        let signing_bytes = filter.to_signing_bytes()?;
        data_file.write_all(&signing_bytes)?;
        Ok(())
    }
}
