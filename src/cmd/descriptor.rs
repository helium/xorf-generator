use crate::cmd::open_output_file;
use anyhow::{Context, Result};
use std::path::PathBuf;
use xorf_generator::Descriptor;

#[derive(clap::Args, Debug)]
pub struct Cmd {
    #[command(subcommand)]
    pub cmd: DescriptorCommand,
}

impl Cmd {
    pub fn run(&self) -> Result<()> {
        self.cmd.run()
    }
}

/// Commands on filters
#[derive(clap::Subcommand, Debug)]
pub enum DescriptorCommand {
    Generate(Generate),
    CountEdges(CountEdges),
}

impl DescriptorCommand {
    pub fn run(&self) -> Result<()> {
        match self {
            Self::Generate(cmd) => cmd.run(),
            Self::CountEdges(cmd) => cmd.run(),
        }
    }
}

/// Generate a descriptor file for the given csv file
#[derive(Debug, clap::Args)]
pub struct Generate {
    /// The input csv file to generate a descriptor for
    input: PathBuf,
    /// The file to write the resulting descriptor file to
    #[arg(default_value = "descriptor.bin")]
    output: PathBuf,
}

impl Generate {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_csv(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;
        descriptor.to_path(open_output_file(&self.output, false)?)?;
        Ok(())
    }
}

/// Generate a json file with the number of edges per public key in a descriptor
///
/// A full hotspot is listed with edge count -1
#[derive(Debug, clap::Args)]
pub struct CountEdges {
    /// The input descriptor file to generate signing bytes for
    #[arg(default_value = "descriptor.bin")]
    input: PathBuf,
    /// The file to write the resulting edge counts to
    #[arg(default_value = "edge_counts.json")]
    output: PathBuf,
}

impl CountEdges {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_path(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;
        let counts = descriptor.edge_counts();
        let file = open_output_file(&self.output, false)?;
        serde_json::to_writer_pretty(file, &counts)?;
        Ok(())
    }
}
