use crate::cmd::{open_output_file, print_json};
use anyhow::{Context, Result};
use helium_crypto::PublicKey;
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
    Find(Box<Find>),
}

impl DescriptorCommand {
    pub fn run(&self) -> Result<()> {
        match self {
            Self::Generate(cmd) => cmd.run(),
            Self::CountEdges(cmd) => cmd.run(),
            Self::Find(cmd) => cmd.run(),
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

/// Check if a given descriptor file contains a given public key or edge.
#[derive(clap::Args, Debug)]
pub struct Find {
    /// The descriptor file to check for membership
    #[arg(long, short, default_value = "descriptor.bin")]
    input: PathBuf,
    /// The public key to check
    key: PublicKey,
    /// The publc key of the target of an edge to check
    target: Option<PublicKey>,
}

impl Find {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_path(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;
        let source = self.key.clone().into();
        let json = if let Some(target) = self.target.clone() {
            let edge = descriptor
                .find_edge(&source, &target.into())
                .ok_or_else(|| anyhow::anyhow!("edge not found"))?;
            serde_json::to_value(edge)?
        } else {
            let node = descriptor
                .find_node(&source)
                .ok_or_else(|| anyhow::anyhow!("node not found"))?;
            serde_json::to_value(node)?
        };
        print_json(&json)
    }
}
