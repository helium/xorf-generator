use crate::cmd::{open_output_file, print_json};
use anyhow::{Context, Result};
use helium_crypto::{PublicKey, PublicKeyBinary};
use serde_json::json;
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
    Info(Info),
}

impl DescriptorCommand {
    pub fn run(&self) -> Result<()> {
        match self {
            Self::Generate(cmd) => cmd.run(),
            Self::CountEdges(cmd) => cmd.run(),
            Self::Find(cmd) => cmd.run(),
            Self::Info(cmd) => cmd.run(),
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

/// Check if a given descriptor file contains a given public key as a full node
/// or in any of the contained edges
#[derive(clap::Args, Debug)]
pub struct Find {
    /// The descriptor file to check for membership
    #[arg(long, short, default_value = "descriptor.bin")]
    input: PathBuf,
    /// The public key to check
    key: PublicKey,
}

impl Find {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_path(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;

        let mut json = json!({});
        let key: PublicKeyBinary = self.key.clone().into();
        if let Some(node) = descriptor.find_node(&key) {
            json["node"] = serde_json::to_value(node)?;
        }
        let edges = descriptor.find_edges(&key);
        if !edges.is_empty() {
            json["edges"] = serde_json::to_value(edges)?;
        }
        print_json(&json)
    }
}

/// Print basic information about a descriptor file
#[derive(clap::Args, Debug)]
pub struct Info {
    /// The descriptor file to check for membership
    #[arg(long, short, default_value = "descriptor.bin")]
    input: PathBuf,
}

impl Info {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_path(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;

        let node_count = descriptor.nodes.len();
        let (key_count, edge_count) = descriptor
            .edges
            .map(|edges| (edges.keys.len(), edges.edges.len()))
            .unwrap_or((0, 0));
        let json = json!({
            "nodes": node_count,
            "edges": {
                "edges": edge_count,
                "keys": key_count,
            }
        });
        print_json(&json)
    }
}
