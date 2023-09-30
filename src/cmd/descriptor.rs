use crate::{
    cmd::{open_output_file, print_json},
    Descriptor,
};
use anyhow::{Context, Result};
use helium_crypto::PublicKey;
use std::{collections::HashMap, path::PathBuf};

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
    #[arg(default_value = "descriptor.json")]
    output: PathBuf,
}

impl Generate {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_csv(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;
        let file = open_output_file(&self.output, false)?;
        serde_json::to_writer(file, &descriptor)?;
        Ok(())
    }
}

#[derive(Debug, clap::Args)]
pub struct CountEdges {
    /// The input descriptor file to generate signing bytes for
    #[arg(default_value = "descriptor.json")]
    input: PathBuf,
    /// The file to write the resulting signing bytes to
    #[arg(default_value = "edgecount.csv")]
    output: PathBuf,
}

impl CountEdges {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_json(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;
        let mut counts: HashMap<&PublicKey, i32> = HashMap::new();
        for node in &descriptor.nodes {
            counts.insert(&node.key, -1); // -1 denotes all edges
        }
        for edge in &descriptor.edges.edges {
            let source = &descriptor.edges.keys[edge.source as usize];
            let target = &descriptor.edges.keys[edge.target as usize];
            counts
                .entry(source)
                .and_modify(|counter| *counter += 1)
                .or_insert(1);
            counts
                .entry(target)
                .and_modify(|counter| *counter += 1)
                .or_insert(1);
        }

        print_json(&counts)
    }
}
