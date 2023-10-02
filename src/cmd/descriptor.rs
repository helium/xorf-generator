use crate::cmd::open_output_file;
use anyhow::{Context, Result};
use std::{collections::HashMap, path::PathBuf};
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

#[derive(Debug, clap::Args)]
pub struct CountEdges {
    /// The input descriptor file to generate signing bytes for
    #[arg(default_value = "descriptor.bin")]
    input: PathBuf,
    /// The file to write the resulting edgecounts to
    #[arg(default_value = "edgecount.json")]
    output: PathBuf,
}

impl CountEdges {
    pub fn run(&self) -> Result<()> {
        let descriptor = Descriptor::from_path(&self.input)
            .context(format!("reading descriptor {}", self.input.display()))?;
        let mut counts: HashMap<&Vec<u8>, i32> = HashMap::new();
        for node in &descriptor.nodes {
            counts.insert(&node.key, -1); // -1 denotes all edges
        }
        if let Some(edges) = &descriptor.edges {
            for edge in &edges.edges {
                let source = &edges.keys[edge.source as usize];
                let target = &edges.keys[edge.target as usize];
                counts
                    .entry(source)
                    .and_modify(|counter| *counter += 1)
                    .or_insert(1);
                counts
                    .entry(target)
                    .and_modify(|counter| *counter += 1)
                    .or_insert(1);
            }
        }

        let file = open_output_file(&self.output, false)?;
        serde_json::to_writer_pretty(file, &counts)?;
        Ok(())
    }
}
