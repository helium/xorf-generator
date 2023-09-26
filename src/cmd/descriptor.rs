use crate::{cmd::open_output_file, Descriptor, Result};
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct Cmd {
    #[command(subcommand)]
    pub cmd: DescriptorCommand,
}

impl Cmd {
    pub fn run(&self) -> Result {
        self.cmd.run()
    }
}

/// Commands on filters
#[derive(clap::Subcommand, Debug)]
pub enum DescriptorCommand {
    Generate(Generate),
}

impl DescriptorCommand {
    pub fn run(&self) -> Result {
        match self {
            Self::Generate(cmd) => cmd.run(),
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
    pub fn run(&self) -> Result {
        let descriptor = Descriptor::from_csv(&self.input)?;
        let file = open_output_file(&self.output, false)?;
        serde_json::to_writer(file, &descriptor)?;
        Ok(())
    }
}
