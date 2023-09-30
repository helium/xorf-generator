use anyhow::Result;
use clap::Parser;
use xorf_generator::cmd;

#[derive(Debug, Parser)]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(name = env!("CARGO_BIN_NAME"))]
pub struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    Descriptor(cmd::descriptor::Cmd),
    Data(cmd::data::Cmd),
    Filter(cmd::filter::Cmd),
    Key(cmd::key::Cmd),
    Manifest(cmd::manifest::Cmd),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Data(cmd) => cmd.run(),
        Cmd::Descriptor(cmd) => cmd.run(),
        Cmd::Filter(cmd) => cmd.run(),
        Cmd::Key(cmd) => cmd.run(),
        Cmd::Manifest(cmd) => cmd.run(),
    }
}
