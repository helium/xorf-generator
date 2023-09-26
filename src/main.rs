use clap::Parser;
use xorf_generator::{cmd, Result};

#[derive(Debug, Parser)]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(name = env!("CARGO_BIN_NAME"))]
pub struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    Filter(cmd::filter::Cmd),
    Key(cmd::key::Cmd),
    Manifest(cmd::manifest::Cmd),
}

fn main() -> Result {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> Result {
    match cli.cmd {
        Cmd::Filter(cmd) => cmd.run(),
        Cmd::Key(cmd) => cmd.run(),
        Cmd::Manifest(cmd) => cmd.run(),
    }
}
