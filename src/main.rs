use structopt::StructOpt;
use xorf_generator::{cmd, Result};

#[derive(Debug, StructOpt)]
#[structopt(name = env!("CARGO_BIN_NAME"), version = env!("CARGO_PKG_VERSION"), about = "Gateway Manufacturing ")]
pub struct Cli {
    #[structopt(flatten)]
    cmd: Cmd,
}

#[derive(Debug, StructOpt)]
pub enum Cmd {
    Filter(Box<cmd::filter::Cmd>),
    Key(cmd::key::Cmd),
    Manifest(cmd::manifest::Cmd),
}

fn main() -> Result {
    let cli = Cli::from_args();
    run(cli)
}

fn run(cli: Cli) -> Result {
    match cli.cmd {
        Cmd::Filter(cmd) => cmd.run(),
        Cmd::Key(cmd) => cmd.run(),
        Cmd::Manifest(cmd) => cmd.run(),
    }
}
