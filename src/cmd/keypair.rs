use crate::{
    cmd::{open_output_file, print_json},
    Result,
};
use helium_crypto::{KeyTag, Keypair};
use rand::rngs::OsRng;
use serde_json::json;
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};
use structopt::StructOpt;

/// Commands on keypairs
#[derive(StructOpt, Debug)]
pub enum Cmd {
    Create(Create),
    Info(Info),
}

impl Cmd {
    pub fn run(&self) -> Result {
        match self {
            Self::Create(cmd) => cmd.run(),
            Self::Info(cmd) => cmd.run(),
        }
    }
}

/// Create a keypair and write it go a given output file
#[derive(StructOpt, Debug)]
pub struct Create {
    /// Output file to write the generated keypair to
    output: PathBuf,
}

impl Create {
    fn run(&self) -> Result {
        let keypair = Keypair::generate(KeyTag::default(), &mut OsRng);
        let mut file = open_output_file(&self.output, true)?;
        file.write_all(&keypair.to_vec())?;

        print_keypair(&keypair)
    }
}

/// Displays key information for a given keypair
#[derive(StructOpt, Debug)]
pub struct Info {
    /// Input to read
    input: PathBuf,
}

impl Info {
    pub fn run(&self) -> Result {
        let mut file = File::open(&self.input)?;
        let mut keydata = vec![];
        file.read_to_end(&mut keydata)?;
        let keypair = Keypair::try_from(keydata.as_ref())?;

        print_keypair(&keypair)
    }
}

fn print_keypair(keypair: &Keypair) -> Result {
    let json = json!({
        "address": keypair.public_key().to_string()
    });
    print_json(&json)
}
