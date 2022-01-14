use crate::{
    cmd::{open_output_file, print_json},
    Filter, Result,
};
use helium_crypto::{Keypair, PublicKey};
use serde::Deserialize;
use serde_json::json;
use std::{
    convert::TryFrom,
    fs::File,
    hash::Hasher,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use structopt::StructOpt;
use twox_hash::XxHash64;
use xorf::BinaryFuse32;

/// Commands on filters
#[derive(StructOpt, Debug)]
pub enum Cmd {
    Generate(Generate),
    Contains(Contains),
    Verify(Verify),
}

impl Cmd {
    pub fn run(&self) -> Result {
        match self {
            Self::Generate(cmd) => cmd.run(),
            Self::Contains(cmd) => cmd.run(),
            Self::Verify(cmd) => cmd.run(),
        }
    }
}

/// Check if a given filter file contains a given public key
#[derive(StructOpt, Debug)]
pub struct Contains {
    /// The input file to generate a filter for
    #[structopt(long, short)]
    input: PathBuf,
    /// The public key to check
    #[structopt(long)]
    key: PublicKey,
}

impl Contains {
    pub fn run(&self) -> Result {
        let filter = read_filter(&self.input)?;
        let hash = public_key_hash(&self.key);
        let json = json!({
            "address":  self.key.to_string(),
            "in_filter": filter.contains(&hash),
        });
        print_json(&json)
    }
}

/// Verifies a given filter against the given public key
#[derive(StructOpt, Debug)]
pub struct Verify {
    /// The input file to verify the signature for
    #[structopt(long, short)]
    input: PathBuf,
    /// The public key to use for verification
    #[structopt(long)]
    key: PublicKey,
}

impl Verify {
    pub fn run(&self) -> Result {
        let filter = read_filter(&self.input)?;
        filter.verify(&self.key)?;
        let json = json!({
            "address":  self.key.to_string(),
            "verify": true,
        });
        print_json(&json)
    }
}

/// Generate a binary filter for the hotspots listed in the given file.
///
/// This converts a csv file of given hotspot public keys and generates a binary
/// xor filter (a binary fuse with 32 bit fingerprints to be precise). If a
/// signing key is given on the command line the resulting binary is signed and
/// the signature included in the resulting output.
#[derive(Debug, StructOpt)]
pub struct Generate {
    /// The input file to generate a filter for
    #[structopt(long, short)]
    input: PathBuf,
    /// The file to write the resulting binary filter to
    #[structopt(long, short)]
    output: PathBuf,

    /// The serial number of the resulting filter
    #[structopt(long)]
    serial: u32,

    /// The path a signing key to use
    #[structopt(long)]
    sign: PathBuf,
}

#[derive(Debug, Deserialize)]
struct CsvRow {
    public_key: PublicKey,
}

impl Generate {
    pub fn run(&self) -> Result {
        // Read public keys
        let mut hashes: Vec<u64> = Vec::new();

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(File::open(&self.input)?);
        for record in rdr.deserialize() {
            let row: CsvRow = record?;
            hashes.push(public_key_hash(&row.public_key));
        }
        hashes.sort_unstable();
        hashes.dedup();
        let xor_filter = BinaryFuse32::try_from(&hashes).expect("filter");
        let keypair = read_keypair(&self.sign)?;
        let filter = Filter::new(&keypair, self.serial, xor_filter)?;
        let filter_bytes = filter.to_bytes()?;
        let mut file = open_output_file(&self.output, true)?;
        file.write_all(&filter_bytes)?;
        Ok(())
    }
}

fn public_key_hash(public_key: &PublicKey) -> u64 {
    let mut hasher = XxHash64::default();
    hasher.write(&public_key.to_vec());
    hasher.finish()
}

fn read_keypair(path: &Path) -> Result<Keypair> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let keypair = Keypair::try_from(data.as_ref())?;
    Ok(keypair)
}

fn read_filter(path: &Path) -> Result<Filter> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let filter = Filter::from_bytes(&data)?;
    Ok(filter)
}
