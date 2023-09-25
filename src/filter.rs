use crate::Result;
use bytes::{Buf, BufMut, BytesMut};
use helium_crypto::{PublicKey, Verify};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, hash::Hasher, io::Read, path::Path};
use twox_hash::XxHash64;
use xorf::{Filter as XorFilter, Xor32};

pub const VERSION: u8 = 1;

#[derive(Serialize)]
pub struct Filter {
    pub(crate) version: u8,
    pub(crate) signature: Vec<u8>,
    pub(crate) serial: u32,
    #[serde(skip_serializing)]
    pub(crate) filter: Xor32,
}

impl Filter {
    pub fn new(serial: u32, filter: Xor32) -> Result<Self> {
        Ok(Self {
            version: VERSION,
            serial,
            signature: vec![],
            filter,
        })
    }

    pub fn from_csv<P: AsRef<Path>>(serial: u32, path: P) -> Result<Self> {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(File::open(path)?);
        let mut hashes: Vec<u64> = Vec::new();
        for record in rdr.deserialize() {
            let row: CsvRow = record?;
            if let Some(second_edge_key) = row.second_edge_key {
                // edge key order needs to be sorted to be deterministic
                // irregardless of edge direction
                let mut a = [row.public_key, second_edge_key];
                a.sort();
                hashes.push(edge_hash(&a[0], &a[1]));
            } else {
                hashes.push(public_key_hash(&row.public_key));
            }
        }
        hashes.sort_unstable();
        hashes.dedup();
        let xor_filter = Xor32::try_from(&hashes)?;
        Filter::new(serial, xor_filter)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let filter = Filter::from_bytes(&data)?;
        Ok(filter)
    }

    pub fn hash(&self) -> Result<Vec<u8>> {
        let bytes = self.signing_bytes()?;
        Ok(Sha256::digest(&bytes).to_vec())
    }

    pub fn contains(&self, public_key: &PublicKey) -> bool {
        self.filter.contains(&public_key_hash(public_key))
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result {
        let msg = self.signing_bytes()?;
        public_key.verify(&msg, &self.signature)?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_u32_le(self.serial);
        let filter_bin = bincode::serialize(&self.filter)?;
        buf.extend_from_slice(&filter_bin);
        Ok(buf.to_vec())
    }

    pub fn from_bytes<D: AsRef<[u8]>>(data: D) -> Result<Self> {
        let mut buf = data.as_ref();
        let version = buf.get_u8();
        let signature_len = buf.get_u16_le() as usize;
        let signature = buf.copy_to_bytes(signature_len).to_vec();
        let serial = buf.get_u32_le();
        let filter = bincode::deserialize(buf)?;
        Ok(Self {
            version,
            signature,
            serial,
            filter,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.version);
        buf.put_u16_le(self.signature.len() as u16);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.signing_bytes()?);
        Ok(buf.to_vec())
    }
}

#[derive(Debug, Deserialize)]
struct CsvRow {
    public_key: PublicKey,
    second_edge_key: Option<PublicKey>,
}

fn public_key_hash(public_key: &PublicKey) -> u64 {
    let mut hasher = XxHash64::default();
    hasher.write(&public_key.to_vec());
    hasher.finish()
}

fn edge_hash(a: &PublicKey, b: &PublicKey) -> u64 {
    let mut hasher = XxHash64::default();
    hasher.write(&a.to_vec());
    hasher.write(&b.to_vec());
    hasher.finish()
}
