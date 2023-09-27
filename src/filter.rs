use crate::{Descriptor, Result};
use bytes::{Buf, BufMut, BytesMut};
use helium_crypto::{PublicKey, Verify};
use serde::Serialize;
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

    pub fn from_descriptor(serial: u32, descriptor: &Descriptor) -> Result<Self> {
        let mut hashes: Vec<u64> = Vec::new();
        for node in &descriptor.nodes {
            hashes.push(public_key_hash(&node.key));
        }
        for edge in &descriptor.edges.edges {
            let source = &descriptor.edges.keys[edge.source as usize];
            let target = &descriptor.edges.keys[edge.target as usize];
            hashes.push(edge_hash(source, target));
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
        Ok(Sha256::digest(bytes).to_vec())
    }

    pub fn contains(&self, public_key: &PublicKey) -> bool {
        self.filter.contains(&public_key_hash(public_key))
    }

    pub fn contains_edge(&self, source: &PublicKey, target: &PublicKey) -> bool {
        self.filter.contains(&edge_hash(source, target))
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

fn public_key_hash(public_key: &PublicKey) -> u64 {
    let mut hasher = XxHash64::default();
    hasher.write(&public_key.to_vec());
    hasher.finish()
}

pub(crate) fn edge_order<'a>(a: &'a PublicKey, b: &'a PublicKey) -> (&'a PublicKey, &'a PublicKey) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

pub(crate) fn edge_hash(a: &PublicKey, b: &PublicKey) -> u64 {
    let (a, b) = edge_order(a, b);
    let mut hasher = XxHash64::default();
    hasher.write(&a.to_vec());
    hasher.write(&b.to_vec());
    hasher.finish()
}
