use crate::{base64_serde, Descriptor, Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use helium_crypto::{PublicKey, PublicKeyBinary, Verify};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, hash::Hasher, io::Read, path::Path};
use twox_hash::XxHash64;
use xorf::{BinaryFuse32, Filter as _, Xor32};

pub const FILTTER_VERSION: u8 = 2;

#[derive(Serialize)]
pub struct Filter {
    pub version: u8,
    #[serde(with = "base64_serde")]
    pub signature: Vec<u8>,
    pub serial: u32,
    #[serde(skip_serializing)]
    pub filter: FilterData,
}

#[derive(Serialize, Deserialize)]
pub enum FilterData {
    Xor(Xor32),
    BFuse(BinaryFuse32),
}

impl From<Xor32> for FilterData {
    fn from(filter: Xor32) -> Self {
        Self::Xor(filter)
    }
}

impl From<BinaryFuse32> for FilterData {
    fn from(filter: BinaryFuse32) -> Self {
        Self::BFuse(filter)
    }
}

impl FilterData {
    pub fn contains(&self, hash: &u64) -> bool {
        match self {
            Self::Xor(filter) => filter.contains(hash),
            Self::BFuse(filter) => filter.contains(hash),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Xor(filter) => filter.len(),
            Self::BFuse(filter) => filter.len(),
        }
    }

    pub fn to_signing_bytes(&self, version: u8) -> Result<Vec<u8>> {
        match version {
            1 => {
                if let Self::Xor(data) = self {
                    Ok(bincode::serialize(data)?)
                } else {
                    Err(Error::filter("Unsupported filter version"))
                }
            }
            2 => Ok(bincode::serialize(self)?),
            _ => Err(Error::filter("Unsupported filter version")),
        }
    }

    pub fn from_signing_bytes(data: &[u8], version: u8) -> Result<Self> {
        match version {
            1 => {
                let filter: Xor32 = bincode::deserialize(data)?;
                Ok(Self::Xor(filter))
            }
            2 => {
                let filter: Self = bincode::deserialize(data)?;
                Ok(filter)
            }
            _ => Err(Error::filter("Unsupported filter version")),
        }
    }
}

impl Filter {
    pub fn new<F: Into<FilterData>>(serial: u32, filter: F) -> Result<Self> {
        let filter = filter.into();
        Ok(Self {
            version: FILTTER_VERSION,
            serial,
            signature: vec![],
            filter,
        })
    }

    pub fn len(&self) -> usize {
        self.filter.len()
    }

    pub fn is_empty(&self) -> bool {
        self.filter.len() == 0
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
        let filter = Xor32::from(&hashes);
        Filter::new(serial, filter)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let filter = Self::from_bytes(&data)?;
        Ok(filter)
    }

    pub fn from_signing_path(path: &Path, version: u8) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let filter = Self::from_signing_bytes(&data, version)?;
        Ok(filter)
    }

    pub fn hash(&self) -> Result<Vec<u8>> {
        let bytes = &self.to_signing_bytes()?;
        Ok(Sha256::digest(bytes).to_vec())
    }

    pub fn contains(&self, public_key: &PublicKeyBinary) -> bool {
        self.filter.contains(&public_key_hash(public_key))
    }

    pub fn contains_edge(&self, source: &PublicKeyBinary, target: &PublicKeyBinary) -> bool {
        self.filter.contains(&edge_hash(source, target))
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result {
        let msg = self.to_signing_bytes()?;
        public_key.verify(&msg, &self.signature)?;
        Ok(())
    }

    pub fn to_signing_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_u32_le(self.serial);
        let filter_data = self.filter.to_signing_bytes(self.version)?;
        buf.extend_from_slice(&filter_data);
        Ok(buf.to_vec())
    }

    pub fn from_signing_bytes(data: &[u8], version: u8) -> Result<Self> {
        let mut buf = data;
        let serial = buf.get_u32_le();
        let filter_data = FilterData::from_signing_bytes(buf, version)?;
        Ok(Self {
            version,
            signature: vec![],
            serial,
            filter: filter_data,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut buf = data;
        let version = buf.get_u8();
        let signature_len = buf.get_u16_le() as usize;
        let signature = buf.copy_to_bytes(signature_len).to_vec();
        let mut filter = Self::from_signing_bytes(buf, version)?;
        filter.signature = signature;
        filter.version = version;
        Ok(filter)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.version);
        buf.put_u16_le(self.signature.len() as u16);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.to_signing_bytes()?);
        Ok(buf.to_vec())
    }
}

pub fn public_key_hash(public_key: &PublicKeyBinary) -> u64 {
    let mut hasher = XxHash64::default();
    hasher.write(public_key.as_ref());
    hasher.finish()
}

pub fn edge_order<'a>(
    a: &'a PublicKeyBinary,
    b: &'a PublicKeyBinary,
) -> (&'a PublicKeyBinary, &'a PublicKeyBinary) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

pub fn edge_hash(a: &PublicKeyBinary, b: &PublicKeyBinary) -> u64 {
    let (a, b) = edge_order(a, b);
    let mut hasher = XxHash64::default();
    hasher.write(a.as_ref());
    hasher.write(b.as_ref());
    hasher.finish()
}
