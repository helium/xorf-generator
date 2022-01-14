use crate::Result;
use bytes::{Buf, BufMut, BytesMut};
use helium_crypto::{Keypair, PublicKey, Sign, Verify};
use serde::Serialize;
use xorf::{BinaryFuse32, Filter as XorFilter};

#[derive(Serialize)]
pub struct Filter {
    version: u8,
    signature: Vec<u8>,
    serial: u32,
    #[serde(skip_serializing)]
    filter: BinaryFuse32,
}

impl Filter {
    pub fn new(keypair: &Keypair, serial: u32, filter: BinaryFuse32) -> Result<Self> {
        let msg = Self::signing_bytes(serial, &filter)?;
        let signature = keypair.sign(&msg)?;
        Ok(Self {
            version: 1,
            serial,
            signature,
            filter,
        })
    }

    pub fn contains(&self, hash: &u64) -> bool {
        self.filter.contains(hash)
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result {
        let msg = Self::signing_bytes(self.serial, &self.filter)?;
        public_key.verify(&msg, &self.signature)?;
        Ok(())
    }

    fn signing_bytes(serial: u32, filter: &BinaryFuse32) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        buf.put_u32_le(serial);
        let filter_bin = bincode::serialize(filter)?;
        buf.extend_from_slice(&filter_bin);
        Ok(buf.to_vec())
    }

    pub fn from_bytes(data: impl AsRef<[u8]>) -> Result<Self> {
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
        buf.extend_from_slice(&Self::signing_bytes(self.serial, &self.filter)?);
        Ok(buf.to_vec())
    }
}
