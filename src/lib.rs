pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bincode: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("json decode: {0}")]
    Json(#[from] serde_json::Error),
    #[error("csv decode: {0}")]
    Csv(#[from] csv::Error),
    #[error("proto decode: {0}")]
    Proto(#[from] prost::DecodeError),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("crypto: {0}")]
    Crypto(#[from] helium_crypto::Error),
    #[error("filter: {0}")]
    Filter(String),
}

impl Error {
    pub fn filter(err: &str) -> Self {
        Self::Filter(err.to_string())
    }
}

mod filter;
pub use filter::{edge_hash, edge_order, public_key_hash, Filter, FILTTER_VERSION};

mod manifest;
pub use manifest::{
    Manifest, ManifestAddres, ManifestSignature, ManifestSignatureVerify, PublicKeyManifest,
};

mod descriptor;
pub use descriptor::{Descriptor, Edges};

pub use xorf;

pub mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(d: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let sig_string = String::deserialize(d)?;
        if sig_string.is_empty() {
            return Ok(vec![]);
        }
        decode(&sig_string).map_err(|err| de::Error::custom(format!("invalid base64: \"{}\"", err)))
    }

    pub fn serialize<S>(data: &[u8], s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if data.is_empty() {
            return s.serialize_str("");
        }
        s.serialize_str(&encode(data))
    }

    pub fn encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    pub fn decode(str: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
        STANDARD.decode(str)
    }
}
