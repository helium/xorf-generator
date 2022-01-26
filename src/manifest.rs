use crate::Result;
use helium_crypto::{multihash, multisig, Network, PublicKey, Verify};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader, ops::Deref, path::Path};

#[derive(Deserialize, Serialize, Debug)]
pub struct Manifest {
    pub(crate) serial: u32,
    pub(crate) hash: String,
    pub(crate) signatures: Vec<ManifestSignature>,
}

impl Manifest {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let manifest = serde_json::from_reader(BufReader::new(file))?;
        Ok(manifest)
    }

    pub fn sign(&self, key_manifest: &PublicKeyManifest) -> Result<Vec<u8>> {
        let public_key = key_manifest.public_key()?;
        let keys = key_manifest.public_keys();
        let signatures: Vec<(PublicKey, Vec<u8>)> = self
            .signatures
            .iter()
            .filter(|ms| !ms.signature.is_empty())
            .map(|ms| (ms.address.0.clone(), ms.signature.clone()))
            .collect();

        let signature = multisig::Signature::new(&public_key, &keys, &signatures)?;
        Ok(signature.to_vec())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyManifest {
    pub(crate) public_keys: Vec<ManifestAddres>,
    pub(crate) required: u8,
}

impl PublicKeyManifest {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let manifest = serde_json::from_reader(BufReader::new(file))?;
        Ok(manifest)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let public_keys: Vec<PublicKey> =
            self.public_keys.iter().map(|k| k.deref().clone()).collect();
        let public_key = multisig::PublicKey::generate(
            Network::MainNet,
            self.required,
            multihash::Code::Sha2_256,
            &public_keys,
        )?;
        Ok(public_key)
    }

    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.public_keys.iter().map(|addr| addr.0.clone()).collect()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ManifestSignature {
    address: ManifestAddres,
    #[serde(with = "base64")]
    signature: Vec<u8>,
}

impl ManifestSignature {
    pub fn verify(&self, msg: &[u8]) -> ManifestSignatureVerify {
        ManifestSignatureVerify {
            signature: self.clone(),
            verified: self.address.verify(msg, &self.signature).is_ok(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ManifestAddres(#[serde(with = "public_key")] PublicKey);

impl Deref for ManifestAddres {
    type Target = PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ManifestAddres> for PublicKey {
    fn from(val: ManifestAddres) -> Self {
        val.0
    }
}

impl From<&ManifestAddres> for ManifestSignature {
    fn from(val: &ManifestAddres) -> Self {
        Self {
            address: val.clone(),
            signature: vec![],
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ManifestSignatureVerify {
    #[serde(flatten)]
    signature: ManifestSignature,
    verified: bool,
}

mod public_key {
    use helium_crypto::PublicKey;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(d: D) -> std::result::Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key_string = String::deserialize(d)?;
        match key_string.parse() {
            Ok(key) => Ok(key),
            Err(err) => Err(de::Error::custom(format!(
                "invalid public key: \"{}\"",
                err
            ))),
        }
    }

    pub fn serialize<S>(public_key: &PublicKey, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&public_key.to_string())
    }
}

mod base64 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(d: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let sig_string = String::deserialize(d)?;
        if sig_string.is_empty() {
            return Ok(vec![]);
        }
        base64::decode(sig_string)
            .map_err(|err| de::Error::custom(format!("invalid base64: \"{}\"", err)))
    }

    pub fn serialize<S>(data: &[u8], s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if data.is_empty() {
            return s.serialize_str("");
        }
        s.serialize_str(&base64::encode(&data))
    }
}
