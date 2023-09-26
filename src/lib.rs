pub mod cmd;

pub type Result<T = ()> = anyhow::Result<T>;
pub type Error = anyhow::Error;

mod filter;
pub use filter::Filter;

mod manifest;
pub use manifest::{Manifest, PublicKeyManifest};

mod descriptor;
pub use descriptor::{Descriptor, Edges};
