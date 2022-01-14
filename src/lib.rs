pub mod cmd;

pub type Result<T = ()> = anyhow::Result<T>;
pub type Error = anyhow::Error;

mod filter;
pub use filter::Filter;
