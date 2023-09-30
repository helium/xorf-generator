use std::{fs, path::Path};

pub mod data;
pub mod descriptor;
pub mod filter;
pub mod key;
pub mod manifest;

pub fn print_json<T: ?Sized + serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn open_output_file(filename: &Path, create_new: bool) -> anyhow::Result<fs::File> {
    use anyhow::Context;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(create_new)
        .truncate(true)
        .open(filename)
        .context(format!("opening output file {}", filename.display()))
}
