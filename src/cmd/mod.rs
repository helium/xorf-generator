use std::{fs, io, path::Path};

pub mod filter;
pub mod manifest;
pub mod public_key;

pub fn print_json<T: ?Sized + serde::Serialize>(value: &T) -> crate::Result {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn open_output_file(filename: &Path, create_new: bool) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(create_new)
        .truncate(true)
        .open(filename)
}
