use std::{fs, io, path::Path};

pub mod descriptor;
pub mod filter;
pub mod key;
pub mod manifest;

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
