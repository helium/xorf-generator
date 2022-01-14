use std::{fs, io, path::Path};

pub mod filter;
pub mod keypair;

pub fn print_json<T: ?Sized + serde::Serialize>(value: &T) -> crate::Result {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn open_output_file(filename: &Path, create: bool) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(create)
        .create_new(create)
        .truncate(true)
        .open(filename)
}
