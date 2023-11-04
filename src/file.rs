use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// Function to read a file and return its contents as bytes
pub fn read_file_as_bytes<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}
