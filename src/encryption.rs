use aes::{Aes128, Aes192, Aes256};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, File};
use std::io::{Read, Write, Error};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes192Cbc = Cbc<Aes192, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Encrypt the provided file with AES and the specified key.
pub fn encrypt_file(file_path: &str, key: &[u8], output_path: &str) -> Result<(), Error> {
    // Ensure the key length matches one of the acceptable lengths
    match key.len() {
        16 => {}, // For AES128
        24 => {}, // For AES192
        32 => {}, // For AES256
        _ => return Err(Error::new(std::io::ErrorKind::InvalidInput, "Invalid key size")),
    }

    let data = fs::read(file_path)?;
    let encrypted_data = encrypt_data(&data, key)?;
    let mut output = File::create(output_path)?;
    output.write_all(&encrypted_data)?;
    Ok(())
}

/// Encrypt data with AES using the provided key.
fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let iv = generate_random_bytes(16); // 16 bytes IV is common for all AES variants
    let cipher = match key.len() {
        16 => Aes128Cbc::new_var(key, &iv),
        24 => Aes192Cbc::new_var(key, &iv),
        32 => Aes256Cbc::new_var(key, &iv),
        _ => return Err(Error::new(std::io::ErrorKind::InvalidInput, "Invalid key size")),
    }.map_err(|e| Error::new(std::io::ErrorKind::InvalidInput, e))?;
    
    let mut buffer = [iv.as_slice(), data].concat();
    cipher.encrypt(&mut buffer, data.len()).map_err(|e| Error::new(std::io::ErrorKind::InvalidInput, e))?;
    Ok(buffer)
}

/// Generate random bytes of the given length.
fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut buf = vec![0u8; length];
    rng.fill_bytes(&mut buf);
    buf
}

