use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;

/// Generates an openssl ErrorStack with a custom message
fn create_error(message: &str) -> ErrorStack {
    // create a new ErrorStack with a custom error message
    let mut error_stack = ErrorStack::new();
    // add the message to this error stack
    error_stack.add(0, message);
    // return the error stack
    error_stack
}

/// Accepts a byte slice of data to be encrypted, a key of length 16 to perform the encryption
/// with, and an initialization vector of length 16. Returns an Ok result containing the encrypted
/// data if all goes well, otherwise returns an error
pub fn encrypt_aes_128(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    // ensure that key and IV lengths are valid for AES-128-CBC
    let iv_len_aes_128 = 16;    // the initialization vector should be 16 bytes
    let key_len_aes_128 = 16;   // the key length should be 16 bytes for AES128
    if key.len() != 16 || iv.len() != 16 {
        return Err(create_error("Invalid key length or iv length"));
    }
    
    // choose the AES-128-CBC cipher.
    let cipher = Cipher::aes_128_cbc();
    
    // Create a Crypter in encryption mode
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;

    // Encrypt and finalize data
    let mut encrypted = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut encrypted)?;
    let rest = crypter.finalize(&mut encrypted[count..])?;
    encrypted.truncate(count + rest); // remove any padding bytes
    
    Ok(encrypted)
}

/// Accepts a byte slice of data to be encrypted, a key of length 24 to perform the encryption
/// with, and an initialization vector of length 16. Returns an Ok result containing the encrypted
/// data if all goes well, otherwise returns an error
pub fn encrypt_aes_192(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    // ensure that key and IV lengths are valid for AES-192-CBC
    let iv_len_aes_192 = 16;    // the initialization vector should be 16 bytes
    let key_len_aes_192 = 24;   // the key length should be 16 bytes for AES192
    if key.len() != key_len_aes_192 || iv.len() != iv_len_aes_192 {
        return Err(create_error("Invalid key length or iv length"));
    }
    
    // choose the AES-192-CBC cipher.
    let cipher = Cipher::aes_192_cbc();
    
    // Create a Crypter in encryption mode
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;

    // Encrypt and finalize data
    let mut encrypted = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut encrypted)?;
    let rest = crypter.finalize(&mut encrypted[count..])?;
    encrypted.truncate(count + rest); // remove any padding bytes
    
    Ok(encrypted)
}

/// Accepts a byte slice of data to be encrypted, a key of length 32 to perform the encryption
/// with, and an initialization vector of length 16. Returns an Ok result containing the encrypted
/// data if all goes well, otherwise returns an error
pub fn encrypt_aes_256(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    // ensure that key and IV lengths are valid for AES-256-CBC
    let iv_len_aes_256 = 16;    // the initialization vector should be 16 bytes
    let key_len_aes_256 = 32;   // the key length should be 16 bytes for AES256
    if key.len() != key_len_aes_256 || iv.len() != iv_len_aes_256 {
        return Err(create_error("Invalid key length or iv length"));
    }
    
    // choose the AES-256-CBC cipher.
    let cipher = Cipher::aes_256_cbc();
    
    // Create a Crypter in encryption mode
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;

    // Encrypt and finalize data
    let mut encrypted = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut encrypted)?;
    let rest = crypter.finalize(&mut encrypted[count..])?;
    encrypted.truncate(count + rest); // remove any padding bytes
    
    Ok(encrypted)
}
