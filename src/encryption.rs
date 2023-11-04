use aes_gcm::{Aes256Gcm, Aes128Gcm, Aes192Gcm, NewAead};
use aes_gcm::aead::{Aead, KeyInit};
use aead::{Aead, NewAead};
use aes::{Aes128, Aes192, Aes256};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use rand::{thread_rng, RngCore, rngs::OsRng};
use pbkdf2::pbkdf2;
use aes_gcm::aead::generic_array::GenericArray;

type HmacSha256 = Hmac<Sha256>;
const PBKDF2_ITERATIONS: u32 = 100_000;

// Function to convert a String into a byte slice
pub fn string_to_password_bytes(password: String) -> Vec<u8> {
    password.into_bytes()
}

pub fn aes_encrypt(plaindata: &[u8], key: &[u8]) -> Vec<u8> {
    // Choose the appropriate AES variant based on key length and create a nonce
    let nonce = GenericArray::from_slice(b"unique nonce"); // NOTE: In real applications, use a unique nonce for each message

    let cipher = match key.len() {
        16 => Aes128Gcm::new(GenericArray::from_slice(key)),
        24 => Aes192Gcm::new(GenericArray::from_slice(key)),
        32 => Aes256Gcm::new(GenericArray::from_slice(key)),
        _ => panic!("Invalid key size"),
    };

    // Encrypt the plaintext, handling the result in case of an error
    cipher.encrypt(nonce, plaindata).expect("encryption failure")
}

pub fn aes_decrypt(cipherdata: &[u8], key: &[u8]) -> Vec<u8> {
    // Choose the appropriate AES variant based on key length and create a nonce
    let nonce = GenericArray::from_slice(b"unique nonce"); // NOTE: The nonce should be the same as the one used during encryption

    let cipher = match key.len() {
        16 => Aes128Gcm::new(GenericArray::from_slice(key)),
        24 => Aes192Gcm::new(GenericArray::from_slice(key)),
        32 => Aes256Gcm::new(GenericArray::from_slice(key)),
        _ => panic!("Invalid key size"),
    };

    // Decrypt the ciphertext, handling the result in case of an error
    cipher.decrypt(nonce, cipherdata).expect("decryption failure")
}

pub fn derive_key_iv(password_str: String, key_size: usize) -> (Vec<u8>, Vec<u8>) {
    let password = password_str.into_bytes();
    let mut rng = OsRng;
    let mut salt = vec![0u8; 16];
    rng.fill_bytes(&mut salt);

    let mut key = vec![0u8; key_size];
    pbkdf2::<HmacSha256>(&password, &salt, PBKDF2_ITERATIONS, &mut key);

    (key, salt) // In AES-GCM, the IV is commonly known as a nonce, and it is recommended to be unique for every operation.
}
