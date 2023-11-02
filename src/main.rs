#![feature(string_remove_matches)]    

use std::io;
use std::io::Write;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use block_modes::{blockmode, cbc};
use block_modes::block_padding::Pkcs7;
use rand::{rngs::OsRng, RngCore};

pub mod input;
pub mod encryption;

use input::*;
use encryption::*;

fn main() {
    let file_prompt = String::from("What file to encrypt?");
    let file = prompt(Some(file_prompt), None).unwrap();

    let output_prompt = String::from("Enter output destination");
    let output = prompt(Some(output_prompt), None).unwrap();

    let password_prompt = String::from("Enter a password");
    let password = prompt(Some(password_prompt), None).unwrap();
    
    let aes_prompt = String::from("Enter AES variant [128|192|256]");
    let aes = prompt(Some(aes_prompt), None).unwrap();
   
    let key_size = match aes.as_str() {
        "128" => 16,
        "192" => 24,
        "256" => 32,
        _ => {
            writeln!(io::stderr(), "Invalid AES variant.").unwrap();
            std::process::exit(1);
        }
    };

    let key = derive_key_from_password(&password, key_size).unwrap();

    encrypt_file(&file, &key, &output);
    
    println!("Successfully encrypted file. Output placed at {}", output);
}

fn derive_key_from_password(password: &str, key_size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let mut salt = vec![0u8; 16]; // 128-bit salt
    rng.fill_bytes(&mut salt);

    let mut key = vec![0u8; key_size];
    const PBKDF2_ITERATIONS: u32 = 100_000;

    // Deriving the key with PBKDF2 using HMAC-SHA256.
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );

    Ok(key)
}

