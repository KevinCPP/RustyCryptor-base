#![feature(string_remove_matches)]    

use std::io::{self, Write};
use once_cell::sync::Lazy;
use std::ops::Deref;

pub mod file;
pub mod input;
pub mod password;
pub mod encryption;
pub mod decryption;
pub mod encryption_params;

use file::*;
use input::*;
use password::*;
use encryption::*;
use decryption::*;

fn main() {
    let file_path = String::from("/home/fornzltoth/Documents/Programming/rust_projects/corroded_cipher_base/src/");
    let result = read_binary_file(file_path.clone() + "test.txt").unwrap();

    let password = "password";
    let key = derive_key_from_password(password, 16).unwrap();

    let encrypted = encrypt_aes_128(&result, &key, &generate_secure_iv(16).unwrap());
    write_binary_file(file_path.clone() + "test_encrypted.txt", &encrypted.unwrap());

    let read_encrypted = read_binary_file(file_path.clone() + "test_encrypted.txt").unwrap();
    let decrypted = decrypt_aes_128(&read_encrypted, &key).unwrap();

    match String::from_utf8(decrypted) {
        Ok(s) => println!("Decrypted string: {}", s),
        Err(e) => eprintln!("Failed to convert decrypted file to string. {}", e),
    }
}
