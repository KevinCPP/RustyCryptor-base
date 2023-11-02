#![feature(string_remove_matches)]    

use std::io;
use std::io::Write;

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
    

}

