#![feature(string_remove_matches)]    

use std::io::{self, Write};
use once_cell::sync::Lazy;
use std::ops::Deref;

pub mod input;
pub mod password;
pub mod encryption;

use input::*;
use password::*;
use encryption::*;

static MAIN_MENU_STR: Lazy<String> = Lazy::new(|| {
    String::from("Main Menu:
1. Encryption Menu
2. Decryption Menu
3. Hashing Menu
0. Exit")
});

static ENCRYPTION_MENU_STR: Lazy<String> = Lazy::new(|| {
    String::from("Encryption Menu:
1. Encrypt With AES128
2. Encrypt With AES192
3. Encrypt With AES256
0. Back")
});

static DECRYPTION_MENU_STR: Lazy<String> = Lazy::new(|| {
    String::from("Decryption Menu:
1. Decrypt With AES128
2. Decrypt With AES192
3. Decrypt With AES256
0. Back")
});

static HASHING_MENU_STR: Lazy<String> = Lazy::new(|| {
    String::from("Hashing Menu:
1. Perform SHA256 Hash
0. Back")
});


fn display_menu(menu_string: String, default_value: i64) -> i64 {
    to_i64(prompt(Some(menu_string), None)).unwrap_or(default_value)
}

fn encryption_menu() {
    let error_value: i64 = -1;
    loop {
        let option = display_menu(ENCRYPTION_MENU_STR.deref().clone(), error_value);
        match option {
            0 => return,
            1 | 2 | 3 => {},
            _ => {
                println!("invalid option!");
                continue;
            }
        }

        let file = remove_special_chars(prompt(Some(String::from("Enter the file path")), None)).unwrap_or(String::new());
        let passwd = remove_special_chars(prompt(Some(String::from("Enter a Password")), None)).unwrap_or(String::new());
        let output = remove_special_chars(prompt(Some(String::from("Enter output directory")), None)).unwrap_or(String::new());
    } 
}

fn decryption_menu() {
    let error_value: i64 = -1;
    loop {
        let option = display_menu(DECRYPTION_MENU_STR.deref().clone(), error_value);
        match option {
            0 => return,
            1 | 2 | 3 => {},
            _ => {
                println!("invalid option!");
                continue;
            }
        }

        let file = remove_special_chars(prompt(Some(String::from("Enter the file path")), None)).unwrap_or(String::new());
        let passwd = remove_special_chars(prompt(Some(String::from("Enter a Password")), None)).unwrap_or(String::new());
        let output = remove_special_chars(prompt(Some(String::from("Enter output directory")), None)).unwrap_or(String::new());
    } 
}

fn hashing_menu() {
    let error_value: i64 = -1;
    loop {
        let option = display_menu(HASHING_MENU_STR.deref().clone(), error_value);
        match option {
            0 => return,
            1 => {},
            _ => {
                println!("invalid option!");
                continue;
            }
        }

        let file = remove_special_chars(prompt(Some(String::from("Enter the file path")), None)).unwrap_or(String::new());
    } 
}


fn main_menu() {
    let error_value: i64 = -1;
    loop {
        let main_menu_option = display_menu(MAIN_MENU_STR.deref().clone(), error_value);
        match main_menu_option {
            1 => encryption_menu(),
            2 => decryption_menu(),
            3 => hashing_menu(),
            0 => return,
            _ => {
                println!("Invalid option selected!");
            }
        }
    }
}



fn main() {
    main_menu();
}

