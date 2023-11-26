use serde::{Deserialize, Serialize};
use tfhe::{prelude::FheDecrypt, ClientKey};

use crate::ciphertext::{fheasciichar::FheAsciiChar, fhestring::FheString};

#[derive(Serialize, Deserialize, Clone)]
pub struct MyClientKey {
    client_key: ClientKey,
}

impl MyClientKey {
    pub fn new(client_key: ClientKey) -> Self {
        MyClientKey { client_key }
    }

    pub fn encrypt(&self, string: &str, padding: usize) -> FheString {
        assert!(
            string.chars().all(|char| char.is_ascii() && char != '\0'),
            "The input string must only contain ascii letters and not include null characters"
        );

        let string = format!("{}{}", string, "\0".repeat(padding));

        let fhe_bytes = string
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &self.client_key))
            .collect::<Vec<FheAsciiChar>>();
        let cst = FheAsciiChar::encrypt(32u8, &self.client_key);

        FheString::from_vec(fhe_bytes)
    }

    pub fn encrypt_no_padding(&self, string: &str) -> Vec<FheAsciiChar> {
        assert!(
            string.chars().all(|char| char.is_ascii() && char != '\0'),
            "The input string must only contain ascii letters and not include null characters"
        );

        let fhe_bytes = string
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &self.client_key))
            .collect::<Vec<FheAsciiChar>>();
        let cst = FheAsciiChar::encrypt(32u8, &self.client_key);

        fhe_bytes
    }

    pub fn decrypt_char(&self, cipher_char: &FheAsciiChar) -> u8 {
        FheAsciiChar::decrypt(cipher_char, &self.client_key)
    }

    pub fn encrypt_char(&self, plain_char: u8) -> FheAsciiChar {
        FheAsciiChar::encrypt(plain_char, &self.client_key)
    }

    fn truncate_at_null_byte(vec: Vec<u8>) -> Vec<u8> {
        match vec.iter().position(|&byte| byte == 0) {
            Some(pos) => vec.into_iter().take(pos).collect(),
            None => vec,
        }
    }

    pub fn decrypt(&self, cipher_string: FheString) -> String {
        let ascii_bytes = cipher_string
            .bytes
            .iter()
            .map(|fhe_b| fhe_b.inner.decrypt(&self.client_key))
            .collect::<Vec<u8>>();

        // Truncate zeroes
        let ascii_bytes = Self::truncate_at_null_byte(ascii_bytes);

        String::from_utf8(ascii_bytes).unwrap()
    }
}
