use tfhe::{boolean::client_key, generate_keys, prelude::FheDecrypt, ClientKey, ConfigBuilder};

use crate::ciphertext::{fheasciichar::FheAsciiChar, fhestring::FheString};

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

    pub fn decrypt(&self, cipher_string: FheString, padding: usize) -> String {
        let new_len = cipher_string.bytes.len().saturating_sub(padding);
        let trimed_bytes: Vec<FheAsciiChar> = cipher_string.bytes.clone()[..new_len].to_vec();

        let ascii_bytes = trimed_bytes
            .iter()
            .map(|fhe_b| fhe_b.inner.decrypt(&self.client_key))
            .collect::<Vec<u8>>();
        String::from_utf8(ascii_bytes).unwrap()
    }
}
