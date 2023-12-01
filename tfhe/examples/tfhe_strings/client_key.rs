use crate::ciphertext::fheasciichar::FheAsciiChar;
use crate::ciphertext::fhestring::FheString;
use crate::ciphertext::public_parameters::PublicParameters;
use crate::server_key::MyServerKey;
use serde::{Deserialize, Serialize};
use tfhe::integer::{gen_keys_radix, PublicKey, RadixClientKey};
use tfhe::shortint::ClassicPBSParameters;

#[derive(Serialize, Deserialize, Clone)]
pub struct MyClientKey {
    client_key: RadixClientKey,
    server_key: tfhe::integer::ServerKey,
    public_paramters: PublicParameters,
}

impl MyClientKey {
    pub fn new(
        client_key: RadixClientKey,
        server_key: tfhe::integer::ServerKey,
        public_paramters: PublicParameters,
    ) -> Self {
        MyClientKey {
            client_key,
            server_key,
            public_paramters,
        }
    }

    // Requirement to create key from params or directtly
    pub fn from_params(params: ClassicPBSParameters, num_blocks: usize) -> Self {
        let (client_key, server_key) = gen_keys_radix(params, num_blocks);
        let public_key = PublicKey::new(&client_key);
        let public_parameters = PublicParameters::new(public_key, num_blocks);
        MyClientKey::new(client_key, server_key, public_parameters)
    }

    pub fn get_server_key(&self) -> MyServerKey {
        MyServerKey::new(self.server_key.clone())
    }

    pub fn get_public_parameters(&self) -> PublicParameters {
        self.public_paramters.clone()
    }

    pub fn encrypt(
        &self,
        string: &str,
        padding: usize,
        public_parameters: &PublicParameters,
        server_key: &tfhe::integer::ServerKey,
    ) -> FheString {
        assert!(
            string.chars().all(|char| char.is_ascii() && char != '\0'),
            "The input string must only contain ascii letters and not include null characters"
        );

        let string = format!("{}{}", string, "\0".repeat(padding));

        let fhe_bytes = string
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &self.client_key))
            .collect::<Vec<FheAsciiChar>>();

        FheString::from_vec(fhe_bytes, public_parameters, server_key)
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

        fhe_bytes
    }

    pub fn decrypt_char(&self, cipher_char: &FheAsciiChar) -> u8 {
        FheAsciiChar::decrypt(&cipher_char.inner, &self.client_key)
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
            .iter()
            .map(|fhe_b| self.client_key.decrypt::<u8>(&fhe_b.inner))
            .collect::<Vec<u8>>();

        // Truncate zeroes
        let ascii_bytes = Self::truncate_at_null_byte(ascii_bytes);

        String::from_utf8(ascii_bytes).unwrap()
    }
}
