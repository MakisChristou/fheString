use crate::client_key::MyClientKey;
use crate::{FheAsciiChar, FheString};

pub struct FheStrip {
    pub string: FheString,
    pub pattern_found: FheAsciiChar,
}

impl FheStrip {
    pub fn new(string: FheString, pattern_found: FheAsciiChar) -> Self {
        FheStrip {
            string,
            pattern_found,
        }
    }

    // Equivalent to running collect() on the iterator
    pub fn decrypt(
        fhe_strip: FheStrip,
        my_client_key: &MyClientKey,
        padding: usize,
    ) -> (String, u8) {
        let decrypted_string = my_client_key.decrypt(fhe_strip.string);
        let decrypted_flag = my_client_key.decrypt_char(&fhe_strip.pattern_found);

        (decrypted_string, decrypted_flag)
    }
}
