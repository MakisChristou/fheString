use crate::client_key::MyClientKey;
use crate::{FheAsciiChar, FheString};

pub struct FheSplit {
    pub buffers: Vec<FheString>,
    pub pattern_found: FheAsciiChar,
}

impl FheSplit {
    pub fn new(buffers: Vec<Vec<FheAsciiChar>>, pattern_found: FheAsciiChar) -> Self {
        let mut fhe_string_buffers = Vec::new();
        for buffer in buffers {
            fhe_string_buffers.push(FheString::from_vec(buffer));
        }

        FheSplit {
            buffers: fhe_string_buffers,
            pattern_found,
        }
    }

    // Equivalent to running collect() on the iterator
    pub fn decrypt(fhe_split: FheSplit, my_client_key: &MyClientKey) -> (Vec<String>, u8) {
        let mut plain_split = Vec::new();

        for some_fhe_string in fhe_split.buffers {
            let dec_string = my_client_key.decrypt(some_fhe_string);
            plain_split.push(dec_string);
        }

        let plain_pattern_found = my_client_key.decrypt_char(&fhe_split.pattern_found);

        (plain_split, plain_pattern_found)
    }
}
