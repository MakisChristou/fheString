use tfhe::ClientKey;

use crate::{fheasciichar::FheAsciiChar, FheString};

pub struct FheSplit {
    pub buffers: Vec<FheString>,
}

impl FheSplit {
    pub fn new(buffers: Vec<Vec<FheAsciiChar>>) -> Self {
        let mut fhe_string_buffers = Vec::new();
        for buffer in buffers {
            fhe_string_buffers.push(FheString::from_vec(buffer));
        }

        FheSplit {
            buffers: fhe_string_buffers,
        }
    }

    // Equivalent to running collect() on the iterator
    pub fn decrypt(fhe_split: FheSplit, client_key: &ClientKey, padding: usize) -> Vec<String> {
        let mut plain_split = Vec::new();

        for some_fhe_string in fhe_split.buffers {
            let dec_string = FheString::decrypt(&some_fhe_string, &client_key, padding);
            plain_split.push(dec_string);
        }

        plain_split
    }
}
