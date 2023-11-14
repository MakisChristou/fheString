use crate::client_key::MyClientKey;
use crate::{FheAsciiChar, FheString, PublicParameters};

pub struct FheSplit {
    pub buffers: Vec<FheString>,
}

impl FheSplit {
    pub fn new(buffers: Vec<Vec<FheAsciiChar>>, public_parameters: &PublicParameters) -> Self {
        let mut fhe_string_buffers = Vec::new();
        for buffer in buffers {
            fhe_string_buffers.push(FheString::from_vec(buffer, public_parameters));
        }

        FheSplit {
            buffers: fhe_string_buffers,
        }
    }

    // Equivalent to running collect() on the iterator
    pub fn decrypt(
        fhe_split: FheSplit,
        my_client_key: &MyClientKey,
        padding: usize,
    ) -> Vec<String> {
        let mut plain_split = Vec::new();

        for some_fhe_string in fhe_split.buffers {
            let dec_string = my_client_key.decrypt(some_fhe_string, padding);
            plain_split.push(dec_string);
        }

        plain_split
    }
}
