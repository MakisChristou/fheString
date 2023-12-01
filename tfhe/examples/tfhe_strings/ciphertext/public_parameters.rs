use serde::{Deserialize, Serialize};
use tfhe::integer::PublicKey;

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicParameters {
    pub public_key: PublicKey,
    pub num_blocks: usize,
}

impl PublicParameters {
    pub fn new(public_key: PublicKey, num_blocks: usize) -> Self {
        PublicParameters {
            public_key,
            num_blocks,
        }
    }
}
