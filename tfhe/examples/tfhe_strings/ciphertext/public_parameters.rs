use tfhe::integer::PublicKey;

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
