use tfhe::shortint::PublicKey;

use crate::FheAsciiChar;

pub struct FheString {
    pub bytes: Vec<FheAsciiChar>,
    pub cst: FheAsciiChar,
}

pub enum Comparison {
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,
}

impl FheString {
    pub fn from_vec(
        bytes: Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> Self {
        let cst = FheAsciiChar::encrypt_trivial(32u8, public_key, num_blocks);
        FheString { bytes, cst }
    }
}
