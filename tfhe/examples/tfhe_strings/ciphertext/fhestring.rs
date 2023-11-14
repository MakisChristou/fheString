use tfhe::shortint::PublicKey;

use crate::{FheAsciiChar, PublicParameters};

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
    pub fn from_vec(bytes: Vec<FheAsciiChar>, public_paramters: &PublicParameters) -> Self {
        let cst = FheAsciiChar::encrypt_trivial(32u8, public_paramters);
        FheString { bytes, cst }
    }
}
