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
    pub fn from_vec(bytes: Vec<FheAsciiChar>) -> Self {
        let cst = FheAsciiChar::encrypt_trivial(32u8);
        FheString { bytes, cst }
    }
}
