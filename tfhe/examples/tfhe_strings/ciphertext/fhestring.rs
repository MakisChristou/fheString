use super::public_parameters::PublicParameters;
use crate::FheAsciiChar;
use std::ops::{Index, IndexMut, RangeTo};

#[derive(Clone)]
pub struct FheString {
    bytes: Vec<FheAsciiChar>,
    cst: FheAsciiChar,
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
        public_parameters: &PublicParameters,
        server_key: &tfhe::integer::ServerKey,
    ) -> Self {
        let cst = FheAsciiChar::encrypt_trivial(32u8, public_parameters, server_key);
        FheString { bytes, cst }
    }

    pub fn new(bytes: Vec<FheAsciiChar>, cst: FheAsciiChar) -> FheString {
        FheString { bytes, cst }
    }

    // Returns the length of the string
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn get_bytes(&self) -> Vec<FheAsciiChar> {
        self.bytes.clone()
    }

    pub fn append(&mut self, other: FheString) {
        self.bytes.append(&mut other.get_bytes());
    }

    pub fn push(&mut self, char: FheAsciiChar) {
        self.bytes.push(char);
    }

    pub fn get_cst(&self) -> FheAsciiChar {
        self.cst.clone()
    }
}

impl FheString {
    pub fn iter(&self) -> impl Iterator<Item = &FheAsciiChar> {
        self.bytes.iter()
    }
}

impl FheString {
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut FheAsciiChar> {
        self.bytes.iter_mut()
    }
}

impl Index<usize> for FheString {
    type Output = FheAsciiChar;

    fn index(&self, index: usize) -> &Self::Output {
        &self.bytes[index]
    }
}

impl IndexMut<usize> for FheString {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.bytes[index]
    }
}

impl Index<RangeTo<usize>> for FheString {
    type Output = [FheAsciiChar];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.bytes[index]
    }
}
