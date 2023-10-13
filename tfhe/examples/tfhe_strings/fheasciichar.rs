use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXorAssign, Not, Sub, SubAssign,
};

use tfhe::{
    prelude::{FheDecrypt, FheEncrypt, FheEq, FheOrd, FheTrivialEncrypt},
    ClientKey, FheUint8,
};

#[derive(Clone)]
pub struct FheAsciiChar {
    pub inner: FheUint8,
}

impl FheAsciiChar {
    pub fn new(value: FheUint8) -> Self {
        FheAsciiChar { inner: value }
    }

    pub fn encrypt_trivial(value: u8) -> FheAsciiChar {
        FheAsciiChar::new(FheUint8::encrypt_trivial(value))
    }

    pub fn encrypt(value: u8, client_key: &ClientKey) -> FheAsciiChar {
        FheAsciiChar::new(FheUint8::encrypt(value, client_key))
    }

    pub fn decrypt(value: &FheAsciiChar, client_key: &ClientKey) -> u8 {
        FheUint8::decrypt(&value.inner, client_key)
    }

    pub fn eq(&self, other: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(self.inner.eq(&other.inner))
    }

    pub fn ne(&self, other: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(self.inner.ne(&other.inner))
    }

    pub fn le(&self, other: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(self.inner.le(&other.inner))
    }

    pub fn lt(&self, other: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(self.inner.lt(&other.inner))
    }

    pub fn ge(&self, other: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(self.inner.ge(&other.inner))
    }

    pub fn gt(&self, other: &FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(self.inner.gt(&other.inner))
    }

    pub fn if_then_else(
        &self,
        true_value: &FheAsciiChar,
        false_value: &FheAsciiChar,
    ) -> FheAsciiChar {
        let res = self
            .inner
            .if_then_else(&true_value.inner, &false_value.inner);
        FheAsciiChar::new(res)
    }

    pub fn is_whitespace(&self) -> FheAsciiChar {
        let space = FheAsciiChar::encrypt_trivial(0x20u8); // Space
        let tab = FheAsciiChar::encrypt_trivial(0x09u8); // Horizontal Tab
        let newline = FheAsciiChar::encrypt_trivial(0x0Au8); // Newline
        let vertical_tab = FheAsciiChar::encrypt_trivial(0x0Bu8); // Vertical Tab
        let form_feed = FheAsciiChar::encrypt_trivial(0x0Cu8); // Form Feed
        let carriage_return = FheAsciiChar::encrypt_trivial(0x0Du8); // Carriage Return
    
        self.eq(&space)
            | self.eq(&tab)
            | self.eq(&newline)
            | self.eq(&vertical_tab)
            | self.eq(&form_feed)
            | self.eq(&carriage_return)
    }
    
    pub fn is_uppercase(&self) -> FheAsciiChar {
        let uppercase_a = FheAsciiChar::encrypt_trivial(0x41u8); // 'A'
        let uppercase_z = FheAsciiChar::encrypt_trivial(0x5Au8); // 'Z'
    
        self.ge(&uppercase_a) & self.le(&uppercase_z)
    }
    
    pub fn is_lowercase(&self) -> FheAsciiChar {
        let lowercase_a = FheAsciiChar::encrypt_trivial(0x61u8); // 'a'
        let lowercase_z = FheAsciiChar::encrypt_trivial(0x7Au8); // 'z'
    
        self.ge(&lowercase_a) & self.le(&lowercase_z)
    }
    
    pub fn is_alphabetic(&self) -> FheAsciiChar {
        let is_uppercase = self.is_uppercase();
        let is_lowercase = self.is_lowercase();
    
        is_uppercase | is_lowercase
    }
    
    pub fn is_number(&self) -> FheAsciiChar {
        let digit_0 = FheAsciiChar::encrypt_trivial(0x30u8); // '0'
        let digit_9 = FheAsciiChar::encrypt_trivial(0x39u8); // '9'
    
        self.ge(&digit_0) & self.le(&digit_9)
    }
    
    pub fn is_alphanumeric(&self) -> FheAsciiChar {
        let is_alphabetic = self.is_alphabetic();
        let is_number = self.is_number();
    
        is_alphabetic | is_number
    }
    
    // Input must be either 0 or 1
    pub fn flip(&self) -> FheAsciiChar {
        let one = FheAsciiChar::encrypt_trivial(1u8);
        &one - self
    }

}

// Implementing Add
impl Add for FheAsciiChar {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self::new(self.inner + other.inner)
    }
}

// Implementing Add for references
impl<'a, 'b> Add<&'b FheAsciiChar> for &'a FheAsciiChar {
    type Output = FheAsciiChar;

    fn add(self, other: &'b FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(&self.inner + &other.inner)
    }
}

// Implementing Sub
impl Sub for FheAsciiChar {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self::new(self.inner - other.inner)
    }
}

// Implementing Sub for references
impl<'a, 'b> Sub<&'b FheAsciiChar> for &'a FheAsciiChar {
    type Output = FheAsciiChar;

    fn sub(self, other: &'b FheAsciiChar) -> FheAsciiChar {
        FheAsciiChar::new(&self.inner - &other.inner)
    }
}

// Implementing Bitwise OR (|) for logical OR
impl BitOr for FheAsciiChar {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self::new(self.inner | other.inner)
    }
}

// Implementing Bitwise AND (&) for logical AND
impl BitAnd for FheAsciiChar {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        Self::new(self.inner & other.inner)
    }
}

// Implementing Bitwise NOT (!) for logical NOT
impl Not for FheAsciiChar {
    type Output = Self;

    fn not(self) -> Self {
        Self::new(!self.inner)
    }
}

// Implementing Bitwise OR Assign (|=)
impl BitOrAssign for FheAsciiChar {
    fn bitor_assign(&mut self, other: Self) {
        self.inner |= other.inner;
    }
}

// Implementing Bitwise AND Assign (&=)
impl BitAndAssign for FheAsciiChar {
    fn bitand_assign(&mut self, other: Self) {
        self.inner &= other.inner;
    }
}

// Implementing Bitwise XOR Assign (^=)
impl BitXorAssign for FheAsciiChar {
    fn bitxor_assign(&mut self, other: Self) {
        self.inner ^= other.inner;
    }
}

// Implementing Add Assign (+=)
impl AddAssign for FheAsciiChar {
    fn add_assign(&mut self, other: Self) {
        self.inner += other.inner;
    }
}

// Implementing Subtract Assign (-=)
impl SubAssign for FheAsciiChar {
    fn sub_assign(&mut self, other: Self) {
        self.inner -= other.inner;
    }
}
