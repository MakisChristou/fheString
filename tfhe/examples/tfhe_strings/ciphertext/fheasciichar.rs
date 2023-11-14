use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::RadixClientKey;
use tfhe::shortint::Ciphertext;

use crate::PublicParameters;

#[derive(Clone)]
pub struct FheAsciiChar {
    pub inner: BaseRadixCiphertext<Ciphertext>,
}

impl FheAsciiChar {
    pub fn new(value: BaseRadixCiphertext<Ciphertext>) -> Self {
        FheAsciiChar { inner: value }
    }

    pub fn encrypt_trivial(value: u8, public_parameters: &PublicParameters) -> FheAsciiChar {
        let public_key = &public_parameters.public_key;
        let num_blocks = public_parameters.num_blocks;
        FheAsciiChar::new(public_key.encrypt_radix(value as u64, num_blocks))
    }

    pub fn encrypt(value: u8, client_key: &RadixClientKey) -> FheAsciiChar {
        FheAsciiChar::new(client_key.encrypt(value as u64))
    }

    pub fn decrypt(value: &BaseRadixCiphertext<Ciphertext>, client_key: &RadixClientKey) -> u8 {
        client_key.decrypt::<u8>(value)
    }

    pub fn eq(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.eq_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn ne(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res: BaseRadixCiphertext<Ciphertext> =
            server_key.ne_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn le(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.le_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn lt(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.lt_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn ge(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res: BaseRadixCiphertext<Ciphertext> =
            server_key.ge_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn gt(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.gt_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn bitand(
        &self,
        server_key: &tfhe::integer::ServerKey,
        other: &FheAsciiChar,
    ) -> FheAsciiChar {
        let res = server_key.bitand_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn bitor(
        &self,
        server_key: &tfhe::integer::ServerKey,
        other: &FheAsciiChar,
    ) -> FheAsciiChar {
        let res = server_key.bitor_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn bitxor(
        &self,
        server_key: &tfhe::integer::ServerKey,
        other: &FheAsciiChar,
    ) -> FheAsciiChar {
        let res = server_key.bitxor_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn bitnot(&self, server_key: &tfhe::integer::ServerKey) -> FheAsciiChar {
        let res = server_key.bitnot_parallelized(&self.inner);
        FheAsciiChar::new(res)
    }

    pub fn sub(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.sub_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn add(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.add_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn mul(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.mul_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn div(&self, server_key: &tfhe::integer::ServerKey, other: &FheAsciiChar) -> FheAsciiChar {
        let res = server_key.div_parallelized(&self.inner, &other.inner);
        FheAsciiChar::new(res)
    }

    pub fn if_then_else(
        &self,
        server_key: &tfhe::integer::ServerKey,
        true_value: &FheAsciiChar,
        false_value: &FheAsciiChar,
    ) -> FheAsciiChar {
        let res = server_key.if_then_else_parallelized(
            &self.inner,
            &true_value.inner,
            &false_value.inner,
        );
        FheAsciiChar::new(res)
    }

    pub fn is_whitespace(
        &self,
        server_key: &tfhe::integer::ServerKey,
        public_parameters: &PublicParameters,
    ) -> FheAsciiChar {
        let space = FheAsciiChar::encrypt_trivial(0x20u8, public_parameters); // Space
        let tab = FheAsciiChar::encrypt_trivial(0x09u8, public_parameters); // Horizontal Tab
        let newline = FheAsciiChar::encrypt_trivial(0x0Au8, public_parameters); // Newline
        let vertical_tab = FheAsciiChar::encrypt_trivial(0x0Bu8, public_parameters); // Vertical Tab
        let form_feed = FheAsciiChar::encrypt_trivial(0x0Cu8, public_parameters); // Form Feed
        let carriage_return = FheAsciiChar::encrypt_trivial(0x0Du8, public_parameters); // Carriage Return

        let res1 = self.eq(server_key, &space);
        let res2 = self.eq(server_key, &tab);
        let res3 = self.eq(server_key, &newline);
        let res4 = self.eq(server_key, &vertical_tab);
        let res5 = self.eq(server_key, &form_feed);
        let res6 = self.eq(server_key, &carriage_return);

        res1.bitor(server_key, &res2)
            .bitor(server_key, &res3)
            .bitor(server_key, &res4)
            .bitor(server_key, &res5)
            .bitor(server_key, &res6)
    }

    pub fn is_uppercase(
        &self,
        server_key: &tfhe::integer::ServerKey,
        public_parameters: &PublicParameters,
    ) -> FheAsciiChar {
        let uppercase_a = FheAsciiChar::encrypt_trivial(0x41u8, public_parameters); // 'A'
        let uppercase_z = FheAsciiChar::encrypt_trivial(0x5Au8, public_parameters); // 'Z'

        let res1 = self.ge(server_key, &uppercase_a);
        let res2 = self.le(server_key, &uppercase_z);

        res1.bitand(server_key, &res2)
    }

    pub fn is_lowercase(
        &self,
        server_key: &tfhe::integer::ServerKey,
        public_parameters: &PublicParameters,
    ) -> FheAsciiChar {
        let lowercase_a = FheAsciiChar::encrypt_trivial(0x61u8, public_parameters); // 'a'
        let lowercase_z = FheAsciiChar::encrypt_trivial(0x7Au8, public_parameters); // 'z'

        let res1 = self.ge(server_key, &lowercase_a);
        let res2 = self.le(server_key, &lowercase_z);

        res1.bitand(server_key, &res2)
    }

    pub fn is_alphabetic(
        &self,
        server_key: &tfhe::integer::ServerKey,
        public_parameters: &PublicParameters,
    ) -> FheAsciiChar {
        let is_uppercase = self.is_uppercase(server_key, public_parameters);
        let is_lowercase = self.is_lowercase(server_key, public_parameters);

        is_uppercase.bitor(server_key, &is_lowercase)
    }

    pub fn is_number(
        &self,
        server_key: &tfhe::integer::ServerKey,
        public_parameters: &PublicParameters,
    ) -> FheAsciiChar {
        let digit_0 = FheAsciiChar::encrypt_trivial(0x30u8, public_parameters); // '0'
        let digit_9 = FheAsciiChar::encrypt_trivial(0x39u8, public_parameters); // '9'

        let res1 = self.ge(server_key, &digit_0);
        let res2 = self.le(server_key, &digit_9);

        res1.bitand(server_key, &res2)
    }

    pub fn is_alphanumeric(
        &self,
        server_key: &tfhe::integer::ServerKey,
        public_parameters: &PublicParameters,
    ) -> FheAsciiChar {
        let is_alphabetic = self.is_alphabetic(server_key, public_parameters);
        let is_number = self.is_number(server_key, public_parameters);

        is_alphabetic.bitor(server_key, &is_number)
    }

    // Input must be either 0 or 1
    pub fn flip(
        &self,
        server_key: &tfhe::integer::ServerKey,
        public_parameters: &PublicParameters,
    ) -> FheAsciiChar {
        let one = FheAsciiChar::encrypt_trivial(1u8, public_parameters);
        one.sub(server_key, self)
    }
}
