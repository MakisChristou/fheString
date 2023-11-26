use crate::ciphertext::fheasciichar::FheAsciiChar;
use crate::ciphertext::fhestring::FheString;
use crate::ciphertext::public_parameters::PublicParameters;
use crate::utils;

use super::MyServerKey;

impl MyServerKey {
    pub fn trim_end(&self, string: &FheString, public_parameters: &PublicParameters) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters, &self.key);

        let mut stop_trim_flag = zero.clone();
        let mut result = vec![zero.clone(); string.bytes.len()];

        // Replace whitespace with \0 starting from the end
        for i in (0..string.bytes.len()).rev() {
            let is_not_zero = string.bytes[i].ne(&self.key, &zero);

            let is_not_whitespace = string.bytes[i]
                .is_whitespace(&self.key, public_parameters)
                .flip(&self.key, public_parameters);
            stop_trim_flag = stop_trim_flag.bitor(
                &self.key,
                &is_not_whitespace.bitand(&self.key, &is_not_zero),
            );
            result[i] = stop_trim_flag.if_then_else(&self.key, &string.bytes[i], &zero);
        }

        FheString::from_vec(result, public_parameters, &self.key)
    }

    pub fn trim_start(
        &self,
        string: &FheString,
        public_parameters: &PublicParameters,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters, &self.key);

        let mut stop_trim_flag = zero.clone();
        let mut result = vec![zero.clone(); string.bytes.len()];

        // Replace whitespace with \0 starting from the start
        for (i, result_char) in result.iter_mut().enumerate().take(string.bytes.len()) {
            let is_not_zero = string.bytes[i].ne(&self.key, &zero);
            let is_not_whitespace = string.bytes[i]
                .is_whitespace(&self.key, public_parameters)
                .flip(&self.key, public_parameters);

            stop_trim_flag = stop_trim_flag.bitor(
                &self.key,
                &is_not_whitespace.bitand(&self.key, &is_not_zero),
            );
            *result_char = stop_trim_flag.if_then_else(&self.key, &string.bytes[i], &zero)
        }

        FheString::from_vec(
            utils::bubble_zeroes_left(result, &self.key, public_parameters),
            public_parameters,
            &self.key,
        )
    }

    pub fn trim(&self, string: &FheString, public_parameters: &PublicParameters) -> FheString {
        let result = self.trim_end(string, public_parameters);
        self.trim_start(&result, public_parameters)
    }
}
