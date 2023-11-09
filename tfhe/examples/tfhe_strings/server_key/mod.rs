use serde::{Deserialize, Serialize};

use crate::{
    ciphertext::{
        fheasciichar::FheAsciiChar,
        fhesplit::FheSplit,
        fhestring::{Comparison, FheString},
    },
    utils::{self, abs_difference},
    MAX_FIND_LENGTH, MAX_REPETITIONS,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct MyServerKey {
    key: tfhe::integer::ServerKey,
}

impl MyServerKey {
    pub fn new(server_key: tfhe::integer::ServerKey) -> Self {
        MyServerKey { key: server_key }
    }

    pub fn to_upper(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        FheString {
            bytes: string
                .bytes
                .iter()
                .map(|b| {
                    let is_not_lowercase = b
                        .is_lowercase(&self.key, public_key, num_blocks)
                        .flip(&self.key, public_key, num_blocks);
                    b.sub(
                        &self.key,
                        &is_not_lowercase.if_then_else(&self.key, &zero, &string.cst),
                    )
                })
                .collect::<Vec<FheAsciiChar>>(),
            cst: string.cst.clone(),
        }
    }

    pub fn to_lower(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        FheString {
            bytes: string
                .bytes
                .iter()
                .map(|b| {
                    let is_not_uppercase = b
                        .is_uppercase(&self.key, public_key, num_blocks)
                        .flip(&self.key, public_key, num_blocks);
                    b.add(
                        &self.key,
                        &is_not_uppercase.if_then_else(&self.key, &zero, &string.cst),
                    )
                })
                .collect::<Vec<FheAsciiChar>>(),
            cst: string.cst.clone(),
        }
    }

    pub fn contains(
        &self,
        string: &FheString,
        needle: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);

        for i in 0..string.bytes.len() - needle.len() {
            let mut current_result = one.clone();
            for j in 0..needle.len() {
                let eql = string.bytes[i + j].eq(&self.key, &needle[j]);
                current_result = current_result.bitand(&self.key, &eql);
            }
            result = result.bitor(&self.key, &current_result);
        }
        result
    }

    pub fn contains_clear(
        &self,
        string: &FheString,
        clear_needle: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let needle = clear_needle
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();

        self.contains(string, &needle, public_key, num_blocks)
    }

    pub fn ends_with(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        padding: usize,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut j = pattern.len() - 1;
        for i in (string.bytes.len() - pattern.len()..string.bytes.len() - padding).rev() {
            let eql = string.bytes[i].eq(&self.key, &pattern[j]);
            result = result.bitand(&self.key, &eql);
            j -= 1;
        }
        result
    }

    pub fn ends_with_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        padding: usize,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let pattern = clear_pattern
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        self.ends_with(string, &pattern, padding, public_key, num_blocks)
    }

    pub fn starts_with(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        for i in 0..pattern.len() {
            let eql = string.bytes[i].eq(&self.key, &pattern[i]);
            result = result.bitand(&self.key, &eql);
        }
        result
    }

    pub fn starts_with_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let pattern = clear_pattern
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        self.starts_with(string, &pattern, public_key, num_blocks)
    }

    pub fn is_empty(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);

        if string.bytes.is_empty() {
            return one;
        }

        let mut result = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);

        for i in 0..string.bytes.len() {
            let eql = string.bytes[i].eq(&self.key, &zero);
            result = result.bitand(&self.key, &eql);
        }

        result
    }

    pub fn len(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);

        if string.bytes.is_empty() {
            return zero;
        }

        let mut result = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);

        for i in 0..string.bytes.len() {
            let is_not_zero = string.bytes[i].ne(&self.key, &zero);
            result = result.add(&self.key, &is_not_zero);
        }

        result
    }

    pub fn trim_end(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);

        let mut stop_trim_flag = zero.clone();
        let mut result = vec![zero.clone(); string.bytes.len()];

        // Replace whitespace with \0 starting from the end
        for i in (0..string.bytes.len()).rev() {
            let is_not_zero = string.bytes[i].ne(&self.key, &zero);

            let is_not_whitespace = string.bytes[i]
                .is_whitespace(&self.key, public_key, num_blocks)
                .flip(&self.key, public_key, num_blocks);
            stop_trim_flag = stop_trim_flag.bitor(
                &self.key,
                &is_not_whitespace.bitand(&self.key, &is_not_zero),
            );
            let mask = stop_trim_flag.bitnot(&self.key).add(&self.key, &one);
            result[i] = string.bytes[i].bitand(&self.key, &zero.bitor(&self.key, &mask));
        }

        FheString::from_vec(result, public_key, num_blocks)
    }

    pub fn trim_start(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);

        let mut stop_trim_flag = zero.clone();
        let mut result = vec![zero.clone(); string.bytes.len()];

        // Replace whitespace with \0 starting from the start
        for i in 0..string.bytes.len() {
            let is_not_zero = string.bytes[i].ne(&self.key, &zero);
            let is_not_whitespace = string.bytes[i]
                .is_whitespace(&self.key, public_key, num_blocks)
                .flip(&self.key, public_key, num_blocks);

            stop_trim_flag = stop_trim_flag.bitor(
                &self.key,
                &is_not_whitespace.bitand(&self.key, &is_not_zero),
            );
            let mask = stop_trim_flag.bitnot(&self.key).add(&self.key, &one);
            result[i] = string.bytes[i].bitand(&self.key, &zero.bitor(&self.key, &mask));
        }

        FheString::from_vec(
            utils::bubble_zeroes_left(result, &self.key, public_key, num_blocks),
            public_key,
            num_blocks,
        )
    }

    pub fn trim(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let result = self.trim_end(string, public_key, num_blocks);
        self.trim_start(&result, public_key, num_blocks)
    }

    pub fn repeat_clear(
        &self,
        string: &FheString,
        repetitions: usize,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let mut result = string.bytes.clone();

        for _ in 0..repetitions - 1 {
            result.append(&mut string.bytes.clone());
        }

        FheString::from_vec(
            utils::bubble_zeroes_left(result, &self.key, public_key, num_blocks),
            public_key,
            num_blocks,
        )
    }

    pub fn repeat(
        &self,
        string: &FheString,
        repetitions: FheAsciiChar,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let mut result = vec![zero.clone(); MAX_REPETITIONS * string.bytes.len()];
        let str_len = string.bytes.len();

        for i in 0..MAX_REPETITIONS {
            let enc_i = FheAsciiChar::encrypt_trivial(i as u8, public_key, num_blocks);
            let copy_flag = enc_i.lt(&self.key, &repetitions);

            for j in 0..str_len {
                result[i * str_len + j] =
                    copy_flag.if_then_else(&self.key, &string.bytes[j], &zero);
            }
        }

        FheString::from_vec(
            utils::bubble_zeroes_left(result, &self.key, public_key, num_blocks),
            public_key,
            num_blocks,
        )
    }

    pub fn replace(
        &self,
        string: &FheString,
        from: &Vec<FheAsciiChar>,
        to: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let n = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        if from.len() >= to.len() {
            Self::handle_longer_from(
                string.bytes.clone(),
                from.clone(),
                to.clone(),
                n,
                false,
                &self.key,
                public_key,
                num_blocks,
            )
        } else {
            Self::handle_shorter_from(
                string.bytes.clone(),
                from.clone(),
                to.clone(),
                n,
                false,
                &self.key,
                public_key,
                num_blocks,
            )
        }
    }

    pub fn replace_clear(
        &self,
        string: &FheString,
        clear_from: &str,
        clear_to: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let from = clear_from
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();

        let to = clear_to
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();

        self.replace(string, &from, &to, public_key, num_blocks)
    }

    pub fn rfind(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut pattern_position =
            FheAsciiChar::encrypt_trivial(MAX_FIND_LENGTH as u8, public_key, num_blocks);

        if string.bytes.len() >= MAX_FIND_LENGTH + pattern.len() {
            panic!("Maximum supported size for find reached");
        }

        // Search for pattern
        for i in 0..string.bytes.len() - pattern.len() {
            let mut pattern_found_flag = one.clone();

            for j in 0..pattern.len() {
                pattern_found_flag = pattern_found_flag
                    .bitand(&self.key, &pattern[j].eq(&self.key, &string.bytes[i + j]));
            }

            let enc_i = FheAsciiChar::encrypt_trivial(i as u8, public_key, num_blocks);
            pattern_position =
                pattern_found_flag.if_then_else(&self.key, &enc_i, &pattern_position);
        }

        pattern_position
    }

    pub fn rfind_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();

        self.rfind(string, &pattern, public_key, num_blocks)
    }

    // The "easy" case
    fn handle_longer_from(
        bytes: Vec<FheAsciiChar>,
        from: Vec<FheAsciiChar>,
        mut to: Vec<FheAsciiChar>,
        n: FheAsciiChar,
        use_counter: bool,
        server_key: &tfhe::integer::ServerKey,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let size_difference = abs_difference(from.len(), to.len());
        let mut counter = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);

        // Pad to with zeroes
        for _ in 0..size_difference {
            to.push(zero.clone());
        }

        let mut result = bytes.clone();

        // Replace from wih to
        for i in 0..result.len() - from.len() {
            let mut pattern_found_flag = one.clone();

            for j in 0..from.len() {
                pattern_found_flag =
                    pattern_found_flag.bitand(server_key, &from[j].eq(server_key, &bytes[i + j]));
            }

            // Stop replacing after n encounters of from
            if use_counter {
                counter = counter.add(server_key, &pattern_found_flag);
                let keep_replacing = n.ge(server_key, &counter);
                pattern_found_flag = pattern_found_flag.bitand(server_key, &keep_replacing);
            }

            for k in 0..to.len() {
                result[i + k] = pattern_found_flag.if_then_else(server_key, &to[k], &result[i + k]);
            }
        }
        return FheString::from_vec(
            utils::bubble_zeroes_left(result, server_key, public_key, num_blocks),
            public_key,
            num_blocks,
        );
    }

    // The "hard" case
    fn handle_shorter_from(
        bytes: Vec<FheAsciiChar>,
        from: Vec<FheAsciiChar>,
        to: Vec<FheAsciiChar>,
        n: FheAsciiChar,
        use_counter: bool,
        server_key: &tfhe::integer::ServerKey,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let size_difference = abs_difference(from.len(), to.len());
        let mut counter = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);

        let max_possible_output_len = (bytes.len() / from.len()) * (size_difference) + bytes.len();

        let mut result = bytes.clone();

        for _ in 0..max_possible_output_len - bytes.len() {
            result.push(zero.clone());
        }

        let mut copy_buffer = vec![zero.clone(); max_possible_output_len];

        // Replace from wih to
        for i in 0..result.len() - to.len() {
            let mut pattern_found_flag = one.clone();

            for j in 0..from.len() {
                pattern_found_flag =
                    pattern_found_flag.bitand(server_key, &from[j].eq(server_key, &result[i + j]));
            }

            // Stop replacing after n encounters of from
            if use_counter {
                counter = counter.add(server_key, &pattern_found_flag);
                let keep_replacing = n.ge(server_key, &counter);
                pattern_found_flag = pattern_found_flag.bitand(server_key, &keep_replacing);
            }

            // Copy original string to buffer
            for k in 0..max_possible_output_len {
                copy_buffer[k] = pattern_found_flag.if_then_else(server_key, &result[k], &zero);
            }

            // Replace from with to
            for k in 0..to.len() {
                result[i + k] = pattern_found_flag.if_then_else(server_key, &to[k], &result[i + k]);
            }

            // Fix the result buffer by copying back the rest of the string
            for k in i + to.len()..max_possible_output_len {
                result[k] = pattern_found_flag.if_then_else(
                    server_key,
                    &copy_buffer[k - size_difference],
                    &result[k],
                );
            }
        }
        return FheString::from_vec(result, public_key, num_blocks);
    }

    pub fn find(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut pattern_position =
            FheAsciiChar::encrypt_trivial(MAX_FIND_LENGTH as u8, public_key, num_blocks);

        if string.bytes.len() >= MAX_FIND_LENGTH + pattern.len() {
            panic!("Maximum supported size for find reached");
        }

        // Search for pattern
        for i in (0..string.bytes.len() - pattern.len()).rev() {
            let mut pattern_found_flag = one.clone();

            for j in (0..pattern.len()).rev() {
                pattern_found_flag = pattern_found_flag
                    .bitand(&self.key, &pattern[j].eq(&self.key, &string.bytes[i + j]));
            }

            let enc_i = FheAsciiChar::encrypt_trivial(i as u8, public_key, num_blocks);
            pattern_position =
                pattern_found_flag.if_then_else(&self.key, &enc_i, &pattern_position);
        }

        pattern_position
    }

    pub fn find_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();

        self.find(string, &pattern, public_key, num_blocks)
    }

    pub fn eq(
        &self,
        string: &FheString,
        other: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut is_eq = one.clone();
        let min_length = usize::min(string.bytes.len(), other.bytes.len());

        for i in 0..min_length {
            let are_equal = string.bytes[i].eq(&self.key, &other.bytes[i]);
            let is_first_eq_zero = string.bytes[i].eq(&self.key, &zero);
            let is_second_eq_zero = other.bytes[i].eq(&self.key, &zero);

            let res = is_first_eq_zero.bitand(&self.key, &is_second_eq_zero);
            let res = res.bitor(&self.key, &are_equal);

            is_eq = is_eq.bitand(&self.key, &res);
        }

        is_eq
    }

    pub fn eq_ignore_case(
        &self,
        string: &FheString,
        other: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let self_lowercase = self.to_lower(string, public_key, num_blocks);
        let other_lowercase = self.to_lower(&other, public_key, num_blocks);

        self.eq(&self_lowercase, &other_lowercase, public_key, num_blocks)
    }

    pub fn strip_prefix(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut result = string.bytes.clone();
        let mut pattern_found_flag = one.clone();

        for j in 0..pattern.len() {
            pattern_found_flag =
                pattern_found_flag.bitand(&self.key, &pattern[j].eq(&self.key, &result[j]));
        }

        for j in 0..pattern.len() {
            result[j] = pattern_found_flag.if_then_else(&self.key, &zero, &result[j]);
        }

        FheString::from_vec(
            utils::bubble_zeroes_left(result, &self.key, public_key, num_blocks),
            public_key,
            num_blocks,
        )
    }

    pub fn strip_suffix(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut result = string.bytes.clone();
        let mut pattern_found_flag = one.clone();

        let start_of_pattern = result.len() - pattern.len();
        let end_of_pattern = result.len();
        let mut k = pattern.len() - 1;

        for j in (start_of_pattern..end_of_pattern).rev() {
            pattern_found_flag =
                pattern_found_flag.bitand(&self.key, &pattern[k].eq(&self.key, &result[j]));
            k -= 1;
        }

        for j in (start_of_pattern..end_of_pattern).rev() {
            result[j] = pattern_found_flag.if_then_else(&self.key, &zero, &result[j]);
        }

        FheString::from_vec(result, public_key, num_blocks)
    }

    pub fn strip_prefix_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        self.strip_prefix(string, &pattern, public_key, num_blocks)
    }

    pub fn strip_suffix_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        self.strip_suffix(string, &pattern, public_key, num_blocks)
    }

    pub fn comparison(
        &self,
        string: &FheString,
        other: &FheString,
        operation: Comparison,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let min_length = usize::min(string.bytes.len(), other.bytes.len());
        let mut encountered_comparison = zero.clone();
        let mut has_flag_became_one = zero.clone();

        let mut ret = FheAsciiChar::encrypt_trivial(255u8, public_key, num_blocks);

        for i in 0..min_length {
            let comparison_result = match operation {
                Comparison::LessThan => string.bytes[i].lt(&self.key, &other.bytes[i]),
                Comparison::LessEqual => string.bytes[i].le(&self.key, &other.bytes[i]),
                Comparison::GreaterThan => string.bytes[i].gt(&self.key, &other.bytes[i]),
                Comparison::GreaterEqual => string.bytes[i].ge(&self.key, &other.bytes[i]),
            };

            let is_ne = string.bytes[i].ne(&self.key, &other.bytes[i]);

            encountered_comparison = encountered_comparison.bitor(&self.key, &is_ne); // skip when the prefix is common among strings

            let flag = encountered_comparison.bitand(
                &self.key,
                &has_flag_became_one.flip(&self.key, public_key, num_blocks),
            );
            has_flag_became_one = has_flag_became_one.bitor(&self.key, &flag); // this flag is required to only consider the first character we compare
            ret = flag.if_then_else(&self.key, &comparison_result, &ret)
        }

        ret
    }

    pub fn lt(
        &self,
        string: &FheString,
        other: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        self.comparison(string, other, Comparison::LessThan, public_key, num_blocks)
    }

    pub fn le(
        &self,
        string: &FheString,
        other: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        self.comparison(string, other, Comparison::LessEqual, public_key, num_blocks)
    }

    pub fn gt(
        &self,
        string: &FheString,
        other: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        self.comparison(
            string,
            other,
            Comparison::GreaterThan,
            public_key,
            num_blocks,
        )
    }

    pub fn ge(
        &self,
        string: &FheString,
        other: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheAsciiChar {
        self.comparison(
            string,
            other,
            Comparison::GreaterEqual,
            public_key,
            num_blocks,
        )
    }

    pub fn replacen(
        &self,
        string: &FheString,
        from: &Vec<FheAsciiChar>,
        to: &Vec<FheAsciiChar>,
        n: FheAsciiChar,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        if from.len() >= to.len() {
            Self::handle_longer_from(
                string.bytes.clone(),
                from.clone(),
                to.clone(),
                n,
                true,
                &self.key,
                public_key,
                num_blocks,
            )
        } else {
            Self::handle_shorter_from(
                string.bytes.clone(),
                from.clone(),
                to.clone(),
                n,
                true,
                &self.key,
                public_key,
                num_blocks,
            )
        }
    }

    fn _split(
        &self,
        string: &FheString,
        pattern: Vec<FheAsciiChar>,
        is_inclusive: bool,
        is_terminator: bool,
        n: Option<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        let max_buffer_size = string.bytes.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut current_copy_buffer = zero.clone();
        let mut stop_counter_increment = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

        for i in 0..(string.bytes.len() - pattern.len()) {
            // Copy ith character to the appropriate buffer
            for j in 0..max_no_buffers {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8, public_key, num_blocks);
                let copy_flag = enc_j.eq(&self.key, &current_copy_buffer);
                result[j][i] = copy_flag.if_then_else(&self.key, &string.bytes[i], &result[j][i]);
            }

            let mut pattern_found = one.clone();
            for j in 0..pattern.len() {
                let eql = string.bytes[i + j].eq(&self.key, &pattern[j]);
                pattern_found = pattern_found.bitand(&self.key, &eql);
            }

            // If its splitn stop after n splits
            match &n {
                None => {
                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = pattern_found.if_then_else(
                        &self.key,
                        &current_copy_buffer.add(&self.key, &one),
                        &current_copy_buffer,
                    );
                }
                Some(max_splits) => {
                    stop_counter_increment = stop_counter_increment.bitor(
                        &self.key,
                        &current_copy_buffer.eq(&self.key, &(max_splits.sub(&self.key, &one))),
                    );

                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = (pattern_found
                        .bitand(&self.key, &stop_counter_increment))
                    .flip(&self.key, public_key, num_blocks)
                    .if_then_else(
                        &self.key,
                        &(current_copy_buffer.add(&self.key, &one)),
                        &current_copy_buffer,
                    );
                }
            };
        }

        match &n {
            Some(max_splits) => {
                let to: Vec<FheAsciiChar> = "\0"
                    .repeat(pattern.len())
                    .as_bytes()
                    .iter()
                    .map(|b| FheAsciiChar::encrypt_trivial(*b, public_key, num_blocks))
                    .collect();
                let mut stop_replacing_pattern = zero.clone();

                for i in 0..max_no_buffers {
                    let enc_i = FheAsciiChar::encrypt_trivial(i as u8, public_key, num_blocks);
                    stop_replacing_pattern = stop_replacing_pattern.bitor(
                        &self.key,
                        &max_splits.eq(&self.key, &enc_i.add(&self.key, &one)),
                    );

                    let current_string =
                        FheString::from_vec(result[i].clone(), public_key, num_blocks);
                    let current_string = FheString::from_vec(
                        utils::bubble_zeroes_left(
                            current_string.bytes,
                            &self.key,
                            public_key,
                            num_blocks,
                        ),
                        public_key,
                        num_blocks,
                    );
                    let replacement_string =
                        self.replace(&&current_string, &pattern, &to, public_key, num_blocks);

                    // Don't remove pattern from (n-1)th buffer
                    for j in 0..max_buffer_size {
                        result[i][j] = stop_replacing_pattern.if_then_else(
                            &self.key,
                            &current_string.bytes[j],
                            &replacement_string.bytes[j],
                        );
                    }
                }
            }
            None => {
                if !is_inclusive {
                    let to: Vec<FheAsciiChar> = "\0"
                        .repeat(pattern.len())
                        .as_bytes()
                        .iter()
                        .map(|b| FheAsciiChar::encrypt_trivial(*b, public_key, num_blocks))
                        .collect();

                    // Since the pattern is also copied at the end of each buffer go through them and delete it
                    for i in 0..max_no_buffers {
                        let current_string =
                            FheString::from_vec(result[i].clone(), public_key, num_blocks);
                        let replacement_string =
                            self.replace(&current_string, &pattern, &to, public_key, num_blocks);
                        result[i] = replacement_string.bytes;
                    }
                } else {
                    for i in 0..max_no_buffers {
                        let new_buf = utils::bubble_zeroes_left(
                            result[i].clone(),
                            &self.key,
                            public_key,
                            num_blocks,
                        );
                        result[i] = new_buf;
                    }
                }

                // Zero out the last populated buffer if it starts with the pattern
                if is_terminator {
                    let mut non_zero_buffer_found = zero.clone();
                    for i in (0..max_no_buffers).rev() {
                        let mut is_buff_zero = one.clone();

                        for j in 0..max_buffer_size {
                            is_buff_zero =
                                is_buff_zero.bitand(&self.key, &result[i][j].eq(&self.key, &zero));
                        }

                        // Here we know if the current buffer is non-empty
                        // Now we have to check if it starts with the pattern
                        let starts_with_pattern = self.starts_with(
                            &FheString::from_vec(result[i].clone(), public_key, num_blocks),
                            &pattern,
                            public_key,
                            num_blocks,
                        );
                        let should_delete =
                            starts_with_pattern.bitand(&self.key, &is_buff_zero).bitand(
                                &self.key,
                                &non_zero_buffer_found.flip(&self.key, public_key, num_blocks),
                            );

                        for j in 0..max_buffer_size {
                            result[i][j] =
                                should_delete.if_then_else(&self.key, &zero, &result[i][j]);
                        }

                        non_zero_buffer_found = non_zero_buffer_found.bitor(
                            &self.key,
                            &is_buff_zero.flip(&self.key, public_key, num_blocks),
                        );
                    }
                }
            }
        }

        FheSplit::new(result, public_key, num_blocks)
    }

    pub fn split(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        self._split(
            string,
            pattern.clone(),
            false,
            false,
            None,
            public_key,
            num_blocks,
        )
    }

    pub fn split_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        self.split(string, &pattern, public_key, num_blocks)
    }

    pub fn split_inclusive(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        self._split(
            string,
            pattern.clone(),
            true,
            false,
            None,
            public_key,
            num_blocks,
        )
    }

    pub fn split_inclusive_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        self.split_inclusive(string, &pattern, public_key, num_blocks)
    }

    pub fn split_terminator(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        self._split(
            string,
            pattern.clone(),
            false,
            true,
            None,
            public_key,
            num_blocks,
        )
    }

    pub fn split_ascii_whitespace(
        &self,
        string: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        let max_buffer_size = string.bytes.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut current_copy_buffer = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];
        let mut previous_was_whitespace =
            FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);

        for i in 0..(string.bytes.len()) {
            let pattern_found = string.bytes[i].is_whitespace(&self.key, public_key, num_blocks);
            let should_increment_buffer = pattern_found.bitand(
                &self.key,
                &previous_was_whitespace.flip(&self.key, public_key, num_blocks),
            );

            // Here we know if the pattern is found for position i
            // If its found we need to switch from copying to old buffer and start copying to new one
            current_copy_buffer = should_increment_buffer.if_then_else(
                &self.key,
                &current_copy_buffer.add(&self.key, &one),
                &current_copy_buffer,
            );

            // Copy ith character to the appropriate buffer
            for j in 0..max_no_buffers {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8, public_key, num_blocks);
                let mut copy_flag = enc_j.eq(&self.key, &current_copy_buffer);
                copy_flag = copy_flag.bitand(
                    &self.key,
                    &string.bytes[i]
                        .is_whitespace(&self.key, public_key, num_blocks)
                        .flip(&self.key, public_key, num_blocks),
                ); // copy if its not whitespace
                result[j][i] = copy_flag.if_then_else(&self.key, &string.bytes[i], &result[j][i]);
            }

            previous_was_whitespace = pattern_found;
        }

        // Replace whitespace with \0
        for i in 0..max_no_buffers {
            for j in 0..max_buffer_size {
                let replace_with_zero =
                    result[i][j].is_whitespace(&self.key, public_key, num_blocks);
                result[i][j] = replace_with_zero.if_then_else(&self.key, &zero, &result[i][j]);
            }
        }

        for i in 0..max_no_buffers {
            let new_buf =
                utils::bubble_zeroes_left(result[i].clone(), &self.key, public_key, num_blocks);
            result[i] = new_buf;
        }

        FheSplit::new(result, public_key, num_blocks)
    }

    pub fn splitn(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        n: FheAsciiChar,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        self._split(
            string,
            pattern.clone(),
            false,
            false,
            Some(n),
            public_key,
            num_blocks,
        )
    }

    pub fn splitn_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        clear_n: usize,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(clear_n as u8, public_key, num_blocks);
        self._split(
            string,
            pattern,
            false,
            false,
            Some(n),
            public_key,
            num_blocks,
        )
    }

    pub fn concatenate(
        &self,
        string: &FheString,
        other: &FheString,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheString {
        let mut result = string.bytes.clone();
        let mut clone_other = other.bytes.clone();
        result.append(&mut clone_other);
        FheString::from_vec(
            utils::bubble_zeroes_left(result, &self.key, public_key, num_blocks),
            public_key,
            num_blocks,
        )
    }

    fn _rsplit(
        &self,
        string: &FheString,
        pattern: Vec<FheAsciiChar>,
        is_inclusive: bool,
        is_terminator: bool,
        n: Option<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        let max_buffer_size = string.bytes.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_key, num_blocks);
        let mut current_copy_buffer = zero.clone();
        let mut stop_counter_increment = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

        for i in (0..(string.bytes.len() - pattern.len())).rev() {
            // Copy ith character to the appropriate buffer
            for j in 0..max_no_buffers {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8, public_key, num_blocks);
                let copy_flag = enc_j.eq(&self.key, &current_copy_buffer);
                result[j][i] = copy_flag.if_then_else(&self.key, &string.bytes[i], &result[j][i]);
            }

            let mut pattern_found = one.clone();
            for j in 0..pattern.len() {
                let eql = string.bytes[i + j].eq(&self.key, &pattern[j]);
                pattern_found = pattern_found.bitand(&self.key, &eql);
            }

            // If its splitn stop after n splits
            match &n {
                None => {
                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = pattern_found.if_then_else(
                        &self.key,
                        &current_copy_buffer.add(&self.key, &one),
                        &current_copy_buffer,
                    );
                }
                Some(max_splits) => {
                    stop_counter_increment = stop_counter_increment.bitor(
                        &self.key,
                        &current_copy_buffer.eq(&self.key, &max_splits.sub(&self.key, &one)),
                    );

                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = (pattern_found.bitand(
                        &self.key,
                        &stop_counter_increment.flip(&self.key, public_key, num_blocks),
                    ))
                    .if_then_else(
                        &self.key,
                        &current_copy_buffer.add(&self.key, &one),
                        &current_copy_buffer,
                    );
                }
            };
        }

        match &n {
            Some(max_splits) => {
                let to: Vec<FheAsciiChar> = "\0"
                    .repeat(pattern.len())
                    .as_bytes()
                    .iter()
                    .map(|b| FheAsciiChar::encrypt_trivial(*b, public_key, num_blocks))
                    .collect();
                let mut stop_replacing_pattern = zero.clone();

                for i in 0..max_no_buffers {
                    let enc_i = FheAsciiChar::encrypt_trivial(i as u8, public_key, num_blocks);
                    stop_replacing_pattern = stop_replacing_pattern.bitor(
                        &self.key,
                        &max_splits.eq(&self.key, &enc_i.add(&self.key, &one)),
                    );

                    let current_string =
                        FheString::from_vec(result[i].clone(), public_key, num_blocks);
                    let current_string = FheString::from_vec(
                        utils::bubble_zeroes_left(
                            current_string.bytes,
                            &self.key,
                            public_key,
                            num_blocks,
                        ),
                        public_key,
                        num_blocks,
                    );
                    let replacement_string =
                        self.replace(&current_string, &pattern, &to, public_key, num_blocks);

                    // Don't remove pattern from (n-1)th buffer
                    for j in 0..max_buffer_size {
                        result[i][j] = stop_replacing_pattern.if_then_else(
                            &self.key,
                            &current_string.bytes[j],
                            &replacement_string.bytes[j],
                        );
                    }
                }
            }
            None => {
                if !is_inclusive {
                    let to: Vec<FheAsciiChar> = "\0"
                        .repeat(pattern.len())
                        .as_bytes()
                        .iter()
                        .map(|b| FheAsciiChar::encrypt_trivial(*b, public_key, num_blocks))
                        .collect();

                    // Since the pattern is also copied at the end of each buffer go through them and delete it
                    for i in 0..max_no_buffers {
                        let current_string =
                            FheString::from_vec(result[i].clone(), public_key, num_blocks);
                        let replacement_string =
                            self.replace(&current_string, &pattern, &to, public_key, num_blocks);
                        result[i] = replacement_string.bytes;
                    }
                } else {
                    for i in 0..max_no_buffers {
                        let new_buf = utils::bubble_zeroes_left(
                            result[i].clone(),
                            &self.key,
                            public_key,
                            num_blocks,
                        );
                        result[i] = new_buf;
                    }
                }

                // Zero out the last populated buffer if it starts with the pattern
                if is_terminator {
                    let mut non_zero_buffer_found = zero.clone();
                    for i in (0..max_no_buffers).rev() {
                        let mut is_buff_zero = one.clone();

                        for j in 0..max_buffer_size {
                            is_buff_zero =
                                is_buff_zero.bitand(&self.key, &result[i][j].eq(&self.key, &zero));
                        }

                        // Here we know if the current buffer is non-empty
                        // Now we have to check if it starts with the pattern
                        let starts_with_pattern = self.starts_with(
                            &FheString::from_vec(result[i].clone(), public_key, num_blocks),
                            &pattern,
                            public_key,
                            num_blocks,
                        );
                        let should_delete =
                            starts_with_pattern.bitand(&self.key, &is_buff_zero).bitand(
                                &self.key,
                                &non_zero_buffer_found.flip(&self.key, public_key, num_blocks),
                            );

                        for j in 0..max_buffer_size {
                            result[i][j] =
                                should_delete.if_then_else(&self.key, &zero, &result[i][j])
                        }
                        non_zero_buffer_found = non_zero_buffer_found.bitor(
                            &self.key,
                            &is_buff_zero.flip(&self.key, public_key, num_blocks),
                        );
                    }
                }
            }
        }

        FheSplit::new(result, public_key, num_blocks)
    }

    pub fn rsplit(
        &self,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        self._rsplit(
            string,
            pattern.clone(),
            false,
            false,
            None,
            public_key,
            num_blocks,
        )
    }

    pub fn rsplit_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_key: &tfhe::integer::PublicKey,
        num_blocks: usize,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_key, num_blocks))
            .collect::<Vec<FheAsciiChar>>();
        self.rsplit(string, &pattern, public_key, num_blocks)
    }

    // pub fn rsplitn(string: &FheString, pattern: &Vec<FheAsciiChar>, n: FheAsciiChar) -> FheSplit {
    //     MyServerKey::_rsplit(string, pattern.clone(), false, false, Some(n))
    // }

    // pub fn rsplitn_clear(string: &FheString, clear_pattern: &str, clear_n: usize) -> FheSplit {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     let n = FheAsciiChar::encrypt_trivial(clear_n as u8);
    //     MyServerKey::_rsplit(string, pattern, false, false, Some(n))
    // }

    // pub fn rsplit_once(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheSplit {
    //     let n = FheAsciiChar::encrypt_trivial(2u8);
    //     MyServerKey::_rsplit(string, pattern.clone(), false, false, Some(n))
    // }

    // pub fn rsplit_once_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     let n = FheAsciiChar::encrypt_trivial(2u8);
    //     MyServerKey::_rsplit(string, pattern, false, false, Some(n))
    // }

    // pub fn rsplit_terminator(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheSplit {
    //     MyServerKey::_rsplit(string, pattern.clone(), false, true, None)
    // }

    // pub fn rsplit_terminator_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     MyServerKey::_rsplit(string, pattern, false, true, None)
    // }
}
