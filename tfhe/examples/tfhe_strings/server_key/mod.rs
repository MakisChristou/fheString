use serde::{Deserialize, Serialize};
use tfhe::{
    boolean::server_key,
    set_server_key,
    shortint::{public_key, PublicKey},
    ServerKey,
};

use crate::{
    ciphertext::{
        fheasciichar::FheAsciiChar,
        fhesplit::FheSplit,
        fhestring::{Comparison, FheString},
    },
    utils::abs_difference,
    // utils::bubble_zeroes_left,
    MAX_FIND_LENGTH,
    MAX_REPETITIONS,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct MyServerKey {
    key: tfhe::integer::ServerKey,
}

impl MyServerKey {
    pub fn new(server_key: tfhe::integer::ServerKey) -> Self {
        // set_server_key(server_key.clone());
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
            // stop_trim_flag |= is_not_whitespace & is_not_zero;
            // let mask = !stop_trim_flag.clone() + one.clone();
            let mask = stop_trim_flag.bitnot(&self.key).add(&self.key, &one);

            result[i] = string.bytes[i].bitand(&self.key, &zero.bitor(&self.key, &mask));
            // result[i] = string.bytes[i].clone() & (zero.clone() | mask)
        }

        FheString::from_vec(result, public_key, num_blocks)
    }

    // pub fn trim_start(string: &FheString) -> FheString {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);

    //     let mut stop_trim_flag = zero.clone();
    //     let mut result = vec![zero.clone(); string.bytes.len()];

    //     // Replace whitespace with \0 starting from the start
    //     for i in 0..string.bytes.len() {
    //         let is_not_zero = string.bytes[i].ne(&zero);
    //         let is_not_whitespace = string.bytes[i].is_whitespace().flip();

    //         stop_trim_flag |= is_not_whitespace & is_not_zero;
    //         let mask = !stop_trim_flag.clone() + one.clone();

    //         result[i] = string.bytes[i].clone() & (zero.clone() | mask)
    //     }

    //     FheString::from_vec(bubble_zeroes_left(result))
    // }

    // pub fn trim(string: &FheString) -> FheString {
    //     let result = MyServerKey::trim_end(string);
    //     MyServerKey::trim_start(&result)
    // }

    // pub fn repeat_clear(string: &FheString, repetitions: usize) -> FheString {
    //     let mut result = string.bytes.clone();

    //     for _ in 0..repetitions - 1 {
    //         result.append(&mut string.bytes.clone());
    //     }

    //     FheString::from_vec(bubble_zeroes_left(result))
    // }

    // pub fn repeat(string: &FheString, repetitions: FheAsciiChar) -> FheString {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let mut result = vec![zero.clone(); MAX_REPETITIONS * string.bytes.len()];
    //     let str_len = string.bytes.len();

    //     for i in 0..MAX_REPETITIONS {
    //         let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
    //         let copy_flag = enc_i.lt(&repetitions);

    //         for j in 0..str_len {
    //             result[i * str_len + j] = copy_flag.if_then_else(&string.bytes[j], &zero);
    //         }
    //     }

    //     FheString::from_vec(bubble_zeroes_left(result))
    // }

    // pub fn replace(
    //     string: &FheString,
    //     from: &Vec<FheAsciiChar>,
    //     to: &Vec<FheAsciiChar>,
    // ) -> FheString {
    //     let n = FheAsciiChar::encrypt_trivial(0u8);
    //     if from.len() >= to.len() {
    //         Self::handle_longer_from(string.bytes.clone(), from.clone(), to.clone(), n, false)
    //     } else {
    //         Self::handle_shorter_from(string.bytes.clone(), from.clone(), to.clone(), n, false)
    //     }
    // }

    // pub fn replace_clear(string: &FheString, clear_from: &str, clear_to: &str) -> FheString {
    //     let from = clear_from
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let to = clear_to
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();

    //     MyServerKey::replace(string, &from, &to)
    // }

    // pub fn rfind(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheAsciiChar {
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut pattern_position = FheAsciiChar::encrypt_trivial(MAX_FIND_LENGTH as u8);

    //     if string.bytes.len() >= MAX_FIND_LENGTH + pattern.len() {
    //         panic!("Maximum supported size for find reached");
    //     }

    //     // Search for pattern
    //     for i in 0..string.bytes.len() - pattern.len() {
    //         let mut pattern_found_flag = one.clone();

    //         for j in 0..pattern.len() {
    //             pattern_found_flag &= pattern[j].clone().eq(&string.bytes[i + j]);
    //         }

    //         let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
    //         pattern_position = pattern_found_flag.if_then_else(&enc_i, &pattern_position);
    //     }

    //     pattern_position
    // }

    // pub fn rfind_clear(string: &FheString, clear_pattern: &str) -> FheAsciiChar {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();

    //     MyServerKey::rfind(string, &pattern)
    // }

    // // The "easy" case
    // fn handle_longer_from(
    //     bytes: Vec<FheAsciiChar>,
    //     from: Vec<FheAsciiChar>,
    //     mut to: Vec<FheAsciiChar>,
    //     n: FheAsciiChar,
    //     use_counter: bool,
    // ) -> FheString {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let size_difference = abs_difference(from.len(), to.len());
    //     let mut counter = FheAsciiChar::encrypt_trivial(0u8);

    //     // Pad to with zeroes
    //     for _ in 0..size_difference {
    //         to.push(zero.clone());
    //     }

    //     let mut result = bytes.clone();

    //     // Replace from wih to
    //     for i in 0..result.len() - from.len() {
    //         let mut pattern_found_flag = one.clone();

    //         for j in 0..from.len() {
    //             pattern_found_flag &= from[j].clone().eq(&bytes[i + j]);
    //         }

    //         // Stop replacing after n encounters of from
    //         if use_counter {
    //             counter += pattern_found_flag.clone();
    //             let keep_replacing = n.ge(&counter);
    //             pattern_found_flag &= keep_replacing;
    //         }

    //         for k in 0..to.len() {
    //             result[i + k] = pattern_found_flag.if_then_else(&to[k], &result[i + k]);
    //         }
    //     }
    //     return FheString::from_vec(bubble_zeroes_left(result));
    // }

    // // The "hard" case
    // fn handle_shorter_from(
    //     bytes: Vec<FheAsciiChar>,
    //     from: Vec<FheAsciiChar>,
    //     to: Vec<FheAsciiChar>,
    //     n: FheAsciiChar,
    //     use_counter: bool,
    // ) -> FheString {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let size_difference = abs_difference(from.len(), to.len());
    //     let mut counter = FheAsciiChar::encrypt_trivial(0u8);

    //     let max_possible_output_len = (bytes.len() / from.len()) * (size_difference) + bytes.len();

    //     let mut result = bytes.clone();

    //     for _ in 0..max_possible_output_len - bytes.len() {
    //         result.push(zero.clone());
    //     }

    //     let mut copy_buffer = vec![zero.clone(); max_possible_output_len];

    //     // Replace from wih to
    //     for i in 0..result.len() - to.len() {
    //         let mut pattern_found_flag = one.clone();

    //         for j in 0..from.len() {
    //             pattern_found_flag &= from[j].clone().eq(&result[i + j]);
    //         }

    //         // Stop replacing after n encounters of from
    //         if use_counter {
    //             counter += pattern_found_flag.clone();
    //             let keep_replacing = n.ge(&counter);
    //             pattern_found_flag &= keep_replacing;
    //         }

    //         // Copy original string to buffer
    //         for k in 0..max_possible_output_len {
    //             copy_buffer[k] = pattern_found_flag.if_then_else(&result[k], &zero);
    //         }

    //         // Replace from with to
    //         for k in 0..to.len() {
    //             result[i + k] = pattern_found_flag.if_then_else(&to[k], &result[i + k]);
    //         }

    //         // Fix the result buffer by copying back the rest of the string
    //         for k in i + to.len()..max_possible_output_len {
    //             result[k] =
    //                 pattern_found_flag.if_then_else(&copy_buffer[k - size_difference], &result[k]);
    //         }
    //     }
    //     return FheString::from_vec(result);
    // }

    // pub fn find(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheAsciiChar {
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut pattern_position = FheAsciiChar::encrypt_trivial(MAX_FIND_LENGTH as u8);

    //     if string.bytes.len() >= MAX_FIND_LENGTH + pattern.len() {
    //         panic!("Maximum supported size for find reached");
    //     }

    //     // Search for pattern
    //     for i in (0..string.bytes.len() - pattern.len()).rev() {
    //         let mut pattern_found_flag = one.clone();

    //         for j in (0..pattern.len()).rev() {
    //             pattern_found_flag &= pattern[j].clone().eq(&string.bytes[i + j]);
    //         }

    //         let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
    //         pattern_position = pattern_found_flag.if_then_else(&enc_i, &pattern_position);
    //     }

    //     pattern_position
    // }

    // pub fn find_clear(string: &FheString, clear_pattern: &str) -> FheAsciiChar {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();

    //     MyServerKey::find(string, &pattern)
    // }

    // pub fn eq(string: &FheString, other: &FheString) -> FheAsciiChar {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut is_eq = one.clone();
    //     let min_length = usize::min(string.bytes.len(), other.bytes.len());

    //     for i in 0..min_length {
    //         is_eq &= string.bytes[i].eq(&other.bytes[i])
    //             | (string.bytes[i].eq(&zero) & other.bytes[i].eq(&zero))
    //     }

    //     is_eq
    // }

    // pub fn eq_ignore_case(string: &FheString, other: &FheString) -> FheAsciiChar {
    //     let self_lowercase = MyServerKey::to_lower(string);
    //     let other_lowercase = MyServerKey::to_lower(&self_lowercase);

    //     MyServerKey::eq(&self_lowercase, &other_lowercase)
    // }

    // pub fn strip_prefix(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheString {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut result = string.bytes.clone();
    //     let mut pattern_found_flag = one.clone();

    //     for j in 0..pattern.len() {
    //         pattern_found_flag &= pattern[j].eq(&result[j]);
    //     }

    //     for j in 0..pattern.len() {
    //         result[j] = pattern_found_flag.if_then_else(&zero, &result[j]);
    //     }

    //     FheString::from_vec(bubble_zeroes_left(result))
    // }

    // pub fn strip_suffix(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheString {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut result = string.bytes.clone();
    //     let mut pattern_found_flag = one.clone();

    //     let start_of_pattern = result.len() - pattern.len();
    //     let end_of_pattern = result.len();
    //     let mut k = pattern.len() - 1;

    //     for j in (start_of_pattern..end_of_pattern).rev() {
    //         pattern_found_flag &= pattern[k].eq(&result[j]);
    //         k -= 1;
    //     }

    //     for j in (start_of_pattern..end_of_pattern).rev() {
    //         result[j] = pattern_found_flag.if_then_else(&zero, &result[j]);
    //     }

    //     FheString::from_vec(result)
    // }

    // pub fn strip_prefix_clear(string: &FheString, clear_pattern: &str) -> FheString {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     MyServerKey::strip_prefix(string, &pattern)
    // }

    // pub fn strip_suffix_clear(string: &FheString, clear_pattern: &str) -> FheString {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     MyServerKey::strip_suffix(string, &pattern)
    // }

    // pub fn comparison(
    //     string: &FheString,
    //     other: &FheString,
    //     operation: Comparison,
    // ) -> FheAsciiChar {
    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let min_length = usize::min(string.bytes.len(), other.bytes.len());
    //     let mut encountered_comparison = zero.clone();
    //     let mut has_flag_became_one = zero.clone();

    //     let mut ret = FheAsciiChar::encrypt_trivial(255u8);

    //     for i in 0..min_length {
    //         let comparison_result = match operation {
    //             Comparison::LessThan => string.bytes[i].lt(&other.bytes[i]),
    //             Comparison::LessEqual => string.bytes[i].le(&other.bytes[i]),
    //             Comparison::GreaterThan => string.bytes[i].gt(&other.bytes[i]),
    //             Comparison::GreaterEqual => string.bytes[i].ge(&other.bytes[i]),
    //         };

    //         let is_ne = string.bytes[i].ne(&other.bytes[i]);

    //         encountered_comparison |= is_ne; // skip when the prefix is common among strings

    //         let flag = encountered_comparison.clone() & has_flag_became_one.flip();
    //         has_flag_became_one |= flag.clone(); // this flag is required to only consider the first character we compare
    //         ret = flag.if_then_else(&comparison_result, &ret)
    //     }

    //     ret
    // }

    // pub fn lt(string: &FheString, other: &FheString) -> FheAsciiChar {
    //     MyServerKey::comparison(string, other, Comparison::LessThan)
    // }

    // pub fn le(string: &FheString, other: &FheString) -> FheAsciiChar {
    //     MyServerKey::comparison(string, other, Comparison::LessEqual)
    // }

    // pub fn gt(string: &FheString, other: &FheString) -> FheAsciiChar {
    //     MyServerKey::comparison(string, other, Comparison::GreaterThan)
    // }

    // pub fn ge(string: &FheString, other: &FheString) -> FheAsciiChar {
    //     MyServerKey::comparison(string, other, Comparison::GreaterEqual)
    // }

    // pub fn replacen(
    //     string: &FheString,
    //     from: &Vec<FheAsciiChar>,
    //     to: &Vec<FheAsciiChar>,
    //     n: FheAsciiChar,
    // ) -> FheString {
    //     if from.len() >= to.len() {
    //         Self::handle_longer_from(string.bytes.clone(), from.clone(), to.clone(), n, true)
    //     } else {
    //         Self::handle_shorter_from(string.bytes.clone(), from.clone(), to.clone(), n, true)
    //     }
    // }

    // fn _split(
    //     string: &FheString,
    //     pattern: Vec<FheAsciiChar>,
    //     is_inclusive: bool,
    //     is_terminator: bool,
    //     n: Option<FheAsciiChar>,
    // ) -> FheSplit {
    //     let max_buffer_size = string.bytes.len(); // when a single buffer holds the whole input
    //     let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut current_copy_buffer = zero.clone();
    //     let mut stop_counter_increment = zero.clone();
    //     let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

    //     for i in 0..(string.bytes.len() - pattern.len()) {
    //         // Copy ith character to the appropriate buffer
    //         for j in 0..max_no_buffers {
    //             let enc_j = FheAsciiChar::encrypt_trivial(j as u8);
    //             let copy_flag = enc_j.eq(&current_copy_buffer);
    //             result[j][i] = copy_flag.if_then_else(&string.bytes[i], &result[j][i]);
    //         }

    //         let mut pattern_found = one.clone();
    //         for j in 0..pattern.len() {
    //             let eql = string.bytes[i + j].eq(&pattern[j]);
    //             pattern_found &= eql;
    //         }

    //         // If its splitn stop after n splits
    //         match &n {
    //             None => {
    //                 // Here we know if the pattern is found for position i
    //                 // If its found we need to switch from copying to old buffer and start copying to new one
    //                 current_copy_buffer = pattern_found
    //                     .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
    //             }
    //             Some(max_splits) => {
    //                 stop_counter_increment |= current_copy_buffer.eq(&(max_splits - &one));

    //                 // Here we know if the pattern is found for position i
    //                 // If its found we need to switch from copying to old buffer and start copying to new one
    //                 current_copy_buffer = (pattern_found & stop_counter_increment.flip())
    //                     .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
    //             }
    //         };
    //     }

    //     match &n {
    //         Some(max_splits) => {
    //             let to: Vec<FheAsciiChar> = "\0"
    //                 .repeat(pattern.len())
    //                 .as_bytes()
    //                 .iter()
    //                 .map(|b| FheAsciiChar::encrypt_trivial(*b))
    //                 .collect();
    //             let mut stop_replacing_pattern = zero.clone();

    //             for i in 0..max_no_buffers {
    //                 let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
    //                 stop_replacing_pattern |= max_splits.eq(&(&enc_i + &one));

    //                 let current_string = FheString::from_vec(result[i].clone());
    //                 let current_string =
    //                     FheString::from_vec(bubble_zeroes_left(current_string.bytes));
    //                 let replacement_string = MyServerKey::replace(&&current_string, &pattern, &to);

    //                 // Don't remove pattern from (n-1)th buffer
    //                 for j in 0..max_buffer_size {
    //                     result[i][j] = stop_replacing_pattern
    //                         .if_then_else(&current_string.bytes[j], &replacement_string.bytes[j]);
    //                 }
    //             }
    //         }
    //         None => {
    //             if !is_inclusive {
    //                 let to: Vec<FheAsciiChar> = "\0"
    //                     .repeat(pattern.len())
    //                     .as_bytes()
    //                     .iter()
    //                     .map(|b| FheAsciiChar::encrypt_trivial(*b))
    //                     .collect();

    //                 // Since the pattern is also copied at the end of each buffer go through them and delete it
    //                 for i in 0..max_no_buffers {
    //                     let current_string = FheString::from_vec(result[i].clone());
    //                     let replacement_string =
    //                         MyServerKey::replace(&current_string, &pattern, &to);
    //                     result[i] = replacement_string.bytes;
    //                 }
    //             } else {
    //                 for i in 0..max_no_buffers {
    //                     let new_buf = bubble_zeroes_left(result[i].clone());
    //                     result[i] = new_buf;
    //                 }
    //             }

    //             // Zero out the last populated buffer if it starts with the pattern
    //             if is_terminator {
    //                 let mut non_zero_buffer_found = zero.clone();
    //                 for i in (0..max_no_buffers).rev() {
    //                     let mut is_buff_zero = one.clone();

    //                     for j in 0..max_buffer_size {
    //                         is_buff_zero &= result[i][j].eq(&zero);
    //                     }

    //                     // Here we know if the current buffer is non-empty
    //                     // Now we have to check if it starts with the pattern
    //                     let starts_with_pattern = MyServerKey::starts_with(
    //                         &FheString::from_vec(result[i].clone()),
    //                         &pattern,
    //                     );
    //                     let should_delete = starts_with_pattern
    //                         & is_buff_zero.clone()
    //                         & non_zero_buffer_found.flip();

    //                     for j in 0..max_buffer_size {
    //                         result[i][j] = should_delete.if_then_else(&zero, &result[i][j]);
    //                     }

    //                     non_zero_buffer_found |= is_buff_zero.flip();
    //                 }
    //             }
    //         }
    //     }

    //     FheSplit::new(result)
    // }

    // pub fn split(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheSplit {
    //     MyServerKey::_split(string, pattern.clone(), false, false, None)
    // }

    // pub fn split_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     MyServerKey::split(string, &pattern)
    // }

    // pub fn split_inclusive(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheSplit {
    //     MyServerKey::_split(string, pattern.clone(), true, false, None)
    // }

    // pub fn split_inclusive_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     MyServerKey::split_inclusive(string, &pattern)
    // }

    // pub fn split_terminator(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheSplit {
    //     MyServerKey::_split(string, pattern.clone(), false, true, None)
    // }

    // pub fn split_ascii_whitespace(string: &FheString) -> FheSplit {
    //     let max_buffer_size = string.bytes.len(); // when a single buffer holds the whole input
    //     let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut current_copy_buffer = zero.clone();
    //     let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];
    //     let mut previous_was_whitespace = FheAsciiChar::encrypt_trivial(1u8);

    //     for i in 0..(string.bytes.len()) {
    //         let pattern_found = string.bytes[i].is_whitespace();
    //         let should_increment_buffer = pattern_found.clone() & previous_was_whitespace.flip();

    //         // Here we know if the pattern is found for position i
    //         // If its found we need to switch from copying to old buffer and start copying to new one
    //         current_copy_buffer = should_increment_buffer
    //             .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);

    //         // Copy ith character to the appropriate buffer
    //         for j in 0..max_no_buffers {
    //             let enc_j = FheAsciiChar::encrypt_trivial(j as u8);
    //             let mut copy_flag = enc_j.eq(&current_copy_buffer);
    //             copy_flag = copy_flag & string.bytes[i].is_whitespace().flip(); // copy if its not whitespace
    //             result[j][i] = copy_flag.if_then_else(&string.bytes[i], &result[j][i]);
    //         }

    //         previous_was_whitespace = pattern_found;
    //     }

    //     // Replace whitespace with \0
    //     for i in 0..max_no_buffers {
    //         for j in 0..max_buffer_size {
    //             let replace_with_zero = result[i][j].is_whitespace();
    //             result[i][j] = replace_with_zero.if_then_else(&zero, &result[i][j]);
    //         }
    //     }

    //     for i in 0..max_no_buffers {
    //         let new_buf = bubble_zeroes_left(result[i].clone());
    //         result[i] = new_buf;
    //     }

    //     FheSplit::new(result)
    // }

    // pub fn splitn(string: &FheString, pattern: &Vec<FheAsciiChar>, n: FheAsciiChar) -> FheSplit {
    //     MyServerKey::_split(string, pattern.clone(), false, false, Some(n))
    // }

    // pub fn splitn_clear(string: &FheString, clear_pattern: &str, clear_n: usize) -> FheSplit {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     let n = FheAsciiChar::encrypt_trivial(clear_n as u8);
    //     MyServerKey::_split(string, pattern, false, false, Some(n))
    // }

    // pub fn concatenate(string: &FheString, other: &FheString) -> FheString {
    //     let mut result = string.bytes.clone();
    //     let mut clone_other = other.bytes.clone();
    //     result.append(&mut clone_other);
    //     FheString::from_vec(bubble_zeroes_left(result))
    // }

    // fn _rsplit(
    //     string: &FheString,
    //     pattern: Vec<FheAsciiChar>,
    //     is_inclusive: bool,
    //     is_terminator: bool,
    //     n: Option<FheAsciiChar>,
    // ) -> FheSplit {
    //     let max_buffer_size = string.bytes.len(); // when a single buffer holds the whole input
    //     let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

    //     let zero = FheAsciiChar::encrypt_trivial(0u8);
    //     let one = FheAsciiChar::encrypt_trivial(1u8);
    //     let mut current_copy_buffer = zero.clone();
    //     let mut stop_counter_increment = zero.clone();
    //     let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

    //     for i in (0..(string.bytes.len() - pattern.len())).rev() {
    //         // Copy ith character to the appropriate buffer
    //         for j in 0..max_no_buffers {
    //             let enc_j = FheAsciiChar::encrypt_trivial(j as u8);
    //             let copy_flag = enc_j.eq(&current_copy_buffer);
    //             result[j][i] = copy_flag.if_then_else(&string.bytes[i], &result[j][i]);
    //         }

    //         let mut pattern_found = one.clone();
    //         for j in 0..pattern.len() {
    //             let eql = string.bytes[i + j].eq(&pattern[j]);
    //             pattern_found &= eql;
    //         }

    //         // If its splitn stop after n splits
    //         match &n {
    //             None => {
    //                 // Here we know if the pattern is found for position i
    //                 // If its found we need to switch from copying to old buffer and start copying to new one
    //                 current_copy_buffer = pattern_found
    //                     .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
    //             }
    //             Some(max_splits) => {
    //                 stop_counter_increment |= current_copy_buffer.eq(&(max_splits - &one));

    //                 // Here we know if the pattern is found for position i
    //                 // If its found we need to switch from copying to old buffer and start copying to new one
    //                 current_copy_buffer = (pattern_found & stop_counter_increment.flip())
    //                     .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
    //             }
    //         };
    //     }

    //     match &n {
    //         Some(max_splits) => {
    //             let to: Vec<FheAsciiChar> = "\0"
    //                 .repeat(pattern.len())
    //                 .as_bytes()
    //                 .iter()
    //                 .map(|b| FheAsciiChar::encrypt_trivial(*b))
    //                 .collect();
    //             let mut stop_replacing_pattern = zero.clone();

    //             for i in 0..max_no_buffers {
    //                 let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
    //                 stop_replacing_pattern |= max_splits.eq(&(&enc_i + &one));

    //                 let current_string = FheString::from_vec(result[i].clone());
    //                 let current_string =
    //                     FheString::from_vec(bubble_zeroes_left(current_string.bytes));
    //                 let replacement_string = MyServerKey::replace(&current_string, &pattern, &to);

    //                 // Don't remove pattern from (n-1)th buffer
    //                 for j in 0..max_buffer_size {
    //                     result[i][j] = stop_replacing_pattern
    //                         .if_then_else(&current_string.bytes[j], &replacement_string.bytes[j]);
    //                 }
    //             }
    //         }
    //         None => {
    //             if !is_inclusive {
    //                 let to: Vec<FheAsciiChar> = "\0"
    //                     .repeat(pattern.len())
    //                     .as_bytes()
    //                     .iter()
    //                     .map(|b| FheAsciiChar::encrypt_trivial(*b))
    //                     .collect();

    //                 // Since the pattern is also copied at the end of each buffer go through them and delete it
    //                 for i in 0..max_no_buffers {
    //                     let current_string = FheString::from_vec(result[i].clone());
    //                     let replacement_string =
    //                         MyServerKey::replace(&current_string, &pattern, &to);
    //                     result[i] = replacement_string.bytes;
    //                 }
    //             } else {
    //                 for i in 0..max_no_buffers {
    //                     let new_buf = bubble_zeroes_left(result[i].clone());
    //                     result[i] = new_buf;
    //                 }
    //             }

    //             // Zero out the last populated buffer if it starts with the pattern
    //             if is_terminator {
    //                 let mut non_zero_buffer_found = zero.clone();
    //                 for i in (0..max_no_buffers).rev() {
    //                     let mut is_buff_zero = one.clone();

    //                     for j in 0..max_buffer_size {
    //                         is_buff_zero &= result[i][j].eq(&zero);
    //                     }

    //                     // Here we know if the current buffer is non-empty
    //                     // Now we have to check if it starts with the pattern
    //                     let starts_with_pattern = MyServerKey::starts_with(
    //                         &FheString::from_vec(result[i].clone()),
    //                         &pattern,
    //                     );
    //                     let should_delete = starts_with_pattern
    //                         & is_buff_zero.clone()
    //                         & non_zero_buffer_found.flip();

    //                     for j in 0..max_buffer_size {
    //                         result[i][j] = should_delete.if_then_else(&zero, &result[i][j])
    //                     }
    //                     non_zero_buffer_found |= is_buff_zero.flip();
    //                 }
    //             }
    //         }
    //     }

    //     FheSplit::new(result)
    // }

    // pub fn rsplit(string: &FheString, pattern: &Vec<FheAsciiChar>) -> FheSplit {
    //     MyServerKey::_rsplit(string, pattern.clone(), false, false, None)
    // }

    // pub fn rsplit_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
    //     let pattern = clear_pattern
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt_trivial(b))
    //         .collect::<Vec<FheAsciiChar>>();
    //     MyServerKey::rsplit(string, &pattern)
    // }

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
