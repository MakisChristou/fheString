use fheasciichar::FheAsciiChar;
use fhesplit::FheSplit;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder};

const STRING_PADDING: usize = 3;
const MAX_REPETITIONS: usize = 4;
const MAX_FIND_LENGTH: usize = 255;

mod fheasciichar;
mod fhesplit;

pub struct FheString {
    bytes: Vec<FheAsciiChar>,
    cst: FheAsciiChar,
}

fn abs_difference(a: usize, b: usize) -> usize {
    a.checked_sub(b).unwrap_or_else(|| b - a)
}

fn bubble_zeroes_left(mut result: Vec<FheAsciiChar>) -> Vec<FheAsciiChar> {
    let zero = FheAsciiChar::encrypt_trivial(0u8);

    // Bring non \0 characters in front O(n^2), essentially bubble sort
    for _ in 0..result.len() {
        for i in 0..result.len() - 1 {
            let should_swap = result[i].eq(&zero);

            result[i] = should_swap.if_then_else(&result[i + 1], &result[i]);
            result[i + 1] = should_swap.if_then_else(&zero, &result[i + 1]);
        }
    }

    result
}

enum Comparison {
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,
}

impl FheString {
    fn from_vec(bytes: Vec<FheAsciiChar>) -> Self {
        let cst = FheAsciiChar::encrypt_trivial(32u8);
        FheString { bytes, cst }
    }

    fn encrypt(string: &str, client_key: &ClientKey, padding: usize) -> Self {
        assert!(
            string.chars().all(|char| char.is_ascii() && char != '\0'),
            "The input string must only contain ascii letters and not include null characters"
        );

        let string = format!("{}{}", string, "\0".repeat(padding));

        let fhe_bytes = string
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, client_key))
            .collect::<Vec<FheAsciiChar>>();
        let cst = FheAsciiChar::encrypt(32u8, client_key);

        Self {
            bytes: fhe_bytes,
            cst,
        }
    }

    fn decrypt(&self, client_key: &ClientKey, padding: usize) -> String {
        let new_len = self.bytes.len().saturating_sub(padding);
        let trimed_bytes: Vec<FheAsciiChar> = self.bytes.clone()[..new_len].to_vec();

        let ascii_bytes = trimed_bytes
            .iter()
            .map(|fhe_b| fhe_b.inner.decrypt(client_key))
            .collect::<Vec<u8>>();
        String::from_utf8(ascii_bytes).unwrap()
    }

    fn to_upper(&self) -> Self {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        Self {
            bytes: self
                .bytes
                .iter()
                .map(|b| {
                    let should_not_convert = b.eq(&zero);
                    let should_not_convert = should_not_convert | b.is_lowercase().flip();
                    b - &should_not_convert.if_then_else(&zero, &self.cst)
                })
                .collect::<Vec<FheAsciiChar>>(),
            cst: self.cst.clone(),
        }
    }

    fn to_lower(&self) -> Self {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        Self {
            bytes: self
                .bytes
                .iter()
                .map(|b| {
                    let should_not_convert = b.eq(&zero);
                    let should_not_convert = should_not_convert | b.is_uppercase().flip();
                    b + &should_not_convert.if_then_else(&zero, &self.cst)
                })
                .collect::<Vec<FheAsciiChar>>(),
            cst: self.cst.clone(),
        }
    }

    fn contains(&self, needle: Vec<FheAsciiChar>) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);

        for i in 0..self.bytes.len() - needle.len() {
            let mut current_result = one.clone();
            for j in 0..needle.len() {
                let eql = self.bytes[i + j].eq(&needle[j]);
                current_result &= eql;
            }
            result |= current_result;
        }
        result
    }

    fn contains_clear(&self, clear_needle: &str) -> FheAsciiChar {
        let needle = clear_needle
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b))
            .collect::<Vec<FheAsciiChar>>();

        self.contains(needle)
    }

    fn ends_with(&self, pattern: Vec<FheAsciiChar>, padding: usize) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(1u8);
        let mut j = pattern.len() - 1;
        for i in (self.bytes.len() - pattern.len()..self.bytes.len() - padding).rev() {
            let eql = self.bytes[i].eq(&pattern[j]);
            result &= eql;
            j -= 1;
        }
        result
    }

    fn ends_with_clear(&self, clear_pattern: &str, padding: usize) -> FheAsciiChar {
        let pattern = clear_pattern
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b))
            .collect::<Vec<FheAsciiChar>>();
        self.ends_with(pattern, padding)
    }

    fn starts_with(&self, pattern: Vec<FheAsciiChar>) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(1u8);
        for i in 0..pattern.len() {
            let eql = self.bytes[i].eq(&pattern[i]);
            result &= eql;
        }
        result
    }

    fn starts_with_clear(&self, clear_pattern: &str) -> FheAsciiChar {
        let pattern = clear_pattern
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b))
            .collect::<Vec<FheAsciiChar>>();
        self.starts_with(pattern)
    }

    fn is_empty(&self) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);

        if self.bytes.is_empty() {
            return one;
        }

        let mut result = FheAsciiChar::encrypt_trivial(1u8);

        for i in 0..self.bytes.len() {
            let eql = self.bytes[i].eq(&zero);
            result &= eql;
        }

        result
    }

    fn len(&self) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8);

        if self.bytes.is_empty() {
            return zero;
        }

        let mut result = FheAsciiChar::encrypt_trivial(0u8);

        for i in 0..self.bytes.len() {
            let is_not_zero = self.bytes[i].ne(&zero);
            result += is_not_zero;
        }

        result
    }

    fn trim_end(&self) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);

        let mut stop_trim_flag = zero.clone();
        let mut result = vec![zero.clone(); self.bytes.len()];

        // Replace whitespace with \0 starting from the end
        for i in (0..self.bytes.len()).rev() {
            let is_not_zero = self.bytes[i].ne(&zero);

            let is_not_whitespace = self.bytes[i].is_whitespace().flip();

            stop_trim_flag |= is_not_whitespace & is_not_zero;
            let mask = !stop_trim_flag.clone() + one.clone();

            result[i] = self.bytes[i].clone() & (zero.clone() | mask)
        }

        FheString::from_vec(result)
    }

    fn trim_start(&self) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);

        let mut stop_trim_flag = zero.clone();
        let mut result = vec![zero.clone(); self.bytes.len()];

        // Replace whitespace with \0 starting from the start
        for i in 0..self.bytes.len() {
            let is_not_zero = self.bytes[i].ne(&zero);
            let is_not_whitespace = self.bytes[i].is_whitespace().flip();

            stop_trim_flag |= is_not_whitespace & is_not_zero;
            let mask = !stop_trim_flag.clone() + one.clone();

            result[i] = self.bytes[i].clone() & (zero.clone() | mask)
        }

        FheString::from_vec(bubble_zeroes_left(result))
    }

    fn trim(&self) -> FheString {
        let result = self.trim_end();
        result.trim_start()
    }

    fn repeat_clear(&self, repetitions: usize) -> FheString {
        let mut result = self.bytes.clone();

        for _ in 0..repetitions - 1 {
            result.append(&mut self.bytes.clone());
        }

        FheString::from_vec(bubble_zeroes_left(result))
    }

    fn repeat(&self, repetitions: FheAsciiChar) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let mut result = vec![zero.clone(); MAX_REPETITIONS * self.bytes.len()];
        let str_len = self.bytes.len();

        for i in 0..MAX_REPETITIONS {
            let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
            let copy_flag = enc_i.lt(&repetitions);

            for j in 0..str_len {
                result[i * str_len + j] = copy_flag.if_then_else(&self.bytes[j], &zero);
            }
        }

        FheString::from_vec(bubble_zeroes_left(result))
    }

    fn replace(&self, from: Vec<FheAsciiChar>, to: Vec<FheAsciiChar>) -> FheString {
        let n = FheAsciiChar::encrypt_trivial(0u8);
        if from.len() >= to.len() {
            Self::handle_longer_from(self.bytes.clone(), from, to, n, false)
        } else {
            Self::handle_shorter_from(self.bytes.clone(), from, to, n, false)
        }
    }

    fn replace_clear(&self, clear_from: &str, clear_to: &str) -> FheString {
        let from = clear_from
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();

        let to = clear_to
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();

        self.replace(from, to)
    }

    // The "easy" case
    fn handle_longer_from(
        bytes: Vec<FheAsciiChar>,
        from: Vec<FheAsciiChar>,
        mut to: Vec<FheAsciiChar>,
        n: FheAsciiChar,
        use_counter: bool,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let size_difference = abs_difference(from.len(), to.len());
        let mut counter = FheAsciiChar::encrypt_trivial(0u8);

        // Pad to with zeroes
        for _ in 0..size_difference {
            to.push(zero.clone());
        }

        let mut result = bytes.clone();

        // Replace from wih to
        for i in 0..result.len() - from.len() {
            let mut pattern_found_flag = one.clone();

            for j in 0..from.len() {
                pattern_found_flag &= from[j].clone().eq(&bytes[i + j]);
            }

            // Stop replacing after n encounters of from
            if use_counter {
                counter += pattern_found_flag.clone();
                let keep_replacing = n.ge(&counter);
                pattern_found_flag &= keep_replacing;
            }

            for k in 0..to.len() {
                result[i + k] = pattern_found_flag.if_then_else(&to[k], &result[i + k]);
            }
        }
        return FheString::from_vec(bubble_zeroes_left(result));
    }

    // The "hard" case
    fn handle_shorter_from(
        bytes: Vec<FheAsciiChar>,
        from: Vec<FheAsciiChar>,
        to: Vec<FheAsciiChar>,
        n: FheAsciiChar,
        use_counter: bool,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let size_difference = abs_difference(from.len(), to.len());
        let mut counter = FheAsciiChar::encrypt_trivial(0u8);

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
                pattern_found_flag &= from[j].clone().eq(&result[i + j]);
            }

            // Stop replacing after n encounters of from
            if use_counter {
                counter += pattern_found_flag.clone();
                let keep_replacing = n.ge(&counter);
                pattern_found_flag &= keep_replacing;
            }

            // Copy original string to buffer
            for k in 0..max_possible_output_len {
                copy_buffer[k] = pattern_found_flag.if_then_else(&result[k], &zero);
            }

            // Replace from with to
            for k in 0..to.len() {
                result[i + k] = pattern_found_flag.if_then_else(&to[k], &result[i + k]);
            }

            // Fix the result buffer by copying back the rest of the string
            for k in i + to.len()..max_possible_output_len {
                result[k] =
                    pattern_found_flag.if_then_else(&copy_buffer[k - size_difference], &result[k]);
            }
        }
        return FheString::from_vec(result);
    }

    fn replacen(
        &self,
        from: Vec<FheAsciiChar>,
        to: Vec<FheAsciiChar>,
        n: FheAsciiChar,
    ) -> FheString {
        if from.len() >= to.len() {
            Self::handle_longer_from(self.bytes.clone(), from, to, n, true)
        } else {
            Self::handle_shorter_from(self.bytes.clone(), from, to, n, true)
        }
    }

    fn rfind(&self, pattern: Vec<FheAsciiChar>) -> FheAsciiChar {
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut pattern_position = FheAsciiChar::encrypt_trivial(MAX_FIND_LENGTH as u8);

        if self.bytes.len() >= MAX_FIND_LENGTH + pattern.len() {
            panic!("Maximum supported size for find reached");
        }

        // Search for pattern
        for i in 0..self.bytes.len() - pattern.len() {
            let mut pattern_found_flag = one.clone();

            for j in 0..pattern.len() {
                pattern_found_flag &= pattern[j].clone().eq(&self.bytes[i + j]);
            }

            let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
            pattern_position = pattern_found_flag.if_then_else(&enc_i, &pattern_position);
        }

        pattern_position
    }

    fn rfind_clear(&self, clear_pattern: &str) -> FheAsciiChar {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();

        self.rfind(pattern)
    }

    fn find(&self, pattern: Vec<FheAsciiChar>) -> FheAsciiChar {
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut pattern_position = FheAsciiChar::encrypt_trivial(MAX_FIND_LENGTH as u8);

        if self.bytes.len() >= MAX_FIND_LENGTH + pattern.len() {
            panic!("Maximum supported size for find reached");
        }

        // Search for pattern
        for i in (0..self.bytes.len() - pattern.len()).rev() {
            let mut pattern_found_flag = one.clone();

            for j in (0..pattern.len()).rev() {
                pattern_found_flag &= pattern[j].clone().eq(&self.bytes[i + j]);
            }

            let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
            pattern_position = pattern_found_flag.if_then_else(&enc_i, &pattern_position);
        }

        pattern_position
    }

    fn find_clear(&self, clear_pattern: &str) -> FheAsciiChar {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();

        self.find(pattern)
    }

    fn eq(&self, other: FheString) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut is_eq = one.clone();
        let min_length = usize::min(self.bytes.len(), other.bytes.len());

        for i in 0..min_length {
            is_eq &= self.bytes[i].eq(&other.bytes[i])
                | (self.bytes[i].eq(&zero) & other.bytes[i].eq(&zero))
        }

        is_eq
    }

    fn eq_ignore_case(&self, other: FheString) -> FheAsciiChar {
        let self_lowercase = self.to_lower();
        let other_lowercase = other.to_lower();

        self_lowercase.eq(other_lowercase)
    }

    fn strip_prefix(&self, pattern: Vec<FheAsciiChar>) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut result = self.bytes.clone();
        let mut pattern_found_flag = one.clone();

        for j in 0..pattern.len() {
            pattern_found_flag &= pattern[j].eq(&result[j]);
        }

        for j in 0..pattern.len() {
            result[j] = pattern_found_flag.if_then_else(&zero, &result[j]);
        }

        FheString::from_vec(bubble_zeroes_left(result))
    }

    fn strip_suffix(&self, pattern: Vec<FheAsciiChar>) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut result = self.bytes.clone();
        let mut pattern_found_flag = one.clone();

        let start_of_pattern = result.len() - pattern.len();
        let end_of_pattern = result.len();
        let mut k = pattern.len() - 1;

        for j in (start_of_pattern..end_of_pattern).rev() {
            pattern_found_flag &= pattern[k].eq(&result[j]);
            k -= 1;
        }

        for j in (start_of_pattern..end_of_pattern).rev() {
            result[j] = pattern_found_flag.if_then_else(&zero, &result[j]);
        }

        FheString::from_vec(result)
    }

    fn strip_prefix_clear(&self, clear_pattern: &str) -> FheString {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.strip_prefix(pattern)
    }

    fn strip_suffix_clear(&self, clear_pattern: &str) -> FheString {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.strip_suffix(pattern)
    }

    fn comparison(&self, other: FheString, operation: Comparison) -> FheAsciiChar {
        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let min_length = usize::min(self.bytes.len(), other.bytes.len());
        let mut encountered_comparison = zero.clone();
        let mut has_flag_became_one = zero.clone();

        let mut ret = FheAsciiChar::encrypt_trivial(255u8);

        for i in 0..min_length {
            let comparison_result = match operation {
                Comparison::LessThan => self.bytes[i].lt(&other.bytes[i]),
                Comparison::LessEqual => self.bytes[i].le(&other.bytes[i]),
                Comparison::GreaterThan => self.bytes[i].gt(&other.bytes[i]),
                Comparison::GreaterEqual => self.bytes[i].ge(&other.bytes[i]),
            };

            let is_ne = self.bytes[i].ne(&other.bytes[i]);

            encountered_comparison |= is_ne; // skip when the prefix is common among strings

            let flag = encountered_comparison.clone() & has_flag_became_one.flip();
            has_flag_became_one |= flag.clone(); // this flag is required to only consider the first character we compare
            ret = flag.if_then_else(&comparison_result, &ret)
        }

        ret
    }

    fn lt(&self, other: FheString) -> FheAsciiChar {
        self.comparison(other, Comparison::LessThan)
    }

    fn le(&self, other: FheString) -> FheAsciiChar {
        self.comparison(other, Comparison::LessEqual)
    }

    fn gt(&self, other: FheString) -> FheAsciiChar {
        self.comparison(other, Comparison::GreaterThan)
    }

    fn ge(&self, other: FheString) -> FheAsciiChar {
        self.comparison(other, Comparison::GreaterEqual)
    }

    fn _split(
        &self,
        pattern: Vec<FheAsciiChar>,
        is_inclusive: bool,
        is_terminator: bool,
        n: Option<FheAsciiChar>,
    ) -> FheSplit {
        let max_buffer_size = self.bytes.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut current_copy_buffer = zero.clone();
        let mut stop_counter_increment = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

        for i in 0..(self.bytes.len() - pattern.len()) {
            // Copy ith character to the appropriate buffer
            for j in 0..max_no_buffers {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8);
                let copy_flag = enc_j.eq(&current_copy_buffer);
                result[j][i] = copy_flag.if_then_else(&self.bytes[i], &result[j][i]);
            }

            let mut pattern_found = one.clone();
            for j in 0..pattern.len() {
                let eql = self.bytes[i + j].eq(&pattern[j]);
                pattern_found &= eql;
            }

            // If its splitn stop after n splits
            match &n {
                None => {
                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = pattern_found
                        .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
                }
                Some(max_splits) => {
                    stop_counter_increment |= current_copy_buffer.eq(&(max_splits - &one));

                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = (pattern_found & stop_counter_increment.flip())
                        .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
                }
            };
        }

        match &n {
            Some(max_splits) => {
                let to: Vec<FheAsciiChar> = "\0"
                    .repeat(pattern.len())
                    .as_bytes()
                    .iter()
                    .map(|b| FheAsciiChar::encrypt_trivial(*b))
                    .collect();
                let mut stop_replacing_pattern = zero.clone();

                for i in 0..max_no_buffers {
                    let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
                    stop_replacing_pattern |= max_splits.eq(&(&enc_i + &one));

                    let current_string = FheString::from_vec(result[i].clone());
                    let current_string =
                        FheString::from_vec(bubble_zeroes_left(current_string.bytes));
                    let replacement_string = current_string.replace(pattern.clone(), to.clone());

                    // Don't remove pattern from (n-1)th buffer
                    for j in 0..max_buffer_size {
                        result[i][j] = stop_replacing_pattern
                            .if_then_else(&current_string.bytes[j], &replacement_string.bytes[j]);
                    }
                }
            }
            None => {
                if !is_inclusive {
                    let to: Vec<FheAsciiChar> = "\0"
                        .repeat(pattern.len())
                        .as_bytes()
                        .iter()
                        .map(|b| FheAsciiChar::encrypt_trivial(*b))
                        .collect();

                    // Since the pattern is also copied at the end of each buffer go through them and delete it
                    for i in 0..max_no_buffers {
                        let current_string = FheString::from_vec(result[i].clone());
                        let replacement_string =
                            current_string.replace(pattern.clone(), to.clone());
                        result[i] = replacement_string.bytes;
                    }
                } else {
                    for i in 0..max_no_buffers {
                        let new_buf = bubble_zeroes_left(result[i].clone());
                        result[i] = new_buf;
                    }
                }

                // Zero out the last populated buffer if it starts with the pattern
                if is_terminator {
                    let mut non_zero_buffer_found = zero.clone();
                    for i in (0..max_no_buffers).rev() {
                        let mut is_buff_zero = one.clone();

                        for j in 0..max_buffer_size {
                            is_buff_zero &= result[i][j].eq(&zero);
                        }

                        // Here we know if the current buffer is non-empty
                        // Now we have to check if it starts with the pattern
                        let starts_with_pattern =
                            FheString::from_vec(result[i].clone()).starts_with(pattern.clone());
                        let should_delete = starts_with_pattern
                            & is_buff_zero.clone()
                            & non_zero_buffer_found.flip();

                        for j in 0..max_buffer_size {
                            result[i][j] = should_delete.if_then_else(&zero, &result[i][j]);
                        }

                        non_zero_buffer_found |= is_buff_zero.flip();
                    }
                }
            }
        }

        FheSplit::new(result)
    }

    fn split(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._split(pattern, false, false, None)
    }

    fn split_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.split(pattern)
    }

    fn split_inclusive(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._split(pattern, true, false, None)
    }

    fn split_inclusive_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.split_inclusive(pattern)
    }

    fn split_terminator(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._split(pattern, false, true, None)
    }

    fn split_ascii_whitespace(&self) -> FheSplit {
        let max_buffer_size = self.bytes.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut current_copy_buffer = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

        for i in 0..(self.bytes.len()) {
            // Copy ith character to the appropriate buffer
            for j in 0..max_no_buffers {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8);
                let copy_flag = enc_j.eq(&current_copy_buffer);
                result[j][i] = copy_flag.if_then_else(&self.bytes[i], &result[j][i]);
            }

            let pattern_found = self.bytes[i].is_whitespace();
            // Here we know if the pattern is found for position i
            // If its found we need to switch from copying to old buffer and start copying to new one
            current_copy_buffer =
                pattern_found.if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
        }

        // Replace whitespace with \0
        for i in 0..max_no_buffers {
            for j in 0..max_buffer_size {
                let replace_with_zero = result[i][j].is_whitespace();
                result[i][j] = replace_with_zero.if_then_else(&zero, &result[i][j]);
            }
        }

        for i in 0..max_no_buffers {
            let new_buf = bubble_zeroes_left(result[i].clone());
            result[i] = new_buf;
        }

        FheSplit::new(result)
    }

    fn splitn(&self, pattern: Vec<FheAsciiChar>, n: FheAsciiChar) -> FheSplit {
        self._split(pattern, false, false, Some(n))
    }

    fn splitn_clear(&self, clear_pattern: &str, clear_n: usize) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(clear_n as u8);
        self._split(pattern, false, false, Some(n))
    }

    fn _rsplit(
        &self,
        pattern: Vec<FheAsciiChar>,
        is_inclusive: bool,
        is_terminator: bool,
        n: Option<FheAsciiChar>,
    ) -> FheSplit {
        let max_buffer_size = self.bytes.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut current_copy_buffer = zero.clone();
        let mut stop_counter_increment = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

        for i in (0..(self.bytes.len() - pattern.len())).rev() {
            // Copy ith character to the appropriate buffer
            for j in 0..max_no_buffers {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8);
                let copy_flag = enc_j.eq(&current_copy_buffer);
                result[j][i] = copy_flag.if_then_else(&self.bytes[i], &result[j][i]);
            }

            let mut pattern_found = one.clone();
            for j in 0..pattern.len() {
                let eql = self.bytes[i + j].eq(&pattern[j]);
                pattern_found &= eql;
            }

            // If its splitn stop after n splits
            match &n {
                None => {
                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = pattern_found
                        .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
                }
                Some(max_splits) => {
                    stop_counter_increment |= current_copy_buffer.eq(&(max_splits - &one));

                    // Here we know if the pattern is found for position i
                    // If its found we need to switch from copying to old buffer and start copying to new one
                    current_copy_buffer = (pattern_found & stop_counter_increment.flip())
                        .if_then_else(&(&current_copy_buffer + &one), &current_copy_buffer);
                }
            };
        }

        match &n {
            Some(max_splits) => {
                let to: Vec<FheAsciiChar> = "\0"
                    .repeat(pattern.len())
                    .as_bytes()
                    .iter()
                    .map(|b| FheAsciiChar::encrypt_trivial(*b))
                    .collect();
                let mut stop_replacing_pattern = zero.clone();

                for i in 0..max_no_buffers {
                    let enc_i = FheAsciiChar::encrypt_trivial(i as u8);
                    stop_replacing_pattern |= max_splits.eq(&(&enc_i + &one));

                    let current_string = FheString::from_vec(result[i].clone());
                    let current_string =
                        FheString::from_vec(bubble_zeroes_left(current_string.bytes));
                    let replacement_string = current_string.replace(pattern.clone(), to.clone());

                    // Don't remove pattern from (n-1)th buffer
                    for j in 0..max_buffer_size {
                        result[i][j] = stop_replacing_pattern
                            .if_then_else(&current_string.bytes[j], &replacement_string.bytes[j]);
                    }
                }
            }
            None => {
                if !is_inclusive {
                    let to: Vec<FheAsciiChar> = "\0"
                        .repeat(pattern.len())
                        .as_bytes()
                        .iter()
                        .map(|b| FheAsciiChar::encrypt_trivial(*b))
                        .collect();

                    // Since the pattern is also copied at the end of each buffer go through them and delete it
                    for i in 0..max_no_buffers {
                        let current_string = FheString::from_vec(result[i].clone());
                        let replacement_string =
                            current_string.replace(pattern.clone(), to.clone());
                        result[i] = replacement_string.bytes;
                    }
                } else {
                    for i in 0..max_no_buffers {
                        let new_buf = bubble_zeroes_left(result[i].clone());
                        result[i] = new_buf;
                    }
                }

                // Zero out the last populated buffer if it starts with the pattern
                if is_terminator {
                    let mut non_zero_buffer_found = zero.clone();
                    for i in (0..max_no_buffers).rev() {
                        let mut is_buff_zero = one.clone();

                        for j in 0..max_buffer_size {
                            is_buff_zero &= result[i][j].eq(&zero);
                        }

                        // Here we know if the current buffer is non-empty
                        // Now we have to check if it starts with the pattern
                        let starts_with_pattern =
                            FheString::from_vec(result[i].clone()).starts_with(pattern.clone());
                        let should_delete = starts_with_pattern
                            & is_buff_zero.clone()
                            & non_zero_buffer_found.flip();

                        for j in 0..max_buffer_size {
                            result[i][j] = should_delete.if_then_else(&zero, &result[i][j])
                        }
                        non_zero_buffer_found |= is_buff_zero.flip();
                    }
                }
            }
        }

        FheSplit::new(result)
    }

    fn rsplit(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._rsplit(pattern, false, false, None)
    }

    fn rsplit_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.rsplit(pattern)
    }

    fn rsplitn(&self, pattern: Vec<FheAsciiChar>, n: FheAsciiChar) -> FheSplit {
        self._rsplit(pattern, false, false, Some(n))
    }

    fn rsplitn_clear(&self, clear_pattern: &str, clear_n: usize) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(clear_n as u8);
        self._rsplit(pattern, false, false, Some(n))
    }

    fn rsplit_once(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        let n = FheAsciiChar::encrypt_trivial(2u8);
        self._rsplit(pattern, false, false, Some(n))
    }

    fn rsplit_once_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(2u8);
        self._rsplit(pattern, false, false, Some(n))
    }

    fn rsplit_terminator(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._rsplit(pattern, false, true, None)
    }

    fn rsplit_terminator_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self._rsplit(pattern, false, true, None)
    }
}

// Concatenation
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXorAssign, Not, Sub, SubAssign,
};

impl Add for FheString {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let mut result = self.bytes.clone();
        let mut clone_other = other.bytes.clone();
        result.append(&mut clone_other);
        FheString::from_vec(bubble_zeroes_left(result))
    }
}

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let my_string_plain1 = ".A.B.C.";
    let pattern_plain = ".";
    let pattern: Vec<FheAsciiChar> = pattern_plain
        .as_bytes()
        .iter()
        .map(|b| FheAsciiChar::encrypt(*b, &client_key))
        .collect();

    let n = FheAsciiChar::encrypt_trivial(3u8);

    let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    let fhe_split = my_string.rsplit_terminator(pattern);
    let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    assert_eq!(
        plain_split,
        vec![
            "\0\0\0\0\0\0\0",
            "C\0\0\0\0\0\0",
            "B\0\0\0\0\0\0",
            "A\0\0\0\0\0\0",
            "\0\0\0\0\0\0\0",
            "\0\0\0\0\0\0\0",
            "\0\0\0\0\0\0\0",
            "\0\0\0\0\0\0\0",
            "\0\0\0\0\0\0\0",
            "\0\0\0\0\0\0\0"
        ]
    );
}

#[cfg(test)]
mod test {
    use crate::{FheAsciiChar, FheSplit, FheString, STRING_PADDING};
    use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, ServerKey};

    fn setup_test() -> (ClientKey, ServerKey) {
        let config = ConfigBuilder::all_disabled()
            .enable_default_integers()
            .build();

        generate_keys(config)
    }

    #[test]
    fn valid_contains() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let heistack = FheString::encrypt("awesomezamaisawesome", &client_key, 3);
        let needle: Vec<FheAsciiChar> = "zama"
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let res = heistack.contains(needle);
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn invalid_contains() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let heistack = FheString::encrypt("hello world", &client_key, 3);
        let needle: Vec<FheAsciiChar> = "zama"
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let res = heistack.contains(needle);
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 0u8);
    }

    #[test]
    fn invalid_ends_with() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let heistack = FheString::encrypt("hello world", &client_key, STRING_PADDING);
        let pattern: Vec<FheAsciiChar> = "worl"
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let res = heistack.ends_with(pattern, STRING_PADDING);
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 0u8);
    }

    #[test]
    fn valid_ends_with() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let heistack = FheString::encrypt("hello world", &client_key, STRING_PADDING);
        let pattern: Vec<FheAsciiChar> = "world"
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let res = heistack.ends_with(pattern, STRING_PADDING);
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn uppercase() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("zama IS awesome", &client_key, STRING_PADDING);
        let my_string_upper = my_string.to_upper();

        let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "ZAMA IS AWESOME");
    }

    #[test]
    fn repeat() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("abc", &client_key, STRING_PADDING);
        let encrypted_repetitions = FheAsciiChar::encrypt(3u8, &client_key);

        let my_string_upper = my_string.repeat(encrypted_repetitions);
        let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "abcabcabc\0\0\0\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn replace1() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("hello world world test", &client_key, STRING_PADDING);
        let from = "world"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let to = "abc"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let my_string_upper = my_string.replace(from, to);
        let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "hello abc abc test\0\0\0\0");
    }

    #[test]
    fn replace2() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("hello abc abc test", &client_key, STRING_PADDING);
        let from = "abc"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let to = "world"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let my_string_upper = my_string.replace(from, to);
        let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "hello world world test\0\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn replacen() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("hello abc abc test", &client_key, STRING_PADDING);
        let n = FheAsciiChar::encrypt(1u8, &client_key);
        let from = "abc"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let to = "world"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let my_string_upper = my_string.replacen(from, to, n);
        let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "hello world abc test\0\0\0\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn lowercase() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("ZAMA is AWESOME 1234", &client_key, STRING_PADDING);

        let my_string_upper = my_string.to_lower();
        let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "zama is awesome 1234");
    }

    #[test]
    fn trim_end() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("ZA MA\n\t \r\x0C", &client_key, STRING_PADDING);

        let res_string = my_string.trim_end();
        let verif_string = res_string.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "ZA MA\0\0\0\0\0");
    }

    #[test]
    fn do_not_trim_end() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("\nZA MA", &client_key, STRING_PADDING);

        let result_string = my_string.trim_end();
        let verif_string = result_string.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "\nZA MA");
    }

    #[test]
    fn trim_start() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("\n\nZA MA", &client_key, STRING_PADDING);

        let res_string = my_string.trim_start();
        let verif_string = res_string.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "ZA MA\0\0");
    }

    #[test]
    fn trim() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("\n\nhello world!   ", &client_key, STRING_PADDING);

        let res_string = my_string.trim();
        let verif_string = res_string.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "hello world!\0\0\0\0\0");
    }

    #[test]
    fn is_empty() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("", &client_key, STRING_PADDING);

        let res = my_string.is_empty();
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn is_not_empty() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("a", &client_key, STRING_PADDING);

        let res = my_string.is_empty();
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 0u8);
    }

    #[test]
    fn valid_length1() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("a", &client_key, STRING_PADDING);

        let res = my_string.len();
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn valid_length2() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("some arbitrary string", &client_key, STRING_PADDING);

        let res = my_string.len();
        let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

        assert_eq!(dec, 21u8);
    }

    #[test]
    fn rfind() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("hello abc abc test", &client_key, STRING_PADDING);
        let pattern = "abc"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let enc_pattern_position = my_string.rfind(pattern);
        let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
        assert_eq!(pattern_positioon, 10u8);
    }

    #[test]
    fn invalid_rfind() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt("hello test", &client_key, STRING_PADDING);
        let pattern = "abc"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let enc_pattern_position = my_string.rfind(pattern);
        let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
        assert_eq!(pattern_positioon, 255u8);
    }

    #[test]
    #[should_panic(expected = "Maximum supported size for find reached")]
    fn unsupported_size_rfind() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt(&"hello test".repeat(100), &client_key, STRING_PADDING);
        let pattern = "abc"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let _ = my_string.rfind(pattern);
    }

    #[test]
    fn find() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING);
        let pattern = "test"
            .bytes()
            .map(|b| FheAsciiChar::encrypt(b, &client_key))
            .collect::<Vec<FheAsciiChar>>();

        let enc_pattern_position = my_string.find(pattern);
        let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
        assert_eq!(pattern_positioon, 6u8);
    }

    #[test]
    fn eq() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string1 = FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING);
        let my_string2 =
            FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING + 20);

        let enc_pattern_position = my_string1.eq(my_string2);
        let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
        assert_eq!(pattern_positioon, 1u8);
    }

    #[test]
    fn eq_ignore_case() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string1 = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
        let my_string2 =
            FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING + 20);

        let enc_pattern_position = my_string1.eq_ignore_case(my_string2);
        let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
        assert_eq!(pattern_positioon, 1u8);
    }

    #[test]
    fn strip_prefix() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
        let pattern: Vec<FheAsciiChar> = "HELLO"
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string_processed = my_string.strip_prefix(pattern);
        let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, " test test HELLO\0\0\0\0\0");
    }

    #[test]
    fn strip_suffix() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);

        // Since the client knows the original string padding he can add it to the pattern without revealing the original length of pattern or my_string
        let pattern: Vec<FheAsciiChar> = format!("HELLO{}", "\0".repeat(STRING_PADDING))
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string_processed = my_string.strip_suffix(pattern);
        let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "HELLO test test \0\0\0\0\0");
    }

    #[test]
    fn dont_strip_suffix() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
        let pattern: Vec<FheAsciiChar> = "WORLD"
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string_processed = my_string.strip_suffix(pattern);
        let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "HELLO test test HELLO");
    }

    #[test]
    fn dont_strip_prefix() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
        let pattern: Vec<FheAsciiChar> = "WORLD"
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string_processed = my_string.strip_prefix(pattern);
        let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
        assert_eq!(verif_string, "HELLO test test HELLO");
    }

    #[test]
    fn concatenate() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string1 = FheString::encrypt(&"Hello", &client_key, STRING_PADDING);
        let my_string2 = FheString::encrypt(&", World!", &client_key, STRING_PADDING);

        let my_string_concatenated = my_string1 + my_string2;
        let verif_string = my_string_concatenated.decrypt(&client_key, STRING_PADDING);
        assert_eq!(
            verif_string,
            format!("Hello, World!{}", "\0".repeat(STRING_PADDING))
        );
    }

    #[test]
    fn less_than() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

        let actual = my_string1.lt(my_string2);
        let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

        let expected = (my_string_plain1 < my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn less_equal() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

        let actual = my_string1.le(my_string2);
        let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

        let expected = (my_string_plain1 <= my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn greater_than() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

        let actual = my_string1.gt(my_string2);
        let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

        let expected = (my_string_plain1 > my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn greater_equal() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

        let actual = my_string1.ge(my_string2);
        let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

        let expected = (my_string_plain1 >= my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn split() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = "Mary had a";
        let pattern_plain = " ";

        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.split(pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "Mary\0\0\0\0\0\0",
                "had\0\0\0\0\0\0\0",
                "a\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn split_inclusive() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = "Mary had a";
        let pattern_plain = " ";
        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.split_inclusive(pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "Mary \0\0\0\0\0",
                "had \0\0\0\0\0\0",
                "a\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn split_terminator() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = ".A.B.";
        let pattern_plain = ".";
        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.split_terminator(pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "\0\0\0\0\0",
                "A\0\0\0\0",
                "B\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn split_ascii_whitespace() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = " A\nB\t";

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.split_ascii_whitespace();
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "\0\0\0\0\0",
                "A\0\0\0\0",
                "B\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0",
                "\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn splitn() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = ".A.B.C.";
        let pattern_plain = ".";
        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let n = FheAsciiChar::encrypt_trivial(2u8);

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.splitn(pattern, n);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "\0\0\0\0\0\0\0",
                "A.B.C.\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn rplit() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = ".A.B.C.";
        let pattern_plain = ".";
        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.rsplit(pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "\0\0\0\0\0\0\0",
                "C\0\0\0\0\0\0",
                "B\0\0\0\0\0\0",
                "A\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn rplit_once() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = ".A.B.C.";
        let pattern_plain = ".";
        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.rsplit_once(pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "\0\0\0\0\0\0\0",
                ".A.B.C\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn rplitn() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = ".A.B.C.";
        let pattern_plain = ".";
        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let n = FheAsciiChar::encrypt_trivial(3u8);

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.rsplitn(pattern, n);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "\0\0\0\0\0\0\0",
                "C\0\0\0\0\0\0",
                ".A.B\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0"
            ]
        );
    }

    #[test]
    fn rplitn_terminator() {
        let (client_key, server_key) = setup_test();
        set_server_key(server_key);

        let my_string_plain1 = ".A.B.C.";
        let pattern_plain = ".";
        let pattern: Vec<FheAsciiChar> = pattern_plain
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt(*b, &client_key))
            .collect();

        let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
        let fhe_split = my_string.rsplit_terminator(pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

        assert_eq!(
            plain_split,
            vec![
                "\0\0\0\0\0\0\0",
                "C\0\0\0\0\0\0",
                "B\0\0\0\0\0\0",
                "A\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0",
                "\0\0\0\0\0\0\0"
            ]
        );
    }
}
