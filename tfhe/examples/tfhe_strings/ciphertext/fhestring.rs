use tfhe::{prelude::FheDecrypt, ClientKey};

use crate::{
    abs_difference, bubble_zeroes_left, FheAsciiChar, FheSplit, MAX_FIND_LENGTH, MAX_REPETITIONS,
};

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
    pub fn from_vec(bytes: Vec<FheAsciiChar>) -> Self {
        let cst = FheAsciiChar::encrypt_trivial(32u8);
        FheString { bytes, cst }
    }

    pub fn encrypt(string: &str, client_key: &ClientKey, padding: usize) -> Self {
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

    pub fn decrypt(&self, client_key: &ClientKey, padding: usize) -> String {
        let new_len = self.bytes.len().saturating_sub(padding);
        let trimed_bytes: Vec<FheAsciiChar> = self.bytes.clone()[..new_len].to_vec();

        let ascii_bytes = trimed_bytes
            .iter()
            .map(|fhe_b| fhe_b.inner.decrypt(client_key))
            .collect::<Vec<u8>>();
        String::from_utf8(ascii_bytes).unwrap()
    }

    pub fn to_upper(&self) -> Self {
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

    pub fn to_lower(&self) -> Self {
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

    pub fn contains(&self, needle: Vec<FheAsciiChar>) -> FheAsciiChar {
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

    pub fn contains_clear(&self, clear_needle: &str) -> FheAsciiChar {
        let needle = clear_needle
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b))
            .collect::<Vec<FheAsciiChar>>();

        self.contains(needle)
    }

    pub fn ends_with(&self, pattern: Vec<FheAsciiChar>, padding: usize) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(1u8);
        let mut j = pattern.len() - 1;
        for i in (self.bytes.len() - pattern.len()..self.bytes.len() - padding).rev() {
            let eql = self.bytes[i].eq(&pattern[j]);
            result &= eql;
            j -= 1;
        }
        result
    }

    pub fn ends_with_clear(&self, clear_pattern: &str, padding: usize) -> FheAsciiChar {
        let pattern = clear_pattern
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b))
            .collect::<Vec<FheAsciiChar>>();
        self.ends_with(pattern, padding)
    }

    pub fn starts_with(&self, pattern: Vec<FheAsciiChar>) -> FheAsciiChar {
        let mut result = FheAsciiChar::encrypt_trivial(1u8);
        for i in 0..pattern.len() {
            let eql = self.bytes[i].eq(&pattern[i]);
            result &= eql;
        }
        result
    }

    pub fn starts_with_clear(&self, clear_pattern: &str) -> FheAsciiChar {
        let pattern = clear_pattern
            .as_bytes()
            .iter()
            .map(|b| FheAsciiChar::encrypt_trivial(*b))
            .collect::<Vec<FheAsciiChar>>();
        self.starts_with(pattern)
    }

    pub fn is_empty(&self) -> FheAsciiChar {
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

    pub fn len(&self) -> FheAsciiChar {
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

    pub fn trim_end(&self) -> FheString {
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

    pub fn trim_start(&self) -> FheString {
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

    pub fn trim(&self) -> FheString {
        let result = self.trim_end();
        result.trim_start()
    }

    pub fn repeat_clear(&self, repetitions: usize) -> FheString {
        let mut result = self.bytes.clone();

        for _ in 0..repetitions - 1 {
            result.append(&mut self.bytes.clone());
        }

        FheString::from_vec(bubble_zeroes_left(result))
    }

    pub fn repeat(&self, repetitions: FheAsciiChar) -> FheString {
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

    pub fn replace(&self, from: Vec<FheAsciiChar>, to: Vec<FheAsciiChar>) -> FheString {
        let n = FheAsciiChar::encrypt_trivial(0u8);
        if from.len() >= to.len() {
            Self::handle_longer_from(self.bytes.clone(), from, to, n, false)
        } else {
            Self::handle_shorter_from(self.bytes.clone(), from, to, n, false)
        }
    }

    pub fn replace_clear(&self, clear_from: &str, clear_to: &str) -> FheString {
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

    pub fn replacen(
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

    pub fn rfind(&self, pattern: Vec<FheAsciiChar>) -> FheAsciiChar {
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

    pub fn rfind_clear(&self, clear_pattern: &str) -> FheAsciiChar {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();

        self.rfind(pattern)
    }

    pub fn find(&self, pattern: Vec<FheAsciiChar>) -> FheAsciiChar {
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

    pub fn find_clear(&self, clear_pattern: &str) -> FheAsciiChar {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();

        self.find(pattern)
    }

    pub fn eq(&self, other: FheString) -> FheAsciiChar {
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

    pub fn eq_ignore_case(&self, other: FheString) -> FheAsciiChar {
        let self_lowercase = self.to_lower();
        let other_lowercase = other.to_lower();

        self_lowercase.eq(other_lowercase)
    }

    pub fn strip_prefix(&self, pattern: Vec<FheAsciiChar>) -> FheString {
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

    pub fn strip_suffix(&self, pattern: Vec<FheAsciiChar>) -> FheString {
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

    pub fn strip_prefix_clear(&self, clear_pattern: &str) -> FheString {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.strip_prefix(pattern)
    }

    pub fn strip_suffix_clear(&self, clear_pattern: &str) -> FheString {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.strip_suffix(pattern)
    }

    pub fn comparison(&self, other: FheString, operation: Comparison) -> FheAsciiChar {
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

    pub fn lt(&self, other: FheString) -> FheAsciiChar {
        self.comparison(other, Comparison::LessThan)
    }

    pub fn le(&self, other: FheString) -> FheAsciiChar {
        self.comparison(other, Comparison::LessEqual)
    }

    pub fn gt(&self, other: FheString) -> FheAsciiChar {
        self.comparison(other, Comparison::GreaterThan)
    }

    pub fn ge(&self, other: FheString) -> FheAsciiChar {
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

    pub fn split(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._split(pattern, false, false, None)
    }

    pub fn split_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.split(pattern)
    }

    pub fn split_inclusive(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._split(pattern, true, false, None)
    }

    pub fn split_inclusive_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.split_inclusive(pattern)
    }

    pub fn split_terminator(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._split(pattern, false, true, None)
    }

    pub fn split_ascii_whitespace(&self) -> FheSplit {
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

    pub fn splitn(&self, pattern: Vec<FheAsciiChar>, n: FheAsciiChar) -> FheSplit {
        self._split(pattern, false, false, Some(n))
    }

    pub fn splitn_clear(&self, clear_pattern: &str, clear_n: usize) -> FheSplit {
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

    pub fn rsplit(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._rsplit(pattern, false, false, None)
    }

    pub fn rsplit_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self.rsplit(pattern)
    }

    pub fn rsplitn(&self, pattern: Vec<FheAsciiChar>, n: FheAsciiChar) -> FheSplit {
        self._rsplit(pattern, false, false, Some(n))
    }

    pub fn rsplitn_clear(&self, clear_pattern: &str, clear_n: usize) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(clear_n as u8);
        self._rsplit(pattern, false, false, Some(n))
    }

    pub fn rsplit_once(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        let n = FheAsciiChar::encrypt_trivial(2u8);
        self._rsplit(pattern, false, false, Some(n))
    }

    pub fn rsplit_once_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(2u8);
        self._rsplit(pattern, false, false, Some(n))
    }

    pub fn rsplit_terminator(&self, pattern: Vec<FheAsciiChar>) -> FheSplit {
        self._rsplit(pattern, false, true, None)
    }

    pub fn rsplit_terminator_clear(&self, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        self._rsplit(pattern, false, true, None)
    }
}

// Concatenation
use std::ops::Add;

impl Add for FheString {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let mut result = self.bytes.clone();
        let mut clone_other = other.bytes.clone();
        result.append(&mut clone_other);
        FheString::from_vec(bubble_zeroes_left(result))
    }
}
