use tfhe::{ClientKey, ServerKey, set_server_key};

use crate::{
    bubble_zeroes_left,
    ciphertext::{fheasciichar::FheAsciiChar, fhesplit::FheSplit, fhestring::FheString},
};

#[derive(Clone)]
pub struct MyServerKey {
    key: ServerKey,
}

impl MyServerKey {
    pub fn new(server_key: ServerKey) -> Self {
        set_server_key(server_key.clone());
        MyServerKey { key: server_key }
    }

    fn _rsplit(
        string: &FheString,
        pattern: Vec<FheAsciiChar>,
        is_inclusive: bool,
        is_terminator: bool,
        n: Option<FheAsciiChar>,
    ) -> FheSplit {
        let max_buffer_size = string.bytes.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8);
        let one = FheAsciiChar::encrypt_trivial(1u8);
        let mut current_copy_buffer = zero.clone();
        let mut stop_counter_increment = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];

        for i in (0..(string.bytes.len() - pattern.len())).rev() {
            // Copy ith character to the appropriate buffer
            for j in 0..max_no_buffers {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8);
                let copy_flag = enc_j.eq(&current_copy_buffer);
                result[j][i] = copy_flag.if_then_else(&string.bytes[i], &result[j][i]);
            }

            let mut pattern_found = one.clone();
            for j in 0..pattern.len() {
                let eql = string.bytes[i + j].eq(&pattern[j]);
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

    pub fn rsplit(string: &FheString, pattern: Vec<FheAsciiChar>) -> FheSplit {
        MyServerKey::_rsplit(string, pattern, false, false, None)
    }

    pub fn rsplit_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        MyServerKey::rsplit(string, pattern)
    }

    pub fn rsplitn(string: &FheString, pattern: Vec<FheAsciiChar>, n: FheAsciiChar) -> FheSplit {
        MyServerKey::_rsplit(string, pattern, false, false, Some(n))
    }

    pub fn rsplitn_clear(string: &FheString, clear_pattern: &str, clear_n: usize) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(clear_n as u8);
        MyServerKey::_rsplit(string, pattern, false, false, Some(n))
    }

    pub fn rsplit_once(string: &FheString, pattern: Vec<FheAsciiChar>) -> FheSplit {
        let n = FheAsciiChar::encrypt_trivial(2u8);
        MyServerKey::_rsplit(string, pattern, false, false, Some(n))
    }

    pub fn rsplit_once_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(2u8);
        MyServerKey::_rsplit(string, pattern, false, false, Some(n))
    }

    pub fn rsplit_terminator(string: &FheString, pattern: Vec<FheAsciiChar>) -> FheSplit {
        MyServerKey::_rsplit(string, pattern, false, true, None)
    }

    pub fn rsplit_terminator_clear(string: &FheString, clear_pattern: &str) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b))
            .collect::<Vec<FheAsciiChar>>();
        MyServerKey::_rsplit(string, pattern, false, true, None)
    }
}
