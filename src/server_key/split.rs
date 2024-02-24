use crate::ciphertext::fheasciichar::FheAsciiChar;
use crate::ciphertext::fhesplit::FheSplit;
use crate::ciphertext::fhestring::FheString;
use crate::ciphertext::public_parameters::PublicParameters;
use crate::utils;

use super::MyServerKey;

impl MyServerKey {
    fn rsplit_pattern_matching(
        &self,
        i: usize,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        ignore_pattern_mask: &mut [FheAsciiChar],
        zero: &FheAsciiChar,
        one: &FheAsciiChar,
    ) -> FheAsciiChar {
        let mut pattern_found = one.clone();

        // This is needed when we are using an empty pattern and we have padding.
        // In such case we should not match the pattern to the padding
        // But the exception apparently is the last padding character before the
        // real string starts 🤔
        if pattern.is_empty() {
            // if current char is \0 do not match empty pattern
            let is_current_char_padding = string[i].eq(&self.key, zero);
            // Avoid out of bounds exceptions
            if i >= 1 {
                let is_previous_char_non_padding = string[i - 1].ne(&self.key, zero);
                let should_match_end_of_string =
                    is_previous_char_non_padding.bitand(&self.key, &is_current_char_padding);

                // Match the last \0 before the string
                pattern_found = should_match_end_of_string.if_then_else(&self.key, one, zero);
                pattern_found = pattern_found.bitor(
                    &self.key,
                    &is_current_char_padding.if_then_else(&self.key, zero, one),
                );
            } else {
                pattern_found = is_current_char_padding.if_then_else(&self.key, zero, one);
            }
        }
        // if pattern is larger than the string or
        // if searching the pattern would case index out of bounds then
        // assume pattern is not found
        else if pattern.len() > string.len() || i + pattern.len() >= string.len() {
            pattern_found = zero.clone();
        }
        // Actually search for pattern
        else {
            for (j, pattern_char) in pattern.iter().enumerate() {
                let eql = string[i + j].eq(&self.key, pattern_char);
                pattern_found = pattern_found.bitand(&self.key, &eql);
                pattern_found = pattern_found.bitand(&self.key, &ignore_pattern_mask[i + j]);
            }
        }

        // Where this pattern matched in the string we are not allowed to match again
        for j in 0..pattern.len() {
            if i + j < string.len() {
                ignore_pattern_mask[i + j] = ignore_pattern_mask[i + j]
                    .bitand(&self.key, &pattern_found.if_then_else(&self.key, zero, one));
            }
        }

        pattern_found
    }

    fn split_pattern_matching(
        &self,
        i: usize,
        string: &FheString,
        pattern: &Vec<FheAsciiChar>,
        ignore_pattern_mask: &mut [FheAsciiChar],
        zero: &FheAsciiChar,
        one: &FheAsciiChar,
    ) -> FheAsciiChar {
        let max_buffer_size = string.len(); // when a single buffer holds the whole input

        let mut pattern_found = one.clone();
        // If pattern is larger than the string or
        // if searching for the pattern would cause underflow then
        // assume pattern is not found
        if pattern.len() > string.len() || (i as i64) < (pattern.len() as i64) - 1 {
            pattern_found = zero.clone();
        }
        // Actually search for pattern
        else {
            for (j, pattern_char) in pattern.iter().enumerate() {
                let string_index = i - pattern.len() + 1 + j;
                let eql = string[string_index].eq(&self.key, pattern_char);
                pattern_found = pattern_found.bitand(&self.key, &eql);
                pattern_found = pattern_found.bitand(&self.key, &ignore_pattern_mask[string_index]);
            }
        }

        // Where this pattern matched in the string we are not allowed to match again
        for j in 0..pattern.len() {
            if i + j < max_buffer_size {
                ignore_pattern_mask[i + j] = ignore_pattern_mask[i + j]
                    .bitand(&self.key, &pattern_found.if_then_else(&self.key, zero, one));
            }
        }
        pattern_found
    }

    fn copy_logic(
        &self,
        i: usize,
        n: &Option<FheAsciiChar>,
        string: &FheString,
        result: &mut [Vec<FheAsciiChar>],
        public_parameters: &PublicParameters,
        flags: (&FheAsciiChar, &FheAsciiChar),
    ) {
        let allow_copying = &flags.0;
        let current_copy_buffer = &flags.1;

        let max_buffer_size = string.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        // Copy ith character to the appropriate buffer
        for (j, result_item) in result.iter_mut().enumerate().take(max_no_buffers) {
            let enc_j = FheAsciiChar::encrypt_trivial(j as u8, public_parameters, &self.key);
            let mut copy_flag = enc_j.eq(&self.key, current_copy_buffer);

            // Edge case, if n = 0 we never copy anything
            if n.is_some() {
                copy_flag = copy_flag.bitand(&self.key, allow_copying);
            }

            result_item[i] = copy_flag.if_then_else(&self.key, &string[i], &result_item[i]);
        }
    }

    fn handle_n_case(
        &self,
        pattern_found: &FheAsciiChar,
        n: &Option<FheAsciiChar>,
        current_copy_buffer: &mut FheAsciiChar,
        stop_counter_increment: &mut FheAsciiChar,
        one: &FheAsciiChar,
        public_parameters: &PublicParameters,
    ) {
        // If its splitn stop after n splits
        match &n {
            None => {
                // Here we know if the pattern is found for position i
                // If its found we need to switch from copying to old buffer and start copying
                // to new one
                *current_copy_buffer = pattern_found.if_then_else(
                    &self.key,
                    &current_copy_buffer.add(&self.key, one),
                    current_copy_buffer,
                );
            }
            Some(max_splits) => {
                *stop_counter_increment = stop_counter_increment.bitor(
                    &self.key,
                    &current_copy_buffer.eq(&self.key, &max_splits.sub(&self.key, one)),
                );

                // Here we know if the pattern is found for position i
                // If its found we need to switch from copying to old buffer and start copying
                // to new one
                *current_copy_buffer = (pattern_found.bitand(
                    &self.key,
                    &stop_counter_increment.flip(&self.key, public_parameters),
                ))
                .if_then_else(
                    &self.key,
                    &current_copy_buffer.add(&self.key, one),
                    current_copy_buffer,
                );
            }
        };
    }

    fn clear_pattern_from_result(
        &self,
        n: &Option<FheAsciiChar>,
        result: &mut Vec<Vec<FheAsciiChar>>,
        pattern: &Vec<FheAsciiChar>,
        public_parameters: &PublicParameters,
        constants: (&FheAsciiChar, &FheAsciiChar),
        flags: (bool, bool),
    ) {
        let zero = constants.0;
        let one = constants.1;

        let is_inclusive = flags.0;
        let is_terminator = flags.1;

        let max_buffer_size = result.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        match &n {
            Some(max_splits) => {
                let to: Vec<FheAsciiChar> = "\0"
                    .repeat(pattern.len())
                    .as_bytes()
                    .iter()
                    .map(|b| FheAsciiChar::encrypt_trivial(*b, public_parameters, &self.key))
                    .collect();
                let mut stop_replacing_pattern = zero.clone();

                for (i, result_buffer) in result.iter_mut().enumerate().take(max_no_buffers) {
                    let enc_i =
                        FheAsciiChar::encrypt_trivial(i as u8, public_parameters, &self.key);
                    stop_replacing_pattern = stop_replacing_pattern.bitor(
                        &self.key,
                        &max_splits.eq(&self.key, &enc_i.add(&self.key, one)),
                    );

                    let current_string =
                        FheString::from_vec(result_buffer.clone(), public_parameters, &self.key);
                    let current_string =
                        utils::bubble_zeroes_right(current_string, &self.key, public_parameters);
                    let replacement_string =
                        self.replace(&current_string, pattern, &to, public_parameters);

                    // Don't remove pattern from (n-1)th buffer
                    for (j, result_buffer_char) in
                        result_buffer.iter_mut().enumerate().take(max_buffer_size)
                    {
                        *result_buffer_char = stop_replacing_pattern.if_then_else(
                            &self.key,
                            &current_string[j],
                            &replacement_string[j],
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
                        .map(|b| FheAsciiChar::encrypt_trivial(*b, public_parameters, &self.key))
                        .collect();

                    // Since the pattern is also copied at the end of each buffer go through them
                    // and delete it
                    for result_buffer in result.iter_mut().take(max_no_buffers) {
                        let current_string = FheString::from_vec(
                            result_buffer.clone(),
                            public_parameters,
                            &self.key,
                        );
                        let replacement_string =
                            self.replace(&current_string, pattern, &to, public_parameters);
                        *result_buffer = replacement_string.get_bytes();
                    }
                } else {
                    for result_buffer in result.iter_mut().take(max_no_buffers) {
                        let new_buf = utils::bubble_zeroes_right(
                            FheString::from_vec(
                                result_buffer.clone(),
                                public_parameters,
                                &self.key,
                            ),
                            &self.key,
                            public_parameters,
                        );
                        *result_buffer = new_buf.get_bytes();
                    }
                }

                // Zero out the last populated buffer if it starts with the pattern
                if is_terminator {
                    let mut non_zero_buffer_found = zero.clone();
                    for i in (0..max_no_buffers).rev() {
                        let mut is_buff_zero = one.clone();

                        for j in 0..max_buffer_size {
                            is_buff_zero =
                                is_buff_zero.bitand(&self.key, &result[i][j].eq(&self.key, zero));
                        }

                        // Here we know if the current buffer is non-empty
                        // Now we have to check if it starts with the pattern
                        let starts_with_pattern = self.starts_with(
                            &FheString::from_vec(result[i].clone(), public_parameters, &self.key),
                            pattern,
                            public_parameters,
                        );
                        let should_delete =
                            starts_with_pattern.bitand(&self.key, &is_buff_zero).bitand(
                                &self.key,
                                &non_zero_buffer_found.flip(&self.key, public_parameters),
                            );

                        for j in 0..max_buffer_size {
                            result[i][j] =
                                should_delete.if_then_else(&self.key, zero, &result[i][j])
                        }
                        non_zero_buffer_found = non_zero_buffer_found
                            .bitor(&self.key, &is_buff_zero.flip(&self.key, public_parameters));
                    }
                }
            }
        }
    }

    fn _rsplit(
        &self,
        mut string: FheString,
        pattern: Vec<FheAsciiChar>,
        is_inclusive: bool,
        is_terminator: bool,
        n: Option<FheAsciiChar>,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        // Compute constants
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters, &self.key);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_parameters, &self.key);

        // Pad the string to avoid edge cases
        string.push(zero.clone());

        let max_buffer_size = string.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let mut current_copy_buffer = zero.clone();
        let mut stop_counter_increment = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];
        let mut global_pattern_found = zero.clone();

        // Edge case flag, if n = 0 we ever copy anything
        let mut allow_copying = zero.clone();
        // Mask that stops overlapping patterns to match
        // for example string = "aaaa" and pattern = "aa"
        // without this flag the pattern would match more times than it should
        let mut ignore_pattern_mask = vec![one.clone(); max_buffer_size];

        // Edge case, if n = 0 we never copy anything
        if n.is_some() {
            let n_value = n.clone().unwrap();
            allow_copying = n_value.ne(&self.key, &zero);
        }

        for i in (0..(string.len())).rev() {
            // Modify result buffers by copying the apropriate character to the
            // apropriate buffer
            self.copy_logic(
                i,
                &n,
                &string,
                &mut result,
                public_parameters,
                (&allow_copying, &current_copy_buffer),
            );

            // Pattern matching logic
            let pattern_found = self.rsplit_pattern_matching(
                i,
                &string,
                &pattern,
                &mut ignore_pattern_mask,
                &zero,
                &one,
            );

            global_pattern_found = global_pattern_found.bitor(&self.key, &pattern_found);

            // Ignore pattern founds if we reached the apropriate number of splits in
            // the n case
            self.handle_n_case(
                &pattern_found,
                &n,
                &mut current_copy_buffer,
                &mut stop_counter_increment,
                &one,
                public_parameters,
            );
        }

        // After we are done with copying, we delete the pattern from the copy buffers
        // depending on the rsplit flavour and move all non \0 chars to the start of the string
        // This is the slowest part of the process
        self.clear_pattern_from_result(
            &n,
            &mut result,
            &pattern,
            public_parameters,
            (&zero, &one),
            (is_inclusive, is_terminator),
        );

        FheSplit::new(result, global_pattern_found, public_parameters, &self.key)
    }

    /// Splits a given `FheString` into multiple parts from the right, based on a specified pattern.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    /// let fhe_split = my_server_key.rsplit(&my_string, &pattern, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "C".to_owned(),
    ///             "B".to_owned(),
    ///             "A".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplit(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        self._rsplit(
            string.clone(),
            pattern.to_owned(),
            false,
            false,
            None,
            public_parameters,
        )
    }

    /// Splits a given `FheString` into multiple parts from the right, based on a specified
    ///  plaintext pattern.
    ///
    /// Same as `rsplit` but with a plaintext pattern.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let fhe_split = my_server_key.rsplit_clear(&my_string, &pattern_plain, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "C".to_owned(),
    ///             "B".to_owned(),
    ///             "A".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplit_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        self.rsplit(string, &pattern, public_parameters)
    }

    /// Splits a given `FheString` into a limited number of parts from the right, based on
    /// a specified pattern.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `n`: FheAsciiChar - The encrypted number of splits to perform.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    /// let n_plain = 3u8;
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    /// let n = FheAsciiChar::encrypt_trivial(n_plain, &public_parameters, &my_server_key.key);
    /// let fhe_split = my_server_key.rsplitn(&my_string, &pattern, n, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "C".to_owned(),
    ///             ".A.B".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplitn(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        n: FheAsciiChar,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        self._rsplit(
            string.clone(),
            pattern.to_owned(),
            false,
            false,
            Some(n),
            public_parameters,
        )
    }

    /// Splits a given `FheString` into a limited number of parts from the right, based on a
    ///  specified plaintext pattern and plaintext count.
    ///
    /// Same as `rsplitn` but with plaintext pattern and count.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    /// let n_plain = 3u8;
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    ///
    /// let fhe_split = my_server_key.rsplitn_clear(
    ///     &my_string,
    ///     &pattern_plain,
    ///     n_plain.into(),
    ///     &public_parameters,
    /// );
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "C".to_owned(),
    ///             ".A.B".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplitn_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        clear_n: usize,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(clear_n as u8, public_parameters, &self.key);
        self._rsplit(
            string.clone(),
            pattern,
            false,
            false,
            Some(n),
            public_parameters,
        )
    }

    /// Splits a given `FheString` into two parts from the right, based on a specified
    /// pattern.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    /// let fhe_split = my_server_key.rsplit_once(&my_string, &pattern, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             ".A.B.C".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplit_once(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let n = FheAsciiChar::encrypt_trivial(2u8, public_parameters, &self.key);
        self._rsplit(
            string.clone(),
            pattern.to_owned(),
            false,
            false,
            Some(n),
            public_parameters,
        )
    }

    /// Splits a given `FheString` into two parts from the right, based on a specified plaintext
    /// pattern.
    ///
    /// Same as `rsplit_once` but with a plaintext pattern.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    ///
    /// let fhe_split = my_server_key.rsplit_once_clear(&my_string, &pattern_plain, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             ".A.B.C".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplit_once_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(2u8, public_parameters, &self.key);
        self._rsplit(
            string.clone(),
            pattern,
            false,
            false,
            Some(n),
            public_parameters,
        )
    }

    /// Splits a given `FheString` into multiple parts from the right, based on a specified pattern,
    /// excluding the trailing empty string if any.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = "....A.B.C.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    ///
    /// let fhe_split = my_server_key.rsplit_terminator(&my_string, &pattern, &public_parameters);
    /// let mut plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "C".to_owned(),
    ///             "B".to_owned(),
    ///             "A".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplit_terminator(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        self._rsplit(
            string.clone(),
            pattern.to_owned(),
            false,
            true,
            None,
            public_parameters,
        )
    }

    /// Splits a given `FheString` into multiple parts from the right, based on a specified
    /// plaintext pattern, excluding the trailing empty string if any.
    ///
    /// Same as `rsplit_terminator` but with a plaintext pattern.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = "....A.B.C.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let fhe_split =
    ///     my_server_key.rsplit_terminator_clear(&my_string, &pattern_plain, &public_parameters);
    /// let mut plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "C".to_owned(),
    ///             "B".to_owned(),
    ///             "A".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn rsplit_terminator_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        self._rsplit(
            string.clone(),
            pattern,
            false,
            true,
            None,
            public_parameters,
        )
    }

    fn _split(
        &self,
        mut string: FheString,
        pattern: Vec<FheAsciiChar>,
        is_inclusive: bool,
        is_terminator: bool,
        n: Option<FheAsciiChar>,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        // Compute constants
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters, &self.key);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_parameters, &self.key);

        // Pad the string to avoid edge cases
        string.push(zero.clone());

        let max_buffer_size = string.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let mut current_copy_buffer = zero.clone();
        let mut stop_counter_increment = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];
        let mut global_pattern_found = zero.clone();

        // Edge case flag, if n = 0 we ever copy anything
        let mut allow_copying = zero.clone();

        // Mask that stops overlapping patterns to match
        // for example string = "aaaa" and pattern = "aa"
        // without this flag the pattern would match more times than it should
        let mut ignore_pattern_mask = vec![one.clone(); max_buffer_size];

        // Edge case, if n = 0 we ever copy anything
        if n.is_some() {
            let n_value = n.clone().unwrap();
            allow_copying = n_value.ne(&self.key, &zero);
        }

        // Handle edge case when 1 < n <= string.len() and pattern is empty
        // In this case we should leave an empty buffer effectively skipping the first one
        // Example1:  "eeeeee".splitn(2, "") --> ["", "eeeeee"]
        // Example2:  "eeeeee".splitn(3, "") --> ["", "e", "eeeee"]
        if pattern.is_empty() && n.is_some() {
            let n_value = n.clone().unwrap();
            let enc_len = self.len(&string, public_parameters);

            let should_skip_first_buffer = n_value
                .gt(&self.key, &one)
                .bitand(&self.key, &n_value.le(&self.key, &enc_len));

            current_copy_buffer = should_skip_first_buffer.if_then_else(
                &self.key,
                &FheAsciiChar::encrypt_trivial(1u8, public_parameters, &self.key),
                &current_copy_buffer,
            );
        }

        for i in 0..(string.len()) {
            // Modify result buffers by copying the apropriate character to the
            // apropriate buffer
            self.copy_logic(
                i,
                &n,
                &string,
                &mut result,
                public_parameters,
                (&allow_copying, &current_copy_buffer),
            );

            let pattern_found = self.split_pattern_matching(
                i,
                &string,
                &pattern,
                &mut ignore_pattern_mask,
                &zero,
                &one,
            );

            global_pattern_found = global_pattern_found.bitor(&self.key, &pattern_found);

            // Ignore pattern founds if we reached the apropriate number of splits in
            // the n case
            self.handle_n_case(
                &pattern_found,
                &n,
                &mut current_copy_buffer,
                &mut stop_counter_increment,
                &one,
                public_parameters,
            );
        }

        // After we are done with copying, we delete the pattern from the copy buffers
        // depending on the rsplit flavour and move all non \0 chars to the start of the string
        // This is the slowest part of the process
        self.clear_pattern_from_result(
            &n,
            &mut result,
            &pattern,
            public_parameters,
            (&zero, &one),
            (is_inclusive, is_terminator),
        );

        FheSplit::new(result, global_pattern_found, public_parameters, &self.key)
    }

    /// Splits a given `FheString` into multiple parts based on a specified pattern.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = " Mary had a";
    /// let pattern_plain = " ";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    /// let fhe_split = my_server_key.split(&my_string, &pattern, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "Mary".to_owned(),
    ///             "had".to_owned(),
    ///             "a".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn split(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        self._split(
            string.clone(),
            pattern.to_owned(),
            false,
            false,
            None,
            public_parameters,
        )
    }

    /// Splits a given `FheString` into multiple parts based on a specified plaintext pattern.
    ///
    /// Same as `split` but with a plaintext pattern.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = " Mary had a";
    /// let pattern_plain = " ";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let fhe_split = my_server_key.split_clear(&my_string, &pattern_plain, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "Mary".to_owned(),
    ///             "had".to_owned(),
    ///             "a".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn split_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        self.split(string, &pattern, public_parameters)
    }

    /// Splits a given `FheString` into multiple parts based on a specified pattern,
    /// including the pattern in the split parts.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = "Mary had a";
    /// let pattern_plain = " ";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    ///
    /// let fhe_split = my_server_key.split_inclusive(&my_string, &pattern, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "Mary ".to_owned(),
    ///             "had ".to_owned(),
    ///             "a".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn split_inclusive(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        self._split(
            string.clone(),
            pattern.to_owned(),
            true,
            false,
            None,
            public_parameters,
        )
    }

    /// Splits a given `FheString` into multiple parts based on a specified plaintext pattern,
    /// including the pattern in the split parts.
    ///
    /// Same as `split_inclusive` but with a plaintext pattern.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = "Mary had a";
    /// let pattern_plain = " ";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let fhe_split =
    ///     my_server_key.split_inclusive_clear(&my_string, &pattern_plain, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "Mary ".to_owned(),
    ///             "had ".to_owned(),
    ///             "a".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn split_inclusive_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        self.split_inclusive(string, &pattern, public_parameters)
    }

    /// Splits a given `FheString` into multiple parts based on a specified pattern,
    /// excluding the trailing empty string if any.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    ///
    /// let fhe_split = my_server_key.split_terminator(&my_string, &pattern, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "A".to_owned(),
    ///             "B".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn split_terminator(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        self._split(
            string.clone(),
            pattern.to_owned(),
            false,
            true,
            None,
            public_parameters,
        )
    }

    /// Splits a given `FheString` into multiple parts based on a specified plaintext pattern,
    /// excluding the trailing empty string if any.
    ///
    /// Same as `split_terminator` but with a plaintext pattern.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.";
    /// let pattern_plain = ".";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    ///
    /// let fhe_split =
    ///     my_server_key.split_terminator_clear(&my_string, &pattern_plain, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "A".to_owned(),
    ///             "B".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn split_terminator_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        self._split(
            string.clone(),
            pattern.to_owned(),
            false,
            true,
            None,
            public_parameters,
        )
    }

    /// Splits a given `FheString` into multiple parts based on ASCII whitespace characters.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = " A\nB\t";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    ///
    /// let fhe_split = my_server_key.split_ascii_whitespace(&my_string, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "A".to_owned(),
    ///             "B".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn split_ascii_whitespace(
        &self,
        string: &FheString,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let max_buffer_size = string.len(); // when a single buffer holds the whole input
        let max_no_buffers = max_buffer_size; // when all buffers hold an empty value

        let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters, &self.key);
        let one = FheAsciiChar::encrypt_trivial(1u8, public_parameters, &self.key);
        let mut current_copy_buffer = zero.clone();
        let mut result = vec![vec![zero.clone(); max_buffer_size]; max_no_buffers];
        let mut previous_was_whitespace =
            FheAsciiChar::encrypt_trivial(1u8, public_parameters, &self.key);
        let mut global_pattern_found = zero.clone();

        for i in 0..(string.len()) {
            let pattern_found = string[i].is_whitespace(&self.key, public_parameters);
            global_pattern_found = global_pattern_found.bitor(&self.key, &pattern_found);

            let should_increment_buffer = pattern_found.bitand(
                &self.key,
                &previous_was_whitespace.flip(&self.key, public_parameters),
            );

            // Here we know if the pattern is found for position i
            // If its found we need to switch from copying to old buffer and start copying
            // to new one
            current_copy_buffer = should_increment_buffer.if_then_else(
                &self.key,
                &current_copy_buffer.add(&self.key, &one),
                &current_copy_buffer,
            );

            // Copy ith character to the appropriate buffer
            for (j, result_buffer) in result.iter_mut().enumerate().take(max_no_buffers) {
                let enc_j = FheAsciiChar::encrypt_trivial(j as u8, public_parameters, &self.key);
                let mut copy_flag = enc_j.eq(&self.key, &current_copy_buffer);
                copy_flag = copy_flag.bitand(
                    &self.key,
                    &string[i]
                        .is_whitespace(&self.key, public_parameters)
                        .flip(&self.key, public_parameters),
                ); // copy if its not whitespace
                result_buffer[i] = copy_flag.if_then_else(&self.key, &string[i], &result_buffer[i]);
            }

            previous_was_whitespace = pattern_found;
        }

        // Replace whitespace with \0
        for result_buffer in result.iter_mut().take(max_no_buffers) {
            for result_buffer_char in result_buffer.iter_mut().take(max_buffer_size) {
                let replace_with_zero =
                    result_buffer_char.is_whitespace(&self.key, public_parameters);
                *result_buffer_char =
                    replace_with_zero.if_then_else(&self.key, &zero, result_buffer_char);
            }
        }

        for result_buffer in result.iter_mut().take(max_no_buffers) {
            let new_buf = utils::bubble_zeroes_right(
                FheString::from_vec(result_buffer.clone(), public_parameters, &self.key),
                &self.key,
                public_parameters,
            );
            *result_buffer = new_buf.get_bytes();
        }

        FheSplit::new(result, global_pattern_found, public_parameters, &self.key)
    }

    /// Splits a given `FheString` into a limited number of parts based on a specified pattern.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string to be split.
    /// * `pattern`: &[FheAsciiChar] - The unpadded pattern to split on.
    /// * `n`: FheAsciiChar - The encrypted number of splits to perform.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheSplit` - A struct containing the split parts of the string and a boolean flag
    /// indicating whether a split was made.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    /// let n_plain = 2u8;
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    /// let n = FheAsciiChar::encrypt_trivial(n_plain, &public_parameters, &my_server_key.key);
    ///
    /// let fhe_split = my_server_key.splitn(&my_string, &pattern, n, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "A.B.C.".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn splitn(
        &self,
        string: &FheString,
        pattern: &[FheAsciiChar],
        n: FheAsciiChar,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        self._split(
            string.clone(),
            pattern.to_owned(),
            false,
            false,
            Some(n),
            public_parameters,
        )
    }

    /// Splits a given `FheString` into a limited number of parts based on a specified
    /// plaintext pattern and plaintext count.
    ///
    /// Same as `splitn` but with plaintext pattern and count.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = ".A.B.C.";
    /// let pattern_plain = ".";
    /// let n_plain = 2u8;
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let fhe_split =
    ///     my_server_key.splitn_clear(&my_string, &pattern_plain, n_plain, &public_parameters);
    /// let plain_split = FheSplit::decrypt(fhe_split, &my_client_key);
    ///
    /// assert_eq!(
    ///     plain_split,
    ///     (
    ///         vec![
    ///             "".to_owned(),
    ///             "A.B.C.".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///             "".to_owned(),
    ///         ],
    ///         1u8
    ///     )
    /// );
    /// ```
    pub fn splitn_clear(
        &self,
        string: &FheString,
        clear_pattern: &str,
        clear_n: usize,
        public_parameters: &PublicParameters,
    ) -> FheSplit {
        let pattern = clear_pattern
            .bytes()
            .map(|b| FheAsciiChar::encrypt_trivial(b, public_parameters, &self.key))
            .collect::<Vec<FheAsciiChar>>();
        let n = FheAsciiChar::encrypt_trivial(clear_n as u8, public_parameters, &self.key);
        self._split(
            string.clone(),
            pattern,
            false,
            false,
            Some(n),
            public_parameters,
        )
    }
}
