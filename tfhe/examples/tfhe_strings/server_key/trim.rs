use crate::ciphertext::fheasciichar::FheAsciiChar;
use crate::ciphertext::fhestring::FheString;
use crate::ciphertext::public_parameters::PublicParameters;
use crate::utils;

use super::MyServerKey;

impl MyServerKey {
    /// Trims trailing whitespace from a `FheString`.
    ///
    /// This method removes any trailing whitespace characters from the provided `FheString`.
    /// Whitespace is defined as any character for which the `is_whitespace` method returns true.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string from which trailing whitespace will be trimmed.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheString` - A new `FheString` with trailing whitespace removed.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = "ZAMA\n\t \r\x0C";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let my_string_upper = my_server_key.trim_end(&my_string, &public_parameters);
    /// let actual = my_client_key.decrypt(my_string_upper);
    ///
    /// assert_eq!(actual, "ZAMA");
    /// ```
    pub fn trim_end(&self, string: &FheString, public_parameters: &PublicParameters) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters, &self.key);

        let mut stop_trim_flag = zero.clone();
        let mut result = vec![zero.clone(); string.len()];

        // Replace whitespace with \0 starting from the end
        for i in (0..string.len()).rev() {
            let is_not_zero = string[i].ne(&self.key, &zero);

            let is_not_whitespace = string[i]
                .is_whitespace(&self.key, public_parameters)
                .flip(&self.key, public_parameters);
            stop_trim_flag = stop_trim_flag.bitor(
                &self.key,
                &is_not_whitespace.bitand(&self.key, &is_not_zero),
            );
            result[i] = stop_trim_flag.if_then_else(&self.key, &string[i], &zero);
        }

        FheString::from_vec(result, public_parameters, &self.key)
    }

    /// Trims leading whitespace from a `FheString`.
    ///
    /// This method removes any leading whitespace characters from the provided `FheString`.
    /// Whitespace is defined as any character for which the `is_whitespace` method returns true.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string from which leading whitespace will be trimmed.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheString` - A new `FheString` with leading whitespace removed.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = "ZAMA\n\t \r\x0C";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let my_string_upper = my_server_key.trim_end(&my_string, &public_parameters);
    /// let actual = my_client_key.decrypt(my_string_upper);
    ///
    /// assert_eq!(actual, "ZAMA");
    /// ```
    pub fn trim_start(
        &self,
        string: &FheString,
        public_parameters: &PublicParameters,
    ) -> FheString {
        let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters, &self.key);

        let mut stop_trim_flag = zero.clone();
        let mut result = FheString::from_vec(
            vec![zero.clone(); string.len()],
            public_parameters,
            &self.key,
        );

        // Replace whitespace with \0 starting from the start
        for (i, result_char) in result.iter_mut().enumerate().take(string.len()) {
            let is_not_zero = string[i].ne(&self.key, &zero);
            let is_not_whitespace = string[i]
                .is_whitespace(&self.key, public_parameters)
                .flip(&self.key, public_parameters);

            stop_trim_flag = stop_trim_flag.bitor(
                &self.key,
                &is_not_whitespace.bitand(&self.key, &is_not_zero),
            );
            *result_char = stop_trim_flag.if_then_else(&self.key, &string[i], &zero)
        }

        utils::bubble_zeroes_left(result, &self.key, public_parameters)
    }

    /// Trims both leading and trailing whitespace from a `FheString`.
    ///
    /// This method removes both leading and trailing whitespace characters from the provided
    /// `FheString`. It first trims the trailing whitespace using `trim_end` and then trims the
    /// leading whitespace using `trim_start`.
    ///
    /// # Arguments
    /// * `string`: &FheString - The string from which both leading and trailing whitespace will be
    /// trimmed.
    /// * `public_parameters`: &PublicParameters - Public parameters for FHE operations.
    ///
    /// # Returns
    /// `FheString` - A new `FheString` with both leading and trailing whitespace removed.
    ///
    /// # Example:
    /// ```
    /// let my_string_plain = "\nZAMA\n\t";
    ///
    /// let my_string = my_client_key.encrypt(
    ///     my_string_plain,
    ///     STRING_PADDING,
    ///     &public_parameters,
    ///     &my_server_key.key,
    /// );
    /// let my_string_upper = my_server_key.trim(&my_string, &public_parameters);
    /// let actual = my_client_key.decrypt(my_string_upper);
    ///
    /// assert_eq!(actual, "ZAMA");
    /// ```
    pub fn trim(&self, string: &FheString, public_parameters: &PublicParameters) -> FheString {
        let result = self.trim_end(string, public_parameters);
        self.trim_start(&result, public_parameters)
    }
}
