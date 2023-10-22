use ciphertext::fheasciichar::FheAsciiChar;
use tfhe::{generate_keys, ConfigBuilder};

use crate::ciphertext::fhesplit::FheSplit;
use crate::ciphertext::fhestring::FheString;
use crate::server_key::MyServerKey;

const STRING_PADDING: usize = 3;
const MAX_REPETITIONS: usize = 4;
const MAX_FIND_LENGTH: usize = 255;

mod ciphertext;
mod client_key;
mod server_key;

use client_key::MyClientKey;

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

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_key) = generate_keys(config);

    let my_client_key = MyClientKey::new(client_key);
    let _ = MyServerKey::new(server_key);

    let my_string_plain = "....A.B.C.";
    let pattern_plain = ".";

    let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    let fhe_split = MyServerKey::rsplit_terminator(&my_string, &pattern);
    let mut plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    // In this case plain_split always has a leading empty string, so the client can safely ignore it
    plain_split.remove(0);

    let expected: Vec<&str> = my_string_plain.rsplit_terminator(pattern_plain).collect();

    assert_eq!(plain_split[..expected.len()], expected);
}

#[cfg(test)]
mod test {
    use crate::{FheAsciiChar, FheSplit, FheString, STRING_PADDING};
    use crate::{MyClientKey, MyServerKey};
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

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("awesomezamaisawesome", 3);
        let needle = my_client_key.encrypt_no_padding("zama");

        let res = MyServerKey::contains(&heistack, &needle);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn invalid_contains() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("hello world", STRING_PADDING);
        let needle = my_client_key.encrypt_no_padding("zama");

        let res = MyServerKey::contains(&heistack, &needle);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 0u8);
    }

    #[test]
    fn invalid_ends_with() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("hello world", STRING_PADDING);
        let needle = my_client_key.encrypt_no_padding("zama");

        let res = MyServerKey::ends_with(&heistack, &needle, STRING_PADDING);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 0u8);
    }

    #[test]
    fn valid_ends_with() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("hello world", STRING_PADDING);
        let needle = my_client_key.encrypt_no_padding("world");

        let res = MyServerKey::ends_with(&heistack, &needle, STRING_PADDING);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn uppercase() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("zama IS awesome", STRING_PADDING);
        let my_string_upper = MyServerKey::to_upper(&my_string);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "ZAMA IS AWESOME");
    }

    #[test]
    fn repeat() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("abc", STRING_PADDING);
        let encrypted_repetitions = my_client_key.encrypt_char(3u8);

        let my_string_upper = MyServerKey::repeat(&my_string, encrypted_repetitions);
        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "abcabcabc");
    }

    #[test]
    fn replace1() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("hello world world test", STRING_PADDING);
        let from = my_client_key.encrypt_no_padding("world");
        let to = my_client_key.encrypt_no_padding("abc");

        let my_new_string = MyServerKey::replace(&my_string, &from, &to);

        let verif_string = my_client_key.decrypt(my_new_string, STRING_PADDING);
        assert_eq!(verif_string, "hello abc abc test");
    }

    #[test]
    fn replace2() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("hello abc abc test", STRING_PADDING);
        let from = my_client_key.encrypt_no_padding("abc");
        let to = my_client_key.encrypt_no_padding("world");

        let my_new_string = MyServerKey::replace(&my_string, &from, &to);

        let verif_string = my_client_key.decrypt(my_new_string, STRING_PADDING);
        assert_eq!(verif_string, "hello world world test");
    }

    #[test]
    fn replacen() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("hello abc abc test", STRING_PADDING);
        let from = my_client_key.encrypt_no_padding("abc");
        let to = my_client_key.encrypt_no_padding("world");
        let n = my_client_key.encrypt_char(1u8);

        let my_new_string = MyServerKey::replacen(&my_string, &from, &to, n);

        let verif_string = my_client_key.decrypt(my_new_string, STRING_PADDING);
        assert_eq!(verif_string, "hello world abc test");
    }

    #[test]
    fn lowercase() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("zama IS awesome", STRING_PADDING);
        let my_string_upper = MyServerKey::to_lower(&my_string);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "zama is awesome");
    }

    #[test]
    fn trim_end() {
        let (client_key, server_key) = setup_test();
        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("ZA MA\n\t \r\x0C", STRING_PADDING);
        let my_string_upper = MyServerKey::trim_end(&my_string);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "ZA MA");
    }

    #[test]
    fn do_not_trim_end() {
        let (client_key, server_key) = setup_test();
        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("\nZA MA", STRING_PADDING);
        let my_string_upper = MyServerKey::trim_end(&my_string);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "\nZA MA");
    }

    #[test]
    fn trim_start() {
        let (client_key, server_key) = setup_test();
        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("\nZA MA", STRING_PADDING);
        let my_string_upper = MyServerKey::trim_start(&my_string);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "ZA MA");
    }

    #[test]
    fn trim() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("\n\nhello world!   ", STRING_PADDING);
        let my_string_upper = MyServerKey::trim(&my_string);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "hello world!");
    }

    #[test]
    fn is_empty() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("", STRING_PADDING);

        let res = MyServerKey::is_empty(&heistack);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn is_not_empty() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("a", STRING_PADDING);

        let res = MyServerKey::is_empty(&heistack);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 0u8);
    }

    #[test]
    fn valid_length1() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("a", STRING_PADDING);

        let res = MyServerKey::len(&heistack);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn valid_length2() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("some arbitrary string", STRING_PADDING);

        let res = MyServerKey::len(&heistack);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 21u8);
    }

    #[test]
    fn rfind() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("hello abc abc test", STRING_PADDING);
        let needle = my_client_key.encrypt_no_padding("abc");

        let res = MyServerKey::rfind(&heistack, &needle);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 10u8);
    }

    #[test]
    fn invalid_rfind() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("hello test", STRING_PADDING);
        let needle = my_client_key.encrypt_no_padding("abc");

        let res = MyServerKey::rfind(&heistack, &needle);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 255u8);
    }

    #[test]
    #[should_panic(expected = "Maximum supported size for find reached")]
    fn unsupported_size_rfind() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt(&"hello test".repeat(100), STRING_PADDING);
        let needle = my_client_key.encrypt_no_padding("abc");

        let res = MyServerKey::rfind(&heistack, &needle);
    }

    #[test]
    fn find() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack = my_client_key.encrypt("hello test", STRING_PADDING);
        let needle = my_client_key.encrypt_no_padding("test");

        let res = MyServerKey::rfind(&heistack, &needle);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 6u8);
    }

    #[test]
    fn eq() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack1 = my_client_key.encrypt("hello test", STRING_PADDING);
        let heistack2 = my_client_key.encrypt("hello test", STRING_PADDING + 20);

        let res = MyServerKey::eq(&heistack1, &heistack2);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn eq_ignore_case() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let heistack1 = my_client_key.encrypt("hello TEST", STRING_PADDING);
        let heistack2 = my_client_key.encrypt("hello test", STRING_PADDING + 20);

        let res = MyServerKey::eq_ignore_case(&heistack1, &heistack2);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 1u8);
    }

    #[test]
    fn strip_prefix() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("HELLO test test HELLO", STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding("HELLO");
        let my_string_upper = MyServerKey::strip_prefix(&my_string, &pattern);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, " test test HELLO");
    }

    #[test]
    fn strip_suffix() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("HELLO test test HELLO", STRING_PADDING);
        let pattern = my_client_key.encrypt("HELLO", STRING_PADDING);
        let my_string_upper = MyServerKey::strip_suffix(&my_string, &pattern.bytes);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "HELLO test test ");
    }

    #[test]
    fn dont_strip_suffix() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("HELLO test test HELLO", STRING_PADDING);
        let pattern = my_client_key.encrypt("WORLD", 0);
        let my_string_upper = MyServerKey::strip_suffix(&my_string, &pattern.bytes);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "HELLO test test HELLO");
    }

    #[test]
    fn dont_strip_prefix() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string = my_client_key.encrypt("HELLO test test HELLO", STRING_PADDING);
        let pattern = my_client_key.encrypt("WORLD", 0);
        let my_string_upper = MyServerKey::strip_prefix(&my_string, &pattern.bytes);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "HELLO test test HELLO");
    }

    #[test]
    fn concatenate() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string1 = my_client_key.encrypt("Hello, ", STRING_PADDING);
        let my_string2 = my_client_key.encrypt("World!", STRING_PADDING);
        let my_string_upper = MyServerKey::concatenate(&my_string1, &my_string2);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        assert_eq!(verif_string, "Hello, World!");
    }

    #[test]
    fn less_than() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
        let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
        let actual = MyServerKey::lt(&heistack1, &heistack2);

        let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

        let expected = (my_string_plain1 < my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn less_equal() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
        let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
        let actual = MyServerKey::le(&heistack1, &heistack2);

        let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

        let expected = (my_string_plain1 <= my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn greater_than() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
        let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
        let actual = MyServerKey::gt(&heistack1, &heistack2);

        let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

        let expected = (my_string_plain1 > my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn greater_equal() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain1 = "aaa";
        let my_string_plain2 = "aaaa";

        let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
        let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
        let actual = MyServerKey::ge(&heistack1, &heistack2);

        let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

        let expected = (my_string_plain1 >= my_string_plain2) as u8;

        assert_eq!(expected, deccrypted_actual);
    }

    #[test]
    fn split() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = " Mary had a";
        let pattern_plain = " ";

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);

        let fhe_split = MyServerKey::split(&my_string, &pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected: Vec<&str> = my_string_plain.split(pattern_plain).collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn split_inclusive() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = "Mary had a";
        let pattern_plain = " ";

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);

        let fhe_split = MyServerKey::split_inclusive(&my_string, &pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected: Vec<&str> = my_string_plain.split_inclusive(pattern_plain).collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn split_terminator() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = ".A.B.";
        let pattern_plain = ".";

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);

        let fhe_split = MyServerKey::split_terminator(&my_string, &pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected: Vec<&str> = my_string_plain.split_terminator(pattern_plain).collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn split_ascii_whitespace() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = " A\nB\t";
        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);

        let fhe_split = MyServerKey::split_ascii_whitespace(&my_string);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected: Vec<&str> = my_string_plain.split_ascii_whitespace().collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn splitn() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = ".A.B.C.";
        let pattern_plain = ".";
        let n_plain = 2u8;

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);
        let n = FheAsciiChar::encrypt_trivial(n_plain);

        let fhe_split = MyServerKey::splitn(&my_string, &pattern, n);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected: Vec<&str> = my_string_plain.splitn(n_plain.into(), pattern_plain).collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn rsplit() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = ".A.B.C.";
        let pattern_plain = ".";

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);

        let fhe_split = MyServerKey::rsplit(&my_string, &pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected: Vec<&str> = my_string_plain.rsplit(pattern_plain).collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn rsplit_once() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = ".A.B.C.";
        let pattern_plain = ".";

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);

        let fhe_split = MyServerKey::rsplit_once(&my_string, &pattern);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected_tuple = my_string_plain.rsplit_once(pattern_plain).unwrap();
        let expected = vec![expected_tuple.1, expected_tuple.0];

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn rsplitn() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = ".A.B.C.";
        let pattern_plain = ".";
        let n_plain = 3u8;

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);
        let n = FheAsciiChar::encrypt_trivial(n_plain);

        let fhe_split = MyServerKey::rsplitn(&my_string, &pattern, n);
        let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        let expected: Vec<&str> = my_string_plain
            .rsplitn(n_plain.into(), pattern_plain)
            .collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }

    #[test]
    fn rplitn_terminator() {
        let (client_key, server_key) = setup_test();

        let my_client_key = MyClientKey::new(client_key);
        let _ = MyServerKey::new(server_key);

        let my_string_plain = "....A.B.C.";
        let pattern_plain = ".";

        let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
        let pattern = my_client_key.encrypt_no_padding(pattern_plain);

        let fhe_split = MyServerKey::rsplit_terminator(&my_string, &pattern);
        let mut plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

        // Plain_split always has a leading empty string, the client can safely ignore it
        plain_split.remove(0);

        let expected: Vec<&str> = my_string_plain.rsplit_terminator(pattern_plain).collect();

        assert_eq!(plain_split[..expected.len()], expected);
    }
}
