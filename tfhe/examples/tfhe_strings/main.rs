use ciphertext::fheasciichar::FheAsciiChar;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder};

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

    let my_string_plain1 = ".A.B.C.";
    let pattern_plain = ".";
    let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    let my_string = my_client_key.encrypt(&my_string_plain1, STRING_PADDING);

    let fhe_split = MyServerKey::rsplit_terminator(&my_string, pattern);

    let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

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

        let res = MyServerKey::contains(&heistack, needle);
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

        let res = MyServerKey::contains(&heistack, needle);
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

        let res = MyServerKey::ends_with(&heistack, needle, STRING_PADDING);
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

        let res = MyServerKey::ends_with(&heistack, needle, STRING_PADDING);
        let dec: u8 = my_client_key.decrypt_char(&res);

        assert_eq!(dec, 1u8);
    }

    // #[test]
    // fn uppercase() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("zama IS awesome", &client_key, STRING_PADDING);
    //     let my_string_upper = my_string.to_upper();

    //     let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "ZAMA IS AWESOME");
    // }

    // #[test]
    // fn repeat() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("abc", &client_key, STRING_PADDING);
    //     let encrypted_repetitions = FheAsciiChar::encrypt(3u8, &client_key);

    //     let my_string_upper = my_string.repeat(encrypted_repetitions);
    //     let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "abcabcabc\0\0\0\0\0\0\0\0\0\0\0\0");
    // }

    // #[test]
    // fn replace1() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("hello world world test", &client_key, STRING_PADDING);
    //     let from = "world"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let to = "abc"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let my_string_upper = my_string.replace(from, to);
    //     let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "hello abc abc test\0\0\0\0");
    // }

    // #[test]
    // fn replace2() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("hello abc abc test", &client_key, STRING_PADDING);
    //     let from = "abc"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let to = "world"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let my_string_upper = my_string.replace(from, to);
    //     let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "hello world world test\0\0\0\0\0\0\0\0\0\0");
    // }

    // #[test]
    // fn replacen() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("hello abc abc test", &client_key, STRING_PADDING);
    //     let n = FheAsciiChar::encrypt(1u8, &client_key);
    //     let from = "abc"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let to = "world"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let my_string_upper = my_string.replacen(from, to, n);
    //     let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "hello world abc test\0\0\0\0\0\0\0\0\0\0\0\0");
    // }

    // #[test]
    // fn lowercase() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("ZAMA is AWESOME 1234", &client_key, STRING_PADDING);

    //     let my_string_upper = my_string.to_lower();
    //     let verif_string = my_string_upper.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "zama is awesome 1234");
    // }

    // #[test]
    // fn trim_end() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("ZA MA\n\t \r\x0C", &client_key, STRING_PADDING);

    //     let res_string = my_string.trim_end();
    //     let verif_string = res_string.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "ZA MA\0\0\0\0\0");
    // }

    // #[test]
    // fn do_not_trim_end() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("\nZA MA", &client_key, STRING_PADDING);

    //     let result_string = my_string.trim_end();
    //     let verif_string = result_string.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "\nZA MA");
    // }

    // #[test]
    // fn trim_start() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("\n\nZA MA", &client_key, STRING_PADDING);

    //     let res_string = my_string.trim_start();
    //     let verif_string = res_string.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "ZA MA\0\0");
    // }

    // #[test]
    // fn trim() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("\n\nhello world!   ", &client_key, STRING_PADDING);

    //     let res_string = my_string.trim();
    //     let verif_string = res_string.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "hello world!\0\0\0\0\0");
    // }

    // #[test]
    // fn is_empty() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("", &client_key, STRING_PADDING);

    //     let res = my_string.is_empty();
    //     let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

    //     assert_eq!(dec, 1u8);
    // }

    // #[test]
    // fn is_not_empty() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("a", &client_key, STRING_PADDING);

    //     let res = my_string.is_empty();
    //     let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

    //     assert_eq!(dec, 0u8);
    // }

    // #[test]
    // fn valid_length1() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("a", &client_key, STRING_PADDING);

    //     let res = my_string.len();
    //     let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

    //     assert_eq!(dec, 1u8);
    // }

    // #[test]
    // fn valid_length2() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("some arbitrary string", &client_key, STRING_PADDING);

    //     let res = my_string.len();
    //     let dec: u8 = FheAsciiChar::decrypt(&res, &client_key);

    //     assert_eq!(dec, 21u8);
    // }

    // #[test]
    // fn rfind() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("hello abc abc test", &client_key, STRING_PADDING);
    //     let pattern = "abc"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let enc_pattern_position = my_string.rfind(pattern);
    //     let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
    //     assert_eq!(pattern_positioon, 10u8);
    // }

    // #[test]
    // fn invalid_rfind() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt("hello test", &client_key, STRING_PADDING);
    //     let pattern = "abc"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let enc_pattern_position = my_string.rfind(pattern);
    //     let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
    //     assert_eq!(pattern_positioon, 255u8);
    // }

    // #[test]
    // #[should_panic(expected = "Maximum supported size for find reached")]
    // fn unsupported_size_rfind() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt(&"hello test".repeat(100), &client_key, STRING_PADDING);
    //     let pattern = "abc"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let _ = my_string.rfind(pattern);
    // }

    // #[test]
    // fn find() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING);
    //     let pattern = "test"
    //         .bytes()
    //         .map(|b| FheAsciiChar::encrypt(b, &client_key))
    //         .collect::<Vec<FheAsciiChar>>();

    //     let enc_pattern_position = my_string.find(pattern);
    //     let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
    //     assert_eq!(pattern_positioon, 6u8);
    // }

    // #[test]
    // fn eq() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string1 = FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING);
    //     let my_string2 =
    //         FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING + 20);

    //     let enc_pattern_position = my_string1.eq(my_string2);
    //     let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
    //     assert_eq!(pattern_positioon, 1u8);
    // }

    // #[test]
    // fn eq_ignore_case() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string1 = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
    //     let my_string2 =
    //         FheString::encrypt(&"hello test test hello", &client_key, STRING_PADDING + 20);

    //     let enc_pattern_position = my_string1.eq_ignore_case(my_string2);
    //     let pattern_positioon: u8 = FheAsciiChar::decrypt(&enc_pattern_position, &client_key);
    //     assert_eq!(pattern_positioon, 1u8);
    // }

    // #[test]
    // fn strip_prefix() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
    //     let pattern: Vec<FheAsciiChar> = "HELLO"
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string_processed = my_string.strip_prefix(pattern);
    //     let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, " test test HELLO\0\0\0\0\0");
    // }

    // #[test]
    // fn strip_suffix() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);

    //     // Since the client knows the original string padding he can add it to the pattern without revealing the original length of pattern or my_string
    //     let pattern: Vec<FheAsciiChar> = format!("HELLO{}", "\0".repeat(STRING_PADDING))
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string_processed = my_string.strip_suffix(pattern);
    //     let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "HELLO test test \0\0\0\0\0");
    // }

    // #[test]
    // fn dont_strip_suffix() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
    //     let pattern: Vec<FheAsciiChar> = "WORLD"
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string_processed = my_string.strip_suffix(pattern);
    //     let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "HELLO test test HELLO");
    // }

    // #[test]
    // fn dont_strip_prefix() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string = FheString::encrypt(&"HELLO test test HELLO", &client_key, STRING_PADDING);
    //     let pattern: Vec<FheAsciiChar> = "WORLD"
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string_processed = my_string.strip_prefix(pattern);
    //     let verif_string = my_string_processed.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(verif_string, "HELLO test test HELLO");
    // }

    // #[test]
    // fn concatenate() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string1 = FheString::encrypt(&"Hello", &client_key, STRING_PADDING);
    //     let my_string2 = FheString::encrypt(&", World!", &client_key, STRING_PADDING);

    //     let my_string_concatenated = my_string1 + my_string2;
    //     let verif_string = my_string_concatenated.decrypt(&client_key, STRING_PADDING);
    //     assert_eq!(
    //         verif_string,
    //         format!("Hello, World!{}", "\0".repeat(STRING_PADDING))
    //     );
    // }

    // #[test]
    // fn less_than() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = "aaa";
    //     let my_string_plain2 = "aaaa";

    //     let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

    //     let actual = my_string1.lt(my_string2);
    //     let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

    //     let expected = (my_string_plain1 < my_string_plain2) as u8;

    //     assert_eq!(expected, deccrypted_actual);
    // }

    // #[test]
    // fn less_equal() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = "aaa";
    //     let my_string_plain2 = "aaaa";

    //     let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

    //     let actual = my_string1.le(my_string2);
    //     let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

    //     let expected = (my_string_plain1 <= my_string_plain2) as u8;

    //     assert_eq!(expected, deccrypted_actual);
    // }

    // #[test]
    // fn greater_than() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = "aaa";
    //     let my_string_plain2 = "aaaa";

    //     let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

    //     let actual = my_string1.gt(my_string2);
    //     let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

    //     let expected = (my_string_plain1 > my_string_plain2) as u8;

    //     assert_eq!(expected, deccrypted_actual);
    // }

    // #[test]
    // fn greater_equal() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = "aaa";
    //     let my_string_plain2 = "aaaa";

    //     let my_string1 = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let my_string2 = FheString::encrypt(&my_string_plain2, &client_key, STRING_PADDING);

    //     let actual = my_string1.ge(my_string2);
    //     let deccrypted_actual: u8 = FheAsciiChar::decrypt(&actual, &client_key);

    //     let expected = (my_string_plain1 >= my_string_plain2) as u8;

    //     assert_eq!(expected, deccrypted_actual);
    // }

    // #[test]
    // fn split() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = "Mary had a";
    //     let pattern_plain = " ";

    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.split(pattern);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "Mary\0\0\0\0\0\0",
    //             "had\0\0\0\0\0\0\0",
    //             "a\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn split_inclusive() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = "Mary had a";
    //     let pattern_plain = " ";
    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.split_inclusive(pattern);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "Mary \0\0\0\0\0",
    //             "had \0\0\0\0\0\0",
    //             "a\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn split_terminator() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = ".A.B.";
    //     let pattern_plain = ".";
    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.split_terminator(pattern);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "\0\0\0\0\0",
    //             "A\0\0\0\0",
    //             "B\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn split_ascii_whitespace() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = " A\nB\t";

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.split_ascii_whitespace();
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "\0\0\0\0\0",
    //             "A\0\0\0\0",
    //             "B\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0",
    //             "\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn splitn() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = ".A.B.C.";
    //     let pattern_plain = ".";
    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let n = FheAsciiChar::encrypt_trivial(2u8);

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.splitn(pattern, n);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "\0\0\0\0\0\0\0",
    //             "A.B.C.\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn rplit() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = ".A.B.C.";
    //     let pattern_plain = ".";
    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.rsplit(pattern);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "\0\0\0\0\0\0\0",
    //             "C\0\0\0\0\0\0",
    //             "B\0\0\0\0\0\0",
    //             "A\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn rplit_once() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = ".A.B.C.";
    //     let pattern_plain = ".";
    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.rsplit_once(pattern);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "\0\0\0\0\0\0\0",
    //             ".A.B.C\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn rplitn() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = ".A.B.C.";
    //     let pattern_plain = ".";
    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let n = FheAsciiChar::encrypt_trivial(3u8);

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.rsplitn(pattern, n);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "\0\0\0\0\0\0\0",
    //             "C\0\0\0\0\0\0",
    //             ".A.B\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0"
    //         ]
    //     );
    // }

    // #[test]
    // fn rplitn_terminator() {
    //     let (client_key, server_key) = setup_test();
    //     set_server_key(server_key);

    //     let my_string_plain1 = ".A.B.C.";
    //     let pattern_plain = ".";
    //     let pattern: Vec<FheAsciiChar> = pattern_plain
    //         .as_bytes()
    //         .iter()
    //         .map(|b| FheAsciiChar::encrypt(*b, &client_key))
    //         .collect();

    //     let my_string = FheString::encrypt(&my_string_plain1, &client_key, STRING_PADDING);
    //     let fhe_split = my_string.rsplit_terminator(pattern);
    //     let plain_split = FheSplit::decrypt(fhe_split, &client_key, STRING_PADDING);

    //     assert_eq!(
    //         plain_split,
    //         vec![
    //             "\0\0\0\0\0\0\0",
    //             "C\0\0\0\0\0\0",
    //             "B\0\0\0\0\0\0",
    //             "A\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0",
    //             "\0\0\0\0\0\0\0"
    //         ]
    //     );
    // }
}
