use ciphertext::fheasciichar::FheAsciiChar;
use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

use crate::ciphertext::fhestring::FheString;
use crate::server_key::MyServerKey;

use tfhe::integer::gen_keys_radix;
use tfhe::integer::PublicKey;

const STRING_PADDING: usize = 3;
const MAX_REPETITIONS: usize = 4;
const MAX_FIND_LENGTH: usize = 255;

mod ciphertext;
mod client_key;
mod server_key;
mod utils;

use client_key::MyClientKey;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_blocks = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);

    //We generate the public key from the secret client key:
    let public_key = PublicKey::new(&client_key);

    let my_client_key = MyClientKey::new(client_key);
    let my_server_key = MyServerKey::new(server_key);

    let heistack1_plain = "hello TEST";
    let heistack2_plain = "hello test";

    let heistack1 = my_client_key.encrypt(heistack1_plain, STRING_PADDING, &public_key, num_blocks);
    let heistack2 = my_client_key.encrypt(
        heistack2_plain,
        STRING_PADDING + 20,
        &public_key,
        num_blocks,
    );

    let res = my_server_key.eq_ignore_case(&heistack1, &heistack2, &public_key, num_blocks);
    let dec: u8 = my_client_key.decrypt_char(&res);
    let expected = heistack1_plain.eq_ignore_ascii_case(heistack2_plain);

    assert_eq!(dec, expected as u8);
}

#[cfg(test)]
mod test {
    use crate::{FheAsciiChar, FheString, STRING_PADDING};
    use crate::{MyClientKey, MyServerKey};
    use tfhe::integer::gen_keys_radix;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    use tfhe::{generate_keys, set_server_key, PublicKey};

    fn setup_test() -> (MyClientKey, MyServerKey, tfhe::integer::PublicKey, usize) {
        // We generate a set of client/server keys, using the default parameters:
        let num_blocks = 4;
        let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);

        //We generate the public key from the secret client key:
        let public_key = tfhe::integer::PublicKey::new(&client_key);

        let my_client_key = MyClientKey::new(client_key);
        let my_server_key = MyServerKey::new(server_key);

        (my_client_key, my_server_key, public_key, num_blocks)
    }

    #[test]
    fn valid_contains() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack_plain = "awesomezamaisawesome";
        let needle_plain = "zama";

        let heistack = my_client_key.encrypt(heistack_plain, 3, &public_key, num_blocks);
        let needle = my_client_key.encrypt_no_padding(needle_plain);

        let res = my_server_key.contains(&heistack, &needle, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = heistack_plain.contains(needle_plain);

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn invalid_contains() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack_plain = "hello world";
        let needle_plain = "zama";

        let heistack = my_client_key.encrypt(heistack_plain, 3, &public_key, num_blocks);
        let needle = my_client_key.encrypt_no_padding(needle_plain);

        let res = my_server_key.contains(&heistack, &needle, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = heistack_plain.contains(needle_plain);

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn invalid_ends_with() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack_plain = "hello world";
        let needle_plain = "zama";

        let heistack =
            my_client_key.encrypt(heistack_plain, STRING_PADDING, &public_key, num_blocks);
        let needle = my_client_key.encrypt_no_padding(needle_plain);

        let res =
            my_server_key.ends_with(&heistack, &needle, STRING_PADDING, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = heistack_plain.ends_with(needle_plain);

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn valid_starts_with() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack_plain = "hello world";
        let needle_plain = "hello";

        let heistack =
            my_client_key.encrypt(heistack_plain, STRING_PADDING, &public_key, num_blocks);
        let needle = my_client_key.encrypt_no_padding(needle_plain);

        let res = my_server_key.starts_with(&heistack, &needle, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = heistack_plain.starts_with(needle_plain);

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn invalid_starts_with() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack_plain = "hello world";
        let needle_plain = "zama";

        let heistack =
            my_client_key.encrypt(heistack_plain, STRING_PADDING, &public_key, num_blocks);
        let needle = my_client_key.encrypt_no_padding(needle_plain);

        let res = my_server_key.starts_with(&heistack, &needle, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = heistack_plain.starts_with(needle_plain);

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn valid_ends_with() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack_plain = "hello world";
        let needle_plain = "world";

        let heistack =
            my_client_key.encrypt(heistack_plain, STRING_PADDING, &public_key, num_blocks);
        let needle = my_client_key.encrypt_no_padding(needle_plain);

        let res =
            my_server_key.ends_with(&heistack, &needle, STRING_PADDING, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = heistack_plain.ends_with(needle_plain);

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn uppercase() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "zama IS awesome";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let my_string_upper = my_server_key.to_upper(&my_string, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        let expected = my_string_plain.to_uppercase();

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn repeat() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "abc";
        let n_plain = 3u8;

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let n = my_client_key.encrypt_char(n_plain);

        let my_string_upper = my_server_key.repeat(&my_string, n, &public_key, num_blocks);
        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        let expected = my_string_plain.repeat(n_plain.into());

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn replace1() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "hello world world test";
        let from_plain = "world";
        let to_plain = "abc";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let from = my_client_key.encrypt_no_padding(from_plain);
        let to = my_client_key.encrypt_no_padding(to_plain);

        let my_new_string = my_server_key.replace(&my_string, &from, &to, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_new_string, STRING_PADDING);
        let expected = my_string_plain.replace(from_plain, to_plain);

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn replace2() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "hello abc abc test";
        let from_plain = "abc";
        let to_plain = "world";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let from = my_client_key.encrypt_no_padding(from_plain);
        let to = my_client_key.encrypt_no_padding(to_plain);

        let my_new_string = my_server_key.replace(&my_string, &from, &to, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_new_string, STRING_PADDING);
        let expected = my_string_plain.replace(from_plain, to_plain);

        assert_eq!(verif_string, expected);
    }

    //     #[test]
    //     fn replacen() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = "hello abc abc test";
    //         let from_plain = "abc";
    //         let to_plain = "world";
    //         let n_plain = 1u8;

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let from = my_client_key.encrypt_no_padding(from_plain);
    //         let to = my_client_key.encrypt_no_padding(to_plain);
    //         let n = my_client_key.encrypt_char(n_plain);

    //         let my_new_string = MyServerKey::replacen(&my_string, &from, &to, n);

    //         let verif_string = my_client_key.decrypt(my_new_string, STRING_PADDING);
    //         let expected = my_string_plain.replacen(from_plain, to_plain, n_plain.into());

    //         assert_eq!(verif_string, expected);
    //     }

    #[test]
    fn lowercase() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "zama IS awesome";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let my_string_upper = my_server_key.to_lower(&my_string, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        let expected = my_string_plain.to_lowercase();

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn trim_end() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "ZA MA\n\t \r\x0C";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let my_string_upper = my_server_key.trim_end(&my_string, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        let expected = my_string_plain.trim_end();

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn do_not_trim_end() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "\nZA MA";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let my_string_upper = my_server_key.trim_end(&my_string, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        let expected = my_string_plain.trim_end();

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn trim_start() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "\nZA MA";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let my_string_upper = my_server_key.trim_start(&my_string, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        let expected = my_string_plain.trim_start();

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn trim() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "\nZA MA\n";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);
        let my_string_upper = my_server_key.trim(&my_string, &public_key, num_blocks);

        let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
        let expected = my_string_plain.trim();

        assert_eq!(verif_string, expected);
    }

    #[test]
    fn is_empty() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "";
        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);

        let res = my_server_key.is_empty(&my_string, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);
        let expected = my_string_plain.is_empty();

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn is_not_empty() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "hello";
        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);

        let res = my_server_key.is_empty(&my_string, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);
        let expected = my_string_plain.is_empty();

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn len() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let my_string_plain = "hello world";

        let my_string =
            my_client_key.encrypt(my_string_plain, STRING_PADDING, &public_key, num_blocks);

        let res = my_server_key.len(&my_string, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = my_string_plain.len();

        assert_eq!(dec, expected as u8);
    }

    //     #[test]
    //     fn rfind() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let heistack_plain = "hello abc abc test";
    //         let needle_plain = "abc";

    //         let heistack = my_client_key.encrypt(heistack_plain, STRING_PADDING);
    //         let needle = my_client_key.encrypt_no_padding(needle_plain);

    //         let res = MyServerKey::rfind(&heistack, &needle);
    //         let dec: u8 = my_client_key.decrypt_char(&res);

    //         let expected = heistack_plain.rfind(needle_plain).unwrap();

    //         assert_eq!(dec, expected as u8);
    //     }

    //     #[test]
    //     fn invalid_rfind() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let heistack_plain = "hello test";
    //         let needle_plain = "abc";

    //         let heistack = my_client_key.encrypt(heistack_plain, STRING_PADDING);
    //         let needle = my_client_key.encrypt_no_padding(needle_plain);

    //         let res = MyServerKey::rfind(&heistack, &needle);
    //         let dec: u8 = my_client_key.decrypt_char(&res);

    //         // The original algoritm returns None but since we don't have this luxury we will use a placeholder value
    //         let _ = heistack_plain.rfind(needle_plain);

    //         assert_eq!(dec, 255u8);
    //     }

    //     #[test]
    //     #[should_panic(expected = "Maximum supported size for find reached")]
    //     fn unsupported_size_rfind() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let heistack_plain = "hello test".repeat(100);
    //         let needle_plain = "abc";

    //         let heistack = my_client_key.encrypt(&heistack_plain, STRING_PADDING);
    //         let needle = my_client_key.encrypt_no_padding(needle_plain);

    //         let res = MyServerKey::rfind(&heistack, &needle);
    //     }

    #[test]
    fn find() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack_plain = "hello test";
        let needle_plain = "test";

        let heistack =
            my_client_key.encrypt(heistack_plain, STRING_PADDING, &public_key, num_blocks);
        let needle = my_client_key.encrypt_no_padding(needle_plain);

        let res = my_server_key.find(&heistack, &needle, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);

        let expected = heistack_plain.find(needle_plain).unwrap();

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn eq() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack1_plain = "hello test";
        let heistack2_plain = "hello test";

        let heistack1 =
            my_client_key.encrypt(heistack1_plain, STRING_PADDING, &public_key, num_blocks);
        let heistack2 = my_client_key.encrypt(
            heistack2_plain,
            STRING_PADDING + 20,
            &public_key,
            num_blocks,
        );

        let res = my_server_key.eq(&heistack1, &heistack2, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);
        let expected = heistack1_plain.eq(heistack2_plain);

        assert_eq!(dec, expected as u8);
    }

    #[test]
    fn eq_ignore_case() {
        let (my_client_key, my_server_key, public_key, num_blocks) = setup_test();

        let heistack1_plain = "hello TEST";
        let heistack2_plain = "hello test";

        let heistack1 =
            my_client_key.encrypt(heistack1_plain, STRING_PADDING, &public_key, num_blocks);
        let heistack2 = my_client_key.encrypt(
            heistack2_plain,
            STRING_PADDING + 20,
            &public_key,
            num_blocks,
        );

        let res = my_server_key.eq_ignore_case(&heistack1, &heistack2, &public_key, num_blocks);
        let dec: u8 = my_client_key.decrypt_char(&res);
        let expected = heistack1_plain.eq_ignore_ascii_case(heistack2_plain);

        assert_eq!(dec, expected as u8);
    }

    //     #[test]
    //     fn strip_prefix() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = "HELLO test test HELLO";
    //         let pattern_plain = "HELLO";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    //         let my_string_upper = MyServerKey::strip_prefix(&my_string, &pattern);

    //         let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
    //         let expected = my_string_plain.strip_prefix(pattern_plain);

    //         let expected = my_string_plain.strip_prefix(pattern_plain).unwrap();

    //         assert_eq!(verif_string, expected);
    //     }

    //     #[test]
    //     fn strip_suffix() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = "HELLO test test HELLO";
    //         let pattern_plain = "HELLO";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt(pattern_plain, STRING_PADDING);
    //         let my_string_upper = MyServerKey::strip_suffix(&my_string, &pattern.bytes);

    //         let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
    //         let expected = my_string_plain.strip_suffix(pattern_plain).unwrap();

    //         assert_eq!(verif_string, expected);
    //     }

    //     #[test]
    //     fn dont_strip_suffix() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = "HELLO test test HELLO";
    //         let pattern_plain = "WORLD";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt(pattern_plain, 0);
    //         let my_string_upper = MyServerKey::strip_suffix(&my_string, &pattern.bytes);

    //         let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);

    //         // This is None but in our case the string is not modified
    //         let _ = my_string_plain.strip_suffix(pattern_plain);

    //         assert_eq!(verif_string, my_string_plain);
    //     }

    //     #[test]
    //     fn dont_strip_prefix() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = "HELLO test test HELLO";
    //         let pattern_plain = "WORLD";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt(pattern_plain, 0);
    //         let my_string_upper = MyServerKey::strip_prefix(&my_string, &pattern.bytes);

    //         let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);

    //         // This is None but in our case the string is not modified
    //         let _ = my_string_plain.strip_prefix(pattern_plain);

    //         assert_eq!(verif_string, my_string_plain);
    //     }

    //     #[test]
    //     fn concatenate() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string1_plain = "Hello, ";
    //         let my_string2_plain = "World!";

    //         let my_string1 = my_client_key.encrypt(my_string1_plain, STRING_PADDING);
    //         let my_string2 = my_client_key.encrypt(my_string2_plain, STRING_PADDING);
    //         let my_string_upper = MyServerKey::concatenate(&my_string1, &my_string2);

    //         let verif_string = my_client_key.decrypt(my_string_upper, STRING_PADDING);
    //         assert_eq!(
    //             verif_string,
    //             format!("{}{}", my_string1_plain, my_string2_plain)
    //         );
    //     }

    //     #[test]
    //     fn less_than() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain1 = "aaa";
    //         let my_string_plain2 = "aaaa";

    //         let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
    //         let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
    //         let actual = MyServerKey::lt(&heistack1, &heistack2);

    //         let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

    //         let expected = (my_string_plain1 < my_string_plain2) as u8;

    //         assert_eq!(expected, deccrypted_actual);
    //     }

    //     #[test]
    //     fn less_equal() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain1 = "aaa";
    //         let my_string_plain2 = "aaaa";

    //         let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
    //         let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
    //         let actual = MyServerKey::le(&heistack1, &heistack2);

    //         let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

    //         let expected = (my_string_plain1 <= my_string_plain2) as u8;

    //         assert_eq!(expected, deccrypted_actual);
    //     }

    //     #[test]
    //     fn greater_than() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain1 = "aaa";
    //         let my_string_plain2 = "aaaa";

    //         let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
    //         let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
    //         let actual = MyServerKey::gt(&heistack1, &heistack2);

    //         let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

    //         let expected = (my_string_plain1 > my_string_plain2) as u8;

    //         assert_eq!(expected, deccrypted_actual);
    //     }

    //     #[test]
    //     fn greater_equal() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain1 = "aaa";
    //         let my_string_plain2 = "aaaa";

    //         let heistack1 = my_client_key.encrypt(my_string_plain1, STRING_PADDING);
    //         let heistack2 = my_client_key.encrypt(my_string_plain2, STRING_PADDING);
    //         let actual = MyServerKey::ge(&heistack1, &heistack2);

    //         let deccrypted_actual: u8 = my_client_key.decrypt_char(&actual);

    //         let expected = (my_string_plain1 >= my_string_plain2) as u8;

    //         assert_eq!(expected, deccrypted_actual);
    //     }

    //     #[test]
    //     fn split() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = " Mary had a";
    //         let pattern_plain = " ";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    //         let fhe_split = MyServerKey::split(&my_string, &pattern);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected: Vec<&str> = my_string_plain.split(pattern_plain).collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn split_inclusive() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = "Mary had a";
    //         let pattern_plain = " ";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    //         let fhe_split = MyServerKey::split_inclusive(&my_string, &pattern);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected: Vec<&str> = my_string_plain.split_inclusive(pattern_plain).collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn split_terminator() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = ".A.B.";
    //         let pattern_plain = ".";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    //         let fhe_split = MyServerKey::split_terminator(&my_string, &pattern);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected: Vec<&str> = my_string_plain.split_terminator(pattern_plain).collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn split_ascii_whitespace() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = " A\nB\t";
    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);

    //         let fhe_split = MyServerKey::split_ascii_whitespace(&my_string);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected: Vec<&str> = my_string_plain.split_ascii_whitespace().collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn splitn() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = ".A.B.C.";
    //         let pattern_plain = ".";
    //         let n_plain = 2u8;

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    //         let n = FheAsciiChar::encrypt_trivial(n_plain);

    //         let fhe_split = MyServerKey::splitn(&my_string, &pattern, n);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected: Vec<&str> = my_string_plain
    //             .splitn(n_plain.into(), pattern_plain)
    //             .collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn rsplit() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = ".A.B.C.";
    //         let pattern_plain = ".";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    //         let fhe_split = MyServerKey::rsplit(&my_string, &pattern);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected: Vec<&str> = my_string_plain.rsplit(pattern_plain).collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn rsplit_once() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = ".A.B.C.";
    //         let pattern_plain = ".";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    //         let fhe_split = MyServerKey::rsplit_once(&my_string, &pattern);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected_tuple = my_string_plain.rsplit_once(pattern_plain).unwrap();
    //         let expected = vec![expected_tuple.1, expected_tuple.0];

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn rsplitn() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = ".A.B.C.";
    //         let pattern_plain = ".";
    //         let n_plain = 3u8;

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);
    //         let n = FheAsciiChar::encrypt_trivial(n_plain);

    //         let fhe_split = MyServerKey::rsplitn(&my_string, &pattern, n);
    //         let plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         let expected: Vec<&str> = my_string_plain
    //             .rsplitn(n_plain.into(), pattern_plain)
    //             .collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }

    //     #[test]
    //     fn rplitn_terminator() {
    //         let (client_key, server_key) = setup_test();

    //         let my_client_key = MyClientKey::new(client_key);
    //         let _ = MyServerKey::new(server_key);

    //         let my_string_plain = "....A.B.C.";
    //         let pattern_plain = ".";

    //         let my_string = my_client_key.encrypt(my_string_plain, STRING_PADDING);
    //         let pattern = my_client_key.encrypt_no_padding(pattern_plain);

    //         let fhe_split = MyServerKey::rsplit_terminator(&my_string, &pattern);
    //         let mut plain_split = FheSplit::decrypt(fhe_split, &my_client_key, STRING_PADDING);

    //         // Plain_split always has a leading empty string, the client can safely ignore it
    //         plain_split.remove(0);

    //         let expected: Vec<&str> = my_string_plain.rsplit_terminator(pattern_plain).collect();

    //         assert_eq!(plain_split[..expected.len()], expected);
    //     }
}
