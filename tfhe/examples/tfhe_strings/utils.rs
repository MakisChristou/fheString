use crate::ciphertext::fheasciichar::FheAsciiChar;
use crate::PublicParameters;

pub fn abs_difference(a: usize, b: usize) -> usize {
    a.checked_sub(b).unwrap_or(b - a)
}

pub fn bubble_zeroes_left(
    mut result: Vec<FheAsciiChar>,
    server_key: &tfhe::integer::ServerKey,
    public_parameters: &PublicParameters,
) -> Vec<FheAsciiChar> {
    let zero = FheAsciiChar::encrypt_trivial(0u8, public_parameters);

    // Bring non \0 characters in front O(n^2), essentially bubble sort
    for _ in 0..result.len() {
        for i in 0..result.len() - 1 {
            let should_swap = result[i].eq(server_key, &zero);

            result[i] = should_swap.if_then_else(server_key, &result[i + 1], &result[i]);
            result[i + 1] = should_swap.if_then_else(server_key, &zero, &result[i + 1]);
        }
    }

    result
}

pub fn trim_vector(mut vec: Vec<String>) -> Vec<String> {
    while vec.first() == Some(&"".to_string()) {
        vec.remove(0);
    }

    while vec.last() == Some(&"".to_string()) {
        vec.pop();
    }

    vec
}

pub fn trim_str_vector(mut vec: Vec<&str>) -> Vec<String> {
    while vec.first() == Some(&"") {
        vec.remove(0);
    }

    while vec.last() == Some(&"") {
        vec.pop();
    }

    vec.into_iter().map(|s| s.to_string()).collect()
}
