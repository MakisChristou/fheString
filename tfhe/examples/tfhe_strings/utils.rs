use crate::ciphertext::fheasciichar::FheAsciiChar;

pub fn abs_difference(a: usize, b: usize) -> usize {
    a.checked_sub(b).unwrap_or_else(|| b - a)
}

pub fn bubble_zeroes_left(
    mut result: Vec<FheAsciiChar>,
    server_key: &tfhe::integer::ServerKey,
    public_key: &tfhe::integer::PublicKey,
    num_blocks: usize,
) -> Vec<FheAsciiChar> {
    let zero = FheAsciiChar::encrypt_trivial(0u8, public_key, num_blocks);

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
