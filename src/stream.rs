use crate::{
    basic::fixed_xor,
    block::aes_ecb_encrypt,
    oracle::{CtrBitFlippingOracle, CtrEditOracle},
};

// Challenge 26

pub(crate) fn ctr_bit_flipping_attack(oracle: &CtrBitFlippingOracle) -> Vec<u8> {
    let ciphertext1 = oracle.encrypt(b"A");
    let ciphertext2 = oracle.encrypt(b"B");
    let prefix_length = ciphertext1
        .iter()
        .zip(ciphertext2.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let target = b";admin=true";
    let zeroes = vec![0u8; target.len()];
    let mut ciphertext = oracle.encrypt(&zeroes);

    for (byte, target_byte) in ciphertext
        .iter_mut()
        .skip(prefix_length)
        .take(target.len())
        .zip(target.iter())
    {
        *byte ^= target_byte;
    }
    ciphertext
}

// Challenge 25

pub(crate) fn break_random_access_read_write_aes_ctr(
    ciphertext: &[u8],
    oracle: &CtrEditOracle,
) -> Vec<u8> {
    let keystream = oracle.edit(ciphertext, 0, &vec![0; ciphertext.len()]);
    fixed_xor(ciphertext, &keystream)
}

// Challenge 18

pub(crate) fn aes_ctr_encrypt(plaintext: &[u8], key: &[u8; 16], nonce: u64) -> Vec<u8> {
    let block_size = 16;
    let mut ciphertext = vec![];
    for (i, chunk) in plaintext.chunks(block_size).enumerate() {
        let nonce_counter = [nonce.to_le_bytes(), (i as u64).to_le_bytes()].concat();
        let keystream = aes_ecb_encrypt(&nonce_counter, key);
        let ciphertext_chunk = fixed_xor(chunk, &keystream[..chunk.len()]);
        ciphertext.extend_from_slice(&ciphertext_chunk);
    }
    ciphertext
}

pub(crate) fn aes_ctr_decrypt(ciphertext: &[u8], key: &[u8; 16], nonce: u64) -> Vec<u8> {
    let block_size = 16;
    let mut plaintext = vec![];
    for (i, chunk) in ciphertext.chunks(block_size).enumerate() {
        let nonce_counter = [nonce.to_le_bytes(), (i as u64).to_le_bytes()].concat();
        let keystream = aes_ecb_encrypt(&nonce_counter, key);
        let plaintext_chunk = fixed_xor(chunk, &keystream[..chunk.len()]);
        plaintext.extend_from_slice(&plaintext_chunk);
    }
    plaintext
}
