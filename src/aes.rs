use crate::fixed_xor;
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

pub fn aes_ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(input.len() % 16 == 0);
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut ciphertext = vec![];
    for chunk in input.chunks(16) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }
    ciphertext
}

pub fn aes_ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut plaintext = vec![];
    let block_len = 16;
    for chunk in input.chunks(block_len) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }
    plaintext
}

pub fn aes_cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert!(input.len() % 16 == 0);
    let mut ciphertext = vec![];
    for (i, chunk) in input.chunks(16).enumerate() {
        let xor: &[u8] = match i {
            0 => iv,
            _ => ciphertext.get(((i - 1) * 16)..(i * 16)).unwrap(), // array_ref!(ciphertext.as_slice(), (i - 1) * 16, i * 16),
        };
        let plaintext_xored = fixed_xor(chunk, xor);
        let plaintext_xored_encrypted = aes_ecb_encrypt(&plaintext_xored, key);
        ciphertext.extend(plaintext_xored_encrypted);
    }
    ciphertext
}

pub fn aes_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = vec![];
    let block_len = 16;
    for (i, chunk) in input.chunks(block_len).enumerate() {
        let decrypted = aes_ecb_decrypt(chunk, key);
        let xor = if i == 0 {
            iv
        } else {
            &input[((i - 1) * block_len)..(i * block_len)]
        };
        let decrypted_xor = fixed_xor(decrypted.as_slice(), xor);
        plaintext.extend_from_slice(&decrypted_xor);
    }
    plaintext
}

pub fn aes_ctr_encrypt(plaintext: &[u8], key: &[u8; 16], nonce: u64) -> Vec<u8> {
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

pub fn aes_ctr_decrypt(ciphertext: &[u8], key: &[u8; 16], nonce: u64) -> Vec<u8> {
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
