use std::{error::Error, ops::Range};

use rand::{thread_rng, Rng};

use crate::{
    block::{aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_encrypt},
    generate_key, pkcs7_pad, pkcs7_unpad,
    stream::{aes_ctr_decrypt, aes_ctr_encrypt},
    BLOCK_SIZE,
};

// Thoughts
// make a string append/prepend oracle that takes and enum for which action to do

pub(crate) type CtrBitFlippingOracle<'a> = BitFlippingOracle<'a, AesCtrOracle>;

pub(crate) struct BitFlippingOracle<'a, T: CipherOracle> {
    cipher: &'a T,
    prefix: &'a [u8],
    suffix: &'a [u8],
}

impl<'a, T: CipherOracle> BitFlippingOracle<'a, T> {
    pub(crate) fn new(cipher: &'a T, prefix: &'a [u8], suffix: &'a [u8]) -> Self {
        Self {
            cipher,
            prefix,
            suffix,
        }
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        assert!(!plaintext.contains(&b';') && !plaintext.contains(&b'='));
        let padded_plaintext = pkcs7_pad(&[self.prefix, plaintext, self.suffix].concat(), 16);
        self.cipher.encrypt(&padded_plaintext)
    }

    pub(crate) fn check_admin(&self, ciphertext: &[u8]) -> Result<bool, Box<dyn Error>> {
        let padded_plaintext = self.cipher.decrypt(ciphertext);
        let plaintext = pkcs7_unpad(&padded_plaintext)?;

        for piece in plaintext.split(|&x| x == b';') {
            let p: Vec<&[u8]> = piece.split(|&x| x == b'=').collect();
            if p.len() != 2 {
                continue;
            }
            let (key, value) = (p[0], p[1]);
            if key == b"admin" && value == b"true" {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub(crate) trait CipherOracle {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

pub(crate) struct AesCtrOracle {
    key: [u8; BLOCK_SIZE],
    nonce: u64,
}

impl AesCtrOracle {
    pub(crate) fn new() -> Self {
        Self {
            key: generate_key(),
            nonce: thread_rng().gen(),
        }
    }
}

impl CipherOracle for AesCtrOracle {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes_ctr_encrypt(plaintext, &self.key, self.nonce)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        aes_ctr_decrypt(ciphertext, &self.key, self.nonce)
    }
}

pub(crate) struct AesCbcOracle {
    key: [u8; BLOCK_SIZE],
    iv: [u8; BLOCK_SIZE],
}

impl AesCbcOracle {
    pub(crate) fn new() -> Self {
        Self {
            key: generate_key(),
            iv: generate_key(),
        }
    }
}

impl CipherOracle for AesCbcOracle {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes_cbc_encrypt(plaintext, &self.key, &self.iv)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        aes_cbc_decrypt(ciphertext, &self.key, &self.iv)
    }
}

pub(crate) type CbcBitFlippingOracle<'a> = BitFlippingOracle<'a, AesCbcOracle>;

pub(crate) struct CtrEditOracle<'a> {
    key: &'a [u8; BLOCK_SIZE],
    nonce: u64,
}

impl<'a> CtrEditOracle<'a> {
    pub(crate) fn new(key: &'a [u8; BLOCK_SIZE], nonce: u64) -> Self {
        Self { key, nonce }
    }
    pub(crate) fn edit(&self, ciphertext: &[u8], offset: usize, new_text: &[u8]) -> Vec<u8> {
        edit(ciphertext, self.key, offset, self.nonce, new_text)
    }
}

fn create_keystream(key: &[u8; BLOCK_SIZE], nonce: u64, range: Range<usize>) -> Vec<u8> {
    let start = range.start / BLOCK_SIZE;
    let end = (range.end + BLOCK_SIZE - 1) / BLOCK_SIZE;
    let keystream = (start..end)
        .into_iter()
        .map(|counter| {
            let nonce_counter = [nonce.to_le_bytes(), (counter as u64).to_le_bytes()].concat();
            aes_ecb_encrypt(&nonce_counter, key)
        })
        .flatten()
        .collect::<Vec<u8>>();

    let offset = start * BLOCK_SIZE;
    keystream[(range.start - offset)..(range.end - offset)].to_vec()
}

fn edit(ciphertext: &[u8], key: &[u8; 16], offset: usize, nonce: u64, new_text: &[u8]) -> Vec<u8> {
    let start = offset;
    let end = offset + new_text.len();
    let keystream = create_keystream(key, nonce, start..end);
    let mut new_ciphertext = ciphertext.to_vec();
    for ((byte, keystream_byte), new_byte) in new_ciphertext
        .iter_mut()
        .skip(offset)
        .take(new_text.len())
        .zip(keystream.iter())
        .zip(new_text.iter())
    {
        *byte = new_byte ^ keystream_byte;
    }
    new_ciphertext
}

pub(crate) struct CbcPaddingOracle<'a> {
    key: &'a [u8; 16],
    iv: &'a [u8; 16],
    plaintexts: Vec<Vec<u8>>,
}

impl<'a> CbcPaddingOracle<'a> {
    pub(crate) fn new(key: &'a [u8; 16], iv: &'a [u8; 16], plaintexts: Vec<Vec<u8>>) -> Self {
        Self {
            key,
            iv,
            plaintexts,
        }
    }

    pub(crate) fn encrypt(&self) -> (Vec<u8>, [u8; 16], usize) {
        // pick random
        let idx = thread_rng().gen_range(0..self.plaintexts.len());
        let plaintext = &self.plaintexts[idx];
        // pad
        let padded_plaintext = pkcs7_pad(plaintext, 16);
        // aes cbc encrypt
        let ciphertext = aes_cbc_encrypt(&padded_plaintext, self.key, self.iv);
        // return ciphertext and iv
        (ciphertext, self.iv.to_owned(), idx)
    }

    pub(crate) fn check_valid_padding(&self, ciphertext: &[u8]) -> bool {
        let padded_plaintext = aes_cbc_decrypt(ciphertext, self.key, self.iv);
        println!("{:?}", padded_plaintext.chunks(16).last().unwrap());
        pkcs7_unpad(&padded_plaintext).is_ok()
    }
}
