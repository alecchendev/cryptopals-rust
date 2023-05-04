use crate::set1::{
    aes_ecb_encrypt, decrypt_single_byte_xor, fixed_xor, generate_key, pkcs7_pad,
    repeating_key_xor, transpose_blocks,
};
use crate::set2::{aes_cbc_decrypt, aes_cbc_encrypt, pkcs7_unpad};
use base64::{engine::general_purpose, Engine};
use rand::{thread_rng, Rng, RngCore};
use std::fs;
use std::io::Read;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Challenge 24

pub(crate) fn generate_password_token(seed: u16) -> u32 {
    let mut rng = MersenneTwisterRng::new(seed as u32);
    let mut token = 0;
    for _ in 0..thread_rng().gen_range(1..1000) {
        token = rng.generate();
    }
    token
}

pub(crate) fn crack_password_token(token: u32) -> Option<u16> {
    for seed in 0..0xFFFF {
        let mut rng = MersenneTwisterRng::new(seed as u32);
        for _ in 0..1000 {
            if token == rng.generate() {
                return Some(seed);
            }
        }
    }
    None
}

pub(crate) fn prng_encrypt_with_prefix(plaintext: &[u8], seed: u16) -> Vec<u8> {
    let prefix: Vec<u8> = vec![0; thread_rng().gen_range(0..256)]
        .iter()
        .map(|_| thread_rng().gen())
        .collect();
    let prefixed_plaintext = [prefix.as_slice(), plaintext].concat();
    mt19937_encrypt(prefixed_plaintext.as_slice(), seed)
}

pub(crate) fn crack_prefixed(ciphertext: &[u8], plaintext: &[u8]) -> Option<u16> {
    let target_bytes = fixed_xor(
        plaintext,
        &ciphertext[(ciphertext.len() - plaintext.len())..],
    );
    let bytes_per_rand = 4;
    for seed in 0u16..0xFFFF {
        // gen ciphertext worth of seeds and compare
        let mut rng = MersenneTwisterRng::new(seed as u32);
        let mut keystream = vec![];
        for chunk in ciphertext.chunks(bytes_per_rand) {
            keystream.extend_from_slice(&rng.generate().to_le_bytes()[..chunk.len()]);
        }
        if &keystream[(ciphertext.len() - plaintext.len())..] == target_bytes.as_slice() {
            return Some(seed);
        }
    }
    None
}

pub(crate) fn mt19937_encrypt(plaintext: &[u8], seed: u16) -> Vec<u8> {
    let mut rng = MersenneTwisterRng::new(seed as u32);
    let mut ciphertext = vec![];
    let bytes_in_rng = 4;
    for (_, chunk) in plaintext.chunks(bytes_in_rng).enumerate() {
        let keystream = rng.generate().to_le_bytes();
        let ciphertext_chunk = fixed_xor(chunk, &keystream[..chunk.len()]);
        ciphertext.extend_from_slice(&ciphertext_chunk);
    }
    ciphertext
}

pub(crate) fn mt19937_decrypt(ciphertext: &[u8], seed: u16) -> Vec<u8> {
    let mut rng = MersenneTwisterRng::new(seed as u32);
    let mut plaintext = vec![];
    let bytes_in_rng = 4;
    for (_, chunk) in ciphertext.chunks(bytes_in_rng).enumerate() {
        let keystream = rng.generate().to_le_bytes();
        let plaintext_chunk = fixed_xor(chunk, &keystream[..chunk.len()]);
        plaintext.extend_from_slice(&plaintext_chunk);
    }
    plaintext
}

#[test]
fn test_password_token() {
    let seed = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - thread_rng().gen_range(40..1000)) as u16;
    let token = generate_password_token(seed);
    assert_eq!(crack_password_token(token).unwrap(), seed);
}

#[test]
fn test_prefixed_prng() {
    let plaintext = [b'A'; 14];
    let seed = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - thread_rng().gen_range(40..1000)) as u16;
    let ciphertext = prng_encrypt_with_prefix(&plaintext, seed);
    let cracked_seed = crack_prefixed(&ciphertext, &plaintext).unwrap();
    assert_eq!(cracked_seed, seed);
}

#[test]
fn test_mt19937_cipher() {
    for _ in 0..20 {
        let plaintext: Vec<u8> = vec![0u8; thread_rng().gen_range(12..=256)]
            .iter()
            .map(|_| thread_rng().gen())
            .collect();
        let seed = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - thread_rng().gen_range(40..1000)) as u16;
        let ciphertext = mt19937_encrypt(&plaintext, seed);
        assert_eq!(mt19937_decrypt(&ciphertext, seed), plaintext);
    }
}

// Challenge 23

pub(crate) fn clone_mt19937(orig: &mut MersenneTwisterRng) -> MersenneTwisterRng {
    let shift = [mt::U, mt::S, mt::T, mt::L];
    let magic = [mt::D, mt::B, mt::C];
    let mut state = [0u32; mt::N];
    for elem in state.iter_mut() {
        let output = orig.generate();
        *elem = invert_temper(output, &shift, &magic);
    }
    MersenneTwisterRng::new_from_state(&state)
}

pub(crate) fn invert_right(output: u32, shift: u32, magic: u32) -> u32 {
    assert_ne!(shift, 0);
    let mut mask = !((1 << (32 - shift)) - 1);
    let mut input = output & mask;
    for _ in 0..((32 + shift - 1) / shift) {
        let in_bytes = output ^ ((input >> shift) & magic);
        mask >>= shift;
        input |= in_bytes & mask;
    }
    input
}

pub(crate) fn invert_left(output: u32, shift: u32, magic: u32) -> u32 {
    assert_ne!(shift, 0);
    let mut mask = (1 << shift) - 1;
    let mut input = output & mask;
    for _ in 0..((32 + shift - 1) / shift) {
        let in_bytes = output ^ ((input << shift) & magic);
        mask <<= shift;
        input |= in_bytes & mask;
    }
    input
}

pub(crate) fn invert_temper(out: u32, shift: &[u32; 4], magic: &[u32; 3]) -> u32 {
    let out = invert_right(out, shift[3], 0xFFFFFFFF);
    let out = invert_left(out, shift[2], magic[2]);
    let out = invert_left(out, shift[1], magic[1]);
    invert_right(out, shift[0], magic[0])
}

#[test]
fn test_clone_mt19937() {
    let seed: u32 = thread_rng().gen();
    let rng_init = MersenneTwisterRng::new(seed);
    let mut rng_mut = MersenneTwisterRng::new(seed);
    let rng_clone = clone_mt19937(&mut rng_mut);
    assert_eq!(rng_clone, rng_init);
}

#[test]
fn test_invert_right() {
    for _ in 0..20 {
        let shift = thread_rng().gen_range(1..32);
        let magic: u32 = thread_rng().gen();
        let input: u32 = thread_rng().gen();
        let output = input ^ ((input >> shift) & magic);
        assert_eq!(invert_right(output, shift, magic), input);
    }
}

#[test]
fn test_invert_left() {
    for _ in 0..20 {
        let shift = thread_rng().gen_range(1..32);
        let magic: u32 = thread_rng().gen();
        let input: u32 = thread_rng().gen();
        let output = input ^ ((input << shift) & magic);
        assert_eq!(invert_left(output, shift, magic), input);
    }
}

#[test]
fn test_invert_temper() {
    for _ in 0..20 {
        let input: u32 = thread_rng().gen();
        let mut output = input;
        let mut shift = [0u32; 4];
        for num in shift.iter_mut() {
            *num = thread_rng().gen_range(1..32);
        }
        let mut magic = [0u32; 3];
        thread_rng().fill(&mut magic);
        output ^= (output >> shift[0]) & magic[0];
        output ^= (output << shift[1]) & magic[1];
        output ^= (output << shift[2]) & magic[2];
        output ^= output >> shift[3];
        assert_eq!(invert_temper(output, &shift, &magic), input);
    }
}

// Challenge 22

pub(crate) fn crack_mt19937_time_seed(num: u32) -> Option<u32> {
    // assume the seed has been generated in the past x seconds
    let max_secs_passed = 60 * 24 * 7; // one week
    let max_generated = 1000;
    for secs_passed in 0..=max_secs_passed {
        // time if generated secs_passed ago
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
            - secs_passed;
        let mut rng = MersenneTwisterRng::new(seed);
        for _ in 0..max_generated {
            if rng.generate() == num {
                return Some(seed);
            }
        }
    }
    None
}

fn gen_wait_time() -> u32 {
    thread_rng().gen_range(40..=1000)
}

fn wait_random() {
    let wait_time = Duration::new(gen_wait_time().into(), 0);
    thread::sleep(wait_time);
}

#[cfg(wait)]
#[test]
fn test_crack_mt19937_time_seed_wait() {
    wait_random();

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut rng = MersenneTwisterRng::new(seed);

    wait_random();

    let rand_num = rng.generate();
    let cracked_seed = crack_mt19937_time_seed(rand_num).unwrap();

    assert_eq!(cracked_seed, seed);
}

#[test]
fn test_crack_mt19937_time_seed() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let seed = current_time - gen_wait_time();

    let mut rng = MersenneTwisterRng::new(seed);

    let rand_num = rng.generate();
    let cracked_seed = crack_mt19937_time_seed(rand_num).unwrap();

    assert_eq!(cracked_seed, seed);
}

// Challenge 21

mod mt {
    pub const N: usize = 624;

    pub const F: u64 = 1812433253;

    pub const W: u32 = 32;
    pub const R: u32 = 31;
    pub const M: usize = 397;
    pub const A: u32 = 0x9908B0DF;

    pub const U: u32 = 11;
    pub const D: u32 = 0xFFFFFFFF;
    pub const S: u32 = 7;
    pub const B: u32 = 0x9D2C5680;
    pub const T: u32 = 15;
    pub const C: u32 = 0xEFC60000;
    pub const L: u32 = 18;
}

#[derive(Debug, PartialEq)]
pub(crate) struct MersenneTwisterRng {
    state: [u32; mt::N],
    index: usize,
}

impl MersenneTwisterRng {
    fn lowest_bits(num: u64) -> u32 {
        (num & 0xFFFFFFFF) as u32
    }

    pub(crate) fn new(seed: u32) -> Self {
        let mut state = [0u32; mt::N];
        state[0] = seed;
        for i in 1..mt::N {
            state[i] = Self::lowest_bits(
                mt::F * (state[i - 1] ^ (state[i - 1] >> (mt::W - 2))) as u64 + i as u64,
            );
        }
        let mut obj = Self {
            state,
            index: mt::N,
        };
        obj.twist();
        obj
    }

    pub(crate) fn new_from_state(state: &[u32; mt::N]) -> MersenneTwisterRng {
        Self {
            state: *state,
            index: 0,
        }
    }

    pub(crate) fn generate(&mut self) -> u32 {
        assert!(self.index <= mt::N, "Generator was never seeded");
        if self.index == mt::N {
            self.twist()
        }
        let mut y = self.state[self.index];
        y ^= (y >> mt::U) & mt::D;
        y ^= (y << mt::S) & mt::B;
        y ^= (y << mt::T) & mt::C;
        y ^= y >> mt::L;
        self.index += 1;
        y
    }

    fn twist(&mut self) {
        let lower_mask = (1 << mt::R) - 1;
        let upper_mask = 1 << mt::R;
        for i in 0..mt::N {
            let x = (self.state[i] & upper_mask) | (self.state[(i + 1) % mt::N] & lower_mask);
            let mut x_a = x >> 1;
            if x & 1 == 1 {
                x_a ^= mt::A;
            }
            self.state[i] = self.state[(i + mt::M) % mt::N] ^ x_a;
        }
        self.index = 0;
    }
}

#[test]
fn test_mt19937_rng() {
    let expected_results: [u32; 20] = [
        2124297904, 554800608, 979609483, 319445101, 1097252129, 2619664350, 1702224004, 92067910,
        1620556005, 653697094, 4280253718, 4100431597, 1753193605, 3456085250, 3315259487,
        1048960250, 3266480199, 1396711791, 1331480004, 1886800846,
    ];
    let seed = 50;
    let mut rng = MersenneTwisterRng::new(seed);
    for &result in expected_results.iter() {
        assert_eq!(rng.generate(), result);
    }
}

// Challenge 20

pub(crate) fn fixed_nonce_ctr_attack(ciphertexts: &[&[u8]]) -> Vec<u8> {
    let transposed = transpose_blocks(ciphertexts);

    let mut key_stream = vec![];
    for block in transposed.into_iter() {
        let (_score, single_byte_key, _plaintext) = decrypt_single_byte_xor(block);
        key_stream.push(single_byte_key);
    }

    key_stream
}

#[test]
fn test_fixed_nonce_ctr_attack() {
    let mut file = fs::File::open("data/20_sol.txt").unwrap();
    let mut solution_contents = String::new();
    file.read_to_string(&mut solution_contents).unwrap();
    let solution: Vec<&[u8]> = solution_contents.lines().map(|l| l.as_bytes()).collect();

    let mut file = fs::File::open("data/20.txt").unwrap();
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents).unwrap();
    let plaintexts: Vec<Vec<u8>> = file_contents
        .lines()
        .map(|line| general_purpose::STANDARD.decode(line).unwrap())
        .collect();
    let plaintexts: Vec<&[u8]> = plaintexts.iter().map(|v| v.as_slice()).collect();

    let key = generate_key();
    let ciphertexts: Vec<Vec<u8>> = plaintexts
        .iter()
        .map(|&plaintext| aes_ctr_encrypt(&plaintext, &key, 0))
        .collect();
    let ciphertexts: Vec<&[u8]> = ciphertexts.iter().map(|c| c.as_slice()).collect();
    let shortest_length = ciphertexts
        .iter()
        .map(|c| c.len())
        .reduce(|min_len, len| std::cmp::min(min_len, len))
        .unwrap();
    let ciphertexts: Vec<&[u8]> = ciphertexts.iter().map(|c| &c[..shortest_length]).collect();

    let key_stream = fixed_nonce_ctr_attack(&ciphertexts);
    let output: Vec<Vec<u8>> = ciphertexts
        .iter()
        .map(|c| repeating_key_xor(&key_stream, c))
        .collect();
    let output: Vec<&[u8]> = output.iter().map(|v| v.as_slice()).collect();
    assert_eq!(output, solution);
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

#[test]
fn test_aes_ctr_mode() {
    let b64_ciphertext =
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let ciphertext = general_purpose::STANDARD.decode(b64_ciphertext).unwrap();
    let key = b"YELLOW SUBMARINE";
    let nonce = 0;
    let expected_output = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec();
    let output = aes_ctr_decrypt(&ciphertext, key, nonce);
    assert_eq!(output, expected_output);
    assert_eq!(aes_ctr_encrypt(&output, key, nonce), ciphertext);
}

// Challenge 17

pub(crate) fn cbc_padding_oracle_attack(
    ciphertext: &[u8],
    iv: &[u8],
    oracle: &CbcPaddingOracle,
) -> Vec<u8> {
    // Assume block size
    let block_size = 16;

    // decrypt
    let mut plaintext = vec![];
    for (block_idx, block) in ciphertext.chunks(block_size).enumerate().rev() {
        let mut prev_block = if block_idx == 0 {
            iv.to_owned()
        } else {
            ciphertext
                .chunks(block_size)
                .nth(block_idx - 1)
                .unwrap()
                .to_owned()
        };

        let base: Vec<u8> = if block_idx == 0 {
            vec![]
        } else {
            ciphertext
                .iter()
                .take((block_idx - 1) * 16)
                .copied()
                .collect()
        };

        let mut plaintext_block = vec![0u8; block.len()];
        for byte_idx in (0..block.len()).rev() {
            let pad_byte = (block_size - byte_idx) as u8;

            let mut working_prev_block = prev_block.clone();
            for byte in working_prev_block
                .iter_mut()
                .take(block.len())
                .skip(byte_idx + 1)
            {
                *byte ^= pad_byte;
            }
            for byte in 0..=255 {
                if block_idx == ciphertext.chunks(block_size).len() - 1
                    && byte_idx == block.len() - 1
                    && byte == prev_block[byte_idx]
                {
                    continue;
                }
                working_prev_block[byte_idx] = byte;
                let input = [base.as_slice(), working_prev_block.as_slice(), block].concat();
                if oracle.check_valid_padding(&input) {
                    // decrypted[byte_idx] ^ working_prev_block[byte_idx] = pad_byte
                    plaintext_block[byte_idx] = prev_block[byte_idx] ^ byte ^ pad_byte;
                    prev_block[byte_idx] = byte ^ pad_byte;
                    break;
                }
            }
        }
        plaintext = [plaintext_block, plaintext].concat();
    }

    plaintext
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

#[test]
fn test_cbc_padding_oracle_attack() {
    let plaintexts = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    let plaintexts: Vec<Vec<u8>> = plaintexts
        .iter()
        .map(|b64| general_purpose::STANDARD.decode(b64.as_bytes()).unwrap())
        .collect();
    let key = &generate_key();
    let iv = &generate_key();
    let oracle = CbcPaddingOracle::new(key, iv, plaintexts.clone());
    let (ciphertext, iv, idx) = oracle.encrypt();

    let output = cbc_padding_oracle_attack(&ciphertext, &iv, &oracle);
    assert_eq!(output, pkcs7_pad(&plaintexts[idx], 16));
}
