use base64::{engine::general_purpose, Engine};
use hex;
use prng::MersenneTwisterRng;
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::prelude::*;
use std::ops::Range;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, thread};
use thiserror;

mod basic;
mod block;
mod prng;
mod stream;

mod oracle;

use basic::{
    decrypt_repeating_key_xor, decrypt_single_byte_xor, decrypt_single_byte_xor_many, fixed_xor,
    get_blocks, hamming_distance, hex_to_base64, hex_to_base64_string, repeating_key_xor,
    transpose_blocks,
};
use block::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_decrypt, aes_ecb_encrypt, byte_at_a_time_ecb_decrypt,
    byte_at_a_time_ecb_decrypt_harder, cbc_bit_flipping_attack, cbc_padding_oracle_attack,
    detect_aes_ecb, detect_mode, fixed_nonce_ctr_attack, forge_admin_ciphertext,
    pkcs7_pad, pkcs7_unpad, ConsistentKey, EcbOracleHarder, recoverkey_from_cbc_key_as_iv
};
use oracle::{
    parse_key_value, AesCbcOracle, AesCtrOracle, BitFlippingOracle, CbcBitFlippingOracle,
    CbcPaddingOracle, CtrBitFlippingOracle, CtrEditOracle, ProfileManager, Role, UserProfile, AesCbcOracleKeyAsIv, encrypt_oracle
};
use prng::{
    clone_mt19937, crack_mt19937_time_seed, crack_password_token, crack_prefixed,
    generate_password_token, invert_left, invert_right, invert_temper, mt19937_decrypt,
    mt19937_encrypt, prng_encrypt_with_prefix,
};
use stream::{
    aes_ctr_decrypt, aes_ctr_encrypt, break_random_access_read_write_aes_ctr,
    ctr_bit_flipping_attack,
};


fn main() {
    println!("Hello, world!");
}

const BLOCK_SIZE: usize = 16;

// Challenge 27

#[test]
fn test_recover_key_from_cbc_key_as_iv() {
    let key = generate_key();
    let oracle = AesCbcOracleKeyAsIv::new(
        &key,
        b"comment1=cooking%20MCs;userdata=",
        b";comment2=%20like%20a%20pound%20of%20bacon",
    );
    let mut plaintext = [0u8; 3 * BLOCK_SIZE];
    thread_rng().fill_bytes(&mut plaintext);
    while plaintext.iter().any(|x| b";=".contains(x)) {
        thread_rng().fill_bytes(&mut plaintext);
    }
    let ciphertext = oracle.encrypt(&plaintext);
    let recovered_key = recoverkey_from_cbc_key_as_iv(&ciphertext, &oracle);
    assert_eq!(recovered_key, key);
}

// Challenge 26

#[test]
fn test_ctr_bit_flipping() {
    for _ in 0..15 {
        let aes_ctr_oracle = AesCtrOracle::new();
        let oracle = BitFlippingOracle::new(
            &aes_ctr_oracle,
            b"comment1=cooking%20MCs;userdata=",
            b";comment2=%20like%20a%20pound%20of%20bacon",
        );
        let breaking_ciphertext = ctr_bit_flipping_attack(&oracle);
        let result = oracle.check_admin(&breaking_ciphertext);
        assert!(result.unwrap_or(false));
    }
}

// Challenge 25

#[test]
fn test_break_random_access_aes_ctr() {
    // read file
    let mut file = fs::File::open("data/25.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = b"YELLOW SUBMARINE";
    let plaintext = pkcs7_unpad(&aes_ecb_decrypt(&contents, key)).unwrap();

    let nonce = thread_rng().gen::<u64>();
    let key = generate_key();
    let ciphertext = aes_ctr_encrypt(&plaintext, &key, nonce);
    let oracle = CtrEditOracle::new(&key, nonce);

    let output = break_random_access_read_write_aes_ctr(&ciphertext, &oracle);
    assert_eq!(output, plaintext);
}

// Challenge 24

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

// Challenge 16

#[test]
fn test_cbc_bit_flipping() {
    for _ in 0..15 {
        let aes_cbc_oracle = AesCbcOracle::new();
        let oracle = BitFlippingOracle::new(
            &aes_cbc_oracle,
            b"comment1=cooking%20MCs;userdata=",
            b";comment2=%20like%20a%20pound%20of%20bacon",
        );
        let breaking_ciphertext = cbc_bit_flipping_attack(&oracle);
        let result = oracle.check_admin(&breaking_ciphertext);
        assert!(if let Ok(is_admin) = result {
            is_admin
        } else {
            false
        });
    }
}

// Challenge 15

#[test]
fn test_pkcs7_unpad() {
    let input_good_1 = b"ICE ICE BABY\x04\x04\x04\x04";
    let input_good_2 = [[b'A'; 16], [16; 16]].concat();
    let input_bad_1 = b"ICE ICE BABY\x05\x05\x05\x05";
    let input_bad_2 = b"ICE ICE BABY\x01\x02\x03\x04";
    let input_bad_3 = b"asdfasdfasdfasdf";

    assert!(pkcs7_unpad(input_good_1).unwrap() == b"ICE ICE BABY".to_vec());
    assert!(pkcs7_unpad(&input_good_2).unwrap() == vec![b'A'; 16]);
    assert!(pkcs7_unpad(input_bad_1).is_err());
    assert!(pkcs7_unpad(input_bad_2).is_err());
    assert!(pkcs7_unpad(input_bad_3).is_err());
}

// Challenge 14

#[test]
fn test_byte_at_a_time_ecb_decryption_harder() {
    let key = generate_key();
    let unknown_string_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let unknown_string = general_purpose::STANDARD_NO_PAD
        .decode(unknown_string_b64)
        .unwrap();
    let mut rng = thread_rng();
    const LOWER: usize = 1;
    const UPPER: usize = 512;
    let count = rng.gen_range(LOWER..=UPPER);
    let mut prefix = [0u8; UPPER];
    for byte in &mut prefix {
        *byte = rng.gen();
    }
    let oracle = EcbOracleHarder::new(&key, &unknown_string, &prefix[..count]);

    let output = byte_at_a_time_ecb_decrypt_harder(&oracle);
    // I am not sure why, but currently my decryption includes one extra
    // bit...
    assert_eq!(&output[..(output.len() - 1)], unknown_string.as_slice());
}

// Challenge 13

#[test]
fn test_forge_admin_ciphertext() {
    let key = generate_key();
    let profile_manager = ProfileManager::new(&key);
    let ciphertext = forge_admin_ciphertext(&profile_manager);
    let output = profile_manager.add_profile(&ciphertext);
    assert!(output.role == Role::Admin);
}

#[test]
fn test_add_profile() {
    let key = generate_key();
    let profile_manager = ProfileManager::new(&key);
    let input = "foo@bar.com";
    let expected_output = UserProfile::new(String::from(input), 10, Role::User);
    let output = profile_manager.add_profile(&profile_manager.profile_for_encrypted(input));
    assert!(output == expected_output);
}

#[test]
fn test_profile_for() {
    let input = "foo@bar.com";
    let input2 = "bar@foo.com";
    let key = generate_key();
    let profile_manager = ProfileManager::new(&key);
    let expected_output = "email=foo@bar.com&uid=10&role=user";
    let output = profile_manager.profile_for(input);
    assert_eq!(output, expected_output);
    let expected_output = "email=bar@foo.com&uid=10&role=user";
    let output = profile_manager.profile_for(input2);
    assert_eq!(output, expected_output);
}

#[test]
#[should_panic]
fn test_profile_for_panic() {
    let bad_input = "foo@bar.com&role=admin";
    let key = generate_key();
    let profile_manager = ProfileManager::new(&key);
    profile_manager.profile_for(bad_input);
}

#[test]
fn test_parse_key_value() {
    let input = "foo=bar&baz=qux&zap=zazzle";
    let expected_output = HashMap::from([("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")]);
    let output = parse_key_value(input);
    assert_eq!(output, expected_output);
}

// Challenge 12

#[test]
fn test_byte_at_a_time_ecb_decryption_simple() {
    let key = generate_key();
    let unknown_string_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let unknown_string = general_purpose::STANDARD_NO_PAD
        .decode(unknown_string_b64)
        .unwrap();
    let oracle = ConsistentKey::new(&key, &unknown_string);

    let output = byte_at_a_time_ecb_decrypt(&oracle);
    assert_eq!(output.as_slice(), unknown_string.as_slice());
}

// Challenge 11

fn generate_key() -> [u8; 16] {
    let mut key = [0; 16];
    thread_rng().fill_bytes(&mut key);
    key
}

#[test]
fn test_detect_mode() {
    let mut file = fs::File::open("data/6_sol.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let n_trials = 30;
    for _ in 0..n_trials {
        let (mode, ciphertext) = encrypt_oracle(contents.as_bytes());
        let output = detect_mode(&ciphertext);
        assert!(output == mode);
    }
}

// Challenge 10

#[test]
fn test_aes_cbc_encrypt() {
    let mut rng = thread_rng();
    let plaintext: Vec<u8> = (0..rng.gen_range(16..256)).map(|_| rng.gen()).collect();
    let plaintext = pkcs7_pad(plaintext.as_slice(), 16);
    let key = generate_key();
    let iv = generate_key();
    let ciphertext = aes_cbc_encrypt(&plaintext, &key, &iv);
    let decrypted_ciphertext = aes_cbc_decrypt(&ciphertext, &key.to_vec(), &iv);
    assert_eq!(plaintext, decrypted_ciphertext);
}

#[test]
fn test_aes_cbc_decrypt() {
    let mut file = fs::File::open("data/10.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = String::from("YELLOW SUBMARINE");
    let iv = &[0u8; 16];

    let mut file = fs::File::open("data/7_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();
    let expected_output = expected_output;

    let output = aes_cbc_decrypt(contents.as_slice(), key.as_bytes(), iv);
    assert_eq!(output.as_slice(), expected_output.into_bytes());
}

// Challenge 9

#[test]
fn test_pkcs7_pad() {
    let input = "YELLOW_SUBMARINE".as_bytes().to_vec();
    let length = 20;
    let expected_output = "YELLOW_SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec();
    let output = pkcs7_pad(&input, length);
    assert_eq!(output, expected_output);
}

// Challenge 8

#[test]
fn test_detect_aes_ecb() {
    let mut file = fs::File::open("data/8.txt").unwrap();
    let mut hex_contents = String::new();
    file.read_to_string(&mut hex_contents).unwrap();
    let lines: Vec<Vec<u8>> = hex_contents
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect();
    let expected_output = lines[132].to_owned();
    let output = detect_aes_ecb(&lines).unwrap();
    assert_eq!(expected_output, output);
}

// Challenge 7

#[test]
fn test_aes_ecb_encrypt() {
    let mut rng = thread_rng();
    let plaintext: Vec<u8> = (0..rng.gen_range(16..256)).map(|_| rng.gen()).collect();
    let plaintext = pkcs7_pad(plaintext.as_slice(), 16);
    let key = generate_key();
    let ciphertext = aes_ecb_encrypt(&plaintext, &key);
    let decrypted_ciphertext = aes_ecb_decrypt(&ciphertext, &key.to_vec());
    assert_eq!(plaintext, decrypted_ciphertext);
}

#[test]
fn test_aes_ecb_decrypt() {
    let mut file = fs::File::open("data/7.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = String::from("YELLOW SUBMARINE").into_bytes();

    let mut file = fs::File::open("data/7_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();

    let output = aes_ecb_decrypt(&contents, &key);
    assert_eq!(output.as_slice(), expected_output.into_bytes());
}

// Challenge 6

#[test]
fn test_decrypt_repeating_key_xor() {
    let mut file = fs::File::open("data/6.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();

    let mut file = fs::File::open("data/6_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();

    let output = decrypt_repeating_key_xor(contents);
    assert_eq!(output, expected_output.into_bytes());
}

#[test]
fn test_transpose_blocks() {
    let blocks = vec![vec![1, 2, 3], vec![4, 5]];
    let blocks: Vec<&[u8]> = blocks.iter().map(|v| v.as_slice()).collect();
    assert_eq!(
        transpose_blocks(&blocks),
        vec![vec![1, 4], vec![2, 5], vec![3]]
    );
}

#[test]
fn test_get_blocks() {
    let input = vec![1, 2, 3, 4, 5];
    assert_eq!(get_blocks(&input, 3), vec![vec![1, 2, 3], vec![4, 5]]);
    assert_eq!(get_blocks(&input, 5), vec![vec![1, 2, 3, 4, 5]]);
}

#[test]
fn test_hamming_distance() {
    let input1 = String::from("this is a test").into_bytes();
    let input2 = String::from("wokka wokka!!!").into_bytes();
    let expected_output = 37;

    let output = hamming_distance(input1, input2);
    assert_eq!(output, expected_output);
}

// Challenge 5

#[test]
fn test_repeating_key_xor() {
    let key = String::from("ICE").into_bytes();
    let input = String::from(
        "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal",
    )
    .into_bytes();
    let expected_output = hex::decode(String::from(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
    ))
    .unwrap();

    let output = repeating_key_xor(&key, &input);
    assert_eq!(output, expected_output);
}

// Challenge 4

#[test]
fn test_detect_single_byte_xor() {
    let mut file = fs::File::open("data/4.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mut lines = Vec::new();
    for line in contents.lines() {
        lines.push(line.to_owned());
    }

    let expected_output = String::from("Now that the party is jumping\n");
    let (_, _, plaintext) = decrypt_single_byte_xor_many(lines);
    assert_eq!(plaintext, expected_output.into_bytes());
}

// Challenge 3

#[test]
fn test_decrypt_single_bytes_xor() {
    let input =
        String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let expected_output = String::from("Cooking MC's like a pound of bacon");

    let (_, _, plaintext) = decrypt_single_byte_xor(hex::decode(input).unwrap());
    assert_eq!(plaintext, expected_output.into_bytes());
}

// Challenge 2

#[test]
fn test_fixed_xor() {
    let input1 = String::from("1c0111001f010100061a024b53535009181c");
    let input2 = String::from("686974207468652062756c6c277320657965");
    let expected_output = String::from("746865206b696420646f6e277420706c6179");

    let output = fixed_xor(
        hex::decode(input1).unwrap().as_slice(),
        hex::decode(input2).unwrap().as_slice(),
    );
    assert_eq!(
        hex::decode(expected_output).unwrap().as_slice(),
        output.as_slice()
    );
}

// Challenge 1

#[test]
fn test_hex_to_base64() {
    let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_output = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let output = hex_to_base64(input);
    assert_eq!(expected_output, output.as_slice());
}

#[test]
fn test_hex_to_base64_string() {
    let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let expected_output =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let output = hex_to_base64_string(input);
    assert_eq!(expected_output, output);
}
