use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::{engine::general_purpose, Engine};
use hex;
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::str::FromStr;
use thiserror::Error;

fn main() {
    println!("Hello, world!");
}

// Challenge 15

#[derive(Error, Debug)]
enum MyError {
    #[error("Invalid PKCS#7 padding")]
    InvalidPkcs7Padding,
}

fn pkcs7_unpad(input: &[u8]) -> Result<Vec<u8>, MyError> {
    assert!(!input.is_empty());
    let last_byte = *input.last().unwrap();
    if last_byte as usize > input.len() {
        return Err(MyError::InvalidPkcs7Padding);
    }
    let is_padded = input[(input.len() - last_byte as usize)..]
        .iter()
        .all(|&b| b == last_byte);
    if is_padded {
        Ok(input[..(input.len() - last_byte as usize)].to_vec())
    } else {
        Err(MyError::InvalidPkcs7Padding)
    }
}

#[test]
fn test_pkcs7_unpad() {
    let input = b"ICE ICE BABY\x04\x04\x04\x04";
    let input_bad_1 = b"ICE ICE BABY\x05\x05\x05\x05";
    let input_bad_2 = b"ICE ICE BABY\x01\x02\x03\x04";

    assert!(pkcs7_unpad(input).unwrap() == b"ICE ICE BABY");
    assert!(pkcs7_unpad(input_bad_1).is_err());
    assert!(pkcs7_unpad(input_bad_2).is_err());
}

// Challenge 14

fn byte_at_a_time_ecb_decrypt_harder(oracle: &EcbOracleHarder) -> Vec<u8> {
    // Find block size - see when padding jumps
    let base_ciphertext = oracle.encrypt(&[]);
    let mut block_size = 0;
    let mut base_padding_length = 0;
    for i in 1..64 {
        let ciphertext = oracle.encrypt(&vec![b'A'; i]);
        let diff = ciphertext.len() - base_ciphertext.len();
        if diff != 0 {
            block_size = diff;
            base_padding_length = i - 1;
            break;
        }
    }
    assert!(block_size > 0);
    let block_size = block_size;

    // Find length of prefix and target bytes
    let mut prefix_length = 0;
    let mut input = vec![b'A'; block_size * 2];
    for offset in 0..block_size {
        let ciphertext = oracle.encrypt(&input);
        for i in 0..(ciphertext.len() / block_size - 1) {
            let chunk1 = &ciphertext[(i * block_size)..((i + 1) * block_size)];
            let chunk2 = &ciphertext[((i + 1) * block_size)..((i + 2) * block_size)];
            if chunk1 == chunk2 {
                prefix_length = i * block_size - offset;
                break;
            }
        }
        if prefix_length != 0 {
            break;
        }
        input.push(b'A');
    }
    let prefix_length = prefix_length;
    let prefix_padding = vec![0u8; block_size - (prefix_length % block_size)];
    let prefix_block_length = prefix_length + prefix_padding.len();
    let target_length = base_ciphertext.len() - prefix_length - base_padding_length;

    // decrypt
    let mut plaintext = vec![0u8; target_length];
    for idx in 0..target_length {
        // get the target block
        let filler = [
            prefix_padding.clone(),
            vec![b'A'; block_size - (idx % block_size) - 1],
        ]
        .concat();
        let ciphertext = oracle.encrypt(&filler);
        let target_block = ciphertext
            .iter()
            .skip(prefix_block_length)
            .map(|&byte| byte)
            .collect::<Vec<u8>>();
        let target_block = target_block
            .chunks(block_size)
            .nth(idx / block_size)
            .unwrap();

        // get the base
        let base = [
            prefix_padding.clone(),
            if idx < block_size {
                [vec![b'A'; block_size - idx - 1], plaintext[..idx].to_vec()].concat()
            } else {
                plaintext
                    .iter()
                    .skip(idx - (block_size - 1))
                    .take(block_size - 1)
                    .map(|&byte| byte)
                    .collect()
            },
        ]
        .concat();

        // cycle through
        let mut plaintext_byte = 0;
        for byte in 0..=255 {
            let input = [&base[..], &[byte]].concat();
            let ciphertext = oracle.encrypt(input.as_slice());
            let block: Vec<u8> = ciphertext
                .iter()
                .skip(prefix_block_length)
                .take(block_size)
                .map(|&byte| byte)
                .collect();
            if block.as_slice() == target_block {
                plaintext_byte = byte;
                break;
            }
        }
        plaintext[idx] = plaintext_byte;
    }

    plaintext
}

struct EcbOracleHarder<'a> {
    key: &'a [u8],
    target: &'a [u8],
    prefix: &'a [u8],
}

impl<'a> EcbOracleHarder<'a> {
    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let plaintext: &[u8] = &[self.prefix, input, self.target].concat();
        let plaintext_padded = pkcs7_pad(plaintext, 16);
        aes_ecb_encrypt(&plaintext_padded, self.key)
    }
}

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
    let oracle = EcbOracleHarder {
        key: &key,
        target: &unknown_string,
        prefix: &prefix[..count],
    };

    let output = byte_at_a_time_ecb_decrypt_harder(&oracle);
    println!("{}", String::from_utf8(output.clone()).unwrap());
    // I am not sure why, but currently my decryption includes one extra
    // bit...
    assert_eq!(&output[..(output.len() - 1)], unknown_string.as_slice());
}

// Challenge 13

fn forge_admin_ciphertext(oracle: &ProfileManager) -> Vec<u8> {
    let block_size = 16;
    // get ciphertext block of "adminPADDING"
    let email = String::from("fooo@barr.")
        + std::str::from_utf8(&pkcs7_pad("admin".as_bytes(), block_size)).unwrap();
    let admin_ciphertext = oracle.profile_for_encrypted(email.as_str());
    let admin_block = admin_ciphertext.chunks(block_size).nth(1).unwrap();
    // get first two blocks of "email=asdf&uid=asdf&role="
    let email = "fooo@barr.com";
    let prefix_ciphertext = oracle.profile_for_encrypted(email);
    let prefix_blocks = &prefix_ciphertext[..(block_size * 2)];
    // add together
    [prefix_blocks, admin_block].concat()
}

#[test]
fn test_forge_admin_ciphertext() {
    let key = generate_key();
    let profile_manager = ProfileManager::new(&key);
    let ciphertext = forge_admin_ciphertext(&profile_manager);
    let output = profile_manager.add_profile(&ciphertext);
    assert!(output.role == Role::Admin);
}

struct ProfileManager<'a> {
    key: &'a [u8],
}

impl<'a> ProfileManager<'a> {
    fn new(key: &'a [u8]) -> Self {
        Self { key }
    }

    fn add_profile(&self, ciphertext: &'a [u8]) -> UserProfile {
        let plaintext = pkcs7_unpad_unchecked(&aes_ecb_decrypt(ciphertext, self.key));
        let profile = UserProfile::decode(std::str::from_utf8(&plaintext).unwrap());
        // (add profile)
        profile
    }

    fn profile_for(&self, email: &str) -> String {
        assert!(!email.contains('=') && !email.contains('&'));
        UserProfile {
            email: String::from(email),
            uid: 10,
            role: Role::User,
        }
        .encode()
    }

    fn profile_for_encrypted(&self, email: &str) -> Vec<u8> {
        aes_ecb_encrypt(&pkcs7_pad(self.profile_for(email).as_bytes(), 16), self.key)
    }
}

#[derive(PartialEq)]
enum Role {
    User,
    Admin,
}

#[derive(PartialEq)]
struct UserProfile {
    email: String,
    uid: usize,
    role: Role,
}

impl UserProfile {
    fn encode(&self) -> String {
        String::from("email=")
            + &self.email
            + "&uid="
            + &self.uid.to_string()
            + "&role="
            + match self.role {
                Role::User => "user",
                Role::Admin => "admin",
            }
    }

    fn decode(input: &str) -> Self {
        let key_value_map = parse_key_value(input);
        assert!(
            key_value_map.contains_key("email")
                && key_value_map.contains_key("uid")
                && key_value_map.contains_key("role")
        );
        let email = *key_value_map.get("email").unwrap();
        assert!(!email.contains('=') && !email.contains('&'));
        let uid = key_value_map.get("uid").unwrap().parse::<usize>().unwrap();
        let role = *key_value_map.get("role").unwrap();
        println!("{} {:?}", input, role.as_bytes());
        let role = match role {
            "user" => Role::User,
            "admin" => Role::Admin,
            _ => panic!(),
        };
        Self {
            email: String::from(email),
            uid,
            role,
        }
    }
}

#[test]
fn test_add_profile() {
    let key = generate_key();
    let mut profile_manager = ProfileManager::new(&key);
    let input = "foo@bar.com";
    let expected_output = UserProfile {
        email: String::from(input),
        uid: 10,
        role: Role::User,
    };
    let output = profile_manager.add_profile(&profile_manager.profile_for_encrypted(input));
    assert!(output == expected_output);
}

#[test]
fn test_profile_for() {
    let input = "foo@bar.com";
    let input2 = "bar@foo.com";
    let key = generate_key();
    let mut profile_manager = ProfileManager::new(&key);
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
    let mut profile_manager = ProfileManager::new(&key);
    profile_manager.profile_for(bad_input);
}

fn parse_key_value(input: &str) -> HashMap<&str, &str> {
    let mut object: HashMap<&str, &str> = HashMap::new();
    for s in input.split('&') {
        let key_value: Vec<&str> = s.split('=').collect();
        assert!(key_value.len() == 2);
        let key = key_value[0];
        let value = key_value[1];
        let prev_value = object.insert(key, value);
        assert!(prev_value.is_none());
    }
    object
}

#[test]
fn test_parse_key_value() {
    let input = "foo=bar&baz=qux&zap=zazzle";
    let expected_output = HashMap::from([("foo", "bar"), ("baz", "qux"), ("zap", "zazzle")]);
    let output = parse_key_value(input);
    assert_eq!(output, expected_output);
}

#[test]
fn test_ecb_cut_and_paste() {}

// Challenge 12

fn byte_at_a_time_ecb_decrypt(oracle: &ConsistentKey) -> Vec<u8> {
    // We know the general format of the encryption I guess
    // so we know this to be just the encrypted appendage
    let ciphertext_len = 138; // hardcoded but I should actually find this later

    // get block size
    // only way I can think to get block size is to assume Ecb
    // so it kinda defeats the point...? hardcoding for now
    let block_size = 16;

    // detect that the function is using ECB
    let modified_ciphertext = oracle.encrypt(&[65; 32]);
    let mode = detect_mode(&modified_ciphertext);
    assert!(mode == AesBlockCipherMode::Ecb);

    // decrypt
    let mut decrypted = Vec::new();
    for idx in 0..ciphertext_len {
        // Get key block
        let my_string = if idx < block_size {
            vec![65u8; block_size - idx - 1]
        } else {
            vec![65u8; block_size - (idx % block_size) - 1]
        };
        let ciphertext_with_last_byte = oracle.encrypt(&my_string);
        let target_block: [u8; 16] = if idx < block_size {
            ciphertext_with_last_byte[0..16].try_into().unwrap()
        } else {
            ciphertext_with_last_byte
                [(idx / block_size * block_size)..((idx / block_size + 1) * block_size)]
                .try_into()
                .unwrap()
        };

        // Construct pre-byte block
        let my_string = if idx < block_size {
            let mut my_string = vec![65u8; block_size - idx - 1];
            my_string.extend(decrypted.iter().take(idx));
            my_string
        } else {
            decrypted[(idx + 1 - block_size)..(idx)].to_vec()
        };
        let my_string: &[u8] = &my_string;

        // iterate through bytes
        let mut decrypted_byte = 0;
        for byte in 0..=255 {
            let plaintext: [u8; 16] = [my_string, &[byte]].concat().try_into().unwrap();
            let ciphertext = oracle.encrypt(&plaintext);
            if byte > 43 && byte < 47 {}
            let first_block: [u8; 16] = ciphertext[0..16].try_into().unwrap();
            if first_block == target_block {
                decrypted_byte = *plaintext.last().unwrap();
            }
        }

        // Append result
        decrypted.push(decrypted_byte);
    }
    decrypted
}

struct ConsistentKey<'a> {
    key: &'a [u8],
    append_text: &'a [u8],
}

impl<'a> ConsistentKey<'a> {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let plaintext_with_append: &[u8] = &[plaintext, self.append_text].concat();
        let plaintext_to_encrypt = pkcs7_pad(plaintext_with_append, 16);
        aes_ecb_encrypt(&plaintext_to_encrypt, self.key)
    }
}

#[test]
fn test_byte_at_a_time_ecb_decryption_simple() {
    let key = generate_key();
    let unknown_string_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let unknown_string = general_purpose::STANDARD_NO_PAD
        .decode(unknown_string_b64)
        .unwrap();
    let oracle = ConsistentKey {
        key: &key,
        append_text: &unknown_string,
    };

    //     let expected_output = "Rollin' in my 5.0
    // With my rag-top down so my hair can blow
    // The girlies on standby waving just to say hi
    // Did you stop? No, I just drove by"
    //         .as_bytes();
    let output = byte_at_a_time_ecb_decrypt(&oracle);
    println!("{}", String::from_utf8(output.clone()).unwrap());
    assert_eq!(output.as_slice(), unknown_string.as_slice());
}

// Challenge 11

fn generate_key() -> [u8; 16] {
    let mut key = [0; 16];
    thread_rng().fill_bytes(&mut key);
    key
}

#[derive(PartialEq)]
enum AesBlockCipherMode {
    Ecb,
    Cbc,
}

fn detect_mode(ciphertext: &[u8]) -> AesBlockCipherMode {
    assert!(ciphertext.len() % 16 == 0);
    let mut max_repeat = 1;
    for offset in 0..16 {
        let ciphertext = &ciphertext[offset..];
        let mut block_frequency: HashMap<[u8; 16], u32> = HashMap::new();
        for chunk in ciphertext.chunks(16) {
            if chunk.len() != 16 {
                continue;
            }
            let block: [u8; 16] = chunk.try_into().unwrap();
            block_frequency
                .entry(block)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
        let mut values: Vec<u32> = block_frequency.into_values().collect();
        values.sort();
        values.reverse();
        max_repeat = std::cmp::max(max_repeat, values[0]);
    }
    if max_repeat > 1 {
        AesBlockCipherMode::Ecb
    } else {
        AesBlockCipherMode::Cbc
    }
}

fn encrypt_oracle(input: &[u8]) -> (AesBlockCipherMode, Vec<u8>) {
    // append 5-10 bytes before and after plaintext
    let mut rng = thread_rng();
    let random_bytes: Vec<u8> = (0..rng.gen_range(5..=10)).map(|_| rng.gen()).collect();
    let mut plaintext = vec![];
    plaintext.extend(random_bytes.iter());
    plaintext.extend_from_slice(input);
    plaintext.extend(random_bytes.iter());
    let plaintext = pkcs7_pad(plaintext.as_slice(), 16);

    // randomly encrypt using ECB or CBC
    let key = generate_key();
    match thread_rng().gen_range(0..2) {
        0 => (AesBlockCipherMode::Ecb, aes_ecb_encrypt(&plaintext, &key)),
        1 => {
            let iv = generate_key();
            (
                AesBlockCipherMode::Cbc,
                aes_cbc_encrypt(&plaintext, &key, &iv),
            )
        }
        _ => panic!("Generated number out of range"),
    }
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

fn aes_cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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

#[test]
fn test_aes_cbc_encrypt() {
    let mut rng = thread_rng();
    let plaintext: Vec<u8> = (0..rng.gen_range(16..256)).map(|_| rng.gen()).collect();
    let plaintext = pkcs7_pad(plaintext.as_slice(), 16);
    println!("{}", plaintext.len() % 16);
    let key = generate_key();
    println!("{}", key.len());
    let iv = generate_key();
    let ciphertext = aes_cbc_encrypt(&plaintext, &key, &iv);
    let decrypted_ciphertext = aes_cbc_decrypt(&ciphertext, &key.to_vec(), &iv);
    assert_eq!(plaintext, decrypted_ciphertext);
}

fn aes_ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
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

#[test]
fn test_aes_ecb_encrypt() {
    let mut rng = thread_rng();
    let plaintext: Vec<u8> = (0..rng.gen_range(16..256)).map(|_| rng.gen()).collect();
    let plaintext = pkcs7_pad(plaintext.as_slice(), 16);
    println!("{}", plaintext.len() % 16);
    let key = generate_key();
    let ciphertext = aes_ecb_encrypt(&plaintext, &key);
    let decrypted_ciphertext = aes_ecb_decrypt(&ciphertext, &key.to_vec());
    assert_eq!(plaintext, decrypted_ciphertext);
}

// Challenge 10

fn aes_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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

#[test]
fn test_aes_cbc_decrypt() {
    let mut file = fs::File::open("data/10.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = String::from("YELLOW SUBMARINE");
    let iv = &[0u8; 16];

    let mut file = fs::File::open("data/6_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();
    let expected_output = expected_output.into_bytes();

    let output =
        pkcs7_unpad_unchecked(aes_cbc_decrypt(contents.as_slice(), key.as_bytes(), iv).as_slice());
    assert_eq!(output, expected_output);
}

// Challenge 9

fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    if block_size > input.len() {
        let pad_len = block_size - input.len();
        let pad_len: u8 = pad_len.try_into().unwrap();
        let mut output = input.to_vec();
        output.extend(vec![pad_len; pad_len as usize].into_iter());
        output
    } else {
        pkcs7_pad(input, input.len() + block_size - (input.len() % block_size))
    }
}

#[test]
fn test_pkcs7_pad() {
    let input = "YELLOW_SUBMARINE".as_bytes().to_vec();
    let length = 20;
    let expected_output = "YELLOW_SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec();
    let output = pkcs7_pad(&input, length);
    assert_eq!(output, expected_output);
}

// Challenge 8

fn detect_aes_ecb(lines: &[Vec<u8>]) -> Option<Vec<u8>> {
    for line in lines.iter() {
        let mut block_frequency: HashMap<[u8; 16], u32> = HashMap::new();
        for i in 0..(line.len() / 16) {
            let block: [u8; 16] = line[(i * 16)..((i + 1) * 16)].try_into().unwrap();
            block_frequency
                .entry(block)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
        let mut values: Vec<u32> = block_frequency.into_values().collect();
        values.sort();
        values.reverse();
        if values[0] > 1 {
            return Some(line.to_owned());
        }
    }
    None
}

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

fn pkcs7_unpad_unchecked(input: &[u8]) -> Vec<u8> {
    assert!(!input.is_empty());
    let last_byte = *input.last().unwrap();
    if last_byte as usize > input.len() {
        return input.to_vec();
    }
    let is_padded = input[(input.len() - last_byte as usize)..input.len()]
        .iter()
        .all(|&b| b == last_byte);
    if is_padded {
        input[..(input.len() - last_byte as usize)].to_vec()
    } else {
        input.to_vec()
    }
}

fn aes_ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
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

#[test]
fn test_aes_ecb_decrypt() {
    let mut file = fs::File::open("data/7.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = String::from("YELLOW SUBMARINE").into_bytes();

    let mut file = fs::File::open("data/6_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();
    let expected_output = expected_output.into_bytes();

    let output = pkcs7_unpad_unchecked(aes_ecb_decrypt(&contents, &key).as_slice());
    assert_eq!(output, expected_output);
}

// Challenge 6

fn get_best_key_size(input: &[u8]) -> usize {
    get_key_sizes(input)[0]
}

fn get_key_sizes(input: &[u8]) -> Vec<usize> {
    let candidate_key_sizes = 2..40;
    let mut key_size_scores = Vec::new();
    for key_size in candidate_key_sizes {
        let score = get_key_size_score(input, key_size);
        key_size_scores.push((score, key_size));
    }
    key_size_scores.sort();
    key_size_scores.iter().map(|&(_score, key)| key).collect()
}

fn get_key_size_score(input: &[u8], key_size: usize) -> u32 {
    let n_blocks = 4;
    assert!(input.len() > key_size * n_blocks);

    let mut blocks = Vec::new();
    for i in 0..n_blocks {
        blocks.push(&input[(i * key_size)..((i + 1) * key_size)]);
    }

    let mut score = 0;
    for i in 0..(n_blocks - 1) {
        let block_i = blocks[i];
        for block_j in blocks.iter().take(n_blocks).skip(i + 1) {
            let distance = hamming_distance(block_i.to_vec(), block_j.to_vec());
            score += normalize_distance(distance, key_size);
        }
    }

    score
}

fn decrypt_repeating_key_xor(input: Vec<u8>) -> Vec<u8> {
    // Get key_size
    let key_size = get_best_key_size(&input);

    // Break into key_size blocks
    let blocks = get_blocks(&input, key_size);

    // Transpose blocks
    let transposed = transpose_blocks(&blocks);

    // Single byte xor decrypt blocks
    let mut key = vec![];
    for block in transposed.into_iter() {
        let (_score, single_byte_key, _plaintext) = decrypt_single_byte_xor(block);
        key.push(single_byte_key);
    }

    // Decrypt
    repeating_key_xor(key, input)
}

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

fn transpose_blocks(blocks: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert!(!blocks.is_empty());
    let key_size = blocks[0].len();
    let mut transposed = vec![];
    for col in 0..key_size {
        let mut block = vec![];
        for blocks_row in blocks {
            if blocks_row.len() <= col {
                break;
            }
            block.push(blocks_row[col]);
        }
        transposed.push(block);
    }
    transposed
}

#[test]
fn test_transpose_blocks() {
    let blocks = vec![vec![1, 2, 3], vec![4, 5]];
    assert_eq!(
        transpose_blocks(&blocks),
        vec![vec![1, 4], vec![2, 5], vec![3]]
    );
}

fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

fn get_blocks(input: &[u8], key_size: usize) -> Vec<Vec<u8>> {
    let mut blocks = vec![];
    let n_blocks = div_ceil(input.len(), key_size);
    for block_idx in 0..n_blocks {
        let start = block_idx * key_size;
        let end = std::cmp::min(start + key_size, input.len());
        blocks.push(input[start..end].to_vec());
    }
    blocks
}

#[test]
fn test_get_blocks() {
    let input = vec![1, 2, 3, 4, 5];
    assert_eq!(get_blocks(&input, 3), vec![vec![1, 2, 3], vec![4, 5]]);
    assert_eq!(get_blocks(&input, 5), vec![vec![1, 2, 3, 4, 5]]);
}

fn normalize_distance(distance: u32, key_size: usize) -> u32 {
    distance * 10000 / (8 * key_size as u32)
}

fn hamming_distance(input1: Vec<u8>, input2: Vec<u8>) -> u32 {
    assert!(input1.len() == input2.len());
    let mut distance = 0;
    for i in 0..input1.len() {
        let byte1 = input1[i];
        let byte2 = input2[i];
        let diff_bits = byte1 ^ byte2;
        for bit in 0..8 {
            distance += (diff_bits & (1 << bit) != 0) as u32;
        }
    }
    distance
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

fn repeating_key_xor(key: Vec<u8>, input: Vec<u8>) -> Vec<u8> {
    assert!(!key.is_empty());
    assert!(!input.is_empty());
    let mut output = Vec::new();
    let mut key_idx = 0;
    for byte in input.iter() {
        output.push(byte ^ key[key_idx]);
        key_idx = (key_idx + 1) % key.len();
    }
    output
}

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

    let output = repeating_key_xor(key, input);
    assert_eq!(output, expected_output);
}

// Challenge 4

fn decrypt_single_byte_xor_many(lines: Vec<String>) -> (u32, u8, Vec<u8>) {
    let mut max_score = 0;
    let mut max_score_values = (0, vec![]);
    for line in lines {
        let (score, key, plaintext) = decrypt_single_byte_xor(hex::decode(line).unwrap());
        if score > max_score {
            max_score = score;
            max_score_values = (key, plaintext);
        }
    }
    (max_score, max_score_values.0, max_score_values.1)
}

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

fn decrypt_single_byte_xor(ciphertext: Vec<u8>) -> (u32, u8, Vec<u8>) {
    let mut max_score = 0;
    let mut max_score_values = (0, vec![]);
    for i in 0..=255 {
        let key = vec![i; ciphertext.len()];
        let plaintext = fixed_xor(ciphertext.as_slice(), key.as_slice());
        let score = calculate_score(&plaintext);
        if score > max_score {
            max_score = score;
            max_score_values = (i, plaintext);
        }
    }

    (max_score, max_score_values.0, max_score_values.1)
}

fn calculate_score(plaintext: &[u8]) -> u32 {
    // https://en.wikipedia.org/wiki/Letter_frequency
    let letter_frequency_percent: HashMap<char, u32> = HashMap::from([
        ('a', 823),
        ('b', 150),
        ('c', 280),
        ('d', 429),
        ('e', 1280),
        ('f', 224),
        ('g', 203),
        ('h', 614),
        ('i', 614),
        ('j', 15),
        ('k', 77),
        ('l', 406),
        ('m', 242),
        ('n', 680),
        ('o', 757),
        ('p', 194),
        ('q', 9),
        ('r', 603),
        ('s', 638),
        ('t', 913),
        ('u', 278),
        ('v', 98),
        ('w', 238),
        ('x', 15),
        ('y', 199),
        ('z', 7),
        (' ', 1500),
    ]);

    plaintext.iter().fold(0, |acc, byte| {
        let c = (*byte as char).to_ascii_lowercase();
        acc + letter_frequency_percent.get(&c).unwrap_or(&0)
    })
}

#[test]
fn test_decrypt_single_bytes_xor() {
    let input =
        String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let expected_output = String::from("Cooking MC's like a pound of bacon");

    let (_, _, plaintext) = decrypt_single_byte_xor(hex::decode(input).unwrap());
    assert_eq!(plaintext, expected_output.into_bytes());
}

// Challenge 2

fn fixed_xor(input1: &[u8], input2: &[u8]) -> Vec<u8> {
    assert_eq!(input1.len(), input2.len());
    let n = input1.len();
    let mut result = Vec::new();
    for i in 0..n {
        result.push(input1[i] ^ input2[i]);
    }
    result
}

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

fn hex_to_base64(input: &[u8]) -> Vec<u8> {
    let normal = hex::decode(input).unwrap();
    general_purpose::STANDARD_NO_PAD.encode(normal).into_bytes()
}

#[test]
fn test_hex_to_base64() {
    let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_output = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let output = hex_to_base64(input);
    assert_eq!(expected_output, output.as_slice());
}

fn hex_to_base64_string(input: String) -> String {
    let normal = hex::decode(input).unwrap();
    general_purpose::STANDARD_NO_PAD.encode(normal)
}

#[test]
fn test_hex_to_base64_string() {
    let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let expected_output =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let output = hex_to_base64_string(input);
    assert_eq!(expected_output, output);
}
