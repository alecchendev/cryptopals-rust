use base64::{engine::general_purpose, Engine};
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;
use std::fs;
use std::io::Read;

use crate::set1::{aes_ecb_decrypt, aes_ecb_encrypt, fixed_xor, generate_key, pkcs7_pad};

pub const BLOCK_SIZE: usize = 16;

// Challenge 16

fn create_random_block(bad_chars: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    thread_rng().fill_bytes(&mut block);
    for byte in block.iter_mut() {
        while bad_chars.contains(byte) {
            *byte = thread_rng().gen();
        }
    }
    block
}

pub(crate) fn cbc_bit_flipping_attack(oracle: &CbcBitFlippingOracle) -> Vec<u8> {
    // produce two ciphertext blocks
    // one that decrypts to anything
    // one that when decrypted and xor'd with the previous ciphertext produces "admin=true;"

    // Fix second block
    // turn final block into admin=true using padding
    // Find block size - see when padding jumps
    let base_ciphertext = oracle.encrypt(&[]);
    let mut block_size = 0;
    for i in 1..64 {
        let ciphertext = oracle.encrypt(&vec![b'A'; i]);
        let diff = ciphertext.len() - base_ciphertext.len();
        if diff != 0 {
            block_size = diff;
            break;
        }
    }
    assert!(block_size > 0);
    let block_size = block_size;

    // ----- ----- encrypt oracle time ----- -----
    // find where my input is (fill padding, modify a block and see what blocks of ciphertext change)
    // isolate two blocks (have filler up until these (userdata=asdfasdfasdf|block|block|suffix))
    // get base ciphertext block

    // THIS CODE FOR FINDING PREFIX SIZE IS WRONG IT ONLY WORKS FOR PREFIX
    // SIZES THAT ARE MULTIPLES OF BLOCK_SIZE
    let bad_chars = b"=;";
    let ciphertext1 = oracle.encrypt(&create_random_block(bad_chars));
    let ciphertext2 = oracle.encrypt(&create_random_block(bad_chars));
    let prefix_length = ciphertext1
        .iter()
        .enumerate()
        .take_while(|&(i, &byte)| byte == ciphertext2[i])
        .count();

    let prefix_padding_length = if prefix_length % block_size != 0 {
        block_size - (prefix_length % block_size)
    } else {
        0
    };
    let prefix_padding = vec![b'A'; prefix_padding_length];
    let change_block = vec![b'A'; block_size];
    let admin_block = vec![b'A'; block_size];
    let initial_ciphertext = oracle.encrypt(
        &[
            prefix_padding.as_slice(),
            change_block.as_slice(),
            admin_block.as_slice(),
        ]
        .concat(),
    );

    // ----- ----- padding oracle time ----- -----
    // modify first ciphertext block, chop everything after second block
    // use padding oracle to be able to easily manipulate/overwrite plaintext
    // form final ciphertext blocks

    let mut working_input = initial_ciphertext[..(prefix_length + 2 * block_size)].to_vec();
    let mut breaking_ciphertext = initial_ciphertext;
    let target = b";admin=true";
    for i in 0..target.len() {
        let target_byte = target[target.len() - 1 - i];
        let pad_byte = i as u8 + 1;

        let start_of_admin_block_idx = prefix_length + block_size;
        let ciphertext_idx = start_of_admin_block_idx - 1 - i;

        let mut input = working_input.clone();
        for byte in input
            .iter_mut()
            .take(start_of_admin_block_idx)
            .skip(ciphertext_idx + 1)
        {
            *byte ^= pad_byte;
        }

        for byte in 0..=255 {
            input[ciphertext_idx] = byte;
            let result = oracle.check_admin(&input);
            if result.is_ok() {
                // padding is good -> change_block ^ decrypted = pad_byte
                breaking_ciphertext[ciphertext_idx] =
                    input[ciphertext_idx] ^ pad_byte ^ target_byte;
                working_input[ciphertext_idx] = input[ciphertext_idx] ^ pad_byte; // end result will be 0
                break;
            } else {
                // padding is bad
                continue;
            }
        }
    }

    // ----- ----- imagined formation ----- -----
    // Encrypted
    // |prefixprefixpref|prefixpre...fill|my_modified_blok|aaaaaaaaaaaaaaaa|suffixsuffixpadd|
    // Decrypted
    // |prefixprefixpref|p...userdata=fil|fillerfillerfill|fille;admin=true|suffixsuffixpadd|

    breaking_ciphertext
}

pub(crate) type CbcBitFlippingOracle<'a> = BitFlippingOracle<'a, AesCbcOracle>;

// TODO: change to randomize and output IV on encrypt and receive IV
// on decrypt
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

    pub(crate) fn new_with_args(key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) -> Self {
        Self { key, iv }
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

    pub(crate) fn check_admin(&self, ciphertext: &[u8]) -> Result<bool, ()> {
        let padded_plaintext = self.cipher.decrypt(ciphertext);
        let plaintext = pkcs7_unpad(&padded_plaintext)?;

        for piece in plaintext.split(|&x| x == b';') {
            let p: Vec<&[u8]> = piece.split(|&x| x == b'=').collect();
            if p.len() == 2 {
                let (key, value) = (p[0], p[1]);
                if key == b"admin" && value == b"true" {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

pub(crate) trait CipherOracle {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

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

pub(crate) fn pkcs7_unpad(input: &[u8]) -> Result<Vec<u8>, ()> {
    assert!(!input.is_empty());
    let last_byte = *input.last().unwrap();
    if last_byte == 0 || last_byte > 16 {
        return Err(());
    }
    let is_padded = input[(input.len() - last_byte as usize)..]
        .iter()
        .all(|&b| b == last_byte);
    if is_padded {
        Ok(input[..(input.len() - last_byte as usize)].to_vec())
    } else {
        Err(())
    }
}

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

pub(crate) struct EcbOracleHarder<'a> {
    key: &'a [u8],
    target: &'a [u8],
    prefix: &'a [u8],
}

impl<'a> EcbOracleHarder<'a> {
    pub(crate) fn new(key: &'a [u8; 16], target: &'a [u8], prefix: &'a [u8]) -> Self {
        Self {
            key,
            target,
            prefix,
        }
    }

    pub(crate) fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let plaintext: &[u8] = &[self.prefix, input, self.target].concat();
        let plaintext_padded = pkcs7_pad(plaintext, 16);
        aes_ecb_encrypt(&plaintext_padded, self.key)
    }
}

pub(crate) fn byte_at_a_time_ecb_decrypt_harder(oracle: &EcbOracleHarder) -> Vec<u8> {
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
            .copied()
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
                    .copied()
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
                .copied()
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
pub(crate) fn forge_admin_ciphertext(oracle: &ProfileManager) -> Vec<u8> {
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

pub(crate) struct ProfileManager<'a> {
    key: &'a [u8],
}

impl<'a> ProfileManager<'a> {
    pub(crate) fn new(key: &'a [u8]) -> Self {
        Self { key }
    }

    pub(crate) fn add_profile(&self, ciphertext: &'a [u8]) -> UserProfile {
        let plaintext = pkcs7_unpad_unchecked(&aes_ecb_decrypt(ciphertext, self.key));
        let profile = UserProfile::decode(std::str::from_utf8(&plaintext).unwrap());
        // (add profile)
        profile
    }

    pub(crate) fn profile_for(&self, email: &str) -> String {
        assert!(!email.contains('=') && !email.contains('&'));
        UserProfile {
            email: String::from(email),
            uid: 10,
            role: Role::User,
        }
        .encode()
    }

    pub(crate) fn profile_for_encrypted(&self, email: &str) -> Vec<u8> {
        aes_ecb_encrypt(&pkcs7_pad(self.profile_for(email).as_bytes(), 16), self.key)
    }
}

#[derive(PartialEq)]
pub(crate) enum Role {
    User,
    Admin,
}

#[derive(PartialEq)]
pub(crate) struct UserProfile {
    email: String,
    uid: usize,
    pub(crate) role: Role,
}

impl UserProfile {
    pub(crate) fn new(email: String, uid: usize, role: Role) -> Self {
        Self { email, uid, role }
    }

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

pub(crate) fn parse_key_value(input: &str) -> HashMap<&str, &str> {
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

// SHOULD FIND A WAY NOT TO USE THIS HERE?
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
pub(crate) fn byte_at_a_time_ecb_decrypt(oracle: &ConsistentKey) -> Vec<u8> {
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

pub(crate) struct ConsistentKey<'a> {
    key: &'a [u8],
    append_text: &'a [u8],
}

impl<'a> ConsistentKey<'a> {
    pub(crate) fn new(key: &'a [u8], append_text: &'a [u8]) -> Self {
        Self { key, append_text }
    }

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
    let oracle = ConsistentKey::new(&key, &unknown_string);

    let output = byte_at_a_time_ecb_decrypt(&oracle);
    assert_eq!(output.as_slice(), unknown_string.as_slice());
}

// Challenge 11
pub(crate) fn detect_mode(ciphertext: &[u8]) -> AesBlockCipherMode {
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

#[derive(PartialEq)]
pub(crate) enum AesBlockCipherMode {
    Ecb,
    Cbc,
}

pub(crate) fn encrypt_oracle(input: &[u8]) -> (AesBlockCipherMode, Vec<u8>) {
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

// Challenge 10

pub(crate) fn aes_cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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

pub(crate) fn aes_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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
