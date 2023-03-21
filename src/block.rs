use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;

use crate::{
    basic::{decrypt_single_byte_xor, fixed_xor, transpose_blocks},
    generate_key,
    oracle::{CbcBitFlippingOracle, CbcPaddingOracle},
    BLOCK_SIZE,
};

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

// Challenge 19 (SKIPPED)

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

// Challenge 15

#[derive(thiserror::Error, Debug)]
pub(crate) enum MyError {
    #[error("Invalid PKCS#7 padding")]
    InvalidPkcs7Padding,
}

pub(crate) fn pkcs7_unpad(input: &[u8]) -> Result<Vec<u8>, MyError> {
    assert!(!input.is_empty());
    let last_byte = *input.last().unwrap();
    if last_byte == 0 || last_byte > 16 {
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

// Challenge 9

pub(crate) fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let padding_length = block_size - (input.len() % block_size);
    [input, &vec![padding_length as u8; padding_length]].concat()
}

// Challenge 8

pub(crate) fn detect_aes_ecb(lines: &[Vec<u8>]) -> Option<Vec<u8>> {
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

// Challenge 7

pub(crate) fn aes_ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
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

pub(crate) fn aes_ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
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
