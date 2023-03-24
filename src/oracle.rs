use std::{collections::HashMap, error::Error, ops::Range};

use rand::{thread_rng, Rng};

use crate::{
    basic::fixed_xor,
    block::{
        aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_decrypt, aes_ecb_encrypt, AesBlockCipherMode,
    },
    generate_key, pkcs7_pad, pkcs7_unpad,
    stream::{aes_ctr_decrypt, aes_ctr_encrypt},
    BLOCK_SIZE,
};

// Thoughts
// make a string append/prepend oracle that takes and enum for which action to do

// Challenge 27

pub(crate) struct AesCbcOracleKeyAsIv<'a> {
    cipher: AesCbcOracle,
    prefix: &'a [u8],
    suffix: &'a [u8],
}

impl<'a> AesCbcOracleKeyAsIv<'a> {
    pub(crate) fn new(key: &[u8; BLOCK_SIZE], prefix: &'a [u8], suffix: &'a [u8]) -> Self {
        let cipher = AesCbcOracle::new_with_args(key.to_owned(), key.to_owned());
        Self {
            cipher,
            prefix,
            suffix,
        }
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        assert!(!plaintext.contains(&b';') && !plaintext.contains(&b'='));
        let padded_plaintext =
            pkcs7_pad(&[self.prefix, plaintext, self.suffix].concat(), BLOCK_SIZE);
        self.cipher.encrypt(&padded_plaintext)
    }

    pub(crate) fn check_admin(&self, ciphertext: &[u8]) -> Result<bool, Vec<u8>> {
        let padded_plaintext = self.cipher.decrypt(ciphertext);
        let plaintext = pkcs7_unpad(&padded_plaintext).unwrap();

        if !plaintext.is_ascii() {
            Err(plaintext)
        } else {
            Ok(String::from_utf8(plaintext)
                .unwrap()
                .contains(";admin=true;"))
        }
    }
}

// Challenge 26

pub(crate) type CtrBitFlippingOracle<'a> = BitFlippingOracle<'a, AesCtrOracle>;

// TODO: change to randomize and output nonce on encrypt and receive nonce
// on decrypt
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

// Challenge 25

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

// Challenge 17

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

// Challenge 16

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

    pub(crate) fn check_admin(&self, ciphertext: &[u8]) -> Result<bool, Box<dyn Error>> {
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

// Challenge 13

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

// Challenge 11

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
