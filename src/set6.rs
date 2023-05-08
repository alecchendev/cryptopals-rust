use num_bigint::{BigUint, RandBigInt, RandPrime, ToBigInt, ToBigUint};
use num_bigint_dig as num_bigint;
use num_traits::{One, Zero};
use rand::{thread_rng, Rng, RngCore};
use std::{collections::HashSet, ops::Shl};

use crate::{
    set4::{get_random_utf8, sha1, DIGEST_LENGTH_SHA1},
    set5::{cube_root, generate_large_primes, inv_mod, sha2},
};

// Challenge 43

#[test]
fn test_dsa() {
    let params = dsa_default_parameters();
    let (sk, pk) = dsa_new_keypair(&params);
    let message = b"hi mom";
    let sig = dsa_sign(&params, &sk, message);
    assert!(dsa_verify(&params, &pk, message, &sig));
}

fn dsa_new_keypair(params: &DsaParameters) -> (DsaSecretKey, DsaPublicKey) {
    let x = thread_rng().gen_biguint_range(&BigUint::one(), &params.q);
    let y = params.g.modpow(&x, &params.p);
    (DsaSecretKey { x }, DsaPublicKey { y })
}

struct DsaSecretKey {
    x: BigUint,
}

struct DsaPublicKey {
    y: BigUint,
}

struct DsaSignature {
    r: BigUint,
    s: BigUint,
}

fn dsa_sign(params: &DsaParameters, sk: &DsaSecretKey, message: &[u8]) -> DsaSignature {
    loop {
        let k = thread_rng().gen_biguint_range(&BigUint::one(), &params.q);
        if let Some(k_inv) = inv_mod(&k, &params.q) {
            assert!(k.clone() * k_inv.clone() % params.q.clone() == BigUint::one());
            let r = params.g.modpow(&k, &params.p) % params.q.clone();
            if r.is_zero() {
                continue;
            }
            let hash = BigUint::from_bytes_be(&sha2(message));
            let s = (k_inv * (hash + sk.x.clone() * r.clone())) % params.q.clone();
            if s.is_zero() {
                continue;
            }
            return DsaSignature { r, s };
        }
    }
}

fn dsa_verify(
    params: &DsaParameters,
    pk: &DsaPublicKey,
    message: &[u8],
    sig: &DsaSignature,
) -> bool {
    if !(sig.r > BigUint::zero() && sig.r < params.q) {
        return false;
    }
    if !(sig.s > BigUint::zero() && sig.s < params.q) {
        return false;
    }
    let w = match inv_mod(&sig.s, &params.q) {
        Some(s_inv) => s_inv,
        None => return false,
    };
    println!("actually computing");
    let hash = BigUint::from_bytes_be(&sha2(message));
    let u_1 = (hash * w.clone()) % params.q.clone();
    let u_2 = (sig.r.clone() * w) % params.q.clone();
    let v = (params.g.clone().modpow(&u_1, &params.p) * pk.y.clone().modpow(&u_2, &params.p))
        % params.p.clone()
        % params.q.clone();
    v == sig.r
}

struct DsaParameters {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

fn dsa_default_parameters() -> DsaParameters {
    let p = BigUint::from_bytes_be(
        &hex::decode(
            b"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1",
        )
        .unwrap(),
    );
    let q =
        BigUint::from_bytes_be(&hex::decode(b"f4f47f05794b256174bba6e9b396a7707e563c5b").unwrap());
    let g = BigUint::from_bytes_be(
        &hex::decode(
            b"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291",
        )
        .unwrap(),
    );
    DsaParameters { p, q, g }
}

// Challenge 42

fn bleichenbacher_forge_signature(message: &BigUint, key_length: usize) -> BigUint {
    let padding = [0x00, 0x01, 0xFF, 0x00];
    let asn1_data = asn1_sha1();
    let hash = sha1(&message.to_bytes_be());
    let block = [&padding[..], &asn1_data, &hash].concat();
    let block_num = BigUint::from_bytes_be(&block);

    let extra_len = (key_length + 7) / 8 - block.len();
    let cube = block_num.shl(extra_len * 8);
    let cbrt = cube_root(&cube);
    cbrt
}

fn asn1_sha1() -> Vec<u8> {
    hex::decode(b"3021300906052b0e03021a05000414").unwrap()
}

struct RsaKeypair {
    n: BigUint,
    e: BigUint,
    d: BigUint,
}

impl RsaKeypair {
    fn new(e: BigUint, bit_size: usize) -> Self {
        let (p, q) = generate_large_primes(bit_size, &e);
        let n = p.clone() * q.clone();
        let totient = (p.clone() - 1.to_biguint().unwrap()) * (q.clone() - 1.to_biguint().unwrap());
        let d = inv_mod(&e, &totient).unwrap();
        Self { n, e, d }
    }

    /// Importantly, this implementation does not check that there is no
    /// extra data after the hash, which allows for this attack.
    fn verify(&self, message: &BigUint, signature: &BigUint) -> bool {
        let cubed = signature.modpow(&self.e, &self.n);
        let bytes = [vec![0x00; 1], cubed.to_bytes_be()].concat();

        // Check 00 01 FF FF .. FF 00
        if bytes[0] != 0x00 || bytes[1] != 0x01 || bytes[2] != 0xFF {
            return false;
        }
        let mut idx = None;
        for (i, &byte) in bytes.iter().enumerate().skip(3) {
            if byte == 0xFF {
                continue;
            } else if byte == 0x00 {
                idx = Some(i + 1);
                break;
            } else {
                return false;
            }
        }
        let idx = match idx {
            None => return false,
            Some(idx) => idx,
        };

        // Check ASN.1
        let asn1_data = asn1_sha1();
        if &bytes[idx..(idx + asn1_data.len())] != asn1_data.as_slice() {
            return false;
        }

        // Check hash
        let hash_len = DIGEST_LENGTH_SHA1;
        let hash_start_idx = idx + asn1_data.len();
        let hash_end_idx = hash_start_idx + hash_len;
        let hash = &bytes[hash_start_idx..hash_end_idx];
        hash == &sha1(&message.to_bytes_be())
    }

    fn sign(&self, message: &BigUint) -> BigUint {
        let hash = sha1(&message.to_bytes_be());
        let sha256_asn1_data = asn1_sha1();

        let padding_len = (self.n.bits() - hash.len() * 8 - sha256_asn1_data.len() * 8) / 8 - 3;
        let padding_prefix = [0x00, 0x01];
        let padding_ff = vec![0xFF; padding_len];
        let padding_suffix = [0x00];
        let padding = [&padding_prefix, padding_ff.as_slice(), &padding_suffix].concat();

        let data = [padding.as_slice(), sha256_asn1_data.as_slice(), &hash].concat();
        let data = BigUint::from_bytes_be(&data);
        data.modpow(&self.d, &self.n)
    }
}

#[test]
fn test_e_equals_three_bleichenbacher() {
    let message = BigUint::from_bytes_be(b"hi mom");
    let key_length = 1024;
    let keypair = RsaKeypair::new(3.to_biguint().unwrap(), key_length);

    let signature = keypair.sign(&message);
    assert!(keypair.verify(&message, &signature));
    let random_signature = thread_rng().gen_biguint(key_length);
    assert!(!keypair.verify(&message, &random_signature));

    let forged = bleichenbacher_forge_signature(&message, key_length);
    assert!(keypair.verify(&message, &forged));
}

// Challenge 41

struct RsaOracle {
    pk: (BigUint, BigUint),
    sk: BigUint,
    past_requests: HashSet<BigUint>,
}

impl RsaOracle {
    fn new() -> Self {
        let e = 65537.to_biguint().unwrap();
        let (p, q) = generate_large_primes(512, &e);
        let n = p.clone() * q.clone();
        let totient = (p.clone() - 1.to_biguint().unwrap()) * (q.clone() - 1.to_biguint().unwrap());
        let d = inv_mod(&e, &totient).unwrap();
        Self {
            pk: (e, n),
            sk: d,
            past_requests: HashSet::new(),
        }
    }

    fn public_key(&self) -> (BigUint, BigUint) {
        self.pk.clone()
    }

    fn decrypt(&mut self, ciphertext: &BigUint) -> Result<BigUint, ()> {
        if self.past_requests.contains(ciphertext) {
            return Err(());
        }
        self.past_requests.insert(ciphertext.clone());
        let d = &self.sk;
        let n = &self.pk.1;
        let plaintext = ciphertext.modpow(d, n);
        Ok(plaintext)
    }
}

fn recover_message_from_unpadded_oracle(ciphertext: &BigUint, oracle: &mut RsaOracle) -> BigUint {
    let (e, n) = oracle.public_key();
    let (s, s_inv) = loop {
        let s = thread_rng().gen_biguint_range(&2.to_biguint().unwrap(), &n);
        if let Some(s_inv) = inv_mod(&s, &n) {
            break (s, s_inv);
        }
    };
    let c_prime = (s.modpow(&e, &n) * ciphertext) % n.clone();
    let p_prime = oracle.decrypt(&c_prime).unwrap();
    (s_inv * p_prime) % n
}

#[test]
fn test_unpadded_message_recovery_oracle() {
    let message = BigUint::from_bytes_be(&get_random_utf8());
    let mut oracle = RsaOracle::new();
    let (e, n) = oracle.public_key();
    let ciphertext = message.modpow(&e, &n);
    let plaintext = recover_message_from_unpadded_oracle(&ciphertext, &mut oracle);
    assert_eq!(plaintext, message);
}
