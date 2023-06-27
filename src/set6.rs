use num_bigint::{BigInt, BigUint, RandBigInt, RandPrime, ToBigInt, ToBigUint};
use num_bigint_dig as num_bigint;
use num_traits::{Num, One, Zero};
use rand::{thread_rng, Rng, RngCore};
use std::fs;
use std::io::Read;
use std::ops::Range;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use std::{collections::HashSet, ops::Shl};

use crate::{
    set4::{get_random_utf8, sha1, DIGEST_LENGTH_SHA1},
    set5::{cube_root, generate_large_primes, inv_mod},
};

// Challenge 45

#[test]
fn test_dsa_parameter_tampering() {
    let default_params = dsa_default_parameters();
    let hello_world = b"Hello, world";
    let goodbye_world = b"Goodbye, world";

    // g = 0
    let params = DsaParameters {
        g: BigUint::zero(),
        ..default_params.clone()
    };
    let (sk, pk) = dsa_new_keypair(&params);
    let sig = dsa_sign_unsafe(&params, &sk, hello_world);
    assert!(dsa_verify_unsafe(&params, &pk, hello_world, &sig));
    let forge_and_verify = |message| {
        let forged_sig = dsa_sign_g_equals_zero(&params, message);
        assert!(dsa_verify_unsafe(&params, &pk, message, &forged_sig));
    };
    forge_and_verify(hello_world);
    forge_and_verify(goodbye_world);

    // g = 1 mod p
    let params = DsaParameters {
        g: default_params.p.clone() + BigUint::one(),
        ..default_params
    };
    let (sk, pk) = dsa_new_keypair(&params);
    let sig = dsa_sign(&params, &sk, hello_world);
    assert!(dsa_verify(&params, &pk, hello_world, &sig));
    let forge_and_verify = |message| {
        let sig = dsa_sign_g_equals_one_mod_p(&params, &pk);
        assert!(dsa_verify(&params, &pk, message, &sig));
    };
    forge_and_verify(hello_world);
    forge_and_verify(goodbye_world);
}

fn dsa_sign_g_equals_zero(params: &DsaParameters, message: &[u8]) -> DsaSignature {
    let r = BigUint::zero();
    let k_inv = loop {
        let k = thread_rng().gen_biguint_range(&BigUint::one(), &params.q);
        match inv_mod(&k, &params.q) {
            Some(k_inv) => break k_inv,
            None => continue,
        }
    };
    let hash = BigUint::from_bytes_be(&sha1(message));
    let s = (k_inv * hash) % params.q.clone();
    DsaSignature { r, s }
}

fn dsa_sign_g_equals_one_mod_p(params: &DsaParameters, pk: &DsaPublicKey) -> DsaSignature {
    let (z, z_inv) = loop {
        let z = thread_rng().gen_biguint_range(&BigUint::one(), &params.q); // arbitrary range
        match inv_mod(&z, &params.q) {
            Some(z_inv) => break (z, z_inv),
            None => continue,
        }
    };
    // r = (y ** z % p) % q
    let r = pk.y.modpow(&z, &params.p) % params.q.clone();
    // s = r / z % q
    let s = (r.clone() * z_inv) % params.q.clone();
    DsaSignature { r, s }
}

// Challenge 44

#[test]
fn test_repeated_nonce_recovery() {
    let params = dsa_default_parameters();
    let y = BigUint::from_bytes_be(&hex::decode(b"2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821").unwrap());
    let pk = DsaPublicKey { y };

    let mut file = fs::File::open("data/44.txt").unwrap();
    let mut messages = String::new();
    file.read_to_string(&mut messages).unwrap();
    let msgs_and_sigs = messages
        .lines()
        .collect::<Vec<&str>>()
        .chunks(4)
        .map(|chunk| {
            let msg = chunk[0][5..].as_bytes();
            let s = BigUint::from_str_radix(&chunk[1][3..], 10).unwrap();
            let r = BigUint::from_str_radix(&chunk[2][3..], 10).unwrap();
            let m = BigUint::from_str_radix(&chunk[3][3..], 16).unwrap();
            assert_eq!(m.to_bytes_be().as_slice(), &sha1(msg));
            let sig = DsaSignature { r, s };
            assert!(dsa_verify(&params, &pk, msg, &sig));
            (msg.to_owned(), sig)
        })
        .collect::<Vec<(Vec<u8>, DsaSignature)>>();

    let (k, msg, sig) = recover_repeated_nonce_from_messages(&params, msgs_and_sigs).unwrap();
    let sk = find_secret(&params, &sig, &msg, &k);
    let sk_hash = sha1(hex::encode(&sk.x.to_bytes_be()).as_bytes());

    let expected_private_key_hash =
        hex::decode(b"ca8f6f7c66fa362d40760d135b763eb8527d3d52").unwrap();
    assert_eq!(sk_hash.to_vec(), expected_private_key_hash)
}

fn recover_repeated_nonce_from_messages(
    params: &DsaParameters,
    msgs_and_sigs: Vec<(Vec<u8>, DsaSignature)>,
) -> Option<(BigUint, Vec<u8>, DsaSignature)> {
    let hashes_msgs_and_sigs = msgs_and_sigs
        .into_iter()
        .map(|(msg, sig)| (BigUint::from_bytes_be(&sha1(&msg)), msg, sig))
        .collect::<Vec<(BigUint, Vec<u8>, DsaSignature)>>();

    for (i, (m0, _msg0, sig0)) in hashes_msgs_and_sigs
        .iter()
        .enumerate()
        .take(hashes_msgs_and_sigs.len() - 1)
    {
        for (m1, msg1, sig1) in hashes_msgs_and_sigs.iter().skip(i + 1) {
            match (|| -> Option<(BigUint, Vec<u8>, DsaSignature)> {
                let k = recover_repeated_nonce(&params.q, &m0, &sig0.s, &m1, &sig1.s)?;
                let k_inv = inv_mod(&k, &params.q)?;
                let sk = find_secret(params, sig1, msg1, &k);
                let sig0_obs = dsa_sign_given_values(params, &sk, &m0, &k_inv, &sig0.r)?;
                let sig1_obs = dsa_sign_given_values(params, &sk, &m1, &k_inv, &sig1.r)?;
                if &sig0_obs == sig0 && &sig1_obs == sig1 {
                    Some((k, msg1.clone(), sig1.clone()))
                } else {
                    None
                }
            })() {
                Some(res) => return Some(res),
                None => continue,
            };
        }
    }
    None
}

fn recover_repeated_nonce(
    q: &BigUint,
    m0: &BigUint,
    s0: &BigUint,
    m1: &BigUint,
    s1: &BigUint,
) -> Option<BigUint> {
    let m0 = m0.to_bigint().unwrap();
    let s0 = s0.to_bigint().unwrap();
    let m1 = m1.to_bigint().unwrap();
    let s1 = s1.to_bigint().unwrap();
    let q = q.to_bigint().unwrap();
    let sub_mod = |mut expr: BigInt, q: BigInt| -> BigUint {
        while expr < BigInt::zero() {
            expr += q.clone();
        }
        expr.to_biguint().unwrap()
    };
    let numerator = sub_mod(m0 - m1, q.clone());
    let denominator = sub_mod(s0 - s1, q.clone());
    let q = q.to_biguint().unwrap();
    let d_inv = inv_mod(&denominator, &q)?;
    let k = (numerator * d_inv) % q;
    Some(k)
}

// Challenge 43

#[test]
fn test_find_secret_example() {
    let params = dsa_default_parameters();
    let message = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";
    let hash = hex::decode(b"d2d0714f014a9784047eaeccf956520045c45265").unwrap();
    assert_eq!(hash, sha1(message));

    let r = BigUint::from_str("548099063082341131477253921760299949438196259240").unwrap();
    let s = BigUint::from_str("857042759984254168557880549501802188789837994940").unwrap();
    let sig = DsaSignature { r, s };
    let y = BigUint::from_bytes_be(&hex::decode(b"084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17").unwrap());
    let pk = DsaPublicKey { y };
    assert!(dsa_verify(&params, &pk, message, &sig));

    let k_range = 16500..17000; // to speed up test
    let solved_secret = find_secret_k_range(&params, &sig, message, k_range).unwrap();
    assert_eq!(pk.y, params.g.modpow(&solved_secret.x, &params.p));

    let fingerprint = hex::decode(b"0954edd5e0afe5542a4adf012611a91912a3ec16").unwrap();
    let hex_secret = hex::encode(solved_secret.x.to_bytes_be());
    assert_eq!(fingerprint, sha1(&hex_secret.as_bytes()));
}

#[cfg(wait)]
#[test]
fn test_find_secret_dsa_faulty_sign() {
    let params = dsa_default_parameters();
    let (sk, pk) = dsa_new_keypair(&params);
    let message = b"hi mom";
    let k_range = 0..(1 << 16);
    let faulty_sig = dsa_sign_k_range(&params, &sk, message, k_range.clone());
    assert!(dsa_verify(&params, &pk, message, &faulty_sig));
    let solved_secret = find_secret_k_range(&params, &faulty_sig, message, k_range).unwrap();
    assert!(solved_secret == sk);
}

fn find_secret_k_range(
    params: &DsaParameters,
    sig: &DsaSignature,
    message: &[u8],
    k_range: Range<usize>,
) -> Option<DsaSecretKey> {
    let hash = BigUint::from_bytes_be(&sha1(message)).to_bigint().unwrap();
    let r_inv = inv_mod(&sig.r, &params.q).unwrap().to_bigint().unwrap();
    let s = sig.s.to_bigint().unwrap();
    let q = params.q.to_bigint().unwrap();
    for k in k_range {
        let k = k.to_bigint().unwrap();
        let secret = find_secret_given_values(&s, &k, &hash, &r_inv, &q);
        let k = k.to_biguint().unwrap();
        if let Some(candidate_sig) = dsa_sign_given_k(params, &secret, message, &k) {
            if &candidate_sig == sig {
                return Some(secret);
            }
        }
    }
    None
}

fn dsa_sign_k_range(
    params: &DsaParameters,
    sk: &DsaSecretKey,
    message: &[u8],
    k_range: Range<usize>,
) -> DsaSignature {
    let start = k_range.start.to_biguint().unwrap();
    let end = k_range.end.to_biguint().unwrap();
    loop {
        let k = thread_rng().gen_biguint_range(&start, &end);
        if let Some(sig) = dsa_sign_given_k(params, sk, message, &k) {
            return sig;
        }
    }
}

#[test]
fn test_find_secret_given_k() {
    let params = dsa_default_parameters();
    let (sk, pk) = dsa_new_keypair(&params);
    let message = b"hi mom";
    let (k, sig) = loop {
        let k = thread_rng().gen_biguint_range(&BigUint::one(), &params.q);
        if let Some(sig) = dsa_sign_given_k(&params, &sk, message, &k) {
            break (k, sig);
        }
    };
    assert!(dsa_verify(&params, &pk, message, &sig));
    let solved_secret = find_secret(&params, &sig, message, &k);
    assert!(sk == solved_secret);
}

fn find_secret(
    params: &DsaParameters,
    sig: &DsaSignature,
    message: &[u8],
    k: &BigUint,
) -> DsaSecretKey {
    let s = sig.s.to_bigint().unwrap();
    let k = k.to_bigint().unwrap();
    let q = params.q.to_bigint().unwrap();
    let hash = BigUint::from_bytes_be(&sha1(message)).to_bigint().unwrap();
    let r_inv = inv_mod(&sig.r, &params.q).unwrap().to_bigint().unwrap();
    find_secret_given_values(&s, &k, &hash, &r_inv, &q)
}

fn find_secret_given_values(
    s: &BigInt,
    k: &BigInt,
    hash: &BigInt,
    r_inv: &BigInt,
    q: &BigInt,
) -> DsaSecretKey {
    let mut res = ((s * k - hash) * r_inv) % q;
    while res < BigInt::zero() {
        res += q.clone();
    }
    let x = res.to_biguint().unwrap();
    DsaSecretKey { x }
}

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

#[derive(PartialEq)]
struct DsaSecretKey {
    x: BigUint,
}

struct DsaPublicKey {
    y: BigUint,
}

#[derive(Clone, PartialEq, Debug)]
struct DsaSignature {
    r: BigUint,
    s: BigUint,
}

fn dsa_sign(params: &DsaParameters, sk: &DsaSecretKey, message: &[u8]) -> DsaSignature {
    loop {
        let k = thread_rng().gen_biguint_range(&BigUint::one(), &params.q);
        if let Some(sig) = dsa_sign_given_k(params, sk, message, &k) {
            return sig;
        }
    }
}

fn dsa_sign_given_k(
    params: &DsaParameters,
    sk: &DsaSecretKey,
    message: &[u8],
    k: &BigUint,
) -> Option<DsaSignature> {
    let k_inv = match inv_mod(k, &params.q) {
        Some(k_inv) => k_inv,
        None => return None,
    };
    assert!(k.clone() * k_inv.clone() % params.q.clone() == BigUint::one());
    let r = params.g.modpow(k, &params.p) % params.q.clone();
    if r.is_zero() {
        return None;
    }
    let hash = BigUint::from_bytes_be(&sha1(message));
    dsa_sign_given_values(params, sk, &hash, &k_inv, &r)
}

// No check to ensure r, s != 0
fn dsa_sign_unsafe(params: &DsaParameters, sk: &DsaSecretKey, message: &[u8]) -> DsaSignature {
    let (k, k_inv) = loop {
        let k = thread_rng().gen_biguint_range(&BigUint::one(), &params.q);
        match inv_mod(&k, &params.q) {
            Some(k_inv) => break (k, k_inv),
            None => continue,
        }
    };
    let r = params.g.modpow(&k, &params.p) % params.q.clone();
    let hash = BigUint::from_bytes_be(&sha1(message));
    let s = (k_inv * (hash + sk.x.clone() * r.clone())) % params.q.clone();
    DsaSignature { r, s }
}

fn dsa_sign_given_values(
    params: &DsaParameters,
    sk: &DsaSecretKey,
    msg_hash: &BigUint,
    k_inv: &BigUint,
    r: &BigUint,
) -> Option<DsaSignature> {
    let s = (k_inv * (msg_hash + sk.x.clone() * r.clone())) % params.q.clone();
    if s.is_zero() {
        None
    } else {
        Some(DsaSignature { r: r.clone(), s })
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
    let hash = BigUint::from_bytes_be(&sha1(message));
    let u_1 = (hash * w.clone()) % params.q.clone();
    let u_2 = (sig.r.clone() * w) % params.q.clone();
    let v = (params.g.clone().modpow(&u_1, &params.p) * pk.y.clone().modpow(&u_2, &params.p))
        % params.p.clone()
        % params.q.clone();
    v == sig.r
}

// No check to ensure r, s != 0
fn dsa_verify_unsafe(
    params: &DsaParameters,
    pk: &DsaPublicKey,
    message: &[u8],
    sig: &DsaSignature,
) -> bool {
    if sig.r >= params.q {
        return false;
    }
    if sig.s >= params.q {
        return false;
    }
    let w = match inv_mod(&sig.s, &params.q) {
        Some(s_inv) => s_inv,
        None => return false,
    };
    let hash = BigUint::from_bytes_be(&sha1(message));
    let u_1 = (hash * w.clone()) % params.q.clone();
    let u_2 = (sig.r.clone() * w) % params.q.clone();
    let v = (params.g.clone().modpow(&u_1, &params.p) * pk.y.clone().modpow(&u_2, &params.p))
        % params.p.clone()
        % params.q.clone();
    v == sig.r
}

#[derive(Clone)]
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
