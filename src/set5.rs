use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::ops::Sub;

use num_bigint::{BigInt, BigUint, RandBigInt, RandPrime, ToBigInt, ToBigUint};
use num_bigint_dig as num_bigint;
use sha2::{Digest, Sha256};

use crate::set1::{generate_key, pkcs7_pad};
use crate::set2::{aes_cbc_decrypt, aes_cbc_encrypt, BLOCK_SIZE};
use crate::set4::{get_random_utf8, hmac, sha1};

// Challenge 40

#[test]
fn test_e_equals_three_rsa_broadcast_attack() {
    let e = 3.to_biguint().unwrap();
    let message = BigUint::from_bytes_be(&get_random_utf8());
    let zero = 0.to_biguint().unwrap();
    let mut residues = [zero.clone(), zero.clone(), zero.clone()];
    let mut moduli = residues.clone();
    for i in 0..3 {
        let (p, q) = generate_large_primes(384, &e);
        let n = p * q;
        residues[i] = message.modpow(&e, &n);
        moduli[i] = n;
    }

    let plaintext = rsa_broadcast_attack(&residues, &moduli);
    assert_eq!(plaintext, message);
}

fn rsa_broadcast_attack(residues: &[BigUint; 3], moduli: &[BigUint; 3]) -> BigUint {
    let m_s_0 = moduli[1].clone() * moduli[2].clone();
    let m_s_1 = moduli[0].clone() * moduli[2].clone();
    let m_s_2 = moduli[0].clone() * moduli[1].clone();
    let n_012 = moduli[0].clone() * moduli[1].clone() * moduli[2].clone();
    let result = ((residues[0].clone() * m_s_0.clone() * inv_mod(&m_s_0, &moduli[0]).unwrap())
        + (residues[1].clone() * m_s_1.clone() * inv_mod(&m_s_1, &moduli[1]).unwrap())
        + (residues[2].clone() * m_s_2.clone() * inv_mod(&m_s_2, &moduli[2]).unwrap()))
        % n_012;
    result.cbrt()
}

// Challenge 39

fn do_test_rsa(p: &BigUint, q: &BigUint, e: &BigUint, message: &[u8]) {
    let n = p.clone() * q.clone();
    let totient = (p - 1.to_biguint().unwrap()) * (q - 1.to_biguint().unwrap());
    let d = inv_mod(&e, &totient).unwrap();
    let message = BigUint::from_bytes_be(message);
    let ciphertext = message.modpow(&e, &n);
    let plaintext = ciphertext.modpow(&d, &n);
    assert_eq!(message, plaintext);
}

pub fn generate_large_primes(bit_size: usize, exp: &BigUint) -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    loop {
        let (p, q) = (rng.gen_prime(bit_size), rng.gen_prime(bit_size));
        let totient = (p.clone() - 1.to_biguint().unwrap()) * (q.clone() - 1.to_biguint().unwrap());
        if let Some(d) = inv_mod(exp, &totient) {
            return (p, q);
        }
    }
}

#[test]
fn test_rsa() {
    let e = 3.to_biguint().unwrap();

    let (p, q) = (41.to_biguint().unwrap(), 71.to_biguint().unwrap());
    let m = [48];
    do_test_rsa(&p, &q, &e, &m);

    let (p, q) = generate_large_primes(384, &e);
    let m = get_random_utf8();
    do_test_rsa(&p, &q, &e, &m);
}

#[test]
fn test_inv_mod() {
    let e = 17.to_biguint().unwrap();
    let et = 3120.to_biguint().unwrap();
    let d = 2753.to_biguint().unwrap();
    assert_eq!(inv_mod(&e, &et).unwrap(), d);
    let e = 854.to_biguint().unwrap();
    let et = 4567.to_biguint().unwrap();
    let d = 123.to_biguint().unwrap();
    assert_eq!(inv_mod(&e, &et).unwrap(), d);
}

pub fn inv_mod(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (g, x, y) = egcd(a, m);
    if g != 1.to_biguint().unwrap() {
        None
    } else if x < 0.to_bigint().unwrap() {
        Some((x + m.to_bigint().unwrap()).to_biguint().unwrap())
    } else {
        Some(x.to_biguint().unwrap())
    }
}

fn egcd(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt) {
    if a == &0.to_biguint().unwrap() {
        (b.clone(), 0.to_bigint().unwrap(), 1.to_bigint().unwrap())
    } else {
        let (g, y, x) = egcd(&(b % a), a);
        (
            g,
            x - (b.to_bigint().unwrap() / a.to_bigint().unwrap()) * y.clone(),
            y,
        )
    }
}

#[test]
fn test_egcd() {
    let a = 1432.to_biguint().unwrap();
    let b = 123211.to_biguint().unwrap();
    let (g, x, y) = egcd(&a, &b);
    assert_eq!(x, (-22973).to_bigint().unwrap());
    assert_eq!(y, (267).to_bigint().unwrap());
    assert_eq!(
        g,
        (a.to_bigint().unwrap() * x + b.to_bigint().unwrap() * y)
            .to_biguint()
            .unwrap()
    );
}

// Challenge 38

struct SrpMitm {
    n: BigUint,
    g: BigUint,
    k: BigUint,
    salt: BigUint,
    sk: BigUint,
    pk: BigUint,
    u: BigUint,
    passwords_filename: String,
    client_pk: Option<BigUint>,
}

impl SrpMitm {
    fn new(n: BigUint, g: BigUint, k: BigUint, passwords_filename: String) -> Self {
        let sk = thread_rng().gen_biguint_below(&n);
        let pk = g.modpow(&sk, &n);
        Self {
            n,
            g,
            k,
            salt: thread_rng().gen_biguint(256),
            sk,
            pk,
            u: thread_rng().gen_biguint(128),
            passwords_filename,
            client_pk: None,
        }
    }

    fn establish_shared_secret(&mut self, pk: &BigUint) -> Result<(BigUint, BigUint, BigUint), ()> {
        self.client_pk = Some(pk.clone());
        Ok((self.salt.clone(), self.pk.clone(), self.u.clone()))
    }

    fn crack_password(&self, client_hmac: &[u8; 32]) -> Result<String, ()> {
        let mut file = fs::File::open(self.passwords_filename.to_string()).unwrap();
        let mut file_contents = String::new();
        file.read_to_string(&mut file_contents).unwrap();
        for password in file_contents.lines() {
            let v = server_v(&self.salt, password.as_bytes(), &self.n, &self.g);
            let client_pk = match self.client_pk {
                None => return Err(()),
                Some(ref pk) => pk.clone(),
            };
            let s = (client_pk * v.modpow(&self.u, &self.n)).modpow(&self.sk, &self.n);
            let k = sha2(&s.to_bytes_be());
            let hmac = hmac_sha2(&k, &self.salt.to_bytes_be());
            if &hmac == client_hmac {
                return Ok(password.to_string());
            }
        }
        Err(())
    }
}

#[test]
fn test_offline_dictionary_attack_simplified_srp() {
    let passwords_filename = "data/passwords.txt";
    let (client, mut mitm) = init_srp_client_mitm(passwords_filename);

    let (salt, server_pk, u) = mitm.establish_shared_secret(&client.public_key()).unwrap();
    let client_hmac = client.generate_hmac_simplified(&salt, &server_pk, &u);
    let cracked_password = mitm.crack_password(&client_hmac).unwrap();
    assert_eq!(cracked_password, client.password().to_string());
}

fn get_random_password(filename: &str) -> String {
    let mut file = fs::File::open(filename).unwrap();
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents).unwrap();
    let passwords = file_contents.lines().collect::<Vec<&str>>();
    let idx = thread_rng().gen_range(0..passwords.len());
    passwords[idx].to_string()
}

fn init_srp_client_mitm(passwords_filename: &str) -> (SrpClient, SrpMitm) {
    let (n, g, k) = n_g_k();
    let email = String::from("alice@email.com");
    let password = String::from_utf8(get_random_utf8()).unwrap();

    let mut client = SrpClient::new(
        n.clone(),
        g.clone(),
        k.clone(),
        email.clone(),
        password.clone(),
    );
    client.password = get_random_password(passwords_filename);
    let mitm = SrpMitm::new(
        n.clone(),
        g.clone(),
        k.clone(),
        passwords_filename.to_string(),
    );
    (client, mitm)
}

// Challenge 37

fn do_test_break_srp_with_zero_key(public_key: &BigUint) {
    let (client, mut server) = init_srp_client_server();
    assert!(server
        .register(client.email().to_string(), client.password().to_string())
        .is_ok());
    let (salt, _server_pk) = server
        .establish_shared_secret(client.email(), public_key)
        .unwrap();
    let client_hmac = client.generate_zero_key_hmac(&salt);
    assert!(server.authenticate(client.email(), &client_hmac).is_ok());
}

#[test]
fn test_break_srp_with_zero_key() {
    let n = big_prime();
    do_test_break_srp_with_zero_key(&0.to_biguint().unwrap());
    do_test_break_srp_with_zero_key(&(n.clone() * 1.to_biguint().unwrap()));
    do_test_break_srp_with_zero_key(&(n * 2.to_biguint().unwrap()));
}

fn init_srp_client_server() -> (SrpClient, SrpServer) {
    let (n, g, k) = n_g_k();
    let email = String::from("alice@email.com");
    let password = String::from_utf8(get_random_utf8()).unwrap();

    let client = SrpClient::new(
        n.clone(),
        g.clone(),
        k.clone(),
        email.clone(),
        password.clone(),
    );
    let server = SrpServer::new(&n, &g, &k);
    (client, server)
}

fn n_g_k() -> (BigUint, BigUint, BigUint) {
    (
        big_prime(),
        2.to_biguint().unwrap(),
        3.to_biguint().unwrap(),
    )
}

// Challenge 36

pub fn sha2(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().try_into().unwrap()
}

pub fn hmac_sha2(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac(key, message, |message| sha2(message).to_vec())
        .try_into()
        .unwrap()
}

struct SrpClient {
    n: BigUint,
    g: BigUint,
    k: BigUint,
    email: String,
    password: String,
    sk: BigUint,
    pk: BigUint,
}

impl SrpClient {
    fn new(n: BigUint, g: BigUint, k: BigUint, email: String, password: String) -> Self {
        let sk = thread_rng().gen_biguint_below(&n);
        let pk = g.modpow(&sk, &n);
        Self {
            n,
            g,
            k,
            email,
            password,
            sk,
            pk,
        }
    }

    fn email(&self) -> &str {
        &self.email
    }

    fn password(&self) -> &str {
        &self.password
    }

    fn public_key(&self) -> BigUint {
        self.pk.clone()
    }

    fn generate_hmac(&self, salt: &BigUint, pk: &BigUint) -> [u8; 32] {
        let u_hash = sha2(&[self.pk.to_bytes_be(), pk.to_bytes_be()].concat());
        let u = BigUint::from_bytes_be(&u_hash);
        let k = client_K(
            &self.g,
            &self.k,
            &self.n,
            &salt,
            &self.password.as_bytes(),
            &self.sk,
            &u,
            &pk,
        );
        hmac_sha2(&k, &salt.to_bytes_be())
    }

    fn generate_zero_key_hmac(&self, salt: &BigUint) -> [u8; 32] {
        let k = sha2(&0.to_biguint().unwrap().to_bytes_be());
        hmac_sha2(&k, &salt.to_bytes_be())
    }

    fn generate_hmac_simplified(&self, salt: &BigUint, pk: &BigUint, u: &BigUint) -> [u8; 32] {
        let x_hash = sha2(&[&salt.to_bytes_be(), self.password.as_bytes()].concat());
        let x = BigUint::from_bytes_be(&x_hash);
        let s = pk.modpow(&(self.sk.clone() + u * x), &self.n);
        let k = sha2(&s.to_bytes_be());
        hmac_sha2(&k, &salt.to_bytes_be())
    }
}

struct SrpUserInfo {
    salt: BigUint,
    v: BigUint,
    hmac: Option<[u8; 32]>,
}

struct SrpServer {
    n: BigUint,
    g: BigUint,
    k: BigUint,
    user_info: HashMap<String, SrpUserInfo>,
}

impl SrpServer {
    fn new(n: &BigUint, g: &BigUint, k: &BigUint) -> Self {
        Self {
            n: n.clone(),
            g: g.clone(),
            k: k.clone(),
            user_info: HashMap::new(),
        }
    }

    fn register(&mut self, email: String, password: String) -> Result<(), ()> {
        let salt = thread_rng().gen_biguint(256);
        let v = server_v(&salt, password.as_bytes(), &self.n, &self.g);
        if self.user_info.contains_key(&email) {
            Err(())
        } else {
            self.user_info.insert(
                email,
                SrpUserInfo {
                    salt,
                    v,
                    hmac: None,
                },
            );
            Ok(())
        }
    }

    fn establish_shared_secret(
        &mut self,
        email: &str,
        pk: &BigUint,
    ) -> Result<(BigUint, BigUint), ()> {
        let user_info = match self.user_info.get_mut(email) {
            None => return Err(()),
            Some(info) => info,
        };
        let (sk_b, pk_b) = server_sk_pk(&self.n, &self.k, &user_info.v, &self.g);
        let u_hash = sha2(&[pk.to_bytes_be(), pk_b.to_bytes_be()].concat());
        let u = BigUint::from_bytes_be(&u_hash);
        let k = server_K(&pk, &user_info.v, &u, &self.n, &sk_b);
        let hmac = hmac_sha2(&k, &user_info.salt.to_bytes_be());
        user_info.hmac = Some(hmac);
        Ok((user_info.salt.clone(), pk_b))
    }

    fn authenticate(&self, email: &str, hmac: &[u8; 32]) -> Result<(), ()> {
        let info = match self.user_info.get(email) {
            None => return Err(()),
            Some(info) => info,
        };
        let expected_hmac = match info.hmac {
            None => return Err(()),
            Some(hmac) => hmac,
        };
        if hmac == &expected_hmac {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[test]
fn test_srp() {
    let (client, mut server) = init_srp_client_server();
    assert!(server
        .register(client.email().to_string(), client.password().to_string())
        .is_ok());
    let (salt, server_pk) = server
        .establish_shared_secret(client.email(), &client.public_key())
        .unwrap();
    let client_hmac = client.generate_hmac(&salt, &server_pk);
    assert!(server.authenticate(client.email(), &client_hmac).is_ok());
}

fn server_sk_pk(n: &BigUint, k: &BigUint, v: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let sk_b = thread_rng().gen_biguint_below(&n);
    let pk_b = k * v + g.modpow(&sk_b, &n);
    (sk_b, pk_b)
}

fn server_K(pk_a: &BigUint, v: &BigUint, u: &BigUint, n: &BigUint, sk_b: &BigUint) -> [u8; 32] {
    let s = (pk_a * v.modpow(&u, &n)).modpow(&sk_b, &n);
    sha2(&s.to_bytes_be())
}

fn server_v(salt: &BigUint, password: &[u8], n: &BigUint, g: &BigUint) -> BigUint {
    let x_hash = sha2(&[&salt.to_bytes_be(), password].concat());
    let x = BigUint::from_bytes_be(&x_hash);
    g.modpow(&x, &n)
}

fn client_K(
    g: &BigUint,
    k: &BigUint,
    n: &BigUint,
    salt: &BigUint,
    password: &[u8],
    sk_a: &BigUint,
    u: &BigUint,
    pk_b: &BigUint,
) -> [u8; 32] {
    let x_hash = sha2(&[&salt.to_bytes_be(), password].concat());
    let x = BigUint::from_bytes_be(&x_hash);
    let v = server_v(salt, password, n, g);
    let s = (pk_b - k * v).modpow(&(sk_a + u * x), &n);
    sha2(&s.to_bytes_be())
}

fn big_prime() -> BigUint {
    BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap()
}

// Challenge 35

#[test]
fn test_dh_g_equal_p_minus_one() {
    let mut a = DHBasic::new();
    let mut b = DHBasic::new();
    a.g = a.p.clone().sub(1.to_biguint().unwrap());

    a.send_dh_start(&mut b);
    b.send_dh_pk(&mut a);

    let one = 1.to_biguint().unwrap();
    let fixed_secret = if a.public_key() != one && b.public_key() != one {
        a.public_key()
    } else {
        one
    };

    assert_eq!(a.shared_secret, b.shared_secret);
    assert_eq!(a.shared_secret.clone().unwrap(), fixed_secret.clone());
}

#[test]
fn test_dh_g_equal_p() {
    let mut a = DHBasic::new();
    let mut b = DHBasic::new();
    // fix g...somehow?
    let fixed_secret = 0.to_biguint().unwrap();
    a.g = a.p.clone();
    let mut mitm = DHMitm::new(&fixed_secret.clone());

    a.send_dh_start(&mut mitm.dh_a);
    b.receive_dh_start(&mitm.dh_a.p, &mitm.dh_a.g, &a.public_key());
    a.receive_dh_pk(&a.public_key()); // public key doesn't matter

    assert_eq!(a.shared_secret, b.shared_secret);
    assert_eq!(a.shared_secret.clone().unwrap(), fixed_secret.clone());
}

#[test]
fn test_dh_g_equal_one() {
    let mut a = DHBasic::new();
    let mut b = DHBasic::new();
    // fix g...somehow?
    a.g = 1.to_biguint().unwrap();
    let mut mitm = DHMitm::new(&1.to_biguint().unwrap());

    a.send_dh_start(&mut mitm.dh_a);
    b.receive_dh_start(&mitm.dh_a.p, &mitm.dh_a.g, &a.public_key());
    a.receive_dh_pk(&a.public_key()); // public key doesn't matter

    assert_eq!(a.shared_secret, b.shared_secret);
    assert_eq!(a.shared_secret.clone().unwrap(), 1.to_biguint().unwrap());
}

// Challenge 34

#[test]
fn test_dh_interfaces() {
    let mut a = DHBasic::new();
    let mut b = DHBasic::new();
    a.send_dh_start(&mut b);
    b.send_dh_pk(&mut a);
    let plaintext = pkcs7_pad(&get_random_utf8(), BLOCK_SIZE);
    let iv = generate_key();
    let ciphertext_a = a.encrypt(&plaintext, &iv);
    assert_eq!(plaintext, b.decrypt(&ciphertext_a, &iv));
    let ciphertext_b = b.encrypt(&plaintext, &iv);
    assert_eq!(plaintext, a.decrypt(&ciphertext_b, &iv));
}

#[test]
fn test_dh_mitm_param_injection() {
    let mut a = DHBasic::new();
    let mut b = DHBasic::new();
    let mut mitm = DHMitm::new(&0.to_biguint().unwrap());

    a.send_dh_start(&mut mitm.dh_a);
    mitm.dh_b.p = mitm.dh_a.p.clone();
    b.receive_dh_start(&mitm.dh_b.p, &mitm.dh_b.g, &mitm.dh_b.p);
    b.send_dh_pk(&mut mitm.dh_b);
    mitm.dh_a.send_dh_pk(&mut a);
    a.receive_dh_pk(&mitm.dh_a.p);

    let plaintext_a = pkcs7_pad(&get_random_utf8(), BLOCK_SIZE);
    let iv = generate_key();
    let ciphertext_a = a.encrypt(&plaintext_a, &iv);
    let mitm_plaintext_a = mitm.dh_a.decrypt(&ciphertext_a, &iv);
    assert_eq!(plaintext_a, mitm_plaintext_a);

    let plaintext_b = ciphertext_a;
    let iv = generate_key();
    let ciphertext_b = b.encrypt(&plaintext_b, &iv);
    let mitm_plaintext_b = mitm.dh_b.decrypt(&ciphertext_b, &iv);
    assert_eq!(plaintext_b, mitm_plaintext_b);
}

trait DHAesCbc {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8>;
}

trait DHActor {
    fn send_dh_pk(&self, counterparty: &mut impl DHActor);
    fn receive_dh_pk(&mut self, their_pk: &BigUint);
    fn send_dh_start(&mut self, counterparty: &mut impl DHActor);
    fn receive_dh_start(&mut self, p: &BigUint, g: &BigUint, their_pk: &BigUint);
}

struct DHBasic {
    g: BigUint,
    p: BigUint,
    secret: BigUint,
    shared_secret: Option<BigUint>,
    aes_key: Option<[u8; 16]>,
}

impl DHAesCbc for DHBasic {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        aes_cbc_encrypt(
            plaintext,
            &self
                .aes_key
                .expect("Should not call encrypt before creating aes_key"),
            iv,
        )
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        aes_cbc_decrypt(
            ciphertext,
            &self
                .aes_key
                .expect("Should not call decrypt before creating aes_key"),
            iv,
        )
    }
}

impl DHBasic {
    fn new() -> Self {
        let g = 2.to_biguint().unwrap();
        let p = big_prime();
        let secret = generate_dh_secret(&p);
        Self::new_from(&g, &p, &secret)
    }

    fn new_from(g: &BigUint, p: &BigUint, secret: &BigUint) -> Self {
        Self {
            g: g.clone(),
            p: p.clone(),
            secret: secret.clone(),
            shared_secret: None,
            aes_key: None,
        }
    }

    fn new_from_other(g: &BigUint, p: &BigUint, their_pk: &BigUint) -> Self {
        let secret = generate_dh_secret(p);
        Self::new_from_other_with_secret(g, p, their_pk, &secret)
    }

    fn new_from_other_with_secret(
        g: &BigUint,
        p: &BigUint,
        their_pk: &BigUint,
        secret: &BigUint,
    ) -> Self {
        let mut me = Self::new_from(g, p, &secret);
        me.receive_dh_pk(their_pk);
        me
    }

    fn public_key(&self) -> BigUint {
        self.g.modpow(&self.secret, &self.p)
    }
}

impl DHActor for DHBasic {
    fn send_dh_pk(&self, counterparty: &mut impl DHActor) {
        counterparty.receive_dh_pk(&self.public_key());
    }

    fn receive_dh_pk(&mut self, their_pk: &BigUint) {
        let shared_secret = their_pk.modpow(&self.secret, &self.p);
        self.aes_key = Some(aes_key_from_dh_shared_secret(&shared_secret));
        self.shared_secret = Some(shared_secret);
    }
    fn send_dh_start(&mut self, counterparty: &mut impl DHActor) {
        counterparty.receive_dh_start(&self.p, &self.g, &self.public_key());
    }

    fn receive_dh_start(&mut self, p: &BigUint, g: &BigUint, their_pk: &BigUint) {
        *self = Self::new_from_other(g, p, their_pk);
    }
}

struct DHFixedKey {
    g: BigUint,
    p: BigUint,
    shared_secret: BigUint,
    aes_key: [u8; 16],
}

impl DHFixedKey {
    fn new(shared_secret: &BigUint) -> Self {
        let g = 2.to_biguint().unwrap();
        let p = big_prime();
        Self {
            g,
            p,
            shared_secret: shared_secret.clone(),
            aes_key: aes_key_from_dh_shared_secret(shared_secret),
        }
    }
}

impl DHAesCbc for DHFixedKey {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        aes_cbc_encrypt(plaintext, &self.aes_key, iv)
    }
    fn decrypt(&self, ciphertext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        aes_cbc_decrypt(ciphertext, &self.aes_key, iv)
    }
}

impl DHActor for DHFixedKey {
    fn send_dh_pk(&self, counterparty: &mut impl DHActor) {}

    fn receive_dh_pk(&mut self, _their_pk: &BigUint) {}

    fn send_dh_start(&mut self, counterparty: &mut impl DHActor) {}

    fn receive_dh_start(&mut self, p: &BigUint, g: &BigUint, their_pk: &BigUint) {
        self.g = g.clone();
        self.p = p.clone();
        self.receive_dh_pk(their_pk)
    }
}

struct DHMitm {
    g: BigUint,
    p: BigUint,
    dh_a: DHFixedKey,
    dh_b: DHFixedKey,
}

impl DHMitm {
    fn new(key: &BigUint) -> Self {
        // init dummy before getting first message
        let dh_a = DHFixedKey::new(key);
        let dh_b = DHFixedKey::new(key);
        Self {
            g: dh_a.g.clone(),
            p: dh_a.p.clone(),
            dh_a,
            dh_b,
        }
    }
}

fn aes_key_from_dh_shared_secret(shared_secret: &BigUint) -> [u8; 16] {
    let digest = sha1(&shared_secret.to_bytes_be().as_slice());
    let aes_key: [u8; 16] = digest[0..BLOCK_SIZE].try_into().unwrap();
    aes_key
}

fn aes_key_from_dh(my_sk: &BigUint, their_pk: &BigUint, p: &BigUint) -> [u8; 16] {
    let shared_sk = their_pk.modpow(my_sk, p);
    aes_key_from_dh_shared_secret(&shared_sk)
}

fn generate_dh_secret(p: &BigUint) -> BigUint {
    let (low, high) = (1.to_biguint().unwrap() << 512, p.clone());
    thread_rng().gen_biguint_range(&low, &high)
}

// Challenge 33

fn do_test_basic_dh(p: &BigUint, g: &BigUint, a: &BigUint, b: &BigUint) {
    let pka = g.modpow(a, p);
    let pkb = g.modpow(b, p);
    let secret_a = pka.modpow(b, p);
    let secret_b = pkb.modpow(a, p);
    assert_eq!(secret_a, secret_b);
}

#[test]
fn test_basic_dh() {
    do_test_basic_dh(
        &37.to_biguint().unwrap(),
        &5.to_biguint().unwrap(),
        &17.to_biguint().unwrap(),
        &4.to_biguint().unwrap(),
    );

    let p = big_prime();
    let g = 2.to_biguint().unwrap();
    let a = generate_dh_secret(&p);
    let b = generate_dh_secret(&p);
    do_test_basic_dh(&p, &g, &a, &b);
}
