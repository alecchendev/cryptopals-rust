use rand::{thread_rng, Rng, RngCore};
use num_bigint::{BigUint, RandBigInt, RandPrime, ToBigUint};
use num_bigint_dig as num_bigint;
use std::collections::HashSet;
use crate::{set5::{generate_large_primes, inv_mod}, set4::get_random_utf8};

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

