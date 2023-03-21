use std::time::{SystemTime, UNIX_EPOCH};

use rand::{thread_rng, Rng};

use crate::basic::fixed_xor;

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
