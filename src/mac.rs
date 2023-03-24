
use sha1_smol::DIGEST_LENGTH;

// Don't roll your own crypto...unless you have to for a cryptopals challenge..
// Couldn't find a rust implementation of SHA-1 that would allow me to set
// the inner state, so here we are.

/// Naive unoptimized SHA-1 implementation
struct Sha1 {
    state: [u32; 5],
    block: [u8; 64], // leftover
    len: u64, // includes block stuff (len % 64 == amount in block)
}

const DEFAULT_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

#[inline(always)]
fn as_block(input: &[u8]) -> &[u8; 64] {
    unsafe {
        assert!(input.len() == 64);
        let arr: &[u8; 64] = &*(input.as_ptr() as *const [u8; 64]);
        arr
    }
}

impl Sha1 {

    pub fn new() -> Self {
        Self {
            state: DEFAULT_STATE,
            block: [0; 64],
            len: 0
        }
    }

    pub fn from_state(state: [u32; 5], len: u64) -> Self {
        Self {
            state,
            block: [0; 64],
            len
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        // process each 512 bit chunk
        let remaining = self.len % 64;
        if remaining > 0 {
            let len = remaining as usize;
            let amt = std::cmp::min(input.len(), self.block.len() - len);
            self.block[len..len + amt].clone_from_slice(&input[..amt]);
            if len + amt == self.block.len() {
                self.state = self.process(&self.block);
                input = &input[amt..];
            } else {
                self.len += amt as u64;
                return;
            }
        }
        assert_eq!(self.len, 0);
        for chunk in input.chunks(64) {
            if chunk.len() == 64 {
                self.state = self.process(as_block(chunk));
            } else {
                self.block[..chunk.len()].clone_from_slice(chunk);
            }
        }
        self.len += input.len() as u64;
    }

    fn process(&self, block: &[u8; 64]) -> [u32; 5] {
        let mut w = [0u32; 80];
        w.iter_mut().zip(block.chunks(4)).for_each(|(word, chunk)| {
            *word = 
                (chunk[0] as u32) << 24 |
                (chunk[1] as u32) << 16 |
                (chunk[2] as u32) << 8 |
                (chunk[3] as u32) << 0
            ;
        });

        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }

        let mut a = DEFAULT_STATE[0];
        let mut b = DEFAULT_STATE[1];
        let mut c = DEFAULT_STATE[2];
        let mut d = DEFAULT_STATE[3];
        let mut e = DEFAULT_STATE[4];

        let mut f = 0;
        let mut k = 0;

        for i in 0..80 {
            if i < 20 {
                f = (b & c) ^ ((!b) & d);
                k = K0;
            } else if i < 40 {
                f = b ^ c ^ d;
                k = K1;
            } else if i < 60 {
                f = (b & c) ^ (b & d) ^ (c & d);
                k = K2;
            } else {
                f = b ^ c ^ d;
                k = K3;
            }

            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        [self.state[0].wrapping_add(a), self.state[1].wrapping_add(b), self.state[2].wrapping_add(c), self.state[3].wrapping_add(d), self.state[4].wrapping_add(e)]
    }

    pub fn digest(&self) -> [u8; DIGEST_LENGTH] {
        // Pad to 512 bits
        let mut last = pad(self.len);
        let block_len = (self.len % 64) as usize;
        last[..block_len].clone_from_slice(&self.block[..block_len]);
        // Process last chunk
        let mut state = self.state;
        if block_len < 56 {
            state = self.process(as_block(&last[0..64]));
        } else {
            state = self.process(as_block(&last[0..64]));
            state = self.process(as_block(&last[64..128]));
        }
        // Output digest
        [
            (state[0] >> 24) as u8,
            (state[0] >> 16) as u8,
            (state[0] >> 8) as u8,
            (state[0] >> 0) as u8,
            (state[1] >> 24) as u8,
            (state[1] >> 16) as u8,
            (state[1] >> 8) as u8,
            (state[1] >> 0) as u8,
            (state[2] >> 24) as u8,
            (state[2] >> 16) as u8,
            (state[2] >> 8) as u8,
            (state[2] >> 0) as u8,
            (state[3] >> 24) as u8,
            (state[3] >> 16) as u8,
            (state[3] >> 8) as u8,
            (state[3] >> 0) as u8,
            (state[4] >> 24) as u8,
            (state[4] >> 16) as u8,
            (state[4] >> 8) as u8,
            (state[4] >> 0) as u8,
        ]
    }
}

pub fn pad(len: u64) -> [u8; 128] {
    let mut padding = [0u8; 128];
    let blocklen = len % 64;
    padding[blocklen as usize] = 0x80;
    let bit_len = len * 8;
    let bit_len_be = [
        (bit_len >> 56) as u8,
        (bit_len >> 48) as u8,
        (bit_len >> 40) as u8,
        (bit_len >> 32) as u8,
        (bit_len >> 24) as u8,
        (bit_len >> 16) as u8,
        (bit_len >> 8) as u8,
        (bit_len >> 0) as u8,
    ];
    if blocklen < 56 {
        padding[56..64].clone_from_slice(&bit_len_be);
    } else {
        padding[120..].clone_from_slice(&bit_len_be);
    }
    padding
}

#[test]
fn test_sha1() {
    let expected_hash = sha1(b"Hello world!");
    let mut s = Sha1::new();
    s.update(b"Hello world!");
    let hash = s.digest();
}

pub(crate) fn sha1(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    sha1_smol::Sha1::from(data).digest().bytes()
}

pub(crate) fn sha1_mac_sign(message: &[u8], key: &[u8]) -> [u8; DIGEST_LENGTH] {
    sha1(&[key, message].concat())
}

pub(crate) fn sha1_mac_verify(mac: &[u8; DIGEST_LENGTH], message: &[u8], key: &[u8]) -> bool {
    mac == &sha1(&[key, message].concat())
}
