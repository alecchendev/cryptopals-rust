use rand::{thread_rng, Rng};
// use sha1_smol::DIGEST_LENGTH;
use sha1_smol;

// Challenge 30

pub fn md4_mac_sign(message: &[u8], key: &[u8]) -> [u8; DIGEST_LENGTH_MD4] {
    md4(&[key, message].concat())
}

pub fn md4_mac_verify(mac: &[u8; DIGEST_LENGTH_MD4], message: &[u8], key: &[u8]) -> bool {
    mac == &md4_mac_sign(message, key)
}

pub const DIGEST_LENGTH_MD4: usize = 16;

pub const DEFAULT_STATE_MD4: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

pub fn md4_pad(message_len: u64) -> Vec<u8> {
    let block_len = message_len as usize % 64;
    let mut padding = [0u8; 128];
    padding[block_len] = 0x80;
    let message_bit_len = message_len * 8;
    let padding = if block_len < 56 {
        padding[56..64].clone_from_slice(&message_bit_len.to_le_bytes());
        &padding[..64]
    } else {
        padding[120..128].clone_from_slice(&message_bit_len.to_le_bytes());
        &padding[..128]
    };
    padding[block_len..].to_vec()
}

pub fn md4(message: &[u8]) -> [u8; DIGEST_LENGTH_MD4] {
    md4_from_state(message, 0, &DEFAULT_STATE_MD4)
}

// Based on http://practicalcryptography.com/hashes/md4-hash/
pub fn md4_from_state(
    message: &[u8],
    prev_length: u64,
    starting_state: &[u32; 4],
) -> [u8; DIGEST_LENGTH_MD4] {
    let f = |x: u32, y: u32, z: u32| (x & y) | ((!x) & z);
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let op1 = |a: u32, b: u32, c: u32, d: u32, k: u32, s: u32| -> u32 {
        a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
    };
    let op2 = |a: u32, b: u32, c: u32, d: u32, k: u32, s: u32| -> u32 {
        a.wrapping_add(g(b, c, d))
            .wrapping_add(k)
            .wrapping_add(0x5A827999)
            .rotate_left(s)
    };
    let op3 = |a: u32, b: u32, c: u32, d: u32, k: u32, s: u32| -> u32 {
        a.wrapping_add(h(b, c, d))
            .wrapping_add(k)
            .wrapping_add(0x6ED9EBA1)
            .rotate_left(s)
    };

    assert!(prev_length % 64 == 0);
    let mut state = starting_state.clone();

    let padding = md4_pad(prev_length + message.len() as u64);
    let message = &[message, &padding[..]].concat();
    assert!(message.len() % 64 == 0);

    for block in message.chunks(64) {
        let mut x = [0u32; 16];
        for (word, chunk) in x.iter_mut().zip(block.chunks(4)) {
            *word = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        for &i in &[0, 4, 8, 12] {
            a = op1(a, b, c, d, x[i], 3);
            d = op1(d, a, b, c, x[i + 1], 7);
            c = op1(c, d, a, b, x[i + 2], 11);
            b = op1(b, c, d, a, x[i + 3], 19);
        }

        for i in 0..4 {
            a = op2(a, b, c, d, x[i], 3);
            d = op2(d, a, b, c, x[i + 4], 5);
            c = op2(c, d, a, b, x[i + 8], 9);
            b = op2(b, c, d, a, x[i + 12], 13);
        }

        for &i in &[0, 2, 1, 3] {
            a = op3(a, b, c, d, x[i], 3);
            d = op3(d, a, b, c, x[i + 8], 9);
            c = op3(c, d, a, b, x[i + 4], 11);
            b = op3(b, c, d, a, x[i + 12], 15);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    md4_state_to_digest(&state)
}

#[test]
fn test_md4() {
    let expected = hex::decode(b"0d7a9db5a3bed4ae5738ee6d1909649c").unwrap();
    let msg = b"Hello world!";
    let hash = md4(msg);
    assert_eq!(&hash, expected.as_slice());
}

#[test]
fn test_md4_update() {
    let msg1 = b"Hello world!";
    let digest1 = md4(msg1);

    let msg2 = b"Hello again!";
    let padding = md4_pad(msg1.len() as u64);
    let msg1_with_padding = [msg1, &padding[..]].concat();
    let final_msg2 = [&msg1_with_padding[..], msg2].concat();
    let digest2 = md4(&final_msg2);
    let digest2_from_state = md4_from_state(
        msg2,
        msg1_with_padding.len() as u64,
        &md4_digest_to_state(&digest1),
    );
    assert_eq!(digest2, digest2_from_state);
}

pub fn md4_digest_to_state(digest: &[u8; DIGEST_LENGTH_MD4]) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (word, chunk) in w.iter_mut().zip(digest.chunks(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    w
}

pub fn md4_state_to_digest(state: &[u32; 4]) -> [u8; DIGEST_LENGTH_MD4] {
    let mut digest = [0u8; DIGEST_LENGTH_MD4];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..(i * 4 + 4)].clone_from_slice(&word.to_le_bytes());
    }
    digest
}

// Challenge 28/29

// Don't roll your own crypto...unless you have to for a cryptopals challenge..
// Couldn't find a rust implementation of SHA-1 that would allow me to set
// the inner state, so here we are.

const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

const DEFAULT_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

pub const DIGEST_LENGTH_SHA1: usize = 20;

pub fn sha1(message: &[u8]) -> [u8; DIGEST_LENGTH_SHA1] {
    sha1_from_state(message, 0, &DEFAULT_STATE)
}

/// Based on pseudocode from [Wikipedia](https://en.wikipedia.org/wiki/SHA-1)
pub fn sha1_from_state(
    message: &[u8],
    prev_length: u64,
    starting_state: &[u32; 5],
) -> [u8; DIGEST_LENGTH_SHA1] {
    assert!(prev_length % 64 == 0);
    let mut h0 = starting_state[0];
    let mut h1 = starting_state[1];
    let mut h2 = starting_state[2];
    let mut h3 = starting_state[3];
    let mut h4 = starting_state[4];

    // Pad to 512 bits
    let block_len = message.len() % 64;
    let mut padding = [0u8; 128];
    padding[..block_len].clone_from_slice(&message[(message.len() - block_len)..]);
    padding[block_len] = 0x80;
    let message_len = (prev_length + message.len() as u64) * 8;
    let padding = if block_len < 56 {
        padding[56..64].clone_from_slice(&message_len.to_be_bytes());
        &padding[..64]
    } else {
        padding[120..128].clone_from_slice(&message_len.to_be_bytes());
        &padding[..128]
    };
    let message = &[&message[..(message.len() - block_len)], padding].concat();
    assert!(message.len() % 64 == 0);

    // Process 512-bit chunks
    for block in message.chunks(64) {
        let mut w = [0u32; 80];
        w.iter_mut().zip(block.chunks(4)).for_each(|(word, chunk)| {
            *word = (chunk[0] as u32) << 24
                | (chunk[1] as u32) << 16
                | (chunk[2] as u32) << 8
                | (chunk[3] as u32) << 0;
        });

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) ^ ((!b) & d), K0)
            } else if i < 40 {
                (b ^ c ^ d, K1)
            } else if i < 60 {
                ((b & c) ^ (b & d) ^ (c & d), K2)
            } else {
                (b ^ c ^ d, K3)
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    state_to_digest(&[h0, h1, h2, h3, h4])
}

#[test]
fn test_sha1() {
    let msg = b"Hello world!";
    assert_eq!(sha1(msg), sha1_smol::Sha1::from(msg).digest().bytes());
    let msg2 = vec![0; thread_rng().gen_range(64..=128)]
        .iter()
        .map(|_| thread_rng().gen())
        .collect::<Vec<u8>>();
    let msg2 = msg2.as_slice();
    assert_eq!(sha1(msg2), sha1_smol::Sha1::from(msg2).digest().bytes());
}

#[test]
fn test_sha1_update() {
    let msg1 = b"Hello world!";
    let digest = sha1(msg1);
    let s = sha1_smol::Sha1::from(msg1);
    assert_eq!(digest, s.digest().bytes());

    let padding = sha1_pad(msg1.len() as u64);
    let padding = &padding[msg1.len()..(if msg1.len() < 56 { 64 } else { 128 })];
    let msg2 = b"Hello again!";

    let final_message = &[msg1, padding, msg2].concat();
    let s2 = sha1_smol::Sha1::from(final_message);
    assert_eq!(sha1(final_message), s2.digest().bytes());
    assert_eq!(
        sha1_from_state(msg2, 64, &digest_to_state(&digest)),
        sha1(final_message)
    );
}

pub fn state_to_digest(state: &[u32; 5]) -> [u8; DIGEST_LENGTH_SHA1] {
    let mut digest = [0u8; DIGEST_LENGTH_SHA1];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..(i * 4 + 4)].clone_from_slice(&word.to_be_bytes());
    }
    digest
}

pub fn digest_to_state(digest: &[u8; DIGEST_LENGTH_SHA1]) -> [u32; 5] {
    let mut w = [0u32; 5];
    w.iter_mut()
        .zip(digest.chunks(4))
        .for_each(|(word, chunk)| {
            *word = (chunk[0] as u32) << 24
                | (chunk[1] as u32) << 16
                | (chunk[2] as u32) << 8
                | (chunk[3] as u32) << 0;
        });
    w
}

pub fn sha1_pad(len: u64) -> [u8; 128] {
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

pub(crate) fn sha1_mac_sign(message: &[u8], key: &[u8]) -> [u8; DIGEST_LENGTH_SHA1] {
    sha1(&[key, message].concat())
}

pub(crate) fn sha1_mac_verify(mac: &[u8; DIGEST_LENGTH_SHA1], message: &[u8], key: &[u8]) -> bool {
    mac == &sha1(&[key, message].concat())
}
