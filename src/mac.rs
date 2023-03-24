use rand::{thread_rng, Rng};
use sha1_smol::DIGEST_LENGTH;

// Challenge 28/29

// Don't roll your own crypto...unless you have to for a cryptopals challenge..
// Couldn't find a rust implementation of SHA-1 that would allow me to set
// the inner state, so here we are.

const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

const DEFAULT_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

pub fn sha1(message: &[u8]) -> [u8; DIGEST_LENGTH] {
    sha1_from_state(message, 0, &DEFAULT_STATE)
}

/// Based on pseudocode from [Wikipedia](https://en.wikipedia.org/wiki/SHA-1)
pub fn sha1_from_state(
    message: &[u8],
    prev_length: u64,
    starting_state: &[u32; 5],
) -> [u8; DIGEST_LENGTH] {
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

pub fn state_to_digest(state: &[u32; 5]) -> [u8; DIGEST_LENGTH] {
    let mut digest = [0u8; DIGEST_LENGTH];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..(i * 4 + 4)].clone_from_slice(&word.to_be_bytes());
    }
    digest
}

pub fn digest_to_state(digest: &[u8; DIGEST_LENGTH]) -> [u32; 5] {
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

pub(crate) fn sha1_mac_sign(message: &[u8], key: &[u8]) -> [u8; DIGEST_LENGTH] {
    sha1(&[key, message].concat())
}

pub(crate) fn sha1_mac_verify(mac: &[u8; DIGEST_LENGTH], message: &[u8], key: &[u8]) -> bool {
    mac == &sha1(&[key, message].concat())
}
