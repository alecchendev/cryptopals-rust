use base64::{engine::general_purpose, Engine};
use rand::{thread_rng, Rng, RngCore};
use reqwest::{Client, Response, StatusCode};
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io::Read;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use tokio;
use warp::{http, Filter, Reply};

use crate::set1::{aes_ecb_decrypt, aes_ecb_encrypt, fixed_xor, generate_key, pkcs7_pad};
use crate::set2::{pkcs7_unpad, AesCbcOracle, BitFlippingOracle, CipherOracle, BLOCK_SIZE};
use crate::set3::{aes_ctr_decrypt, aes_ctr_encrypt};

// Challenge 32

fn less_insecure_compare(a: &[u8], b: &[u8]) -> bool {
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        if byte_a != byte_b {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    a.len() == b.len()
}

async fn less_artificial_timing_attack<F, Fut>(
    port: u16,
    file: &[u8],
    send_request: F,
) -> [u8; DIGEST_LENGTH_SHA1]
where
    F: Fn(String, String) -> Fut,
    Fut: Future<Output = Response>,
{
    let file = String::from_utf8(file.to_vec()).unwrap();
    let mut signature = [0u8; DIGEST_LENGTH_SHA1];
    let rounds = 8;
    for i in 0..DIGEST_LENGTH_SHA1 {
        let mut best = (0, 0); // (byte, time)
        for byte in 0..=255 {
            let mut sig = signature.clone();
            sig[i] = byte;
            let sig = hex::encode(&sig[..(i + 1)]);
            let mut times = vec![0u128; rounds];
            for round in 0..rounds {
                let start_time = std::time::Instant::now();
                let _ = send_request(file.clone(), sig.clone()).await;
                let end_time = std::time::Instant::now();
                let request_time = end_time.duration_since(start_time).as_millis();
                times[round] = request_time;
            }
            times.sort();
            let median_time = if rounds % 2 == 0 {
                (times[rounds / 2] + times[rounds / 2 + 1]) / 2
            } else {
                times[rounds / 2]
            };
            if median_time > best.1 {
                best = (byte, median_time);
            }
        }
        signature[i] = best.0;
    }
    signature
}

#[cfg(wait)]
#[tokio::test]
async fn test_less_artificial_timing_attack() {
    let port = 9001;
    let key = vec![0u8; thread_rng().gen_range(4..=64)]
        .iter()
        .map(|_| thread_rng().gen())
        .collect::<Vec<u8>>();

    let test_data = [
        (
            "foo",
            hex::encode(hmac_sha1(&key, "foo".as_bytes())),
            StatusCode::OK,
        ),
        (
            "asdf",
            String::from("1234"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    let rand_file = get_random_utf8();
    let expected = hmac_sha1(&key, rand_file.as_slice());

    start_server(port, Arc::new(key), less_insecure_compare);

    for (file, hmac, expected_status) in test_data.iter() {
        let response = send_request(port, file.to_string(), hmac.to_string()).await;
        assert_eq!(response.status(), *expected_status);
    }

    let got =
        less_artificial_timing_attack(port, &rand_file, |file, sig| send_request(port, file, sig))
            .await;
    assert_eq!(got, expected);
}

// Challenge 31

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; DIGEST_LENGTH_SHA1] {
    hmac(key, message, |message| sha1(message).to_vec())
        .try_into()
        .unwrap()
}

pub fn hmac<F>(key: &[u8], message: &[u8], hash: F) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    let block_size = 64;
    let compressed_key = hash(key);
    let key = if key.len() > block_size {
        &compressed_key
    } else {
        key
    };

    let mut inner_pad = [0x36; 64];
    inner_pad
        .iter_mut()
        .zip(key.iter())
        .for_each(|(byte, key_byte)| *byte ^= key_byte);
    let mut outer_pad = [0x5c; 64];
    outer_pad
        .iter_mut()
        .zip(key.iter())
        .for_each(|(byte, key_byte)| *byte ^= key_byte);

    let hash_1 = hash(&[&inner_pad, message].concat());
    let hash_2 = hash(&[&outer_pad, &hash_1[..]].concat());

    hash_2
}

#[test]
fn test_sha1_hmac() {
    let expected = hex::decode("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9").unwrap();
    let got = hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog");
    assert_eq!(got, &expected[..]);
}

pub fn get_random_utf8() -> Vec<u8> {
    let bytes = (0..thread_rng().gen_range(4..=64))
        .map(|_| thread_rng().gen())
        .collect::<Vec<u8>>();
    String::from_utf8_lossy(&bytes).as_bytes().to_vec()
}

fn start_server<F: Clone + Send + Sync + 'static>(port: u16, key: Arc<Vec<u8>>, compare: F)
where
    F: Fn(&[u8], &[u8]) -> bool,
{
    tokio::task::spawn(async move {
        let route = warp::any()
            .and(warp::path("test"))
            .and(warp::query::<HashMap<String, String>>())
            .map(move |map: HashMap<String, String>| {
                let file = map.get("file").unwrap();
                let signature = hex::decode(map.get("signature").unwrap()).unwrap();
                let hmac = hmac_sha1(&key, file.as_bytes());
                let valid_signature = compare(&signature, &hmac);
                http::Response::builder()
                    .status(if valid_signature { 200 } else { 500 })
                    .body("")
            });
        warp::serve(route).run(([127, 0, 0, 1], port)).await
    });
    std::thread::sleep(Duration::from_secs(1));
}

async fn send_request(port: u16, file: String, sig: String) -> Response {
    let url = format!(
        "http://localhost:{}/test?file={}&signature={}",
        port, file, sig
    );
    Client::new().get(&url).send().await.unwrap()
}

fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        if byte_a != byte_b {
            return false;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    a.len() == b.len()
}

async fn artificial_timing_attack<F, Fut>(file: &[u8], send_request: F) -> [u8; DIGEST_LENGTH_SHA1]
where
    F: Fn(String, String) -> Fut,
    Fut: Future<Output = Response>,
{
    let file = String::from_utf8(file.to_vec()).unwrap();
    let mut signature = [0u8; DIGEST_LENGTH_SHA1];
    for i in 0..DIGEST_LENGTH_SHA1 {
        let mut best = (0, 0); // (byte, time)
        for byte in 0..=255 {
            let mut sig = signature.clone();
            sig[i] = byte;
            let sig = hex::encode(&sig[..(i + 1)]);

            let start_time = std::time::Instant::now();
            let _ = send_request(file.clone(), sig).await;
            let end_time = std::time::Instant::now();

            let request_time = end_time.duration_since(start_time).as_millis();
            if request_time > best.1 {
                best = (byte, request_time);
            }
        }
        signature[i] = best.0;
    }
    signature
}

#[cfg(wait)]
#[tokio::test]
async fn test_artificial_timing_attack() {
    let port = 9000;
    let key = vec![0u8; thread_rng().gen_range(4..=64)]
        .iter()
        .map(|_| thread_rng().gen())
        .collect::<Vec<u8>>();

    let test_data = [
        (
            "foo",
            hex::encode(hmac_sha1(&key, "foo".as_bytes())),
            StatusCode::OK,
        ),
        (
            "asdf",
            String::from("1234"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    let rand_file = get_random_utf8();
    let expected = hmac_sha1(&key, rand_file.as_slice());

    start_server(port, Arc::new(key), insecure_compare);

    for (file, hmac, expected_status) in test_data.iter() {
        let response = send_request(port, file.to_string(), hmac.to_string()).await;
        assert_eq!(response.status(), *expected_status);
    }

    let got = artificial_timing_attack(&rand_file, |file, sig| send_request(port, file, sig)).await;
    assert_eq!(got, expected);
}

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

fn extend_secret_prefix_md4_mac<F>(
    mac: &[u8; DIGEST_LENGTH_MD4],
    message: &[u8],
    extension: &[u8],
    check: F,
) -> [u8; DIGEST_LENGTH_MD4]
where
    F: Fn(&[u8; DIGEST_LENGTH_MD4], &[u8]) -> bool,
{
    let w = md4_digest_to_state(mac);
    for key_len in 0..=64 {
        let full_input_len = key_len + message.len() as u64;
        let padding = md4_pad(full_input_len);

        let digest = md4_from_state(extension, full_input_len + padding.len() as u64, &w);

        let final_message = &[&message[..], &padding[..], extension].concat();
        if check(&digest, final_message) {
            return digest;
        }
    }
    [0; DIGEST_LENGTH_MD4]
}

#[test]
fn test_extend_secret_prefix_md4_mac() {
    let key = vec![0u8; thread_rng().gen_range(4..=64)]
        .iter()
        .map(|_| thread_rng().gen())
        .collect::<Vec<u8>>();
    let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = md4_mac_sign(message, &key);
    let extension = b";admin=true";
    let new_mac = extend_secret_prefix_md4_mac(&mac, message, extension, |mac, message| {
        md4_mac_verify(mac, message, &key)
    });
    let padding = md4_pad(key.len() as u64 + message.len() as u64);
    let final_message = &[&message[..], &padding[..], extension].concat();
    assert!(md4_mac_verify(&new_mac, final_message, &key));
}

// Challenge 29

fn extend_secret_prefix_sha1_mac<F>(
    mac: &[u8; DIGEST_LENGTH_SHA1],
    message: &[u8],
    extension: &[u8],
    check: F,
) -> [u8; DIGEST_LENGTH_SHA1]
where
    F: Fn(&[u8; DIGEST_LENGTH_SHA1], &[u8]) -> bool,
{
    for key_len in 0..=64 {
        let w = digest_to_state(mac);

        let full_input_len = key_len + message.len() as u64;
        let block_len = (full_input_len % 64) as usize;
        let padding_len = if block_len < 56 { 64 } else { 128 };

        let digest = sha1_from_state(
            extension,
            full_input_len + (padding_len - block_len) as u64,
            &w,
        );

        let padding = get_padding(&[&vec![0; key_len as usize], message].concat());
        let final_message = &[&message[..], &padding[..], extension].concat();
        if check(&digest, final_message) {
            return digest;
        }
    }
    [0; DIGEST_LENGTH_SHA1]
}

fn get_padding(message: &[u8]) -> Vec<u8> {
    let padding = sha1_pad(message.len() as u64);
    let block_len = message.len() % 64;
    padding[block_len..(if block_len < 56 { 64 } else { 128 })].to_vec()
}

#[test]
fn test_extend_secret_prefix_sha1_mac() {
    let key = vec![0u8; thread_rng().gen_range(4..=64)]
        .iter()
        .map(|_| thread_rng().gen())
        .collect::<Vec<u8>>();
    let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let mac = sha1_mac_sign(message, &key);
    let extension = b";admin=true";
    let new_mac = extend_secret_prefix_sha1_mac(&mac, message, extension, |mac, message| {
        sha1_mac_verify(mac, message, &key)
    });
    let padding = get_padding(&[&key[..], message].concat());
    let final_message = &[&message[..], &padding[..], extension].concat();
    assert!(sha1_mac_verify(&new_mac, final_message, &key));
}

// Challenge 28

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
    let expected_digest = hex::decode("d3486ae9136e7856bc42212385ea797094475802").unwrap();
    let digest = sha1(b"Hello world!");
    assert_eq!(digest, &expected_digest[..]);
}

#[test]
fn test_sha1_update() {
    let msg1 = b"Hello world!";
    let digest = sha1(msg1);

    let padding = sha1_pad(msg1.len() as u64);
    let padding = &padding[msg1.len()..(if msg1.len() < 56 { 64 } else { 128 })];
    let msg2 = b"Hello again!";

    let final_message = &[msg1, padding, msg2].concat();
    let s2 = sha1(final_message);
    assert_eq!(sha1(final_message), s2);
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

#[test]
fn test_sha1_keyed_mac() {
    let key = generate_key();
    let message = vec![0u8; thread_rng().gen_range(12..=256)]
        .iter()
        .map(|_| thread_rng().gen())
        .collect::<Vec<u8>>();
    let mut mac = sha1_mac_sign(&message, &key);
    assert!(sha1_mac_verify(&mac, &message, &key));
    mac[thread_rng().gen_range(0..20)] = thread_rng().gen();
    assert!(!sha1_mac_verify(&mac, &message, &key));
}

// Challenge 27

pub(crate) fn recoverkey_from_cbc_key_as_iv(
    ciphertext: &[u8],
    oracle: &AesCbcOracleKeyAsIv,
) -> [u8; BLOCK_SIZE] {
    let ciphertext = [
        &ciphertext[..BLOCK_SIZE],
        &[0u8; BLOCK_SIZE],
        &ciphertext[..BLOCK_SIZE],
        &ciphertext[(BLOCK_SIZE * 3)..],
    ]
    .concat();
    let plaintext = match oracle.check_admin(&ciphertext) {
        Ok(_) => panic!("Expected error"),
        Err(plaintext) => plaintext,
    };
    let key = fixed_xor(
        &plaintext[..BLOCK_SIZE],
        &plaintext[(BLOCK_SIZE * 2)..(BLOCK_SIZE * 3)],
    );
    key.try_into().unwrap()
}

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

#[test]
fn test_recover_key_from_cbc_key_as_iv() {
    let key = generate_key();
    let oracle = AesCbcOracleKeyAsIv::new(
        &key,
        b"comment1=cooking%20MCs;userdata=",
        b";comment2=%20like%20a%20pound%20of%20bacon",
    );
    let mut plaintext = [0u8; 3 * BLOCK_SIZE];
    thread_rng().fill_bytes(&mut plaintext);
    while plaintext.iter().any(|x| b";=".contains(x)) {
        thread_rng().fill_bytes(&mut plaintext);
    }
    let ciphertext = oracle.encrypt(&plaintext);
    let recovered_key = recoverkey_from_cbc_key_as_iv(&ciphertext, &oracle);
    assert_eq!(recovered_key, key);
}

// Challenge 26

pub(crate) fn ctr_bit_flipping_attack(oracle: &CtrBitFlippingOracle) -> Vec<u8> {
    let ciphertext1 = oracle.encrypt(b"A");
    let ciphertext2 = oracle.encrypt(b"B");
    let prefix_length = ciphertext1
        .iter()
        .zip(ciphertext2.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let target = b";admin=true";
    let zeroes = vec![0u8; target.len()];
    let mut ciphertext = oracle.encrypt(&zeroes);

    for (byte, target_byte) in ciphertext
        .iter_mut()
        .skip(prefix_length)
        .take(target.len())
        .zip(target.iter())
    {
        *byte ^= target_byte;
    }
    ciphertext
}
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

#[test]
fn test_ctr_bit_flipping() {
    for _ in 0..15 {
        let aes_ctr_oracle = AesCtrOracle::new();
        let oracle = BitFlippingOracle::new(
            &aes_ctr_oracle,
            b"comment1=cooking%20MCs;userdata=",
            b";comment2=%20like%20a%20pound%20of%20bacon",
        );
        let breaking_ciphertext = ctr_bit_flipping_attack(&oracle);
        let result = oracle.check_admin(&breaking_ciphertext);
        assert!(result.unwrap_or(false));
    }
}

// Challenge 25

pub(crate) fn break_random_access_read_write_aes_ctr(
    ciphertext: &[u8],
    oracle: &CtrEditOracle,
) -> Vec<u8> {
    let keystream = oracle.edit(ciphertext, 0, &vec![0; ciphertext.len()]);
    fixed_xor(ciphertext, &keystream)
}
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

#[test]
fn test_break_random_access_aes_ctr() {
    // read file
    let mut file = fs::File::open("data/25.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = b"YELLOW SUBMARINE";
    let plaintext = pkcs7_unpad(&aes_ecb_decrypt(&contents, key)).unwrap();

    let nonce = thread_rng().gen::<u64>();
    let key = generate_key();
    let ciphertext = aes_ctr_encrypt(&plaintext, &key, nonce);
    let oracle = CtrEditOracle::new(&key, nonce);

    let output = break_random_access_read_write_aes_ctr(&ciphertext, &oracle);
    assert_eq!(output, plaintext);
}
