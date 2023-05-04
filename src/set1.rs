use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use base64::{engine::general_purpose, Engine};
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;
use std::fs;
use std::io::Read;

// Challenge 8

fn detect_aes_ecb(lines: &[Vec<u8>]) -> Option<Vec<u8>> {
    for line in lines.iter() {
        let mut block_frequency: HashMap<[u8; 16], u32> = HashMap::new();
        for i in 0..(line.len() / 16) {
            let block: [u8; 16] = line[(i * 16)..((i + 1) * 16)].try_into().unwrap();
            block_frequency
                .entry(block)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
        let mut values: Vec<u32> = block_frequency.into_values().collect();
        values.sort();
        values.reverse();
        if values[0] > 1 {
            return Some(line.to_owned());
        }
    }
    None
}

#[test]
fn test_detect_aes_ecb() {
    let mut file = fs::File::open("data/8.txt").unwrap();
    let mut hex_contents = String::new();
    file.read_to_string(&mut hex_contents).unwrap();
    let lines: Vec<Vec<u8>> = hex_contents
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect();
    let expected_output = lines[132].to_owned();
    let output = detect_aes_ecb(&lines).unwrap();
    assert_eq!(expected_output, output);
}

// Challenge 7

pub fn generate_key() -> [u8; 16] {
    let mut key = [0; 16];
    thread_rng().fill_bytes(&mut key);
    key
}

pub fn aes_ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(input.len() % 16 == 0);
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut ciphertext = vec![];
    for chunk in input.chunks(16) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }
    ciphertext
}

pub fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let padding_length = block_size - (input.len() % block_size);
    [input, &vec![padding_length as u8; padding_length]].concat()
}

#[test]
fn test_aes_ecb_encrypt() {
    let mut rng = thread_rng();
    let plaintext: Vec<u8> = (0..rng.gen_range(16..256)).map(|_| rng.gen()).collect();
    let plaintext = pkcs7_pad(plaintext.as_slice(), 16);
    let key = generate_key();
    let ciphertext = aes_ecb_encrypt(&plaintext, &key);
    let decrypted_ciphertext = aes_ecb_decrypt(&ciphertext, &key.to_vec());
    assert_eq!(plaintext, decrypted_ciphertext);
}

pub fn aes_ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    let mut plaintext = vec![];
    let block_len = 16;
    for chunk in input.chunks(block_len) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }
    plaintext
}

#[test]
fn test_aes_ecb_decrypt() {
    let mut file = fs::File::open("data/7.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = String::from("YELLOW SUBMARINE").into_bytes();

    let mut file = fs::File::open("data/7_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();

    let output = aes_ecb_decrypt(&contents, &key);
    assert_eq!(output.as_slice(), expected_output.into_bytes());
}

// Challenge 6

fn get_best_key_size(input: &[u8]) -> usize {
    get_key_sizes(input)[0]
}

fn get_key_sizes(input: &[u8]) -> Vec<usize> {
    let candidate_key_sizes = 2..40;
    let mut key_size_scores = Vec::new();
    for key_size in candidate_key_sizes {
        let score = get_key_size_score(input, key_size);
        key_size_scores.push((score, key_size));
    }
    key_size_scores.sort();
    key_size_scores.iter().map(|&(_score, key)| key).collect()
}

fn normalize_distance(distance: u32, key_size: usize) -> u32 {
    distance * 10000 / (8 * key_size as u32)
}

fn get_key_size_score(input: &[u8], key_size: usize) -> u32 {
    let n_blocks = 4;
    assert!(input.len() > key_size * n_blocks);

    let mut blocks = Vec::new();
    for i in 0..n_blocks {
        blocks.push(&input[(i * key_size)..((i + 1) * key_size)]);
    }

    let mut score = 0;
    for i in 0..(n_blocks - 1) {
        let block_i = blocks[i];
        for block_j in blocks.iter().take(n_blocks).skip(i + 1) {
            let distance = hamming_distance(block_i.to_vec(), block_j.to_vec());
            score += normalize_distance(distance, key_size);
        }
    }

    score
}

fn decrypt_repeating_key_xor(input: Vec<u8>) -> Vec<u8> {
    // Get key_size
    let key_size = get_best_key_size(&input);

    // Break into key_size blocks
    let blocks = get_blocks(&input, key_size);
    let blocks: Vec<&[u8]> = blocks.iter().map(|v| v.as_slice()).collect();

    // Transpose blocks
    let transposed = transpose_blocks(&blocks);

    // Single byte xor decrypt blocks
    let mut key = vec![];
    for block in transposed.into_iter() {
        let (_score, single_byte_key, _plaintext) = decrypt_single_byte_xor(block);
        key.push(single_byte_key);
    }

    // Decrypt
    repeating_key_xor(&key, &input)
}

#[test]
fn test_decrypt_repeating_key_xor() {
    let mut file = fs::File::open("data/6.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();

    let mut file = fs::File::open("data/6_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();

    let output = decrypt_repeating_key_xor(contents);
    assert_eq!(output, expected_output.into_bytes());
}

pub fn transpose_blocks(blocks: &[&[u8]]) -> Vec<Vec<u8>> {
    assert!(!blocks.is_empty());
    let key_size = blocks[0].len();
    let mut transposed = vec![];
    for col in 0..key_size {
        let mut block = vec![];
        for blocks_row in blocks {
            if blocks_row.len() <= col {
                break;
            }
            block.push(blocks_row[col]);
        }
        transposed.push(block);
    }
    transposed
}

#[test]
fn test_transpose_blocks() {
    let blocks = vec![vec![1, 2, 3], vec![4, 5]];
    let blocks: Vec<&[u8]> = blocks.iter().map(|v| v.as_slice()).collect();
    assert_eq!(
        transpose_blocks(&blocks),
        vec![vec![1, 4], vec![2, 5], vec![3]]
    );
}

fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

fn get_blocks(input: &[u8], key_size: usize) -> Vec<Vec<u8>> {
    let mut blocks = vec![];
    let n_blocks = div_ceil(input.len(), key_size);
    for block_idx in 0..n_blocks {
        let start = block_idx * key_size;
        let end = std::cmp::min(start + key_size, input.len());
        blocks.push(input[start..end].to_vec());
    }
    blocks
}

#[test]
fn test_get_blocks() {
    let input = vec![1, 2, 3, 4, 5];
    assert_eq!(get_blocks(&input, 3), vec![vec![1, 2, 3], vec![4, 5]]);
    assert_eq!(get_blocks(&input, 5), vec![vec![1, 2, 3, 4, 5]]);
}

fn hamming_distance(input1: Vec<u8>, input2: Vec<u8>) -> u32 {
    assert!(input1.len() == input2.len());
    let mut distance = 0;
    for i in 0..input1.len() {
        let byte1 = input1[i];
        let byte2 = input2[i];
        let diff_bits = byte1 ^ byte2;
        for bit in 0..8 {
            distance += (diff_bits & (1 << bit) != 0) as u32;
        }
    }
    distance
}

#[test]
fn test_hamming_distance() {
    let input1 = String::from("this is a test").into_bytes();
    let input2 = String::from("wokka wokka!!!").into_bytes();
    let expected_output = 37;

    let output = hamming_distance(input1, input2);
    assert_eq!(output, expected_output);
}

// Challenge 5

pub fn repeating_key_xor(key: &[u8], input: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty());
    assert!(!input.is_empty());
    let mut output = Vec::new();
    let mut key_idx = 0;
    for byte in input.iter() {
        output.push(byte ^ key[key_idx]);
        key_idx = (key_idx + 1) % key.len();
    }
    output
}

#[test]
fn test_repeating_key_xor() {
    let key = String::from("ICE").into_bytes();
    let input = String::from(
        "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal",
    )
    .into_bytes();
    let expected_output = hex::decode(String::from(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
    ))
    .unwrap();

    let output = repeating_key_xor(&key, &input);
    assert_eq!(output, expected_output);
}

// Challenge 4

fn decrypt_single_byte_xor_many(lines: Vec<String>) -> (u32, u8, Vec<u8>) {
    let mut max_score = 0;
    let mut max_score_values = (0, vec![]);
    for line in lines {
        let (score, key, plaintext) = decrypt_single_byte_xor(hex::decode(line).unwrap());
        if score > max_score {
            max_score = score;
            max_score_values = (key, plaintext);
        }
    }
    (max_score, max_score_values.0, max_score_values.1)
}

#[test]
fn test_detect_single_byte_xor() {
    let mut file = fs::File::open("data/4.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mut lines = Vec::new();
    for line in contents.lines() {
        lines.push(line.to_owned());
    }

    let expected_output = String::from("Now that the party is jumping\n");
    let (_, _, plaintext) = decrypt_single_byte_xor_many(lines);
    assert_eq!(plaintext, expected_output.into_bytes());
}

// Challenge 3

pub fn decrypt_single_byte_xor(ciphertext: Vec<u8>) -> (u32, u8, Vec<u8>) {
    let mut max_score = 0;
    let mut max_score_values = (0, vec![]);
    for i in 0..=255 {
        let key = vec![i; ciphertext.len()];
        let plaintext = fixed_xor(ciphertext.as_slice(), key.as_slice());
        let score = calculate_score(&plaintext);
        if score > max_score {
            max_score = score;
            max_score_values = (i, plaintext);
        }
    }

    (max_score, max_score_values.0, max_score_values.1)
}

fn calculate_score(plaintext: &[u8]) -> u32 {
    // https://en.wikipedia.org/wiki/Letter_frequency
    let letter_frequency_percent: HashMap<char, u32> = HashMap::from([
        ('a', 823),
        ('b', 150),
        ('c', 280),
        ('d', 429),
        ('e', 1280),
        ('f', 224),
        ('g', 203),
        ('h', 614),
        ('i', 614),
        ('j', 15),
        ('k', 77),
        ('l', 406),
        ('m', 242),
        ('n', 680),
        ('o', 757),
        ('p', 194),
        ('q', 9),
        ('r', 603),
        ('s', 638),
        ('t', 913),
        ('u', 278),
        ('v', 98),
        ('w', 238),
        ('x', 15),
        ('y', 199),
        ('z', 7),
        (' ', 1500),
    ]);

    plaintext.iter().fold(0, |acc, byte| {
        let c = (*byte as char).to_ascii_lowercase();
        acc + letter_frequency_percent.get(&c).unwrap_or(&0)
    })
}

#[test]
fn test_decrypt_single_bytes_xor() {
    let input =
        String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let expected_output = String::from("Cooking MC's like a pound of bacon");

    let (_, _, plaintext) = decrypt_single_byte_xor(hex::decode(input).unwrap());
    assert_eq!(plaintext, expected_output.into_bytes());
}

// Challenge 2

pub fn fixed_xor(input1: &[u8], input2: &[u8]) -> Vec<u8> {
    assert_eq!(input1.len(), input2.len());
    let n = input1.len();
    let mut result = Vec::new();
    for i in 0..n {
        result.push(input1[i] ^ input2[i]);
    }
    result
}

#[test]
fn test_fixed_xor() {
    let input1 = String::from("1c0111001f010100061a024b53535009181c");
    let input2 = String::from("686974207468652062756c6c277320657965");
    let expected_output = String::from("746865206b696420646f6e277420706c6179");

    let output = fixed_xor(
        hex::decode(input1).unwrap().as_slice(),
        hex::decode(input2).unwrap().as_slice(),
    );
    assert_eq!(
        hex::decode(expected_output).unwrap().as_slice(),
        output.as_slice()
    );
}

// Challenge 1

fn hex_to_base64(input: &[u8]) -> Vec<u8> {
    let normal = hex::decode(input).unwrap();
    general_purpose::STANDARD_NO_PAD.encode(normal).into_bytes()
}

fn hex_to_base64_string(input: String) -> String {
    let normal = hex::decode(input).unwrap();
    general_purpose::STANDARD_NO_PAD.encode(normal)
}

#[test]
fn test_hex_to_base64() {
    let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_output = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let output = hex_to_base64(input);
    assert_eq!(expected_output, output.as_slice());
}

#[test]
fn test_hex_to_base64_string() {
    let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let expected_output =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let output = hex_to_base64_string(input);
    assert_eq!(expected_output, output);
}
