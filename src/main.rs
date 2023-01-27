use base64::{engine::general_purpose, Engine};
use hex;
use openssl::symm;
use std::collections::HashMap;
use std::fs;
use std::io::prelude::*;

fn main() {
    println!("Hello, world!");
    // let mut file = fs::File::open("data/7.txt").unwrap();
    // let mut base64_contents = String::new();
    // file.read_to_string(&mut base64_contents).unwrap();
    // base64_contents = base64_contents.replace("\n", "");
    // let contents_7 = general_purpose::STANDARD.decode(base64_contents).unwrap();
    // let mut file = fs::File::open("data/10.txt").unwrap();
    // let mut base64_contents = String::new();
    // file.read_to_string(&mut base64_contents).unwrap();
    // base64_contents = base64_contents.replace("\n", "");
    // let contents_10 = general_purpose::STANDARD.decode(base64_contents).unwrap();
    // println!("{:?}", &contents_7[0..16]);
    // println!("{:?}", &contents_10[0..16]);
    // let key = String::from("YELLOW SUBMARINE").into_bytes();
    // println!(
    //     "{}",
    //     String::from_utf8(decrypt_aes_ecb_mode(&key, &contents_7[0..16].to_vec()).unwrap())
    //         .unwrap()
    // );
    // println!(
    //     "{}",
    //     String::from_utf8(decrypt_aes_ecb_mode(&key, &contents_10[0..16].to_vec()).unwrap())
    //         .unwrap()
    // );

    let mut file = fs::File::open("data/6_sol.txt").unwrap();
    let mut plaintext = String::new();
    file.read_to_string(&mut plaintext).unwrap();
    println!("{}", plaintext);

    let key = String::from("YELLOW SUBMARINE").into_bytes();
    let iv = String::from("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        .into_bytes();
    let ciphertext = symm::encrypt(
        symm::Cipher::aes_128_cbc(),
        &key,
        Some(&iv),
        &plaintext.clone().into_bytes(),
    )
    .unwrap();
    let ciphertext2 = encrypt_aes_cbc_mode(&plaintext.into_bytes(), &key, &iv);
    println!("{}", ciphertext == ciphertext2);
    let ciphertext_encoded = general_purpose::STANDARD.encode(ciphertext);
    let mut out_file = fs::File::create("data/10_test.txt").unwrap();
    out_file.write_all(&ciphertext_encoded.as_bytes()).unwrap();

    // let mut file = fs::File::open("data/7.txt").unwrap();
    // let mut base64_contents = String::new();
    // file.read_to_string(&mut base64_contents).unwrap();
    // base64_contents = base64_contents.replace("\n", "");
    // let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    // let key = String::from("YELLOW SUBMARINE").into_bytes();
    // let output = decrypt_aes_ecb_mode(&key, &contents).unwrap();
    // println!("{}", String::from_utf8(output).unwrap());
}

// Challenge 10
fn encrypt_aes_cbc_mode(input: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let cipher = symm::Cipher::aes_128_ecb();
    let block_len = cipher.block_size();
    println!("encrypt block size: {}", block_len);
    let padded_input = pkcs7_pad(input, block_len * div_ceil(input.len(), block_len));
    let mut output = vec![];
    for i in 0..(padded_input.len() / block_len) {
        let block = padded_input[(i * block_len)..((i + 1) * block_len)].to_vec();
        let xor_block = if i == 0 {
            iv.to_vec()
        } else {
            output[((i - 1) * block_len)..(i * block_len)].to_vec()
        };
        // xor
        let xor = fixed_xor(&block, &xor_block);
        // encrypt
        let ciphertext = symm::encrypt(symm::Cipher::aes_128_ecb(), key, None, &xor).unwrap();
        output.extend(ciphertext.into_iter());
    }

    output
}

fn decrypt_aes_cbc_mode(input: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let cipher = symm::Cipher::aes_128_ecb();
    let block_len = 32; // cipher.block_size();
    println!("decrypt block size: {}", block_len);
    // assert_eq!(key.len(), block_len);
    assert!(input.len() % block_len == 0);
    let mut output = vec![];
    for block_idx in 0..div_ceil(input.len(), block_len) {
        let start = block_idx * block_len;
        let end = (block_idx + 1) * block_len;
        let block: [u8; 32] = input[start..end].try_into().unwrap();
        // decrypt
        println!("{:?}", &block);
        let dec = symm::decrypt(symm::Cipher::aes_128_ecb(), key, None, &block).unwrap();
        println!("{}", dec.len());
        // xor
        let xor_block = if block_idx == 0 {
            iv.to_vec()
        } else {
            input[((block_idx - 1) * 16)..((block_idx) * 16)].to_vec()
        };
        let dec_xor = fixed_xor(&dec, &xor_block);
        output.extend(dec_xor.into_iter());
    }
    output
}

#[test]
fn test_sanity_openssl() {
    let plaintext = String::from("asdfasdfasdfasdf").into_bytes();
    let key = String::from("YELLOW SUBMARINE").into_bytes();
    let iv = String::from("0000000000000000").into_bytes();
    assert_eq!(
        symm::decrypt(
            symm::Cipher::aes_128_ecb(),
            &key,
            None,
            &symm::encrypt(symm::Cipher::aes_128_ecb(), &key, None, &plaintext).unwrap()
        )
        .unwrap(),
        plaintext
    );
}

#[test]
fn test_encrypt_aes_cbc_mode() {
    let plaintext = String::from("asdfasdfasdfasdf asdfasdfasdfasd dkdkdkdkdkdkdkd").into_bytes();
    let key = String::from("YELLOW SUBMARINE").into_bytes();
    let iv = String::from("0000000000000000").into_bytes();
    let encrypted = encrypt_aes_cbc_mode(&plaintext, &key, &iv);
    println!("{}", encrypted.len());
    println!("{:?}", encrypted);
    assert_eq!(decrypt_aes_cbc_mode(&encrypted, &key, &iv), plaintext);
    assert_eq!(encrypted, String::from("adf").into_bytes());
}

#[test]
fn test_decrypt_aes_cbc_mode() {
    let mut file = fs::File::open("data/10.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    // println!("{:?}", contents);
    let key = String::from("YELLOW SUBMARINE").into_bytes();
    let iv = String::from("0000000000000000").into_bytes();

    let expected_output = String::from("asdf").into_bytes();
    let output = decrypt_aes_cbc_mode(&contents, &key, &iv);
    assert_eq!(output, expected_output);
}

// Challenge 9

fn pkcs7_pad(input: &Vec<u8>, length: usize) -> Vec<u8> {
    let pad_len = length - input.len();
    let pad_len: u8 = pad_len.try_into().unwrap();
    let mut output = input.clone();
    output.extend(vec![pad_len; pad_len as usize].into_iter());
    output
}

#[test]
fn test_pkcs7_pad() {
    let input = "YELLOW_SUBMARINE".as_bytes().to_vec();
    let length = 20;
    let expected_output = "YELLOW_SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec();
    let output = pkcs7_pad(&input, length);
    assert_eq!(output, expected_output);
}

// Challenge 8

fn detect_aes_ecb(lines: &Vec<Vec<u8>>) -> Option<Vec<u8>> {
    for (i, line) in lines.iter().enumerate() {
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
        if values[0] > 0 {
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
    let expected_output = lines[0].to_owned();
    let output = detect_aes_ecb(&lines).unwrap();
    assert_eq!(expected_output, output);
}

// Challenge 7

fn decrypt_aes_ecb_mode(
    key: &Vec<u8>,
    input: &Vec<u8>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    symm::decrypt(symm::Cipher::aes_128_ecb(), key, None, input)
}

#[test]
fn test_decrypt_aes_ecb_mode() {
    let mut file = fs::File::open("data/7.txt").unwrap();
    let mut base64_contents = String::new();
    file.read_to_string(&mut base64_contents).unwrap();
    base64_contents = base64_contents.replace("\n", "");
    let contents = general_purpose::STANDARD.decode(base64_contents).unwrap();
    let key = String::from("YELLOW SUBMARINE").into_bytes();

    let mut file = fs::File::open("data/6_sol.txt").unwrap();
    let mut expected_output = String::new();
    file.read_to_string(&mut expected_output).unwrap();
    let expected_output = expected_output.into_bytes();

    let output = decrypt_aes_ecb_mode(&key, &contents).unwrap();
    assert_eq!(output, expected_output);
}

// Challenge 6

fn get_best_key_size(input: &Vec<u8>) -> usize {
    get_key_sizes(input)[0]
}

fn get_key_sizes(input: &Vec<u8>) -> Vec<usize> {
    let candidate_key_sizes = 2..40;
    let mut key_size_scores = Vec::new();
    for key_size in candidate_key_sizes {
        let score = get_key_size_score(input, key_size);
        key_size_scores.push((score, key_size));
    }
    key_size_scores.sort();
    key_size_scores.iter().map(|&(_score, key)| key).collect()
}

fn get_key_size_score(input: &Vec<u8>, key_size: usize) -> u32 {
    let n_blocks = 4;
    assert!(input.len() > key_size * n_blocks);

    let mut blocks = Vec::new();
    for i in 0..n_blocks {
        blocks.push(&input[(i * key_size)..((i + 1) * key_size)]);
    }

    let mut score = 0;
    for i in 0..(n_blocks - 1) {
        let block_i = blocks[i];
        for j in (i + 1)..n_blocks {
            let block_j = blocks[j];
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

    // Transpose blocks
    let transposed = transpose_blocks(&blocks);

    // Single byte xor decrypt blocks
    let mut key = vec![];
    for block in transposed.into_iter() {
        let (_score, single_byte_key, _plaintext) = decrypt_single_byte_xor(block);
        key.push(single_byte_key);
    }

    // Decrypt
    repeating_key_xor(key, input.clone())
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

fn transpose_blocks(blocks: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    assert!(blocks.len() > 0);
    let key_size = blocks[0].len();
    let mut transposed = vec![];
    for col in 0..key_size {
        let mut block = vec![];
        for row in 0..blocks.len() {
            if blocks[row].len() <= col {
                break;
            }
            block.push(blocks[row][col]);
        }
        transposed.push(block);
    }
    transposed
}

#[test]
fn test_transpose_blocks() {
    let blocks = vec![vec![1, 2, 3], vec![4, 5]];
    assert_eq!(
        transpose_blocks(&blocks),
        vec![vec![1, 4], vec![2, 5], vec![3]]
    );
}

fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

fn get_blocks(input: &Vec<u8>, key_size: usize) -> Vec<Vec<u8>> {
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

fn normalize_distance(distance: u32, key_size: usize) -> u32 {
    distance * 10000 / (8 * key_size as u32)
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

fn repeating_key_xor(key: Vec<u8>, input: Vec<u8>) -> Vec<u8> {
    assert!(key.len() > 0);
    assert!(input.len() > 0);
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

    let output = repeating_key_xor(key, input);
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

fn decrypt_single_byte_xor(ciphertext: Vec<u8>) -> (u32, u8, Vec<u8>) {
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

fn get_candidates(ciphertext: Vec<u8>, n: usize) -> Vec<(u32, String)> {
    let mut results = Vec::new();
    for i in 0..=255 {
        let key = vec![i; ciphertext.len()];
        let plaintext = fixed_xor(ciphertext.as_slice(), key.as_slice());
        let score = calculate_score(&plaintext);
        if let Ok(s) = String::from_utf8(plaintext) {
            results.push((score, s));
        }
    }
    results.sort();
    results.reverse();
    if results.len() >= n {
        results[0..n].to_vec()
    } else {
        results
    }
}

fn calculate_score(plaintext: &Vec<u8>) -> u32 {
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

fn fixed_xor(input1: &[u8], input2: &[u8]) -> Vec<u8> {
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

#[test]
fn test_hex_to_base64() {
    let input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_output = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let output = hex_to_base64(input);
    assert_eq!(expected_output, output.as_slice());
}

fn hex_to_base64_string(input: String) -> String {
    let normal = hex::decode(input).unwrap();
    general_purpose::STANDARD_NO_PAD.encode(normal)
}

#[test]
fn test_hex_to_base64_string() {
    let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let expected_output =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let output = hex_to_base64_string(input);
    assert_eq!(expected_output, output);
}
