fn main() {
    println!("Hello, world!");
}

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
