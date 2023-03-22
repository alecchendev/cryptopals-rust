
use sha1_smol::{Sha1, DIGEST_LENGTH};

pub(crate) fn sha1(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    Sha1::from(data).digest().bytes()
}

pub(crate) fn sha1_mac_sign(message: &[u8], key: &[u8]) -> [u8; DIGEST_LENGTH] {
    sha1(&[key, message].concat())
}

pub(crate) fn sha1_mac_verify(mac: &[u8; DIGEST_LENGTH], message: &[u8], key: &[u8]) -> bool {
    mac == &sha1(&[key, message].concat())
}
