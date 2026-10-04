use openssl::symm::Cipher;
use openssl::hash::MessageDigest;
use aes_gcm::{Aes256Gcm, Nonce};
fn f() {
    Cipher::aes_128_ecb();
    Cipher::aes_256_gcm();
    MessageDigest::md5();
    MessageDigest::sha256();
    let n = Nonce::from_slice(b"unique nonce");
}
