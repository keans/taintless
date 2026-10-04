use openssl::{symm::{Cipher as C}, hash::{MessageDigest as MD, self}};
fn f() {
    C::aes_128_ecb();
    MD::md5();
    MD::sha256();
}
