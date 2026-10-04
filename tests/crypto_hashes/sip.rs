use siphasher::sip::SipHasher24;
use argon2::{Argon2, Params};
fn f() {
    SipHasher24::new_with_key(&[0u8; 16]);
    Params::new(4096, 3, 1, None);
    Params::new(65536, 3, 1, None);
}
