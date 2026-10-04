use sha2::{Sha256, Digest};
use md5 as m;
use sha1::Sha1;
fn f(b: &[u8]) { Sha256::digest(b); m::compute(b); Sha1::new(); }
