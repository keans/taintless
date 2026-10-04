use metrohash::MetroHash64;
use t1ha::t1ha2_atonce;

fn f(p: &[u8]) {
    let mut h = MetroHash64::new();
    t1ha2_atonce(p, 0);
}
