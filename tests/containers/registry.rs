fn alpha() {}
fn beta() {}

fn dispatch(i: usize) {
    let mut hs: Vec<fn()> = Vec::new();
    hs.push(alpha);
    hs.push(beta);
    for h in hs.iter() {
        h();
    }
    hs[i]();
}
