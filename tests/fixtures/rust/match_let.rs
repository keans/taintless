fn r(v: Vec<Option<i32>>, a: bool, b: bool) -> i32 {
    let mut it = v.into_iter();
    while let Some(x) = it.next() {
        if let Some(y) = x { return y; } else if a && !b { break; }
    }
    match a {
        true if b => 1,
        true => 2,
        false => 3,
    }
}
