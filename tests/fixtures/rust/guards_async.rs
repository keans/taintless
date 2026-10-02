fn g(x: i32, ok: bool) -> i32 {
    match x {
        n if n > 0 && ok => 1,
        0 | 1 => 2,
        _ => 3,
    }
}

async fn h() -> Result<i32, E> {
    let f = async {
        step()?;
        Ok(1)
    };
    let v = if cond()? { 1 } else { 2 };
    match next()? {
        Some(k) => k,
        None => 0,
    };
    Ok(v)
}
