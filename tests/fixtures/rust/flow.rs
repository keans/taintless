use std::fs;

fn read(path: &str) -> Result<usize, std::io::Error> {
    let text = fs::read_to_string(path)?;
    let n = if text.is_empty() { 0 } else { text.len() };
    Ok(n)
}

fn run(xs: &[i32], flag: bool) -> i32 {
    let mut total = 0;
    'outer: for x in xs {
        while total < 100 {
            if *x < 0 {
                continue 'outer;
            }
            total += x;
            if total > 50 {
                break 'outer;
            }
        }
    }
    let k = loop {
        total += 1;
        if total > 5 {
            break total;
        }
    };
    match k {
        0 => return 0,
        1 | 2 => total += 1,
        _ => {
            if flag {
                panic!("boom");
            }
        }
    }
    total
}

struct S;
impl S {
    fn method(&self, a: i32) -> i32 {
        if a > 0 { a } else { -a }
    }
}
