fn f(x: Option<i32>) -> i32 {
    let add = |a: i32, b: i32| {
        if a > b { a } else { b }
    };
    let Some(v) = x else {
        return -1;
    };
    add(v, 1)
}
