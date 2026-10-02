fn run(conn: &Conn) {
    let arg = std::env::args().nth(1).unwrap();
    std::process::Command::new("sh").arg("-c").arg(&arg).status();
    let n: i32 = arg.parse().unwrap();
    let q = format!("SELECT {}", arg);
    conn.execute(&q, []);
    let ok = format!("SELECT {}", n);
    conn.execute(&ok, []);
}
