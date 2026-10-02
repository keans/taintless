fn run(c: &str) {
    Command::new(c).status();
}

fn main() {
    let a = std::env::args().nth(1).unwrap();
    run(&a);
    run("ls");
}
