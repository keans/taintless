struct S {
    c: String,
    n: String,
}

impl S {
    fn load(&mut self) {
        self.c = std::env::args().nth(1).unwrap();
    }

    fn run(&self) {
        Command::new(&self.c).status();
        Command::new(&self.n).status();
    }
}
