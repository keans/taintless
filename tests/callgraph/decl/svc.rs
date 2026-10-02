struct Runner;
impl Runner {
    fn run(&self) {}
}

struct Other;
impl Other {
    fn run(&self) {}
}

struct Svc {
    r: Option<Box<Runner>>,
}

impl Svc {
    fn go_(&self) {
        self.r.run();
    }

    fn local(&self) {
        let x: Runner = make();
        x.run();
    }
}
