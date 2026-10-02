struct A;
struct B;

impl A {
    fn new() -> A { A }
    fn run(&self) {}
}

impl B {
    fn new() -> B { B }
    fn run(&self) {}
}

fn outer_resumes() {
    let x = A::new();
    {
        let x = B::new();
        x.run();
    }
    x.run();
}
