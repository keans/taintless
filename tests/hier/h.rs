trait Speak {
    fn speak(&self);
    fn twice(&self) {
        self.speak();
    }
}

struct Dog;

impl Speak for Dog {
    fn speak(&self) {}
}

fn talk(s: &dyn Speak) {
    s.speak();
}
