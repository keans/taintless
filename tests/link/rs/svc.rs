impl Svc {
    pub fn via_field(&self) {
        self.r.run();
    }

    pub fn via_alias(&self) {
        self.r2.run();
    }
}

pub fn via_alias_param(a: R) {
    a.run();
}
