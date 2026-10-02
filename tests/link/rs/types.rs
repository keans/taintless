pub struct Runner;
pub struct Other;

pub type R = Runner;

pub struct Svc {
    pub r: Option<Box<Runner>>,
    pub r2: R,
}
