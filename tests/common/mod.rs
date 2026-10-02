use std::process::{Command, Output};

/// Run the `taintless` binary with `args`.
pub fn taintless(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_taintless")).args(args).output().unwrap()
}
