use std::process::{Command, Output};

/// Run the `taintless` binary with `args`.
pub fn taintless(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_taintless"));
    // Tests already run concurrently, and their fixtures are small. Avoid
    // starting a machine-sized Rayon pool for every child process.
    if std::env::var_os("RAYON_NUM_THREADS").is_none() {
        command.env("RAYON_NUM_THREADS", "2");
    }
    command.args(args).output().unwrap()
}
