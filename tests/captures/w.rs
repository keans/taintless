use std::process::Command;

fn run() {
    let mut cmd = String::new();
    let mut load = || { cmd = std::env::args().nth(1).unwrap(); };
    load();
    Command::new(cmd).status().unwrap();
}

fn shadow() {
    let cmd = String::new();
    let load = || { let cmd = std::env::args().nth(1).unwrap(); cmd };
    load();
    Command::new(cmd).status().unwrap();
}
