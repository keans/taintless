mod common;
use common::taintless;
use std::path::Path;
use taintless::lang::{self, Language};

#[test]
fn missing_paths_fail_every_command() {
    let missing = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("missing-{}", std::process::id()));
    for cmd in ["security", "cfg", "calls", "deps", "flow", "cpg"] {
        let out = taintless(&[cmd, missing.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(if cmd == "security" { 2 } else { 1 }), "{cmd}");
        assert!(!out.stderr.is_empty());
    }
}

#[test]
fn incomplete_scans_preserve_existing_baselines_and_report_valid_files() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("scan-errors-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("good.py"), "import os\nos.system(input())\n").unwrap();
    let baseline = dir.join("baseline.json");
    for bad in [b"\xff".as_slice(), b"def f(:\n    pass\n"] {
        std::fs::write(dir.join("bad.py"), bad).unwrap();
        std::fs::write(&baseline, "existing baseline").unwrap();
        let out = taintless(&["security", dir.to_str().unwrap(), "--format", "json"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stdout).contains("command-injection"));
        let out = taintless(&["security", dir.to_str().unwrap(), "--write-baseline", baseline.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(std::fs::read_to_string(&baseline).unwrap(), "existing baseline");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn parse_apis_reject_errors_and_missing_tokens() {
    for (lang, src) in [(Language::Python, "def f(:\n    pass\n"), (Language::C, "void f() { int x = 1 }"), (Language::C, "int f(int x) { switch(x) { case 1 ... : return 1; } }")] {
        assert!(lang::build_cfgs(lang, src).is_err());
        assert!(lang::build_ast(lang, 0, src).is_err());
        assert!(lang::imports(lang, src).is_err());
    }
}
