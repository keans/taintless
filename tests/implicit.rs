//! Implicit flows (`implicit_flows = true`): a branch on untrusted data taints what it controls.

mod common;
use common::taintless;
use std::path::Path;
use taintless::cpg::graph::{Cpg, SourceFile};
use taintless::cpg::taint::taint_flows_with;
use taintless::lang::{Language, build_cfgs};

fn security(args: &[&str]) -> String {
    let mut a = vec!["security", "tests/implicit/app.py", "--format", "text"];
    a.extend_from_slice(args);
    String::from_utf8(taintless(&a).stdout).unwrap()
}

/// Functions with a command-injection finding in the text report.
fn flagged(report: &str) -> Vec<String> {
    let mut v: Vec<String> = report.lines().filter_map(|l| l.split("(in `").nth(1)?.split('`').next().map(str::to_string)).collect();
    v.sort();
    v
}

#[test]
fn off_by_default() {
    assert!(flagged(&security(&[])).is_empty());
}

#[test]
fn a_branch_on_untrusted_data_taints_what_it_assigns() {
    let t = security(&["--config", "tests/implicit/on.toml"]);
    // a plain branch, a nested one, a loop condition, and a parameter that only decides a branch in the callee
    assert_eq!(flagged(&t), ["caller", "leak", "loop", "nested"], "{t}");
    // a condition that holds no untrusted data decides nothing
    assert!(!t.contains("`clean`"), "{t}");
}

#[test]
fn the_cpg_taint_follows_the_same_flows() {
    let src = std::fs::read_to_string("tests/implicit/app.py").unwrap();
    let cfgs = build_cfgs(Language::Python, &src).unwrap();
    let files = [SourceFile { path: Path::new("app.py"), lang: Language::Python, src: &src, cfgs: &cfgs, imports: &[] }];
    let cpg = Cpg::build(&files).unwrap();
    let lines = |implicit| taint_flows_with(&cpg, implicit).into_iter().map(|f| f.line).collect::<Vec<_>>();
    assert!(lines(false).is_empty());
    // `os.system(cmd)` in leak, nested, caller and loop; not in clean
    assert_eq!(lines(true), [9, 18, 29, 38]);
}
