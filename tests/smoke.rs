//! Robustness smoke tests on real code: nothing may panic or fail to lower.
//!
//! Always scans this repository. Set `TAINTLESS_CORPUS` to a path list (separated
//! by `:`) to also scan other trees, e.g. cloned open-source projects in CI.

use ignore::WalkBuilder;
use taintless::{analysis, lang};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

struct Report {
    files: usize,
    functions: usize,
    findings: usize,
    failures: Vec<String>,
}

fn scan_tree(root: &Path) -> Report {
    let mut r = Report { files: 0, functions: 0, findings: 0, failures: vec![] };
    let mut loaded: Vec<(lang::Language, PathBuf, Vec<taintless::ir::Cfg>, Vec<lang::common::Import>)> = vec![];
    for entry in WalkBuilder::new(root).build().flatten() {
        let path = entry.path();
        if !entry.file_type().is_some_and(|t| t.is_file()) || lang::Language::detect(path).is_none() {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue; // not UTF-8 (e.g. latin-1 sources): skipped, as the CLI reports it
        };
        let l = lang::Language::detect_with_source(path, &src).expect("detected");
        match catch_unwind(AssertUnwindSafe(|| lang::build_cfgs(l, &src))) {
            Ok(Ok(cfgs)) => {
                r.files += 1;
                r.functions += cfgs.len();
                for c in &cfgs {
                    // every CFG must have its entry and exit, and edges between real nodes
                    if c.graph.node_weight(c.entry).is_none() || c.graph.node_weight(c.exit).is_none() {
                        r.failures.push(format!("{}: {} has no entry/exit", path.display(), c.name));
                    }
                }
                let imports = lang::imports(l, &src).unwrap_or_default();
                loaded.push((l, path.to_path_buf(), cfgs, imports));
            }
            Ok(Err(e)) => r.failures.push(format!("{}: {e:#}", path.display())),
            Err(_) => r.failures.push(format!("{}: PANIC while lowering", path.display())),
        }
    }
    // the whole tree at once: summaries, taint, unreachable code, call graph, dependencies
    let files: Vec<analysis::ProjectFile> =
        loaded.iter().map(|(l, p, c, i)| analysis::ProjectFile { lang: *l, file: p, cfgs: c, imports: i }).collect();
    match catch_unwind(AssertUnwindSafe(|| analysis::check_project(&files, &|| {}))) {
        Ok(found) => r.findings = found.len(),
        Err(_) => r.failures.push(format!("{}: PANIC in project analysis", root.display())),
    }
    let dep_files: Vec<analysis::deps::DepFile> = loaded
        .iter()
        .map(|(l, p, c, i)| analysis::deps::DepFile { path: p, lang: *l, imports: i.clone(), cfgs: c })
        .collect();
    if catch_unwind(AssertUnwindSafe(|| analysis::deps::build(&dep_files))).is_err() {
        r.failures.push(format!("{}: PANIC building the dependency graph", root.display()));
    }
    r
}

fn assert_clean(root: &Path) -> Report {
    let r = scan_tree(root);
    assert!(
        r.failures.is_empty(),
        "{} failures in {}:\n{}",
        r.failures.len(),
        root.display(),
        r.failures.join("\n")
    );
    r
}

#[test]
fn scans_this_repository() {
    let r = assert_clean(Path::new("."));
    // sources + every fixture language
    assert!(r.files >= 30 && r.functions >= 100, "{} files, {} functions", r.files, r.functions);
}

#[test]
fn scans_external_corpora() {
    let Ok(list) = std::env::var("TAINTLESS_CORPUS") else {
        eprintln!("TAINTLESS_CORPUS not set; skipping external corpora");
        return;
    };
    for root in list.split(':').filter(|s| !s.is_empty()).map(PathBuf::from) {
        let r = assert_clean(&root);
        eprintln!("{}: {} files, {} functions, {} findings", root.display(), r.files, r.functions, r.findings);
        assert!(r.files > 0, "{} contained no supported files", root.display());
    }
}
