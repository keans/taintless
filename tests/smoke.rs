//! Robustness smoke tests on real code: nothing may panic or fail to lower.
//!
//! Always scans this repository. Set `TAINTLESS_CORPUS` to a path list (separated
//! by `:`) to also scan other trees, e.g. cloned open-source projects in CI.
//! `TAINTLESS_CORPUS_RECOVER_CPP=1` is reserved for compiler-validated corpora:
//! analyze fully parsed C++ functions per unit and report unsupported grammar.

use ignore::WalkBuilder;
use taintless::{analysis, lang};
use taintless::lang::common::Spec;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct Report {
    files: usize,
    functions: usize,
    findings: usize,
    recovered_files: usize,
    skipped_functions: usize,
    failures: Vec<String>,
}

fn scan_tree(root: &Path, recover_cpp: bool) -> Report {
    let mut r = Report::default();
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
        match catch_unwind(AssertUnwindSafe(|| {
            match lang::build_cfgs(l, &src) {
                Err(error) if recover_cpp && l == lang::Language::Cpp => {
                    let (cfgs, skipped) = recover_cpp_functions(&src)?;
                    r.recovered_files += 1;
                    r.skipped_functions += skipped;
                    eprintln!("{}: unsupported C++ grammar: {error}; {} functions lowered, {skipped} skipped",
                        path.display(), cfgs.len());
                    Ok(cfgs)
                }
                result => result,
            }
        })) {
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

fn recover_cpp_functions(src: &str) -> anyhow::Result<(Vec<taintless::ir::Cfg>, usize)> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_cpp::LANGUAGE.into())?;
    let tree = parser.parse(src, None).ok_or_else(|| anyhow::anyhow!("parse failed"))?;
    let spec = lang::c::CLike;
    let mut cfgs = vec![];
    let mut skipped = 0;
    let source: std::sync::Arc<str> = src.into();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if spec.is_function(node) {
            if node.has_error() {
                skipped += 1;
            } else if let Some(cfg) = lang::common::lower_function(&spec, source.clone(), node)? {
                cfgs.push(cfg);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Ok((cfgs, skipped))
}

fn assert_clean(root: &Path, recover_cpp: bool) -> Report {
    let r = scan_tree(root, recover_cpp);
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
    let r = assert_clean(Path::new("."), false);
    // sources + every fixture language
    assert!(r.files >= 30 && r.functions >= 100, "{} files, {} functions", r.files, r.functions);
}

#[test]
fn scans_external_corpora() {
    let Ok(list) = std::env::var("TAINTLESS_CORPUS") else {
        eprintln!("TAINTLESS_CORPUS not set; skipping external corpora");
        return;
    };
    let recover_cpp = std::env::var("TAINTLESS_CORPUS_RECOVER_CPP").is_ok_and(|s| s == "1");
    for root in list.split(':').filter(|s| !s.is_empty()).map(PathBuf::from) {
        // Expanded C++ headers occur in many translation units. Analyze each
        // unit independently, as the compiler does, so repeated definitions
        // do not form one enormous synthetic project.
        let r = if recover_cpp {
            let mut total = Report::default();
            for entry in WalkBuilder::new(&root).build().flatten() {
                if entry.file_type().is_some_and(|t| t.is_file())
                    && lang::Language::detect(entry.path()).is_some()
                {
                    let part = assert_clean(entry.path(), true);
                    total.files += part.files;
                    total.functions += part.functions;
                    total.findings += part.findings;
                    total.recovered_files += part.recovered_files;
                    total.skipped_functions += part.skipped_functions;
                }
            }
            total
        } else {
            assert_clean(&root, false)
        };
        eprintln!("{}: {} files, {} functions, {} findings", root.display(), r.files, r.functions, r.findings);
        assert!(r.files > 0, "{} contained no supported files", root.display());
        assert!(r.functions > 0, "{} contained no fully parsed functions", root.display());
        eprintln!("{}: {} files required C++ recovery, {} function nodes skipped",
            root.display(), r.recovered_files, r.skipped_functions);
    }
}

#[test]
fn cpp_recovery_keeps_complete_functions_and_rejects_incomplete_ones() {
    let src = "namespace test { void good() { sink(input()); } void unsupported() { switch(0) case 0: default: if (ok()) ; else fail(); } }";
    assert!(lang::build_cfgs(lang::Language::Cpp, src).is_err());
    let (cfgs, skipped) = recover_cpp_functions(src).unwrap();
    assert_eq!(skipped, 1);
    assert_eq!(cfgs.len(), 1);
    assert_eq!(cfgs[0].name, "test::good");
    assert_eq!(cfgs[0].source.as_ref(), src);
    let calls: Vec<_> = cfgs[0].graph.node_weights()
        .flat_map(|b| &b.stmts).flat_map(|s| &s.calls).collect();
    assert!(calls.iter().any(|c| c.callee == "sink"));
    assert!(calls.iter().any(|c| c.callee == "input"));
}
