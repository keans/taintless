//! Smoke test of the CPG on external code. Ignored by default; point `SCAN_CORPUS` at a
//! directory whose subdirectories are projects (a cargo registry `src`, `site-packages`, ...):
//!
//!     SCAN_CORPUS=~/.cargo/registry/src/*/ cargo test --release --test cpg_corpus -- --ignored --nocapture
//!
//! Each project must build without a panic, build the same graph twice, and keep the shape of a CPG
//! (a tree of AST edges, one method node per function). Counts are printed. To catch changes in what
//! the graph contains, pin them in a baseline file kept outside the repository:
//!
//!     SCAN_CORPUS_BASELINE=/tmp/corpus.txt SCAN_CORPUS_UPDATE=1 SCAN_CORPUS=... cargo test --test cpg_corpus -- --ignored
//!     SCAN_CORPUS_BASELINE=/tmp/corpus.txt SCAN_CORPUS=... cargo test --test cpg_corpus -- --ignored
//!
//! The first run writes `project files functions nodes edges` per line, the second fails on any difference.

use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
use taintless::lang::{Language, build_cfgs, imports};
use std::path::{Path, PathBuf};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_symlink() {
            continue;
        }
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

type Counts = (usize, usize, usize, usize);

/// `(files, functions, nodes, edges)` of the project at `dir`.
fn build(dir: &Path) -> Counts {
    let mut all = vec![];
    files(dir, &mut all);
    all.sort();
    let loaded: Vec<_> = all
        .into_iter()
        .filter_map(|p| {
            let src = std::fs::read_to_string(&p).ok()?;
            let lang = Language::detect_with_source(&p, &src)?;
            let cfgs = build_cfgs(lang, &src).ok()?; // syntax errors are rejected, not a CPG failure
            let imps = imports(lang, &src).unwrap_or_default();
            Some((p, lang, src, cfgs, imps))
        })
        .collect();
    let fs: Vec<SourceFile> = loaded.iter().map(|(p, lang, src, cfgs, imps)| SourceFile { path: p, lang: *lang, src, cfgs, imports: imps }).collect();
    let c = Cpg::build(&fs).unwrap_or_else(|e| panic!("{}: {e:#}", dir.display()));
    for n in c.graph.node_indices() {
        c.enclosing_method(n);
    }
    assert_eq!(c.methods.len(), loaded.iter().map(|f| f.3.len()).sum::<usize>(), "{}", dir.display());
    // the syntax trees are trees: every node but a file's root has exactly one parent
    let ast_edges = c.graph.edge_weights().filter(|e| e.kind == EdgeKind::Ast).count();
    let ast_nodes: usize = c.files.iter().map(|f| f.ast.nodes.len()).sum();
    assert_eq!(ast_edges + c.files.len(), ast_nodes, "{}", dir.display());
    assert!(c.graph.edge_count() >= ast_edges, "{}", dir.display());
    let counts = (loaded.len(), c.methods.len(), c.graph.node_count(), c.graph.edge_count());
    if !loaded.is_empty() && loaded.len() <= 50 {
        // small projects are built again: same counts
        let again = Cpg::build(&fs).unwrap();
        assert_eq!((again.graph.node_count(), again.graph.edge_count()), (counts.2, counts.3), "{} is not deterministic", dir.display());
    }
    counts
}

/// `project files functions nodes edges` lines, sorted by project.
fn render(rows: &[(String, Counts)]) -> String {
    rows.iter().map(|(n, (f, m, nn, e))| format!("{n} {f} {m} {nn} {e}\n")).collect()
}

/// The harness on code that is always there: the language fixtures of this repository (its own
/// sources are built in `tests/cpg.rs`).
#[test]
fn corpus_harness_on_repository_code() {
    for dir in ["tests/fixtures", "tests/vuln"] {
        let (f, m, n, e) = build(Path::new(dir));
        assert!(f > 0 && m > 0 && n > m && e > n, "{dir}: {f} files {m} functions {n} nodes {e} edges");
    }
    // the baseline format round-trips
    let rows = vec![("a".to_string(), (1, 2, 3, 4)), ("b".to_string(), (5, 6, 7, 8))];
    assert_eq!(render(&rows), "a 1 2 3 4\nb 5 6 7 8\n");
}

#[test]
#[ignore = "needs SCAN_CORPUS"]
fn corpus_projects_build() {
    let Ok(root) = std::env::var("SCAN_CORPUS") else { panic!("set SCAN_CORPUS to a directory of projects") };
    let mut projects: Vec<PathBuf> = std::fs::read_dir(&root).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    projects.sort();
    let mut rows = vec![];
    for p in &projects {
        let (f, m, n, e) = build(p);
        if f == 0 {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        println!("{name:<40} {f:>4} files {m:>6} functions {n:>8} nodes {e:>8} edges");
        assert!(n > 0, "{}", p.display());
        rows.push((name, (f, m, n, e)));
    }
    assert!(!rows.is_empty(), "no analyzable project under {root}");
    // pinned counts, kept outside the repository
    if let Ok(path) = std::env::var("SCAN_CORPUS_BASELINE") {
        let now = render(&rows);
        if std::env::var("SCAN_CORPUS_UPDATE").is_ok() || !Path::new(&path).exists() {
            std::fs::write(&path, &now).unwrap();
            println!("wrote {path}");
        } else {
            let want = std::fs::read_to_string(&path).unwrap();
            let diff: Vec<String> = want
                .lines()
                .filter(|l| !now.lines().any(|n| n == *l))
                .map(|l| format!("- {l}"))
                .chain(now.lines().filter(|n| !want.lines().any(|l| l == *n)).map(|l| format!("+ {l}")))
                .collect();
            assert!(diff.is_empty(), "counts differ from {path}:\n{}", diff.join("\n"));
        }
    }
}
