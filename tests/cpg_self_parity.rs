use std::path::{Path, PathBuf};
use taintless::analysis::{ProjectFile, check_project};
use taintless::cpg::graph::{Cpg, SourceFile};
use taintless::cpg::taint::taint_flows;
use taintless::lang::{Language, build_cfgs};

#[test]
fn rust_source_parity() {
    let mut paths = Vec::new();
    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().is_some_and(|x| x == "rs") {
                out.push(path);
            }
        }
    }
    collect(Path::new("src"), &mut paths);
    paths.sort();
    let loaded: Vec<_> = paths
        .iter()
        .map(|p| {
            let src = std::fs::read_to_string(p).unwrap();
            let cfgs = build_cfgs(Language::Rust, &src).unwrap();
            (p, src, cfgs)
        })
        .collect();
    let pf: Vec<_> = loaded
        .iter()
        .map(|(p, _, cfgs)| ProjectFile {
            lang: Language::Rust,
            file: p,
            cfgs,
            imports: &[],
        })
        .collect();
    let reference: Vec<_> = check_project(&pf, &|| {})
        .into_iter()
        .filter(|f| f.origin.is_some())
        .collect();
    let old: std::collections::BTreeSet<_> = reference
        .iter()
        .map(|f| (f.file.clone(), f.line, f.rule))
        .collect();
    let sf: Vec<_> = loaded
        .iter()
        .map(|(p, src, cfgs)| SourceFile {
            path: p,
            lang: Language::Rust,
            src,
            cfgs,
            imports: &[],
        })
        .collect();
    let cpg = Cpg::build(&sf).unwrap();
    let reports: Vec<_> = taint_flows(&cpg)
        .into_iter()
        .map(|t| t.finding(&cpg))
        .collect();
    let new: std::collections::BTreeSet<_> = reports
        .iter()
        .map(|f| (f.file.clone(), f.line, f.rule))
        .collect();
    assert!(
        !old.is_empty(),
        "the comparison must exercise at least one finding"
    );
    let extra: Vec<_> = new.difference(&old).collect();
    let missing: Vec<_> = old.difference(&new).collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "extra: {extra:?}\nmissing: {missing:?}"
    );
    for f in &reference {
        let got = reports
            .iter()
            .find(|g| g.file == f.file && g.line == f.line && g.rule == f.rule)
            .unwrap();
        assert_eq!(got, f);
    }
}

#[test]
fn all_fixture_finding_details() {
    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut paths = vec![];
    collect(Path::new("tests"), &mut paths);
    paths.sort();
    let mut mismatches = vec![];
    for p in paths {
        if p.starts_with("tests/iface") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Some(lang) = Language::detect_with_source(&p, &src) else {
            continue;
        };
        let Ok(cfgs) = build_cfgs(lang, &src) else {
            continue;
        };
        let old: Vec<_> = taintless::analysis::check_file(lang, &p, &cfgs)
            .into_iter()
            .filter(|f| f.origin.is_some())
            .collect();
        let sf = [SourceFile {
            path: &p,
            lang,
            src: &src,
            cfgs: &cfgs,
            imports: &[],
        }];
        let cpg = Cpg::build(&sf).unwrap();
        let new: Vec<_> = taint_flows(&cpg)
            .into_iter()
            .map(|f| f.finding(&cpg))
            .collect();
        if old.len() != new.len() {
            mismatches.push(format!(
                "{}: {} reference findings, {} CPG findings",
                p.display(),
                old.len(),
                new.len()
            ));
        }
        for f in &old {
            match new
                .iter()
                .find(|g| g.rule == f.rule && g.line == f.line && g.col == f.col)
            {
                Some(g) if g == f => {}
                Some(g) => mismatches.push(format!("{}:{}: {g:?} != {f:?}", p.display(), f.line)),
                None => mismatches.push(format!("{}:{}: missing {f:?}", p.display(), f.line)),
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} detail mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn project_finding_details() {
    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut mismatches = vec![];
    for dir in [
        "tests/interproc",
        "tests/types",
        "tests/hier",
        "tests/imports",
        "tests/bare",
    ] {
        let mut paths = vec![];
        collect(Path::new(dir), &mut paths);
        paths.sort();
        let mut loaded = vec![];
        for p in paths {
            let Ok(src) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Some(lang) = Language::detect_with_source(&p, &src) else {
                continue;
            };
            let Ok(cfgs) = build_cfgs(lang, &src) else {
                continue;
            };
            let imports = taintless::lang::imports(lang, &src).unwrap_or_default();
            loaded.push((p, lang, src, cfgs, imports));
        }
        let pf: Vec<_> = loaded
            .iter()
            .map(|(p, lang, _, cfgs, imports)| ProjectFile {
                lang: *lang,
                file: p,
                cfgs,
                imports,
            })
            .collect();
        let old: Vec<_> = check_project(&pf, &|| {})
            .into_iter()
            .filter(|f| f.origin.is_some())
            .collect();
        let sf: Vec<_> = loaded
            .iter()
            .map(|(p, lang, src, cfgs, imports)| SourceFile {
                path: p,
                lang: *lang,
                src,
                cfgs,
                imports,
            })
            .collect();
        let cpg = Cpg::build(&sf).unwrap();
        let new: Vec<_> = taint_flows(&cpg)
            .into_iter()
            .map(|f| f.finding(&cpg))
            .collect();
        if old.len() != new.len() {
            mismatches.push(format!(
                "{dir}: {} reference findings, {} CPG findings",
                old.len(),
                new.len()
            ));
        }
        for f in &old {
            match new.iter().find(|g| {
                g.file == f.file && g.line == f.line && g.col == f.col && g.rule == f.rule
            }) {
                Some(g) if g == f => {}
                Some(g) => {
                    mismatches.push(format!("{}:{}: {g:?} != {f:?}", f.file.display(), f.line))
                }
                None => mismatches.push(format!("{}:{}: missing {f:?}", f.file.display(), f.line)),
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} detail mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
