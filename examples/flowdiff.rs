use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use taintless::analysis::{ProjectFile, dataflow};
use taintless::cpg::flow::flow_graph;
use taintless::cpg::graph::{Cpg, SourceFile};
use taintless::export::dataflow as ex;
use taintless::lang::{Language, build_cfgs, imports};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() { files(&p, out); } else { out.push(p); }
    }
}

fn lines(t: &str) -> BTreeSet<String> {
    t.lines().map(|l| l.to_string()).collect()
}

fn main() {
    let arg = std::env::args().nth(1).unwrap();
    let control = std::env::args().nth(2).is_some();
    let mut paths = vec![];
    if Path::new(&arg).is_dir() { files(Path::new(&arg), &mut paths); } else { paths.push(PathBuf::from(&arg)); }
    paths.sort();
    let mut loaded = vec![];
    for p in paths {
        let Ok(src) = std::fs::read_to_string(&p) else { continue };
        let Some(lang) = Language::detect_with_source(&p, &src) else { continue };
        let Ok(cfgs) = build_cfgs(lang, &src) else { continue };
        let imps = imports(lang, &src).unwrap_or_default();
        loaded.push((p, lang, src, cfgs, imps));
    }
    let pf: Vec<ProjectFile> = loaded.iter().map(|l| ProjectFile { lang: l.1, file: &l.0, cfgs: &l.3, imports: &l.4 }).collect();
    let old = dataflow::build(&pf, control);
    let sf: Vec<SourceFile> = loaded.iter().map(|l| SourceFile { path: &l.0, lang: l.1, src: &l.2, cfgs: &l.3, imports: &l.4 }).collect();
    let cpg = Cpg::build(&sf).unwrap();
    let new = flow_graph(&cpg, &sf, control);
    let a = ex::to_text(&old, &ex::select(&old, None, None));
    let b = ex::to_text(&new, &ex::select(&new, None, None));
    let (la, lb) = (lines(&a), lines(&b));
    for l in la.difference(&lb) { println!("- {l}"); }
    if std::env::var("DUMP").is_ok() { println!("--- new ---\n{b}"); }
    for l in lb.difference(&la) { println!("+ {l}"); }
    println!("{arg}: old {} lines, new {} lines, same {}", la.len(), lb.len(), la.intersection(&lb).count());
}
