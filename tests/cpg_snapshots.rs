//! Snapshots of the code property graph for the fixture files, and smoke tests on every
//! fixture project: the graph builds, is deterministic and has the expected shape.

use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
use taintless::lang::{Language, build_cfgs, imports};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// The CPG of every analyzable file under `paths` (files or directories).
fn cpg_of(paths: &[&str]) -> Cpg {
    let mut all = vec![];
    for p in paths {
        let p = Path::new(p);
        if p.is_dir() {
            files(p, &mut all);
        } else {
            all.push(p.to_path_buf());
        }
    }
    all.sort();
    let loaded: Vec<_> = all
        .into_iter()
        .filter_map(|p| {
            let src = std::fs::read_to_string(&p).ok()?;
            let lang = Language::detect_with_source(&p, &src)?;
            let cfgs = build_cfgs(lang, &src).ok()?;
            let imps = imports(lang, &src).unwrap_or_default();
            Some((p, lang, src, cfgs, imps))
        })
        .collect();
    let fs: Vec<SourceFile> = loaded.iter().map(|(p, lang, src, cfgs, imps)| SourceFile { path: p, lang: *lang, src, cfgs, imports: imps }).collect();
    Cpg::build(&fs).unwrap()
}

/// Node and edge counts per kind, and the function-level calls with their parameter / return edges.
fn summary(c: &Cpg) -> String {
    let mut nodes: BTreeMap<&str, usize> = BTreeMap::new();
    for n in c.graph.node_weights() {
        *nodes.entry(n.kind.as_str()).or_default() += 1;
    }
    let mut edges: BTreeMap<&str, usize> = BTreeMap::new();
    for e in c.graph.edge_weights() {
        *edges.entry(e.kind.as_str()).or_default() += 1;
    }
    let name = |n: NodeIndex| c.graph[n].name.clone().unwrap_or_else(|| "?".into());
    let mut calls: Vec<String> = c
        .graph
        .edge_references()
        .filter(|e| e.weight().kind == EdgeKind::Call)
        .map(|e| format!("{} -> {}", name(c.enclosing_method(e.source())), name(e.target())))
        .collect();
    calls.sort();
    let mut s = String::new();
    let _ = writeln!(s, "nodes: {nodes:?}\nedges: {edges:?}");
    for l in calls {
        let _ = writeln!(s, "call {l}");
    }
    s
}

#[test]
fn fixture_snapshots() {
    for f in [
        "vuln/app.py", "vuln/app.go", "vuln/app.js", "vuln/app.rs", "vuln/app.c", "vuln/App.java",
        "vuln/closure.py", "vuln/clean.py",
    ] {
        let c = cpg_of(&[&format!("tests/{f}")]);
        insta::assert_snapshot!(format!("cpg_{}", f.replace(['/', '.'], "_")), summary(&c));
    }
}

#[test]
fn project_snapshots() {
    for d in ["callgraph", "interproc", "types", "hier", "imports"] {
        let c = cpg_of(&[&format!("tests/{d}")]);
        insta::assert_snapshot!(format!("cpg_project_{d}"), summary(&c));
    }
}

/// Every fixture directory under `tests/` that holds analyzable source, by name.
fn fixture_dirs() -> Vec<String> {
    let mut dirs: Vec<_> = std::fs::read_dir("tests").unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    dirs.into_iter()
        .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
        // not code under test: snapshot files, and the language fixtures (one snapshot per file below)
        .filter(|n| !matches!(n.as_str(), "snapshots" | "fixtures" | "common"))
        .collect()
}

/// One snapshot per fixture directory (the ones above keep their older names).
#[test]
fn every_fixture_directory_snapshot() {
    let done = ["callgraph", "interproc", "types", "hier", "imports"];
    let mut taken = 0;
    for d in fixture_dirs().into_iter().filter(|d| !done.contains(&d.as_str())) {
        let c = cpg_of(&[&format!("tests/{d}")]);
        if c.graph.node_count() == 0 {
            continue; // no analyzable source in this directory
        }
        taken += 1;
        insta::assert_snapshot!(format!("cpg_dir_{d}"), summary(&c));
    }
    assert!(taken >= 15, "only {taken} fixture directories had source");
}

/// One snapshot per file of the per-language fixtures.
#[test]
fn language_fixture_snapshots() {
    let mut all = vec![];
    files(Path::new("tests/fixtures"), &mut all);
    all.sort();
    let mut taken = 0;
    for p in all {
        let c = cpg_of(&[p.to_str().unwrap()]);
        if c.graph.node_count() == 0 {
            continue; // a header, or a file the lowering rejects
        }
        taken += 1;
        let name = p.strip_prefix("tests/fixtures").unwrap().with_extension("");
        insta::assert_snapshot!(format!("cpg_fixtures_{}", name.to_string_lossy().replace(['/', '.'], "_")), summary(&c));
    }
    assert!(taken >= 25, "only {taken} language fixtures had source");
}

#[test]
fn every_fixture_project_builds_deterministically() {
    let mut dirs: Vec<_> = std::fs::read_dir("tests").unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    let mut built = 0;
    for d in dirs {
        let d = d.to_str().unwrap();
        let (a, b) = (cpg_of(&[d]), cpg_of(&[d]));
        if a.graph.node_count() == 0 {
            continue; // no analyzable source in this directory
        }
        built += 1;
        assert_eq!(summary(&a), summary(&b), "{d} differs between builds");
        for m in &a.methods {
            assert!(a.graph[*m].line > 0 || a.graph[*m].name.is_some(), "{d}: anonymous method without a position");
        }
        for n in a.graph.node_indices() {
            a.enclosing_method(n);
        }
    }
    assert!(built >= 10, "only {built} fixture directories built");
}

mod export {
    use super::*;
    use std::collections::HashSet;
    use taintless::export::cpg::{select, stable_ids, to_json, to_neo4j};

    #[test]
    fn stable_ids_are_unique_and_repeat_across_builds() {
        for d in ["tests/interproc", "tests/types", "tests/vuln"] {
            let (a, b) = (cpg_of(&[d]), cpg_of(&[d]));
            let (ia, ib) = (stable_ids(&a), stable_ids(&b));
            assert_eq!(ia.len(), a.graph.node_count(), "{d}");
            assert_eq!(ia.values().collect::<HashSet<_>>().len(), ia.len(), "{d}: duplicate stable ids");
            // same sources, same ids (node indices of two builds line up because the build is deterministic)
            assert_eq!(ia.values().collect::<std::collections::BTreeSet<_>>(), ib.values().collect(), "{d}");
        }
    }

    #[test]
    fn json_nodes_carry_the_stable_id() {
        let c = cpg_of(&["tests/vuln/app.py"]);
        let j = to_json(&c, &select(&c, &[], None));
        let nodes = j["nodes"].as_array().unwrap();
        assert!(nodes.iter().all(|n| n["stable_id"].as_str().is_some_and(|s| s.contains("app.py"))));
    }

    #[test]
    fn neo4j_csv_names_every_edge_endpoint() {
        let c = cpg_of(&["tests/interproc"]);
        let sel = select(&c, &[], None);
        let (nodes, edges) = to_neo4j(&c, &sel);
        assert!(nodes.starts_with("id:ID,:LABEL,kind,name,code,file,line:int,col:int\n"));
        assert!(edges.starts_with(":START_ID,:END_ID,:TYPE,var,label,order:int\n"));
        assert!(nodes.contains(",Node;Method,method,") && edges.contains(",CALL,"));
        // every selected edge has a row, and its endpoints are nodes of nodes.csv
        let ids = stable_ids(&c);
        let node_ids: HashSet<&str> = sel.nodes.iter().map(|n| ids[n].as_str()).collect();
        assert_eq!(node_ids.len(), sel.nodes.len());
        for &e in &sel.edges {
            let (a, b) = c.graph.edge_endpoints(e).unwrap();
            assert!(node_ids.contains(ids[&a].as_str()) && node_ids.contains(ids[&b].as_str()));
        }
        assert!(edges.lines().count() > sel.edges.len());
    }
}
