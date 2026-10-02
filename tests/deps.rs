use ignore::WalkBuilder;
use taintless::analysis::deps::{self, DepFile, DepGraph};
use taintless::lang::{self, Language};
use std::collections::BTreeSet;
use std::path::PathBuf;
mod common;
use common::taintless;

/// Build the dependency graph of `tests/deps` (paths shown relative to it).
fn graph() -> (DepGraph, Vec<String>) {
    graph_in("tests/deps")
}

fn graph_in(root: &str) -> (DepGraph, Vec<String>) {
    let mut paths: Vec<PathBuf> = WalkBuilder::new(root)
        .build()
        .flatten()
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(|e| e.into_path())
        .filter(|p| Language::detect(p).is_some())
        .collect();
    paths.sort();
    let loaded: Vec<(PathBuf, Language, String)> = paths
        .into_iter()
        .map(|p| {
            let src = std::fs::read_to_string(&p).unwrap();
            let l = Language::detect_with_source(&p, &src).unwrap();
            (p, l, src)
        })
        .collect();
    let cfgs: Vec<_> = loaded.iter().map(|(_, l, s)| lang::build_cfgs(*l, s).unwrap()).collect();
    let files: Vec<DepFile> = loaded
        .iter()
        .zip(&cfgs)
        .map(|((p, l, s), c)| DepFile { path: p, lang: *l, imports: lang::imports(*l, s).unwrap(), cfgs: c })
        .collect();
    let names = loaded.iter().map(|(p, _, _)| format!("/{}", p.strip_prefix(root).unwrap().display())).collect();
    (deps::build(&files), names)
}

fn edges(g: &DepGraph, names: &[String]) -> BTreeSet<(String, String)> {
    g.graph
        .edge_indices()
        .map(|e| {
            let (a, b) = g.graph.edge_endpoints(e).unwrap();
            (names[a.index()].clone(), names[b.index()].clone())
        })
        .collect()
}

fn has(e: &BTreeSet<(String, String)>, a: &str, b: &str) -> bool {
    e.contains(&(a.to_string(), b.to_string()))
}

#[test]
fn imports_resolve_to_files_in_every_language() {
    let (g, names) = graph();
    let e = edges(&g, &names);
    // python: absolute, relative and package imports
    for t in ["/py/pkg/util.py", "/py/pkg/models.py", "/py/pkg/sub/deep.py", "/py/pkg/__init__.py"] {
        assert!(has(&e, "/py/pkg/main.py", t), "main.py -> {t}");
    }
    // javascript / typescript: require, import, directory index, `.js` naming a `.ts`
    assert!(has(&e, "/js/a.js", "/js/b.js") && has(&e, "/js/a.js", "/js/lib/index.ts"));
    assert!(has(&e, "/js/lib/index.ts", "/js/b.js"));
    // rust: `mod x;`, `crate::`, `super::`, grouped `use`, mod.rs
    for (a, b) in [("lib", "a"), ("lib", "b"), ("a", "b")] {
        assert!(has(&e, &format!("/rs/src/{a}.rs"), &format!("/rs/src/{b}.rs")), "{a} -> {b}");
    }
    assert!(has(&e, "/rs/src/lib.rs", "/rs/src/c/mod.rs") && has(&e, "/rs/src/c/mod.rs", "/rs/src/c/d.rs"));
    assert!(has(&e, "/rs/src/a.rs", "/rs/src/c/mod.rs") && has(&e, "/rs/src/c/d.rs", "/rs/src/a.rs"));
    // go: an import path names a directory
    assert!(has(&e, "/go/main.go", "/go/util/util.go"));
    // java: fully qualified class names
    assert!(has(&e, "/java/com/foo/A.java", "/java/com/foo/bar/B.java"));
    // c: quoted includes, relative to the including file
    assert!(has(&e, "/c/main.c", "/c/util.h") && has(&e, "/c/util.h", "/c/common/types.h"));
}

#[test]
fn unresolved_imports_are_external_and_languages_do_not_mix() {
    let (g, names) = graph();
    let ext: BTreeSet<&str> = g.external.keys().map(String::as_str).collect();
    for m in ["lodash", "os", "std::fmt", "serde::Serialize", "stdio.h", "java.util.List", "fmt"] {
        assert!(ext.contains(m), "{m} should be external: {ext:?}");
    }
    // a Python call never lands in a Rust file, and vice versa
    let ext_of = |n: &str| n.rsplit('.').next().unwrap().to_string();
    for (a, b) in edges(&g, &names) {
        let fam = |e: &str| match e {
            "py" => 0,
            "js" | "ts" => 1,
            "rs" => 2,
            "go" => 3,
            "java" => 4,
            _ => 5,
        };
        assert_eq!(fam(&ext_of(&a)), fam(&ext_of(&b)), "{a} -> {b}");
    }
}

#[test]
fn cycles_and_calls_across_files() {
    let (g, names) = graph();
    let cycles: Vec<BTreeSet<&str>> =
        g.cycles().into_iter().map(|c| c.into_iter().map(|n| names[n.index()].as_str()).collect()).collect();
    assert!(cycles.contains(&BTreeSet::from(["/py/pkg/models.py", "/py/pkg/util.py"])));
    assert!(cycles.contains(&BTreeSet::from(["/rs/src/a.rs", "/rs/src/c/d.rs", "/rs/src/c/mod.rs"])));
    assert_eq!(cycles.len(), 2);
    // calls are attributed to the files involved, with an example
    let call = g.graph.edge_indices().find_map(|e| {
        let (a, b) = g.graph.edge_endpoints(e).unwrap();
        (names[a.index()] == "/go/main.go" && names[b.index()] == "/go/util/util.go").then(|| g.graph[e].clone())
    });
    let call = call.unwrap();
    assert_eq!(call.calls, 1);
    assert_eq!(call.examples, ["main → Name"]);
}

#[test]
fn directory_level_view() {
    let (g, _) = graph();
    let d = g.by_dir();
    let dirs: BTreeSet<String> = d.graph.node_weights().map(|p| p.display().to_string()).collect();
    assert!(dirs.contains("tests/deps/rs/src") && dirs.contains("tests/deps/rs/src/c"));
    // src <-> src/c depend on each other
    assert!(d.cycles().iter().any(|c| c.len() == 2));
    assert!(d.graph.node_count() < g.graph.node_count());
}

#[test]
fn cli_outputs() {
    let run = taintless;
    let json: serde_json::Value = serde_json::from_slice(&run(&["deps", "tests/deps", "--format", "json"]).stdout).unwrap();
    assert!(json["files"].as_array().unwrap().len() >= 15);
    assert_eq!(json["cycles"].as_array().unwrap().len(), 2);
    let dot = String::from_utf8(run(&["deps", "tests/deps", "--format", "dot"]).stdout).unwrap();
    assert!(dot.starts_with("digraph deps") && dot.contains("fillcolor=\"#f4d6d6\""));
    let text = String::from_utf8(run(&["deps", "tests/deps", "--format", "text", "--level", "dir", "--external"]).stdout).unwrap();
    assert!(text.contains("external or unresolved modules") && text.contains("dependency cycles"));
}

#[test]
fn manifests_guide_resolution() {
    let (g, names) = graph_in("tests/manifests");
    let e = edges(&g, &names);
    // tsconfig `paths` (with comments and trailing commas) and `baseUrl`; `react` stays external
    for t in ["/ts/src/app/a.ts", "/ts/src/lib/index.ts", "/ts/src/lib/helper.ts"] {
        assert!(has(&e, "/ts/src/main.ts", t), "main.ts -> {t}");
    }
    assert!(g.external.contains_key("react"));
    // go.mod: the module's own package resolves, a look-alike third-party path does not
    assert!(has(&e, "/go/main.go", "/go/pkg/util/util.go"));
    assert!(!has(&e, "/go/main.go", "/go/other/util.go"));
    assert!(g.external.contains_key("github.com/other/util"), "{:?}", g.external.keys().collect::<Vec<_>>());
    // Cargo.toml: `use my_core::..` reaches the other crate of the workspace (`my-core`)
    assert!(has(&e, "/rs/app/src/main.rs", "/rs/core/src/shapes.rs"));
    assert!(has(&e, "/rs/app/src/main.rs", "/rs/core/src/lib.rs"));
    // namespace packages (no `__init__.py`), a file called `mod.py`, and a dynamic import
    let main = g.graph.edge_indices().find_map(|i| {
        let (a, b) = g.graph.edge_endpoints(i).unwrap();
        (names[a.index()] == "/py/main.py" && names[b.index()] == "/py/ns/inner/mod.py").then(|| g.graph[i].imports.clone())
    });
    assert_eq!(main.unwrap().iter().map(|i| i.0).collect::<Vec<_>>(), [2, 6], "import and importlib.import_module");
}

#[test]
fn workspaces_and_layouts_guide_resolution() {
    let (g, names) = graph_in("tests/workspaces");
    let e = edges(&g, &names);
    // package.json workspaces: `main`, `exports` (subpath, pattern, hidden files), a package outside `exports`
    let app = "/js/apps/web/app.js";
    for t in ["/js/packages/core/src/index.js", "/js/packages/core/src/util.js", "/js/packages/core/src/feat/a.js", "/js/packages/ui/src/main.js", "/js/packages/ui/src/widgets/button.js"] {
        assert!(has(&e, app, t), "{app} -> {t}");
    }
    assert!(!has(&e, app, "/js/packages/core/src/hidden.js"), "`exports` hides unlisted files");
    assert!(g.external.contains_key("react"));
    // go.work `use` and go.mod `replace`; an unknown module stays external
    for t in ["/go/lib/lib.go", "/go/lib/sub/sub.go", "/go/vendored/x/x.go"] {
        assert!(has(&e, "/go/svc/main.go", t), "main.go -> {t}");
    }
    assert!(g.external.contains_key("example.com/nope"));
    // pyproject: `src` layout and `where = ["lib"]`, not the look-alike `tests/core.py`
    assert!(has(&e, "/py/tests/test_it.py", "/py/src/mypkg/core.py"));
    assert!(!has(&e, "/py/tests/test_it.py", "/py/tests/core.py"));
    assert!(has(&e, "/py/tests/test_it.py", "/py/lib/other/__init__.py"));
    // Cargo `[lib] path` and `[[bin]] path`: `crate::` and `mod` from the custom roots
    assert!(has(&e, "/rs/tools/tool_main.rs", "/rs/src/shapes.rs"));
    assert!(has(&e, "/rs/tools/tool_main.rs", "/rs/tools/helper.rs"));
    assert!(has(&e, "/rs/tools/helper.rs", "/rs/src/custom_lib.rs"));
    assert!(has(&e, "/rs/src/custom_lib.rs", "/rs/src/shapes.rs"));
    assert!(has(&e, "/rs/src/inner.rs", "/rs/src/shapes.rs"));
}
