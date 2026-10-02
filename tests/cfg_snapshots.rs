use taintless::{
    export::{dot::to_dot, json::to_json, text::to_text},
    ir::{Cfg, EdgeKind},
    lang,
};
use petgraph::visit::{IntoEdgeReferences};
use std::path::PathBuf;

fn fixtures() -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir("tests/fixtures/python")
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v
}

#[test]
fn python_snapshots() {
    for p in fixtures() {
        let src = std::fs::read_to_string(&p).unwrap();
        let cfgs = lang::build_cfgs(lang::Language::Python, &src).unwrap();
        let text: String = cfgs.iter().map(|c| format!("// {}\n{}", c.name, to_dot(c))).collect();
        insta::assert_snapshot!(p.file_stem().unwrap().to_str().unwrap().to_string(), text);
    }
}

#[test]
fn python_function_counts() {
    let count = |f: &str| {
        let src = std::fs::read_to_string(format!("tests/fixtures/python/{f}")).unwrap();
        lang::build_cfgs(lang::Language::Python, &src).unwrap().len()
    };
    assert_eq!(count("class_methods.py"), 3); // one, inner, two
    assert_eq!(count("finally_paths.py"), 2);
}

#[test]
fn json_export_shape() {
    let src = std::fs::read_to_string("tests/fixtures/python/dead_code.py").unwrap();
    let cfgs = lang::build_cfgs(lang::Language::Python, &src).unwrap();
    let j = to_json(&cfgs[0]);
    assert_eq!(j["name"], "early");
    assert!(j["blocks"].as_array().unwrap().len() >= 4);
    assert!(j["edges"].as_array().unwrap().iter().any(|e| e["kind"] == "return"));
}

/// Statements after `return` must land in blocks with no incoming path from entry.
#[test]
fn dead_code_is_unreachable() {
    use petgraph::visit::Dfs;
    let src = std::fs::read_to_string("tests/fixtures/python/dead_code.py").unwrap();
    let cfg = &lang::build_cfgs(lang::Language::Python, &src).unwrap()[0];
    let mut dfs = Dfs::new(&cfg.graph, cfg.entry);
    let mut seen = std::collections::HashSet::new();
    while let Some(n) = dfs.next(&cfg.graph) {
        seen.insert(n);
    }
    let dead: Vec<_> = cfg
        .graph
        .node_indices()
        .filter(|n| !seen.contains(n))
        .flat_map(|n| cfg.graph[n].stmts.iter().map(|s| s.text.clone()))
        .collect();
    assert_eq!(dead, ["print(\"unreachable\")", "print(\"also unreachable\")"]);
}

/// All fixtures of all languages: `(dir name, path)`, sorted.
fn all_fixtures() -> Vec<(String, PathBuf)> {
    let mut out = vec![];
    for dir in std::fs::read_dir("tests/fixtures").unwrap() {
        let dir = dir.unwrap().path();
        for f in std::fs::read_dir(&dir).unwrap() {
            out.push((dir.file_name().unwrap().to_str().unwrap().to_string(), f.unwrap().path()));
        }
    }
    out.sort();
    out
}

fn cfgs_of(path: &std::path::Path) -> Vec<Cfg> {
    let src = std::fs::read_to_string(path).unwrap();
    let l = lang::Language::detect_with_source(path, &src)
        .unwrap_or_else(|| panic!("unsupported fixture {path:?}"));
    lang::build_cfgs(l, &src).unwrap()
}

#[test]
fn text_snapshots_all_languages() {
    for (dir, p) in all_fixtures() {
        let text: String = cfgs_of(&p).iter().map(to_text).collect();
        let name = format!("text_{dir}_{}", p.file_stem().unwrap().to_str().unwrap());
        insta::assert_snapshot!(name, text);
    }
}

fn has_edge(c: &Cfg, kind: EdgeKind) -> bool {
    c.graph.edge_references().any(|e| *e.weight() == kind)
}

fn find<'a>(cfgs: &'a [Cfg], name: &str) -> &'a Cfg {
    cfgs.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no function {name}"))
}

fn names(v: &[Cfg]) -> Vec<String> {
    v.iter().map(|c| c.name.clone()).collect()
}

fn get(p: &str) -> Vec<Cfg> {
    cfgs_of(std::path::Path::new(p))
}

fn stmt_count(c: &Cfg, pred: impl Fn(&taintless::ir::Stmt) -> bool) -> usize {
    c.graph.node_weights().flat_map(|b| &b.stmts).filter(|s| pred(s)).count()
}

fn count_edges(c: &Cfg, kind: EdgeKind) -> usize {
    c.graph.edge_references().filter(|e| *e.weight() == kind).count()
}

/// Per language: expected function names and a few structural properties
/// that must hold regardless of how blocks are numbered.
#[test]
fn language_structure() {
    let js = get("tests/fixtures/javascript/flow.js");
    assert_eq!(names(&js), ["<module>", "scan", "arrow", "block", "K.method"]);
    let scan = find(&js, "scan");
    for k in [EdgeKind::Back, EdgeKind::Break, EdgeKind::Continue, EdgeKind::Exception, EdgeKind::Return] {
        assert!(has_edge(scan, k), "js scan missing {k:?}");
    }

    let ts = get("tests/fixtures/typescript/flow.ts");
    assert_eq!(names(&ts), ["pick", "Box.constructor", "Box.get"]);
    // TSX uses its own grammar: JSX must parse and the `if` must branch
    let tsx = get("tests/fixtures/typescript/view.tsx");
    assert_eq!(names(&tsx), ["<module>", "View"]);
    assert!(has_edge(&tsx[1], EdgeKind::True) && has_edge(&tsx[1], EdgeKind::Return));

    let rs = get("tests/fixtures/rust/flow.rs");
    assert_eq!(names(&rs), ["read", "run", "S::method"]);
    // `?` adds an early return besides the tail expression's fallthrough.
    let read = find(&rs, "read");
    assert_eq!(read.graph.neighbors_directed(read.exit, petgraph::Direction::Incoming).count(), 2);
    assert!(has_edge(read, EdgeKind::Return));

    let go = get("tests/fixtures/go/flow.go");
    assert_eq!(names(&go), ["run", "T.Method", "Method.<anon>"]);

    let java = get("tests/fixtures/java/Flow.java");
    assert_eq!(names(&java), ["Flow.run", "Flow.Flow", "Flow.arrow"]);
    // two catch clauses -> two exception edges from the try block
    assert!(count_edges(find(&java, "Flow.run"), EdgeKind::Exception) >= 2);

    let c = get("tests/fixtures/c/flow.c");
    assert_eq!(names(&c), ["run", "spin"]);
    // `for (;;) {}` never reaches the exit
    let spin = find(&c, "spin");
    assert!(!petgraph::algo::has_path_connecting(&spin.graph, spin.entry, spin.exit, None));

    let cpp = get("tests/fixtures/cpp/flow.cpp");
    assert_eq!(names(&cpp), ["ns::W::run", "W_free"]);
}

#[test]
fn python_on_shared_engine() {
    let m = get("tests/fixtures/python/module_code.py");
    assert_eq!(names(&m), ["<module>", "main"]);
    // `A and (B or not C)` -> one branch per operand
    let branches = stmt_count(&m[0], |s| s.kind == taintless::ir::StmtKind::Branch);
    assert_eq!(branches, 3);

    let nested = get("tests/fixtures/python/nested_loops.py");
    assert_eq!(names(&nested), ["grid"]);
    // for-else: the `else` body is reachable only when the loop is not broken out of
    let t = get("tests/fixtures/python/try_else.py");
    assert!(has_edge(&t[0], EdgeKind::Exception));
    assert_eq!(names(&get("tests/fixtures/python/class_methods.py")), ["A.one", "A.one.inner", "A.two"]);
}

#[test]
fn short_circuit_conditions() {
    let f = &get("tests/fixtures/javascript/cond.js")[0];
    // if (a && (b || !c)) + while (a || b): five tests, not two
    assert_eq!(stmt_count(f, |s| s.kind == taintless::ir::StmtKind::Branch), 5);
    assert!(has_edge(f, EdgeKind::Back));
}

#[test]
fn go_defers_run_on_every_exit() {
    let f = &get("tests/fixtures/go/defers.go")[0];
    let deferred = |c: &Cfg| stmt_count(c, |s| s.text.starts_with("deferred"));
    // return 1 runs b, a; return 2 runs c, a
    assert_eq!(deferred(f), 4);
    // within each return block the deferred calls run in reverse order of registration
    let order: Vec<Vec<&str>> = f
        .graph
        .node_weights()
        .map(|b| b.stmts.iter().filter(|s| s.text.starts_with("deferred")).map(|s| s.text.as_str()).collect())
        .filter(|v: &Vec<&str>| !v.is_empty())
        .collect();
    assert!(order.contains(&vec!["deferred b()", "deferred a()"]));
    assert!(order.contains(&vec!["deferred c()", "deferred a()"]));
}

#[test]
fn closures_lambdas_and_let_else() {
    let rs = get("tests/fixtures/rust/closures.rs");
    assert_eq!(names(&rs), ["f", "f::add"]);
    assert!(has_edge(&rs[0], EdgeKind::Return)); // `let ... else { return }`

    let java = get("tests/fixtures/java/Res.java");
    assert_eq!(names(&java), ["Res.run", "Res.run.job", "Res.run.<lambda>"]);
    assert!(has_edge(&java[0], EdgeKind::Exception));

    let cpp = get("tests/fixtures/cpp/lambda.cpp");
    assert_eq!(names(&cpp), ["g", "g::<lambda>"]);
}

#[test]
fn header_with_cpp_constructs_is_cpp() {
    let p = std::path::Path::new("tests/fixtures/cpp/util.h");
    let src = std::fs::read_to_string(p).unwrap();
    assert_eq!(lang::Language::detect(p), Some(lang::Language::C));
    assert_eq!(lang::Language::detect_with_source(p, &src), Some(lang::Language::Cpp));
    assert_eq!(names(&get("tests/fixtures/cpp/util.h")), ["Util::f"]);
}

#[test]
fn switch_forms_and_exhaustiveness() {
    // Go: select + type switch -> 3 + 2 case blocks, each returning
    let go = &get("tests/fixtures/go/select.go")[0];
    assert_eq!(stmt_count(go, |s| s.text.starts_with("case ") || s.text == "default"), 5);

    // Rust: `match` is exhaustive, so the head has no `false` edge to the join
    let rs = get("tests/fixtures/rust/match_let.rs");
    let r = find(&rs, "r");
    let head = r
        .graph
        .node_indices()
        .find(|&n| r.graph[n].stmts.iter().any(|s| s.text.starts_with("match ")))
        .unwrap();
    assert!(r.graph.edges(head).all(|e| *e.weight() == EdgeKind::True));
    assert_eq!(r.graph.edges(head).count(), 3);

    // Java: arrow-form switch statement lowers `throw` to an exception edge
    let java = get("tests/fixtures/java/Sw.java");
    assert!(has_edge(find(&java, "Sw.a"), EdgeKind::Exception));
    // `!x || y` -> two branch tests
    assert_eq!(stmt_count(find(&java, "Sw.b"), |s| s.kind == taintless::ir::StmtKind::Branch), 2);

    // C: `!a && b` and `a || b` -> four tests
    let c = &get("tests/fixtures/c/cond.c")[0];
    assert_eq!(stmt_count(c, |s| s.kind == taintless::ir::StmtKind::Branch), 4);

    // JS: `for await` is an ordinary loop
    assert!(has_edge(&get("tests/fixtures/javascript/async.js")[0], EdgeKind::Back));
}

fn branches(c: &Cfg) -> usize {
    stmt_count(c, |s| s.kind == taintless::ir::StmtKind::Branch)
}

/// Statement texts in blocks reachable from the entry.
fn reachable_texts(c: &Cfg) -> Vec<String> {
    let mut dfs = petgraph::visit::Dfs::new(&c.graph, c.entry);
    let mut out = vec![];
    while let Some(n) = dfs.next(&c.graph) {
        out.extend(c.graph[n].stmts.iter().map(|s| s.text.clone()));
    }
    out
}

#[test]
fn expression_level_flow_js() {
    let js = get("tests/fixtures/javascript/expr.js");
    assert_eq!(names(&js), ["<module>", "f", "g", "h", "t"]);
    // f: `a ? b?.x : (b ?? 0)` -> tests on a, b (optional) and b (nullish)
    assert_eq!(branches(find(&js, "f")), 3);
    // g: `a && b()` and `a || b` -> two tests, and `b()` only runs after the first
    assert_eq!(branches(find(&js, "g")), 2);
    // h: `o?.p?.q(1)` -> one test per `?.`
    assert_eq!(branches(find(&js, "h")), 2);
    // t: try/finally with no catch -> the finally also runs on the exception path
    let t = find(&js, "t");
    assert!(has_edge(t, EdgeKind::Exception));
    assert_eq!(stmt_count(t, |s| s.text == "done();"), 2);
}

#[test]
fn expression_level_flow_java() {
    let j = get("tests/fixtures/java/Expr.java");
    assert_eq!(names(&j), ["Expr.s", "Expr.t", "Expr.r", "Expr.f"]);
    // `return switch (k) {...}`: head + two case titles
    assert_eq!(branches(find(&j, "Expr.s")), 3);
    assert_eq!(branches(find(&j, "Expr.t")), 1);
    // the resource is closed on the normal, early-return and exception paths
    assert_eq!(stmt_count(find(&j, "Expr.r"), |s| s.text == "r.close()"), 3);
    let f = find(&j, "Expr.f");
    assert!(has_edge(f, EdgeKind::Exception));
    assert_eq!(stmt_count(f, |s| s.text == "done();"), 2);
}

#[test]
fn go_fallthrough_recover_select() {
    let go = get("tests/fixtures/go/fall.go");
    let a = find(&go, "a");
    let case1 = a.graph.node_indices().find(|&n| a.graph[n].stmts.iter().any(|s| s.text == "case 1")).unwrap();
    let out: Vec<_> = a.graph.neighbors(case1).collect();
    assert_eq!(out.len(), 1, "case 1 only falls through");
    assert!(a.graph[out[0]].stmts.iter().any(|s| s.text == "case 2"));

    // a deferred recover() turns the panic into a normal return
    let b = find(&go, "b");
    assert!(has_edge(b, EdgeKind::Return) && !has_edge(b, EdgeKind::Exception));

    let c = find(&go, "c");
    assert_eq!(stmt_count(c, |s| s.text == "case int, int64"), 1);

    // `select` has no "nothing matched" edge
    assert!(!has_edge(find(&go, "d"), EdgeKind::False));
}

#[test]
fn rust_guards_async_and_question_mark() {
    let rs = get("tests/fixtures/rust/guards_async.rs");
    assert_eq!(names(&rs), ["g", "h", "h::<async>"]);
    // guard `n > 0 && ok`: two tests, each failing over to the next arm
    assert_eq!(count_edges(find(&rs, "g"), EdgeKind::False), 2);
    // `?` in an `if` condition and in a `match` scrutinee both exit early
    assert_eq!(count_edges(find(&rs, "h"), EdgeKind::Return), 2);
    assert!(has_edge(find(&rs, "h::<async>"), EdgeKind::Return));
}

#[test]
fn c_case_ranges_and_ternary() {
    let c = get("tests/fixtures/c/ranges_ternary.c");
    assert_eq!(names(&c), ["r", "q"]);
    assert_eq!(branches(find(&c, "q")), 2); // `a ? b : 0` and `a && b`
}

#[test]
fn python_comprehension_ternary_and_guards() {
    let py = get("tests/fixtures/python/exprs.py");
    let f = &py[0];
    assert!(has_edge(f, EdgeKind::Back), "comprehension is a loop");
    let live = reachable_texts(f);
    for needle in ["ok = a and b()", "z = a if b else None", "case 2 | 3"] {
        assert!(live.iter().any(|t| t.starts_with(needle)), "{needle} must be reachable: {live:?}");
    }
    // `case 1 if b`: the guard is a branch whose failure goes to the next case
    assert!(live.iter().any(|t| t == "b"));
}
