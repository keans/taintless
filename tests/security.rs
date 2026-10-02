mod common;
use common::taintless;
use taintless::analysis::{self, Finding, Severity, callgraph, rules};
use taintless::export::{callgraph as cg_export, findings};
use taintless::lang;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn check(path: &str) -> Vec<Finding> {
    let p = Path::new(path);
    let src = std::fs::read_to_string(p).unwrap();
    let l = lang::Language::detect_with_source(p, &src).unwrap();
    let cfgs = lang::build_cfgs(l, &src).unwrap();
    analysis::check_file(l, p, &cfgs)
}

/// `(function, rule)` pairs.
fn pairs(f: &[Finding]) -> BTreeSet<(String, &'static str)> {
    f.iter().map(|x| (x.function.clone(), x.rule)).collect()
}

fn has(f: &[Finding], function: &str, rule: &str, line: usize) -> bool {
    f.iter().any(|x| x.function == function && x.rule == rule && x.line == line)
}

#[test]
fn js_and_go_literal_keys_keep_clean_elements_clean() {
    let js = check("tests/elements/objects.js");
    let ts = check("tests/elements/objects.ts");
    let go = check("tests/elements/composites.go");
    let names = |findings: &[Finding]| findings.iter().map(|f| f.function.clone()).collect::<BTreeSet<_>>();
    assert_eq!(names(&js), BTreeSet::from(["taintedDot".to_string(), "taintedBracket".to_string()]));
    assert_eq!(names(&ts), names(&js));
    assert_eq!(names(&go), BTreeSet::from(["taintedMap".to_string(), "taintedSlice".to_string()]));
}

#[test]
fn python_taint_sources_sanitizers_and_flow() {
    let f = check("tests/vuln/app.py");
    // untrusted request data reaches a shell, with the right origin
    assert!(has(&f, "run", "command-injection", 10));
    assert!(has(&f, "run", "command-injection", 11));
    assert_eq!(f.iter().find(|x| x.line == 10).unwrap().origin.as_deref(), Some("request.args.get() (line 9)"));
    // `int(...)` sanitizes: line 13 must not be reported
    assert!(!f.iter().any(|x| x.line == 13));
    // only the query string (argument 0) matters, not bound parameters
    assert!(has(&f, "db", "sql-injection", 19));
    assert!(!f.iter().any(|x| x.line == 20));
    // may-analysis: one path keeps the taint
    assert!(has(&f, "branches", "command-injection", 27));
    // a plain overwrite clears it
    assert!(!f.iter().any(|x| x.function == "overwritten"));
    // loop variables and comprehensions carry taint
    assert!(has(&f, "loops", "command-injection", 49));
    assert!(has(&f, "comprehension", "command-injection", 55));
    // rules that fire regardless of data
    assert!(has(&f, "always", "code-injection", 37));
    assert!(has(&f, "always", "insecure-deserialization", 38));
    assert!(has(&f, "always", "weak-crypto", 39));
    assert!(has(&f, "dead", "unreachable-code", 44));
}

#[test]
fn clean_code_has_no_findings() {
    assert!(check("tests/vuln/clean.py").is_empty());
}

#[test]
fn other_languages() {
    let js = check("tests/vuln/app.js");
    assert_eq!(
        pairs(&js),
        BTreeSet::from([
            ("handler".to_string(), "command-injection"),
            ("handler".to_string(), "xss"),
            ("handler".to_string(), "code-injection"),
            ("handler".to_string(), "sql-injection"),
        ])
    );
    assert!(has(&js, "handler", "sql-injection", 10) && !js.iter().any(|x| x.line == 9)); // parseInt is clean

    let java = check("tests/vuln/App.java");
    assert!(has(&java, "App.handle", "sql-injection", 4));
    assert!(has(&java, "App.handle", "command-injection", 5));
    assert!(has(&java, "App.handle", "path-traversal", 8));
    assert!(!java.iter().any(|x| x.line == 7)); // Integer.parseInt

    let go = check("tests/vuln/app.go");
    assert!(has(&go, "h", "command-injection", 5));
    assert!(has(&go, "h", "sql-injection", 6));
    assert!(has(&go, "h", "path-traversal", 9));
    assert!(!go.iter().any(|x| x.line == 8)); // Atoi result through Sprintf

    let rs = check("tests/vuln/app.rs");
    assert!(has(&rs, "run", "command-injection", 3));
    assert!(has(&rs, "run", "sql-injection", 6));
    assert!(!rs.iter().any(|x| x.line == 8)); // parse() result

    let c = check("tests/vuln/app.c");
    assert!(has(&c, "main", "command-injection", 4));
    assert!(has(&c, "main", "unsafe-function", 5));
    assert!(has(&c, "main", "format-string", 6));
    assert!(has(&c, "main", "unsafe-function", 10)); // gets
    assert!(!c.iter().any(|x| x.line == 7 || x.line == 9)); // printf("%s", ..) and malloc(atoi(..))
    // strcpy is "always" but escalated to high because argv reaches it
    assert_eq!(c.iter().find(|x| x.line == 5).unwrap().severity, Severity::High);
}

#[test]
fn unreachable_code_ignores_copied_finally_bodies() {
    // `cleanup()` is copied onto several paths; its dead copies must not be reported
    let f = check("tests/fixtures/python/finally_paths.py");
    assert!(f.is_empty(), "{f:?}");
    // but statements after `return` are
    let d = check("tests/fixtures/python/dead_code.py");
    assert_eq!(d.iter().filter(|x| x.rule == "unreachable-code").count(), 2); // after each `return`
}

#[test]
fn pattern_matching() {
    use rules::matches;
    assert!(matches("eval", "eval") && !matches("eval", "obj.eval"));
    assert!(matches("os.system", "os.system") && matches("os.system", "pkg.os.system"));
    assert!(!matches("os.system", "myos.system"));
    assert!(matches("*.execute", "cursor.execute") && !matches("*.execute", "execute"));
    assert!(matches("Command.new", "std.process.Command.new"));
}

#[test]
fn cli_exit_codes_and_formats() {
    // findings -> 1, clean -> 0
    assert_eq!(taintless(&["security", "tests/vuln/app.py"]).status.code(), Some(1));
    assert_eq!(taintless(&["security", "tests/vuln/clean.py"]).status.code(), Some(0));
    // severity filter drops the low findings (md5, unreachable code)
    let all = taintless(&["security", "tests/vuln/app.py", "--format", "json"]);
    let high = taintless(&["security", "tests/vuln/app.py", "--format", "json", "--min-severity", "high"]);
    let n = |o: &std::process::Output| serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap().as_array().unwrap().len();
    assert!(n(&high) < n(&all) && n(&high) > 0);

    // SARIF 2.1.0 with every result pointing at a declared rule
    let out = taintless(&["security", "tests/vuln", "--format", "sarif"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["version"], "2.1.0");
    let run = &v["runs"][0];
    let declared: BTreeSet<_> = run["tool"]["driver"]["rules"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    let results = run["results"].as_array().unwrap();
    assert!(results.len() > 20);
    for r in results {
        assert!(declared.contains(r["ruleId"].as_str().unwrap()));
        let loc = &r["locations"][0]["physicalLocation"];
        assert!(loc["region"]["startLine"].as_u64().unwrap() >= 1);
        assert!(loc["artifactLocation"]["uri"].as_str().unwrap().starts_with("tests/vuln/"));
    }
}

#[test]
fn text_report_shape() {
    let f = check("tests/vuln/app.py");
    let t = findings::to_text(&f);
    assert!(t.contains("tests/vuln/app.py:10:5: high [command-injection]"));
    assert!(t.contains("untrusted input from request.args.get() (line 9)"));
    let sarif = findings::to_sarif(&f);
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), f.len());
}

fn load_calls() -> callgraph::CallGraph {
    let mut files: Vec<(PathBuf, lang::Language, Vec<taintless::ir::Cfg>)> = vec![];
    for name in ["a.py", "b.py"] {
        let p = PathBuf::from("tests/callgraph").join(name);
        let src = std::fs::read_to_string(&p).unwrap();
        files.push((p, lang::Language::Python, lang::build_cfgs(lang::Language::Python, &src).unwrap()));
    }
    callgraph::build(&files)
}

#[test]
fn call_graph_relations() {
    use petgraph::visit::EdgeRef;
    let cg = load_calls();
    let g = &cg.graph;
    let name = |n: petgraph::graph::NodeIndex| g[n].name.as_str();
    let edges: BTreeSet<(&str, &str)> = g.edge_references().map(|e| (name(e.source()), name(e.target()))).collect();
    assert_eq!(
        edges,
        BTreeSet::from([
            ("main", "helper"), // across files
            ("main", "local"),
            ("main", "fact"),
            ("local", "helper"),
            ("fact", "fact"), // direct recursion
            ("K.run", "K.step"), // self.step() resolved to the method
            ("K.step", "helper"),
        ])
    );
    let roots: BTreeSet<_> = cg.roots().into_iter().map(name).collect();
    assert_eq!(roots, BTreeSet::from(["main", "unused", "K.run"]));
    let rec: Vec<Vec<_>> = cg.recursive_groups().into_iter().map(|grp| grp.into_iter().map(name).collect()).collect();
    assert_eq!(rec, vec![vec!["fact"]]);
    // library calls are not edges, but are counted
    assert!(cg.external.contains_key("print") && cg.external.contains_key("open"));

    let dot = cg_export::to_dot(&cg);
    assert!(dot.starts_with("digraph calls") && dot.contains("subgraph cluster_0"));
    assert!(cg_export::to_text(&cg, true).contains("main (line 4) -> helper, local, fact"));
}

fn check_src(lang: lang::Language, src: &str) -> Vec<Finding> {
    let cfgs = lang::build_cfgs(lang, src).unwrap();
    analysis::check_file(lang, Path::new("inline"), &cfgs)
}

fn rules_of(f: &[Finding]) -> BTreeSet<&'static str> {
    f.iter().map(|x| x.rule).collect()
}

#[test]
fn rules_do_not_match_lookalikes() {
    use lang::Language::{Go, Java, JavaScript};
    // syscall.Exec is a command sink, not a database Exec
    let go = check_src(Go, "package p\nfunc f(db *sql.DB) {\n\tsyscall.Exec(os.Args[0], nil, nil)\n\tdb.Exec(os.Args[1])\n}\n");
    assert!(has(&go, "f", "command-injection", 3) && has(&go, "f", "sql-injection", 4));
    assert!(!has(&go, "f", "sql-injection", 3));

    // printing to stdout is not XSS; writing to the response is
    let java = check_src(
        Java,
        "class C { void f(Req req, Resp resp) {\n System.out.println(req.getParameter(\"x\"));\n resp.getWriter().println(req.getParameter(\"x\"));\n } }",
    );
    assert!(has(&java, "C.f", "xss", 3) && !java.iter().any(|x| x.line == 2));

    // only the HTTP response is a sink, not any `.send`
    let js = check_src(JavaScript, "function f(req, res, ws) {\n ws.send(req.query.x);\n res.send(req.query.x);\n}\n");
    assert!(has(&js, "f", "xss", 3) && !js.iter().any(|x| x.line == 2));
}

#[test]
fn taint_through_helpers_loops_and_branches() {
    use lang::Language::Python;
    // taint survives string building, containers and loops until it is cleaned
    let src = "import os\ndef f():\n    parts = []\n    parts.append(input())\n    cmd = ' '.join(parts)\n    while True:\n        if cmd:\n            break\n    os.system(cmd)\n    cmd = int(cmd)\n    os.system(cmd)\n";
    let f = check_src(Python, src);
    assert!(has(&f, "f", "command-injection", 9));
    assert!(!f.iter().any(|x| x.line == 11), "int() cleans the value");
    assert_eq!(rules_of(&f), BTreeSet::from(["command-injection"]));
}

fn check_many(paths: &[&str]) -> Vec<Finding> {
    let loaded: Vec<(lang::Language, PathBuf, Vec<taintless::ir::Cfg>, Vec<lang::common::Import>)> = paths
        .iter()
        .map(|p| {
            let path = PathBuf::from(p);
            let src = std::fs::read_to_string(&path).unwrap();
            let l = lang::Language::detect_with_source(&path, &src).unwrap();
            let cfgs = lang::build_cfgs(l, &src).unwrap();
            let imports = lang::imports(l, &src).unwrap();
            (l, path, cfgs, imports)
        })
        .collect();
    let files: Vec<analysis::ProjectFile> =
        loaded.iter().map(|(l, p, c, i)| analysis::ProjectFile { lang: *l, file: p, cfgs: c, imports: i }).collect();
    analysis::check_project(&files, &|| {})
}

#[test]
fn taint_follows_calls_across_functions_and_files() {
    let f = check_many(&["tests/interproc/app.py", "tests/interproc/util.py"]);
    let at = |file: &str, line: usize| f.iter().find(|x| x.file.ends_with(file) && x.line == line);

    // a parameter that reaches a sink: reported at the sink, naming the call chain
    let sink = at("util.py", 5).expect("os.system(cmd) in run_cmd");
    assert_eq!(sink.rule, "command-injection");
    let origin = sink.origin.as_deref().unwrap();
    // one report per sink; several callers reach it, the origin names one chain
    assert!(origin.contains("request.args.get()") && origin.contains("run_cmd() at util.py") || origin.contains("run_cmd() at app.py"), "{origin}");

    // a parameter that flows to the return value
    assert!(at("app.py", 9).is_some(), "os.system(build(data))");
    // a source that comes out of the return value, with where it came from
    let o = at("app.py", 11).expect("os.system(read_input())").origin.clone().unwrap();
    assert!(o.contains("input() at util.py:13") && o.contains("returned by read_input()"), "{o}");
    // returned through recursion
    assert!(at("app.py", 17).is_some(), "recursion returns input()");

    // a callee that sanitizes, or ignores its argument, makes the call clean
    assert!(at("app.py", 12).is_none() && at("app.py", 13).is_none());
    // clean arguments are clean
    assert!(f.iter().filter(|x| x.file.ends_with("app.py")).all(|x| x.line != 15)); // run_cmd("ls")

    // two hops: main -> nested -> run_cmd -> os.system, same sink, one finding
    assert_eq!(f.iter().filter(|x| x.file.ends_with("util.py") && x.line == 5).count(), 1);
}

#[test]
fn interprocedural_js_and_rust() {
    let js = check_many(&["tests/interproc/web.js", "tests/interproc/lib.js"]);
    let sink = js.iter().find(|x| x.file.ends_with("lib.js") && x.rule == "command-injection").unwrap();
    assert!(sink.origin.as_deref().unwrap().contains("req.query.x"));
    assert_eq!(js.len(), 1, "sh(\"uptime\") is clean: {js:?}");

    let rs = check_many(&["tests/interproc/run.rs"]);
    assert_eq!(rs.iter().filter(|x| x.rule == "command-injection").count(), 1, "{rs:?}");
    assert!(rs[0].origin.as_deref().unwrap().contains("env.args"));
}

#[test]
fn single_file_analysis_is_unchanged_by_summaries() {
    // calls to unknown functions still propagate taint (no summary to consult)
    let f = check_src(lang::Language::Python, "import os\ndef f():\n    x = unknown(input())\n    os.system(x)\n");
    assert!(has(&f, "f", "command-injection", 4));
}

fn load_project(paths: &[&str]) -> Vec<(lang::Language, PathBuf, Vec<taintless::ir::Cfg>, Vec<lang::common::Import>)> {
    paths
        .iter()
        .map(|p| {
            let path = PathBuf::from(p);
            let src = std::fs::read_to_string(&path).unwrap();
            let l = lang::Language::detect_with_source(&path, &src).unwrap();
            (l, path, lang::build_cfgs(l, &src).unwrap(), lang::imports(l, &src).unwrap())
        })
        .collect()
}

#[test]
fn imports_choose_between_same_named_functions() {
    use taintless::analysis::deps::{self, DepFile};
    let loaded = load_project(&[
        "tests/imports/a.py",
        "tests/imports/b.py",
        "tests/imports/m_use_b.py",
        "tests/imports/z_use_a.py",
    ]);
    let refs: Vec<(&Path, lang::Language, &[taintless::ir::Cfg])> =
        loaded.iter().map(|(l, p, c, _)| (p.as_path(), *l, c.as_slice())).collect();
    let edge_set = |cg: &callgraph::CallGraph| -> BTreeSet<(String, String)> {
        use petgraph::visit::EdgeRef;
        cg.graph
            .edge_references()
            .map(|e| {
                let f = |n: petgraph::graph::NodeIndex| format!("{}:{}", cg.graph[n].file.file_name().unwrap().to_string_lossy(), cg.graph[n].name);
                (f(e.source()), f(e.target()))
            })
            .collect()
    };
    // by name alone `go` is ambiguous: both callers are linked to both functions
    let blind = edge_set(&callgraph::build_refs(&refs, None));
    assert!(blind.contains(&("m_use_b.py:main".into(), "a.py:go".into())));
    // with imports each caller is linked to the one it imported
    let dep_files: Vec<DepFile> = loaded
        .iter()
        .map(|(l, p, c, i)| DepFile { path: p, lang: *l, imports: i.clone(), cfgs: c })
        .collect();
    let seen = edge_set(&callgraph::build_refs(&refs, Some(deps::visibility(&dep_files))));
    assert_eq!(
        seen,
        BTreeSet::from([
            ("m_use_b.py:main".to_string(), "b.py:go".to_string()),
            ("z_use_a.py:main".to_string(), "a.py:go".to_string()),
        ])
    );

    // and so does the taint analysis: only the caller of the sink gets the finding
    let f = check_many(&["tests/imports/a.py", "tests/imports/b.py", "tests/imports/m_use_b.py", "tests/imports/z_use_a.py"]);
    let sink = f.iter().find(|x| x.file.ends_with("a.py")).expect("os.system(x) in a.go");
    let origin = sink.origin.as_deref().unwrap();
    assert!(origin.contains("z_use_a.py") && !origin.contains("m_use_b.py"), "{origin}");
}

#[test]
fn go_package_imports_pick_the_right_run() {
    // `pkg2.Run` must not be confused with the sink in `pkg1.Run`
    let f = check_many(&["tests/imports/pkg1/x.go", "tests/imports/pkg2/x.go", "tests/imports/main.go"]);
    assert!(f.is_empty(), "main imports pkg2 only: {f:?}");

    // control: without the imports the two `Run`s cannot be told apart
    let loaded = load_project(&["tests/imports/pkg1/x.go", "tests/imports/pkg2/x.go", "tests/imports/main.go"]);
    let blind: Vec<analysis::ProjectFile> =
        loaded.iter().map(|(l, p, c, _)| analysis::ProjectFile { lang: *l, file: p, cfgs: c, imports: &[] }).collect();
    let g = analysis::check_project(&blind, &|| {});
    assert!(g.iter().any(|x| x.rule == "command-injection"), "ambiguous by name: {g:?}");
}

fn lines(f: &[Finding]) -> Vec<usize> {
    f.iter().filter(|x| x.rule == "command-injection").map(|x| x.line).collect()
}

#[test]
fn taint_is_tracked_per_field() {
    let f = check_many(&["tests/fields/fields.py"]);
    // Job.run (constructor stored it), Req.use (another method stored it), Local.go (this method stored it)
    assert_eq!(lines(&f), [11, 25, 34], "{f:?}");
    // fields that only ever hold clean values stay clean, and a field the method overwrote is clean again
    let origin = f.iter().find(|x| x.line == 11).unwrap().origin.clone().unwrap();
    assert!(origin.contains("input() at fields.py:17") && origin.contains("field `cmd` of Job"), "{origin}");
}

#[test]
fn field_flow_between_methods_in_every_language() {
    // (file, the one command-injection line): the field written from a source in one
    // method reaches the command in another; the field that is never written does not
    for (file, line) in [
        ("tests/fields/Svc.java", 10),
        ("tests/fields/svc.go", 13),
        ("tests/fields/svc.rs", 12),
        ("tests/fields/svc.js", 9),
    ] {
        let f = check_many(&[file]);
        assert_eq!(lines(&f), [line], "{file}: {f:?}");
        assert!(f[0].origin.as_deref().unwrap().contains("field `"), "{file}: {:?}", f[0].origin);
    }
}

#[test]
fn bare_field_names_in_java_and_cpp_methods() {
    // `cmd = ..` in one method reaches `exec(cmd)` in another; a parameter named like
    // the field shadows it, and a field never written stays clean
    for (file, line) in [("tests/bare/Bare.java", 10), ("tests/bare/bare.cpp", 9)] {
        let f = check_many(&[file]);
        assert_eq!(lines(&f), [line], "{file}: {f:?}");
    }
}

#[test]
fn declared_types_pick_the_method() {
    // a factory declared to return `Runner` makes `r.go(..)` resolve to Runner.go
    for file in ["tests/types/t.py", "tests/types/T.java", "tests/types/t.go"] {
        let f = check_many(&[file]);
        assert_eq!(f.len(), 1, "{file}: {f:?}");
        assert!(f[0].origin.as_deref().unwrap().to_lowercase().contains("go() at"), "{file}: {:?}", f[0].origin);
    }
    // declared parameter types do the same; `Safe.go` has no sink
    let two = |body: &str, call: &str| {
        check_src(lang::Language::Python, &format!("import os\nclass Runner:\n    def go(self, c):\n        os.system(c)\nclass Safe:\n    def go(self, c):\n        print(c)\n{body}{call}"))
    };
    let f = two("def f(r: Runner):\n", "    r.go(input())\n");
    assert!(has(&f, "Runner.go", "command-injection", 4), "{f:?}");
    let f = two("def f(r: Safe):\n", "    r.go(input())\n");
    assert!(f.is_empty(), "{f:?}");
    let f = two("def f(r):\n", "    r.go(input())\n");
    assert!(f.is_empty(), "unknown type stays a guess: {f:?}");
}

#[test]
fn aliases_share_writes() {
    let f = check_many(&["tests/fields/alias.py"]);
    let ls = lines(&f);
    assert!(ls.contains(&13), "b.d = .. is seen through a: {f:?}");
    assert!(!ls.contains(&21), "rebinding b ends the alias: {f:?}");
    assert!(!ls.contains(&28), "b.d = \"ls\" cleans a.d too: {f:?}");
}

#[test]
fn aliases_through_calls_and_fields() {
    let f = check_many(&["tests/fields/alias_more.py"]);
    let ls = lines(&f);
    let sink = |func: &str| std::fs::read_to_string("tests/fields/alias_more.py").unwrap().lines().enumerate()
        .skip_while(|(_, l)| !l.starts_with(&format!("def {func}("))).find(|(_, l)| l.contains("os.system")).map(|(i, _)| i + 1).unwrap();
    assert!(ls.contains(&sink("through_call")), "fill(a) writes a.d: {f:?}");
    assert!(ls.contains(&sink("through_field")), "h.r = a, then h.r.d = ..: {f:?}");
    assert!(ls.contains(&sink("through_identity")), "b = identity(a): {f:?}");
    assert!(ls.contains(&sink("through_list")), "xs = [a], then xs[0].d = ..: {f:?}");
    assert!(!ls.contains(&sink("list_append_is_not_a_field_write")), "xs.append(..) does not change a.d: {f:?}");
    assert!(!ls.contains(&sink("other_element_stays_clean")), "xs[0].d = .. does not touch b = xs[1]: {f:?}");
    assert!(ls.contains(&sink("same_element_is_tainted")), "xs[1].d = .. reaches b = xs[1]: {f:?}");
    assert!(!ls.contains(&sink("clean_control")), "an unrelated object stays clean: {f:?}");
}

#[test]
fn literal_element_keys_keep_elements_apart() {
    let f = check_many(&["tests/elements/elements.py"]);
    let ls = lines(&f);
    let src = std::fs::read_to_string("tests/elements/elements.py").unwrap();
    let sink = |func: &str| src.lines().enumerate().skip_while(|(_, l)| !l.starts_with(&format!("def {func}("))).find(|(_, l)| l.contains("os.system")).map(|(i, _)| i + 1).unwrap();
    assert!(!ls.contains(&sink("clean_element_of_a_literal")), "xs = [\"ls\", input()]; xs[0] is clean: {f:?}");
    assert!(ls.contains(&sink("tainted_element_of_a_literal")), "xs[1] holds input(): {f:?}");
    assert!(!ls.contains(&sink("element_written_later")), "xs[1] = input() leaves xs[0] clean: {f:?}");
    assert!(ls.contains(&sink("unknown_index_sees_every_element")), "xs[i] may be any element: {f:?}");
}

#[test]
fn calls_dispatch_through_class_hierarchies() {
    let src = |tail: &str| {
        format!(
            "import os\nclass Base:\n    def run(self, c):\n        pass\n    def sink(self, c):\n        os.system(c)\nclass Child(Base):\n    def run(self, c):\n        os.system(c)\nclass Quiet(Base):\n    def other(self):\n        pass\n{tail}"
        )
    };
    // the object declared as Base may be a Child: its override is a possible target
    let f = check_src(lang::Language::Python, &src("def use(b: Base):\n    b.run(input())\n"));
    assert!(has(&f, "Child.run", "command-injection", 9), "{f:?}");
    // an inherited method is found on the subclass
    let f = check_src(lang::Language::Python, &src("def use():\n    q = Quiet()\n    q.sink(input())\n"));
    assert!(has(&f, "Base.sink", "command-injection", 6), "{f:?}");
    // a class that does not derive from Base is unrelated
    let f = check_src(lang::Language::Python, &src("class Alone:\n    def run(self, c):\n        pass\ndef use(a: Alone):\n    a.run(input())\n"));
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn call_graph_hierarchy_callbacks_and_sites() {
    let graph = |file: &str| {
        let p = PathBuf::from("tests/hier").join(file);
        let src = std::fs::read_to_string(&p).unwrap();
        let l = lang::Language::detect(&p).unwrap();
        let cfgs = lang::build_cfgs(l, &src).unwrap();
        callgraph::build(&[(p, l, cfgs)])
    };
    let edges = |cg: &callgraph::CallGraph| -> std::collections::BTreeSet<(String, String)> {
        cg.graph.edge_indices().map(|e| {
            let (a, b) = cg.graph.edge_endpoints(e).unwrap();
            (cg.graph[a].name.clone(), cg.graph[b].name.clone())
        }).collect()
    };
    let has = |cg: &callgraph::CallGraph, a: &str, b: &str| edges(cg).contains(&(a.to_string(), b.to_string()));
    let py = graph("h.py");
    assert!(has(&py, "Base.run", "Base.step") && has(&py, "Base.run", "Child.step"), "self.step() may be overridden");
    assert!(has(&py, "Other.run", "Base.run"), "super().run()");
    assert!(has(&py, "use", "Child.step"), "b: Base");
    assert!(has(&py, "wire", "helper"), "callback and variable");
    let w = py.graph.edge_indices().find(|&e| {
        let (a, b) = py.graph.edge_endpoints(e).unwrap();
        py.graph[a].name == "wire" && py.graph[b].name == "helper"
    }).unwrap();
    assert_eq!(py.graph[w].callback_lines, [13, 15], "register(helper) and f()");
    assert!(!has(&py, "Other.run", "Child.step"));
    let java = graph("H.java");
    assert!(has(&java, "Canvas.paint", "Circle.draw") && has(&java, "Canvas.paint", "Square.draw"), "interface dispatch");
    assert!(has(&graph("h.ts"), "A.go", "B.hook"));
    let rs = graph("h.rs");
    assert!(has(&rs, "talk", "Dog::speak") && has(&rs, "Speak::twice", "Dog::speak"), "{:?}", edges(&rs));
    assert!(has(&graph("h.cpp"), "Animal::twice", "Cat::speak"), "this->speak() with virtual dispatch");
    let json = cg_export::to_json(&py);
    assert!(json["calls"].as_array().unwrap().iter().all(|c| c["lines"].as_array().unwrap().len() == c["sites"].as_u64().unwrap() as usize));
}

#[test]
fn receiver_state_and_callbacks_in_summaries() {
    let f = check_many(&["tests/fields/hof.py"]);
    let at = |line: usize| f.iter().find(|x| x.line == line);
    // the receiver's own fields reach the sink in the method, from this very object
    let run = at(6).expect("Runner.run reads self.cmd");
    assert!(run.origin.as_deref().unwrap().contains("via Runner.run()"), "{:?}", run.origin);
    // `return self.cmd` hands the receiver's state to the caller
    assert!(at(24).is_some(), "{f:?}");
    // a function passed to a higher-order function is called with its arguments
    let named = at(45).expect("sink(x) called by apply(fn, x)");
    assert!(named.origin.as_deref().unwrap().contains("via sink() via apply()"), "{:?}", named.origin);
    assert!(at(61).is_some(), "the lambda is called by apply: {f:?}");
    // print is not a function of the project: nothing to follow, nothing invented
    assert!(f.iter().all(|x| x.line != 69), "{f:?}");

    // an assigned field no longer depends on the object it was assigned on
    let f = check_src(
        lang::Language::Python,
        "import os\nclass R:\n    def run(self):\n        self.cmd = \"ls\"\n        os.system(self.cmd)\ndef f():\n    r = R()\n    r.cmd = input()\n    r.run()\n",
    );
    assert!(f.is_empty(), "{f:?}");
    // a callback handed on through another function is still called
    let f = check_src(
        lang::Language::Python,
        "import os\ndef sink(x):\n    os.system(x)\ndef apply(fn, x):\n    fn(x)\ndef outer(g, y):\n    apply(g, y)\ndef main():\n    outer(sink, input())\n",
    );
    assert!(has(&f, "sink", "command-injection", 3), "{f:?}");
    // the same in JavaScript, Rust and Java-style closures
    let f = check_src(
        lang::Language::JavaScript,
        "function apply(fn, x) { fn(x); }\nfunction main(req) { apply(v => eval(v), req.query.q); }\n",
    );
    assert!(f.iter().any(|x| x.rule == "code-injection"), "{f:?}");
    let f = check_src(
        lang::Language::Rust,
        "use std::process::Command;\nfn apply<F: Fn(String)>(f: F, x: String) { f(x); }\nfn main() { apply(|v| { Command::new(v).status(); }, std::env::args().nth(1).unwrap()); }\n",
    );
    assert!(f.iter().any(|x| x.rule == "command-injection"), "{f:?}");
}

#[test]
fn functions_stored_in_fields_containers_and_registries() {
    let head = "import os\ndef run(cmd):\n    os.system(cmd)\ndef log(m):\n    print(m)\n";
    // (code after the helpers, does `run` get reached with untrusted data?)
    let cases: [(&str, &str, bool); 10] = [
        ("module dict", "H = {\"run\": run, \"log\": log}\ndef d(n):\n    H[n](input())\n", true),
        ("module list loop", "Q = []\nQ.append(run)\ndef d():\n    for h in Q:\n        h(input())\n", true),
        ("module registry without it", "H = {\"log\": log}\ndef d(n):\n    H[n](input())\n", false),
        ("field set in __init__", "class B:\n    def __init__(self):\n        self.cb = run\n    def fire(self, x):\n        self.cb(x)\ndef u():\n    B().fire(input())\n", true),
        ("field holding a harmless function", "class B:\n    def __init__(self):\n        self.cb = log\n    def fire(self, x):\n        self.cb(x)\ndef u():\n    B().fire(input())\n", false),
        ("field list", "class B:\n    def __init__(self):\n        self.subs = []\n        self.subs.append(run)\n    def all(self, x):\n        for s in self.subs:\n            s(x)\ndef u():\n    B().all(input())\n", true),
        ("local table", "def f():\n    t = {}\n    t[\"go\"] = run\n    t[\"go\"](input())\n", true),
        ("local alias", "def f():\n    g = run\n    g(input())\n", true),
        ("local alias to log", "def f():\n    g = log\n    g(input())\n", false),
        ("alias rebound before the call", "def f():\n    g = run\n    g = log\n    g(input())\n", false),
    ];
    for (name, body, expect) in cases {
        let f = check_src(lang::Language::Python, &format!("{head}{body}"));
        assert_eq!(f.iter().any(|x| x.rule == "command-injection"), expect, "{name}: {f:?}");
    }
    // JavaScript: handler table and a callback kept in a field
    let f = check_src(
        lang::Language::JavaScript,
        "const handlers = { run: (c) => eval(c) };\nfunction d(req) { handlers.run(req.query.q); }\n",
    );
    assert!(f.iter().any(|x| x.rule == "code-injection"), "{f:?}");
}

#[test]
fn closures_that_write_captured_variables() {
    // the closure assigns a variable of its creator's scope; calling it makes the creator see that
    let py = check_many(&["tests/captures/w.py"]);
    let lines = lines(&py);
    assert!(lines.contains(&12), "nonlocal write seen after load(): {py:?}");
    assert!(!lines.contains(&23), "without `nonlocal` the assignment is local: {py:?}");
    assert!(lines.contains(&34), "a parameter of the closure flows into the captured variable: {py:?}");
    let tainted = |f: &[Finding], line: usize| f.iter().any(|x| x.line == line && x.origin.is_some());
    let js = check_many(&["tests/captures/w.js"]);
    assert!(tainted(&js, 5), "{js:?}");
    assert!(!tainted(&js, 12), "`let code` inside the closure shadows the outer variable: {js:?}");
    let go = check_many(&["tests/captures/w.go"]);
    assert_eq!(lines_of(&go), [12], "`:=` declares, `=` assigns the captured one: {go:?}");
    let rs = check_many(&["tests/captures/w.rs"]);
    assert_eq!(lines_of(&rs), [7], "{rs:?}");
}

fn lines_of(f: &[Finding]) -> Vec<usize> {
    f.iter().map(|x| x.line).collect()
}

#[test]
fn objects_without_fields_are_unaffected() {
    // no receiver, no field facts: plain functions behave as before
    let f = check_src(lang::Language::Python, "import os\ndef f(self_like):\n    self_like.cmd = input()\n    os.system(self_like.cmd)\n");
    assert!(has(&f, "f", "command-injection", 4));
}

#[test]
fn objects_are_tracked_as_instances() {
    let f = check_many(&["tests/fields/objects.py"]);
    let at = |line: usize| f.iter().find(|x| x.line == line);
    // r = Req(input()): the instance itself, found without going through the class-level fact
    let direct = at(14).expect("os.system(r.d)");
    assert!(direct.origin.as_deref().unwrap().starts_with("input() (line 13)"), "{:?}", direct.origin);
    // another method of the class sees the field too
    assert!(at(9).is_some(), "Req.run reads self.d");
    // Req("ls") is judged by its own arguments, not by what other instances hold
    assert!(at(20).is_none(), "{f:?}");
    // y = x copies the class, so the field is still known
    assert!(at(26).is_some());
    // an explicit overwrite clears it
    assert!(at(32).is_none());
    // `rn.go(..)` resolves to Runner.go because rn is known to be a Runner (it has no constructor)
    let sink = at(37).expect("os.system(cmd) in Runner.go");
    assert!(sink.origin.as_deref().unwrap().contains("go() at objects.py:42"), "{:?}", sink.origin);
}

#[test]
fn closures_see_what_they_capture() {
    for file in ["tests/vuln/closure.py", "tests/vuln/closure.js"] {
        let f = check(file);
        assert_eq!(f.len(), 1, "{file}: {f:?}");
        assert_eq!(f[0].rule, "command-injection", "{file}");
        assert!(f[0].origin.is_some(), "{file}: names the source");
    }
}

#[test]
fn closures_report_sinks_reached_from_the_creators_parameters() {
    // run(cmd) builds a closure that runs cmd; main passes untrusted data to run
    for file in ["tests/vuln/closure_param.py", "tests/vuln/closure_param.js"] {
        let f = check(file);
        assert_eq!(f.len(), 1, "{file}: {f:?}");
        let origin = f[0].origin.as_deref().unwrap_or("");
        assert!(origin.contains("via run()"), "{file}: {origin}");
    }
}

#[test]
fn java_array_element_writes_carry_taint() {
    let java = check_src(
        lang::Language::Java,
        "class A { void f(java.util.Scanner in) throws Exception {\n String[] a = new String[2];\n a[0] = in.nextLine();\n Runtime.getRuntime().exec(a[0]);\n } }",
    );
    assert!(has(&java, "A.f", "command-injection", 4), "{java:?}");
}

#[test]
fn declared_field_types_decide_the_callee_in_taint() {
    // `s.run.Go(..)` reaches the sink through `Runner.Go`; `s.safe.Go(..)` is `Safe.Go` and does not
    let out = taintless(&["security", "tests/types/fields.go"]);
    let t = String::from_utf8(out.stdout).unwrap();
    assert_eq!(t.matches("[command-injection]").count(), 1, "{t}");
    assert!(t.contains("fields.go:26"), "{t}");
    assert!(!t.contains("fields.go:30"), "{t}");
}

#[test]
fn go_interface_calls_reach_the_types_that_satisfy_them() {
    let scan = |d: &str| String::from_utf8(common::taintless(&["security", &format!("tests/iface/{d}")]).stdout).unwrap();
    // `r.Run(tainted)` through a parameter, `s.r.Run(tainted)` through a field: `Shell.Run` is a sink
    for d in ["param", "field"] {
        let t = scan(d);
        assert!(t.contains("command-injection") && t.contains("via Shell.Run()"), "{d}: {t}");
    }
    // no type with the interface's method set reaches a sink
    assert!(!scan("clean").contains("command-injection"));
}
