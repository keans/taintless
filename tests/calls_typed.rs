mod common;
use common::taintless;

fn calls() -> String {
    let out = taintless(&["calls", "tests/callgraph/typed", "--format", "text"]);
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn calls_follow_return_types_fields_and_copies() {
    let t = calls();
    // r = make() with `-> Runner`, then r.run() and a copy t = r; t.run()
    assert!(t.contains("main (line 31) -> make, Runner.run x2, Svc.__init__, Svc.go"), "{t}");
    // self.runner = Runner() in __init__, then self.runner.run() elsewhere
    assert!(t.contains("Svc.go (line 15) -> Runner.run"), "{t}");
    // through two fields
    assert!(t.contains("Holder.start (line 23) -> Runner.run"), "{t}");
    // a same-named method of an unrelated class is not linked
    assert!(!t.lines().any(|l| l.contains("->") && l.contains("Other.run")), "{t}");
}

#[test]
fn go_interfaces_link_to_the_types_that_satisfy_them() {
    let t = calls();
    // use(r Runner) calls r.Run(): A and B have Run, C does not
    assert!(t.contains("use (line 20) -> A.Run, B.Run"), "{t}");
}

#[test]
fn declared_locals_and_fields_type_the_receiver() {
    let out = taintless(&["calls", "tests/callgraph/decl", "--format", "text"]);
    let t = String::from_utf8(out.stdout).unwrap();
    // `Runner x = make()` / `x: Runner = make()` / `const x: Runner = ..` and a declared field
    // type the receiver, so the unrelated `Other.run` is never linked
    for file in ["Svc.java", "app.py", "svc.ts"] {
        let block = block(&t, file);
        assert!(block.iter().any(|l| l.contains("Svc.go") && l.contains("-> Runner.run") && !l.contains("Other")), "{file}: {t}");
        assert!(block.iter().any(|l| l.contains("Svc.local") && l.contains("Runner.run") && !l.contains("Other")), "{file}: {t}");
    }
}

#[test]
fn typescript_parameter_types_are_understood() {
    let out = taintless(&["calls", "tests/callgraph/decl/svc.ts", "--format", "json"]);
    assert!(out.status.success());
}

#[test]
fn declared_types_in_go_rust_and_cpp_type_the_receiver() {
    let out = taintless(&["calls", "tests/callgraph/decl", "--format", "text"]);
    let t = String::from_utf8(out.stdout).unwrap();
    // `var x Runner`, `let x: Runner`, `Runner x;`, and fields declared as `*Runner`,
    // `Option<Box<Runner>>`, `std::shared_ptr<Runner>` (wrappers are looked through)
    for (file, sep) in [("svc.go", "."), ("svc.rs", "::"), ("svc.cpp", "::")] {
        let block = block(&t, file);
        for m in ["go_", "local"] {
            let want = format!("Svc{sep}{m}");
            let line = block.iter().find(|l| l.contains(&want)).unwrap_or_else(|| panic!("{file}: {t}"));
            assert!(line.contains(&format!("-> Runner{sep}run")) && !line.contains("Other"), "{file} {m}: {t}");
        }
    }
}

#[test]
fn reassigned_callable_variable_does_not_keep_old_target() {
    let out = taintless(&["calls", "tests/callgraph/reassign.py", "--format", "text"]);
    assert!(out.status.success());
    let t = String::from_utf8(out.stdout).unwrap();
    assert!(!t.lines().any(|line| line.contains("caller (line") && line.contains("handler")), "{t}");
}

/// The indented lines under a file's header in the text call graph.
fn block<'a>(t: &'a str, file: &str) -> Vec<&'a str> {
    t.lines().skip_while(|l| !l.ends_with(file)).skip(1).take_while(|l| l.starts_with("  ")).collect()
}

#[test]
fn declarations_in_other_files_and_aliases_type_the_receiver() {
    // the struct / class is declared in one file, its methods live in another;
    // `R` / `T` are aliases of `Runner`
    for (dir, sep, methods) in [
        ("go", ".", ["Svc.viaField", "Svc.viaAlias", "viaAliasParam"]),
        ("rs", "::", ["Svc::via_field", "Svc::via_alias", "via_alias_param"]),
        ("cpp", "::", ["Svc::viaField", "Svc::viaAlias", "viaAliasParam"]),
    ] {
        let out = taintless(&["calls", &format!("tests/link/{dir}"), "--format", "text"]);
        let t = String::from_utf8(out.stdout).unwrap();
        for m in methods {
            let line = t.lines().find(|l| l.trim_start().starts_with(&format!("{m} "))).unwrap_or_else(|| panic!("{dir} {m}: {t}"));
            assert!(line.contains(&format!("-> Runner{sep}run")) && !line.contains("Other"), "{dir} {m}: {t}");
        }
    }
    let out = taintless(&["calls", "tests/link/cpp", "--format", "text"]);
    let t = String::from_utf8(out.stdout).unwrap();
    assert!(t.lines().any(|l| l.contains("Svc::viaTypedef") && l.contains("-> Runner::run") && !l.contains("Other")), "typedef: {t}");
}

#[test]
fn defined_go_types_have_the_fields_of_their_base_and_python_aliases_resolve() {
    let calls = |dir: &str| String::from_utf8(taintless(&["calls", &format!("tests/link/{dir}"), "--format", "text"]).stdout).unwrap();
    // `type H Holder` has Holder's fields (`h.r.run()` reaches Runner.run)
    let t = calls("go");
    assert!(t.lines().any(|l| l.trim_start().starts_with("H.viaDefined ") && l.contains("-> Runner.run") && !l.contains("Other")), "{t}");
    // `R = Runner`, `T: TypeAlias = Runner`, `type U = Runner`
    let t = calls("py");
    for f in ["via_alias", "via_annotated", "via_statement"] {
        assert!(t.lines().any(|l| l.trim_start().starts_with(&format!("{f} ")) && l.contains("-> Runner.run") && !l.contains("Other")), "{f}: {t}");
    }
}

#[test]
fn library_users_get_linked_declarations_without_an_extra_call() {
    use std::path::Path;
    let files = [
        (Path::new("types.go"), "package main\ntype Runner struct{}\ntype R = Runner\n"),
        (Path::new("svc.go"), "package main\nfunc f(a R) { a.run() }\n"),
        (Path::new("note.txt"), "not code"),
    ];
    let out = taintless::analysis::link::analyze_sources(&files);
    assert!(out[2].is_none());
    let f = out[1].as_ref().unwrap().cfgs.iter().find(|c| c.name == "f").unwrap();
    assert!(f.param_types.iter().any(|(n, t)| n == "a" && t == "Runner"), "{:?}", f.param_types);
}

#[test]
fn a_name_declared_in_two_scopes_has_the_type_in_effect_at_each_use() {
    // `Run` is a sink only on `A`; the calls that go through `B` must not be reported
    let scan = |d: &str| String::from_utf8(taintless(&["security", &format!("tests/shadow/{d}")]).stdout).unwrap();
    // Go: `var x A` then a nested `var x B`: the inner call is a `B`, the outer one an `A`
    let t = scan("go_outer_a");
    assert!(t.contains("os.Args[2]") && !t.contains("os.Args[1]"), "{t}");
    // ... and the other way round
    let t = scan("go_inner_a");
    assert!(t.contains("os.Args[1]") && !t.contains("os.Args[2]"), "{t}");
    // Java: the same name declared in two sibling blocks
    let t = scan("java_inner_a");
    assert!(t.contains("at S.java:13") && !t.contains("S.java:16"), "{t}");
    let t = scan("java_outer_a");
    assert!(t.contains("at S.java:16") && !t.contains("S.java:13"), "{t}");
    // the call graph keeps one target per call: both are reached from the function that shadows
    let out = taintless(&["calls", "tests/link/go", "--format", "text"]);
    let t = String::from_utf8(out.stdout).unwrap();
    let line = t.lines().find(|l| l.contains("Svc.shadowed")).unwrap();
    assert!(line.contains("Runner.run") && line.contains("Other.run"), "{t}");
}

/// The call graph text of a fixture directory.
fn calls_in(dir: &str) -> String {
    let out = taintless(&["calls", dir, "--format", "text"]);
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn calls_through_containers_reach_what_was_put_in() {
    let t = calls_in("tests/containers");
    // a module-level dict, a local dict with a later key, a list that is appended to, an iterated list
    for f in ["dispatch", "local_table"] {
        assert!(t.contains(&format!("{f} (line")) && t.lines().any(|l| l.contains(&format!("  {f} (line")) && l.contains("-> start [by reference], stop [by reference]")), "{f}: {t}");
    }
    assert!(t.lines().any(|l| l.contains("  appended (line") && l.contains("start x2 [by reference], stop x2 [by reference]")), "{t}");
    // fields hold what the methods put in them
    assert!(t.contains("Bus.emit (line 66) -> start [by reference]"), "{t}");
    // the classes in a list: both are called, an unrelated class with the same method is not
    assert!(t.contains("objects (line 49) -> Runner.run, Worker.run"), "{t}");
    assert!(!t.lines().any(|l| l.contains("->") && l.contains("Idle.run")), "{t}");
    // something unknown in the container: no guess
    assert!(t.lines().any(|l| l.ends_with("unknown_element (line 55)")), "{t}");
    // never leaks to functions that were not stored
    assert!(!t.lines().any(|l| (l.contains("  dispatch (line 31)") || l.contains("local_table") || l.contains("appended (")) && l.contains("other [")), "{t}");
}

#[test]
fn calls_through_containers_in_other_languages() {
    let t = calls_in("tests/containers");
    // JavaScript object / array, Go map / append, Rust Vec
    assert!(t.contains("dispatch (line 6) -> open [by reference], close [by reference]"), "{t}");
    assert!(t.contains("each (line 10) -> open [by reference], close [by reference]"), "{t}");
    assert!(t.contains("dispatch (line 6) -> up [by reference], down [by reference]"), "{t}");
    assert!(t.contains("each (line 11) -> up x2 [by reference], down x3 [by reference]"), "{t}");
    assert!(t.contains("dispatch (line 4) -> alpha x3 [by reference], beta x3 [by reference]"), "{t}");
    // a container handed to another function hands over what it holds
    assert!(t.contains("handed (line 17) -> open [by reference]"), "{t}");
}

#[test]
fn go_interfaces_use_the_declared_method_set() {
    let t = calls_in("tests/ifaces");
    // a field declared with an interface, never a parameter: B has Run but not Stop, so it is no Runner
    assert!(t.contains("Svc.Go (line 37) -> A.Run\n"), "{t}");
    // a local declared with the interface
    assert!(t.contains("local (line 42) -> A.Run\n"), "{t}");
    // embedded interfaces count: Both = Close + Run
    assert!(t.contains("embedded (line 47) -> A.Run, C.Run"), "{t}");
}

#[test]
fn literal_keys_pick_their_element() {
    let t = calls_in("tests/containers");
    // `table["a"]()` and `hs[1]()` reach one element; an element added at an unknown position joins every key
    assert!(t.contains("keyed_dict (line 71) -> start [by reference]\n"), "{t}");
    assert!(t.contains("keyed_list (line 76) -> stop [by reference]\n"), "{t}");
    assert!(t.contains("appended_position (line 81) -> stop x2 [by reference], start [by reference]\n"), "{t}");
    // JavaScript object literal keys
    let js = t.lines().find(|l| l.contains("keyed (line 22)")).unwrap();
    assert!(js.contains("close [by reference]") && !js.contains("open [by reference]"), "{js}");
}

#[test]
fn constant_computed_key_picks_its_element() {
    let t = calls_in("tests/containers");
    let line = t.lines().find(|l| l.contains("computed_constant_key (line")).unwrap();
    assert!(line.contains("start [by reference]") && !line.contains("stop"), "{line}");
    let unknown = t.lines().find(|l| l.contains("computed_unknown_key (line")).unwrap();
    assert!(unknown.contains("start [by reference]") && unknown.contains("stop [by reference]"), "{unknown}");
}

#[test]
fn containers_returned_passed_and_iterated_as_pairs() {
    let t = calls_in("tests/containers");
    // `table = make_table(); table.values()`
    assert!(t.contains("returned (line 91) -> make_table, start [by reference], stop [by reference]\n"), "{t}");
    // `run_all([start, other])`: the parameter holds what the caller passes
    assert!(t.contains("run_all (line 97) -> start [by reference], other [by reference]\n"), "{t}");
    // `for name, h in COMMANDS.items()`
    assert!(t.contains("items (line 106) -> items, start [by reference], stop [by reference]\n"), "{t}");
}

#[test]
fn go_interfaces_are_satisfied_through_embedded_structs() {
    let t = calls_in("tests/ifaces");
    // Dog gets Wake from the embedded Base; Rock has no Wake
    assert!(t.contains("alarm (line 23) -> Base.Wake\n"), "{t}");
    assert!(t.contains("direct (line 27) -> Base.Wake\n"), "{t}");
    assert!(t.contains("embedded_only (line 35) -> Base.Wake\n"), "{t}");
}

#[test]
fn containers_filled_by_callees_and_pair_keys() {
    let t = calls_in("tests/containers");
    // `fill(hooks)` appends to the list it is given
    assert!(t.contains("filled_in_place (line 116) -> start x2 [by reference], stop x2 [by reference], fill\n"), "{t}");
    // `for name, h in COMMANDS.items(): name()`: the key is not a function
    let line = t.lines().find(|l| l.contains("pair_key (line 123)")).unwrap();
    assert!(!line.contains("start") && !line.contains("stop"), "{line}");
}

/// `caller -> callee@line` for every call edge of a fixture directory.
fn call_lines(dir: &str) -> std::collections::BTreeSet<String> {
    let out = taintless(&["calls", dir, "--format", "json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let name = |i: &serde_json::Value| v["functions"][i.as_u64().unwrap() as usize]["name"].as_str().unwrap().to_string();
    let mut set = std::collections::BTreeSet::new();
    for e in v["calls"].as_array().unwrap() {
        for l in e["lines"].as_array().unwrap() {
            set.insert(format!("{} -> {}@{}", name(&e["from"]), name(&e["to"]), l));
        }
    }
    set
}

#[test]
fn a_shadowed_variable_keeps_one_class_per_scope() {
    let t = call_lines("tests/scopes");
    let has = |s: &str| t.contains(s);
    // the outer `x` is an A again once the inner block with a B ends: one target per call
    for (inner, outer) in [
        ("outer_resumes -> B.run@13", "outer_resumes -> A.run@15"),
        ("outer_resumes -> B::run@18", "outer_resumes -> A::run@20"),
        ("outerResumes -> B.Run@16", "outerResumes -> A.Run@18"),
    ] {
        assert!(has(inner) && has(outer), "{t:?}");
    }
    assert!(!has("outer_resumes -> B.run@15") && !has("outer_resumes -> A.run@13"), "{t:?}");
    assert!(!has("outer_resumes -> B::run@20") && !has("outerResumes -> B.Run@18"), "{t:?}");
    // sibling scopes
    assert!(has("sibling -> A.run@5") && has("sibling -> B.run@6") && !has("sibling -> B.run@5") && !has("sibling -> A.run@6"), "{t:?}");
}

#[test]
fn a_variable_given_different_classes_has_the_one_the_flow_gives_it() {
    let t = call_lines("tests/scopes");
    let has = |s: &str| t.contains(s);
    // sequential reassignment
    assert!(has("sequence -> A.run@11") && has("sequence -> B.run@13") && !has("sequence -> B.run@11") && !has("sequence -> A.run@13"), "{t:?}");
    assert!(has("reassigned -> A.run@29") && !has("reassigned -> B.run@29"), "{t:?}");
    // either class after a branch, and in a loop that reassigns it
    assert!(has("branches -> A.run@21") && has("branches -> B.run@21"), "{t:?}");
    assert!(has("loop_changes_it -> A.run@27") && has("loop_changes_it -> B.run@27"), "{t:?}");
}

#[test]
fn taint_follows_the_class_of_the_variable_in_scope() {
    let out = taintless(&["security", "tests/scopes/shadow.js", "--format", "text"]);
    let t = String::from_utf8(out.stdout).unwrap();
    // only the inner `x` (a B) gets the tainted argument; the outer one is an A again, and `reassigned` ends as an A
    assert!(t.contains("via B.run() at shadow.js:22"), "{t}");
    assert!(!t.contains("shadow.js:15") && !t.contains("shadow.js:29"), "{t}");
}
