//! Aliases and the effects of calls in the code property graph: `Reaching` edges that follow
//! aliases, `ParamOut` / `Capture` edges across calls, keyword arguments, and the call-site
//! precision of the taint query.

use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use std::collections::BTreeSet;
use std::path::Path;
use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
use taintless::cpg::taint::taint_flows;
use taintless::lang::{Language, build_cfgs};

fn cpg(lang: Language, src: &str) -> Cpg {
    let cfgs = build_cfgs(lang, src).unwrap();
    Cpg::build(&[SourceFile { path: Path::new("t"), lang, src, cfgs: &cfgs, imports: &[] }]).unwrap()
}

fn d(c: &Cpg, n: NodeIndex) -> String {
    let x = &c.graph[n];
    format!("{}@{}", x.code, x.line)
}

/// `from -> to [var]` of every edge of `kind`.
fn edges(c: &Cpg, kind: EdgeKind) -> BTreeSet<String> {
    c.graph
        .edge_references()
        .filter(|e| e.weight().kind == kind)
        .map(|e| format!("{} -> {} [{}]", d(c, e.source()), d(c, e.target()), e.weight().var.clone().unwrap_or_default()))
        .collect()
}

/// The lines the taint query reports.
fn lines(src: &str) -> Vec<usize> {
    let c = cpg(Language::Python, src);
    let mut v: Vec<usize> = taint_flows(&c).into_iter().map(|t| t.line).collect();
    v.dedup();
    v
}

#[test]
fn js_and_go_literal_entries_are_separate_in_cpg_taint() {
    for (lang, src, want) in [
        (Language::JavaScript, include_str!("elements/objects.js"), vec![11, 15]),
        (Language::TypeScript, include_str!("elements/objects.ts"), vec![11, 15]),
        (Language::Go, include_str!("elements/composites.go"), vec![9, 17]),
    ] {
        let c = cpg(lang, src);
        let mut got: Vec<_> = taint_flows(&c).into_iter().map(|f| f.line).collect();
        got.sort_unstable();
        assert_eq!(got, want, "{lang:?}");
    }
}

const HEAD: &str = "import os\n\nclass Req:\n    def __init__(self, d):\n        self.d = d\n\n";

fn reaching(src: &str) -> BTreeSet<String> {
    edges(&cpg(Language::Python, src), EdgeKind::Reaching)
}

#[test]
fn aliases_are_resolved_in_reaching_edges() {
    let src = format!(
        "{HEAD}def f():\n    a = Req('x')\n    b = a\n    b.d = input()\n    os.system(a.d)\n\n\
         def g():\n    a = Req('x')\n    h = Req('y')\n    h.r = a\n    h.r.d = input()\n    os.system(a.d)\n\n\
         def i():\n    a = Req('x')\n    xs = [a]\n    xs[0].d = input()\n    os.system(a.d)\n\n\
         def ident(o):\n    return o\n\n\
         def j():\n    a = Req('x')\n    b = ident(a)\n    b.d = input()\n    os.system(a.d)\n"
    );
    let r = reaching(&src);
    for want in [
        "b.d = input()@10 -> os.system(a.d)@11 [a.d]",
        "h.r.d = input()@17 -> os.system(a.d)@18 [a.d]",
        "xs[0].d = input()@23 -> os.system(a.d)@24 [a.d]",
        "b.d = input()@32 -> os.system(a.d)@33 [a.d]",
    ] {
        assert!(r.contains(want), "{want}\n{r:#?}");
    }
    // an unrelated object does not
    let clean = reaching(&format!("{HEAD}def f():\n    a = Req('x')\n    b = Req('y')\n    b.d = input()\n    os.system(a.d)\n"));
    assert!(!clean.iter().any(|e| e.starts_with("b.d = input()") && e.contains("os.system(a.d)")), "{clean:#?}");
}

#[test]
fn what_a_callee_stores_for_its_caller_is_a_param_out_edge() {
    let src = format!(
        "{HEAD}def fill(o):\n    o.d = input()\n\n\
         def f():\n    a = Req('x')\n    fill(a)\n    os.system(a.d)\n\n\
         def g(c):\n    r = Req(c)\n    os.system(r.d)\n\n\
         def h():\n    cmd = ''\n    def load():\n        nonlocal cmd\n        cmd = input()\n    load()\n    os.system(cmd)\n"
    );
    let c = cpg(Language::Python, &src);
    let out = edges(&c, EdgeKind::ParamOut);
    assert!(out.contains("o.d = input()@8 -> fill(a)@12 [o.d>a.d]"), "{out:#?}");
    assert!(out.contains("self.d = d@5 -> r = Req(c)@16 [self.d>r.d]"), "constructor: {out:#?}");
    assert!(out.contains("cmd = input()@23 -> load()@24 [cmd>cmd]"), "closure: {out:#?}");
    // the call defines the variable for the reads after it
    let r = edges(&c, EdgeKind::Reaching);
    assert!(r.contains("fill(a)@12 -> os.system(a.d)@13 [a.d]"), "{r:#?}");
    assert!(r.contains("load()@24 -> os.system(cmd)@25 [cmd]"), "{r:#?}");
}

#[test]
fn closures_read_captured_variables_at_entry() {
    let src = "import os\n\ndef run():\n    cmd = input()\n    go = lambda: os.system(cmd)\n    go()\n";
    let c = cpg(Language::Python, src);
    let cap = edges(&c, EdgeKind::Capture);
    assert!(cap.iter().any(|e| e.contains("go()@6") && e.ends_with("[cmd]")), "{cap:#?}");
    assert!(cap.iter().any(|e| e.contains("go = lambda") && e.ends_with("[cmd]")), "{cap:#?}");
    assert_eq!(lines(src), [5]);
}

#[test]
fn keyword_arguments_bind_parameters_by_name() {
    let src = "import os\n\ndef run(a, b):\n    os.system(b)\n\ndef main():\n    run(b=input(), a='x')\n    run('x', 'y')\n";
    let c = cpg(Language::Python, src);
    let p = edges(&c, EdgeKind::ParamIn);
    // the first argument (`b=..`) binds `b`, the second binds `a`
    assert!(p.iter().any(|e| e.contains("run(b=input(), a='x')") && e.ends_with("[b]")), "{p:#?}");
    assert_eq!(lines(src), [4]);
    // by position the same call would taint `a`, which is never run
    let swapped = "import os\n\ndef run(a, b):\n    os.system(b)\n\ndef main():\n    run(a=input(), b='x')\n";
    assert!(lines(swapped).is_empty(), "{:?}", lines(swapped));
}

#[test]
fn what_one_call_hands_over_does_not_come_out_of_another() {
    // `Req(input())` and `Req("ls")` build different objects
    let src = format!("{HEAD}def tainted():\n    r = Req(input())\n    os.system(r.d)\n\ndef clean():\n    r = Req('ls')\n    os.system(r.d)\n");
    assert_eq!(lines(&src), [9], "{src}");
    // the same for a function that hands its argument back
    let src = "import os\n\ndef ident(x):\n    return x\n\ndef a():\n    os.system(ident(input()))\n\ndef b():\n    os.system(ident('ls'))\n";
    assert_eq!(lines(src), [7]);
}

#[test]
fn a_call_through_a_parameter_calls_what_the_callers_pass() {
    let src = "import os\n\ndef sink(x):\n    os.system(x)\n\ndef apply(fn, x):\n    fn(x)\n\ndef main():\n    apply(sink, input())\n    apply(lambda v: os.system(v), input())\n";
    let c = cpg(Language::Python, src);
    let calls: Vec<String> = c
        .graph
        .edge_references()
        .filter(|e| e.weight().kind == EdgeKind::Call && e.weight().label == Some("param"))
        .map(|e| format!("{} -> {}", d(&c, e.source()), c.graph[e.target()].name.clone().unwrap_or_default()))
        .collect();
    assert!(calls.iter().any(|e| e.starts_with("fn(x)@7") && e.ends_with("-> sink")), "{calls:#?}");
    assert!(calls.iter().any(|e| e.starts_with("fn(x)@7") && e.contains("lambda")), "{calls:#?}");
    assert_eq!(lines(src), [4, 11]);
}

#[test]
fn elements_of_a_literal_are_separate_variables() {
    let src = "import os\n\ndef a():\n    xs = ['ls', input()]\n    os.system(xs[0])\n\ndef b():\n    xs = ['ls', input()]\n    os.system(xs[1])\n\ndef c():\n    xs = ['ls', 'ls']\n    xs[1] = input()\n    os.system(xs[0])\n    os.system(xs[1])\n";
    assert_eq!(lines(src), [9, 15]);
}

/// `from -> to [var] label` of the `Reaching` edges that cross functions.
fn between(c: &Cpg) -> BTreeSet<String> {
    c.graph
        .edge_references()
        .filter(|e| e.weight().kind == EdgeKind::Reaching && e.weight().label.is_some())
        .map(|e| format!("{} -> {} [{}] {}", d(c, e.source()), d(c, e.target()), e.weight().var.clone().unwrap_or_default(), e.weight().label.unwrap()))
        .collect()
}

const INTER: &str = "import os

class Box:
    def __init__(self):
        self.cmd = ''

    def put(self, c):
        self.cmd = c

    def run(self):
        os.system(self.cmd)

def ident(x):
    return x

def main():
    b = Box()
    v = input()
    b.put(v)
    b.run()
    w = ident(v)
    os.system(w)

def apply(fn, x):
    return fn(x)

def cb(y):
    return y

def other():
    z = apply(cb, input())
";

#[test]
fn definitions_reach_across_functions() {
    let c = cpg(Language::Python, INTER);
    let r = between(&c);
    for want in [
        // arguments reach the parameters they bind
        "v = input()@18 -> c@7 [c] param_in",
        "v = input()@18 -> x@13 [x] param_in",
        // the object a method is called on reaches the method's receiver, also after another call stored in it
        "b = Box()@17 -> def put(self, c):@7 [self] param_in",
        "b.put(v)@19 -> def run(self):@10 [self] param_in",
        // a value made in the call itself comes from the call statement
        "z = apply(cb, input())@31 -> x@24 [x] param_in",
        // returns reach the call and the variable it is assigned to
        "return x@14 -> w = ident(v)@21 [w] return",
        "return fn(x)@25 -> z = apply(cb, input())@31 [z] return",
        // what a callee stores for its caller reaches the call: a method, a constructor
        "self.cmd = c@8 -> b.put(v)@19 [b.cmd] param_out",
        "self.cmd = ''@5 -> b = Box()@17 [b.cmd] param_out",
        // what a method stores in a field of its receiver reaches the methods that read it
        "self.cmd = c@8 -> def run(self):@10 [self.cmd] field",
        // calls through a parameter: the argument reaches the callback, its return reaches the call
        "x@24 -> y@27 [y] param_in",
        "return y@28 -> return fn(x)@25 [<return>] return",
    ] {
        assert!(r.contains(want), "{want}\n{r:#?}");
    }
    // edges inside one function carry no label
    let inside = edges(&c, EdgeKind::Reaching);
    assert!(inside.contains("v = input()@18 -> b.put(v)@19 [v]"), "{inside:#?}");
}

#[test]
fn interprocedural_edges_stay_out_of_the_taint_query() {
    // the labelled edges describe flows between functions; the query follows calls itself
    assert_eq!(lines(INTER), [11, 22]);
}
