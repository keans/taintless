//! The node kinds each language sends through the `Spec` kind hooks. A grammar update that
//! renames or adds a kind shows up here instead of silently changing the lowered CFGs.

use taintless::ir::StmtKind;
use taintless::lang::common::Spec;
use taintless::lang::{c, go, java, js, python, rust};
use std::collections::BTreeSet;
use tree_sitter::{Language, Node, Parser};

/// `(comment kinds, subscript kinds, call kinds, assignment kinds)` the hooks pick out of `src`.
fn kinds(spec: &impl Spec, lang: Language, src: &str) -> [String; 4] {
    let mut parser = Parser::new();
    parser.set_language(&lang).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let mut sets: [BTreeSet<String>; 4] = Default::default();
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        let mut visit = |i: usize, hit: bool| {
            if hit {
                sets[i].insert(n.kind().to_string());
            }
        };
        visit(0, spec.is_comment(n));
        visit(1, spec.is_subscript(n));
        visit(2, spec.expr_kind(n) == StmtKind::Call);
        visit(3, spec.expr_kind(n) == StmtKind::Assign);
        let mut c = n.walk();
        stack.extend(n.children(&mut c).collect::<Vec<Node>>());
    }
    sets.map(|s| s.into_iter().collect::<Vec<_>>().join(" "))
}

#[test]
fn python() {
    let src = "# c\nx = a[0]\nx += 1\ny = f(1) if x else g()\nz = Foo()\n";
    let got = kinds(&python::Python, tree_sitter_python::LANGUAGE.into(), src);
    assert_eq!(got, ["comment", "subscript", "call", "assignment augmented_assignment"]);
}

#[test]
fn javascript() {
    let src = "// c\n/* d */\nx = a[0];\nx += 1;\nlet y = f(1) ? new Foo() : await g();\nb?.c();\n";
    let got = kinds(&js::Js, tree_sitter_javascript::LANGUAGE.into(), src);
    assert_eq!(got, ["comment", "subscript_expression", "call_expression new_expression", "assignment_expression augmented_assignment_expression"]);
}

#[test]
fn typescript() {
    let src = "// c\nx = a[0];\nlet y: number = f(1) ? 1 : 2;\nx!.y();\n";
    let got = kinds(&js::Js, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), src);
    assert_eq!(got, ["comment", "subscript_expression", "call_expression", "assignment_expression"]);
}

#[test]
fn rust() {
    let src = "// c\n/* d */\nfn f() { let x = a[0]; x += 1; y = g(1); m!(1); let z = if c { h() } else { 1 }; s.t(); x?; w.await; }\n";
    let got = kinds(&rust::RustSpec, tree_sitter_rust::LANGUAGE.into(), src);
    assert_eq!(got, ["block_comment line_comment", "index_expression", "call_expression macro_invocation", "assignment_expression compound_assignment_expr"]);
}

#[test]
fn go() {
    let src = "package p\n// c\nfunc f() { x = a[0]; x += 1; y := g(1); s.t(); x++ }\n";
    let got = kinds(&go::Go, tree_sitter_go::LANGUAGE.into(), src);
    assert_eq!(got, ["comment", "index_expression", "call_expression", "assignment_statement"]);
}

#[test]
fn java() {
    let src = "class A { // c\n /* d */ void f() { x = a[0]; x += 1; int y = g(1); new Foo(); s.t(); var z = c ? h() : 1; } }\n";
    let got = kinds(&java::Java, tree_sitter_java::LANGUAGE.into(), src);
    assert_eq!(got, ["block_comment line_comment", "array_access", "method_invocation object_creation_expression", "assignment_expression"]);
}

#[test]
fn c_and_cpp() {
    let src = "// c\n/* d */\nvoid f() { x = a[0]; x += 1; int y = g(1); s.t(); p->u(); x++; int z = c ? h() : 1; }\n";
    let got = kinds(&c::CLike, tree_sitter_c::LANGUAGE.into(), src);
    assert_eq!(got, ["comment", "subscript_expression", "call_expression", "assignment_expression"]);
    let got = kinds(&c::CLike, tree_sitter_cpp::LANGUAGE.into(), &format!("{src}void g() {{ new Foo(); auto l = [](){{}}; }}\n"));
    assert_eq!(got, ["comment", "subscript_argument_list subscript_expression", "call_expression new_expression", "assignment_expression"]);
}
