//! Scopes, `Ref` edges, fields and inheritance in the code property graph.

use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use std::collections::BTreeSet;
use std::path::Path;
use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
use taintless::lang::{Language, build_cfgs};

fn cpg(lang: Language, file: &str, src: &str) -> Cpg {
    let cfgs = build_cfgs(lang, src).unwrap();
    Cpg::build(&[SourceFile { path: Path::new(file), lang, src, cfgs: &cfgs, imports: &[] }]).unwrap()
}

/// `kind:name@line` of a node.
fn d(c: &Cpg, n: NodeIndex) -> String {
    let x = &c.graph[n];
    format!("{}:{}@{}", x.kind.as_str(), x.name.clone().unwrap_or_default(), x.line)
}

/// `from -> to` of every edge of `kind`.
fn edges(c: &Cpg, kind: EdgeKind) -> BTreeSet<String> {
    c.graph.edge_references().filter(|e| e.weight().kind == kind).map(|e| format!("{} -> {}", d(c, e.source()), d(c, e.target()))).collect()
}

const PY: &str = "\
import os


class Base:
    def __init__(self):
        self.log = None


class Req(Base):
    cmd: str

    def __init__(self, d, r: Runner):
        self.d = d
        self.runner = r

    def go(self):
        self.runner.run()
        x = self.d
        def inner(y):
            return x + y + self.log
        os.system(x)
        return inner(self.cmd)


class Runner:
    pass
";

#[test]
fn scopes_nest_file_class_method_and_closure() {
    let c = cpg(Language::Python, "s.py", PY);
    let s = edges(&c, EdgeKind::Scope);
    for want in [
        "type_decl:Req@9 -> file:@1",
        "method:Req.go@16 -> type_decl:Req@9",
        "method:Req.go.inner@19 -> method:Req.go@16",
        "method:Base.__init__@5 -> type_decl:Base@4",
    ] {
        assert!(s.contains(want), "{want}\n{s:#?}");
    }
}

#[test]
fn names_refer_to_params_locals_and_captured_variables() {
    let c = cpg(Language::Python, "s.py", PY);
    let r = edges(&c, EdgeKind::Ref);
    // a parameter, a local, and a variable of the enclosing function (captured by `inner`)
    assert!(r.contains("identifier:d@13 -> param:d@12"), "{r:#?}");
    assert!(r.contains("identifier:x@21 -> local:x@18"), "captured: {r:#?}");
    assert!(r.contains("identifier:y@20 -> param:y@19"), "{r:#?}");
    // `os` is imported, not declared in a function: no reference
    assert!(!r.iter().any(|e| e.starts_with("identifier:os")), "{r:#?}");
    // the member of `a.b` is not a variable
    assert!(!r.iter().any(|e| e.starts_with("identifier:d@18") || e.starts_with("identifier:runner")), "{r:#?}");
}

#[test]
fn fields_have_declarations_types_and_references() {
    let c = cpg(Language::Python, "s.py", PY);
    let r = edges(&c, EdgeKind::Ref);
    // `self.d` and `self.runner` are fields assigned in `__init__`; `self.cmd` is declared in the class body
    assert!(r.contains("field_access:d@18 -> field:d@9"), "{r:#?}");
    assert!(r.contains("field_access:runner@17 -> field:runner@9"), "{r:#?}");
    assert!(r.contains("field_access:cmd@22 -> field:cmd@9"), "{r:#?}");
    // a field of the base class is found from the subclass
    assert!(r.contains("field_access:log@20 -> field:log@4"), "{r:#?}");
    let t = edges(&c, EdgeKind::TypeOf);
    assert!(t.contains("field:cmd@9 -> type:str@9"), "{t:#?}");
    assert!(t.contains("param:r@12 -> type:Runner@12"), "{t:#?}");
    // the fields live in the scope of their class
    let contains = edges(&c, EdgeKind::Contains);
    assert!(contains.contains("type_decl:Req@9 -> field:cmd@9"), "{contains:#?}");
    assert!(contains.contains("type_decl:Base@4 -> field:log@4"), "{contains:#?}");
}

#[test]
fn classes_inherit_from_their_bases() {
    let c = cpg(Language::Python, "s.py", PY);
    assert_eq!(edges(&c, EdgeKind::Inherits), BTreeSet::from(["type_decl:Req@9 -> type_decl:Base@4".to_string()]));
}

#[test]
fn bare_names_in_java_methods_are_fields_unless_shadowed() {
    let src = "\
class A {
    String cmd;
    void a() { run(cmd); }
    void b(String cmd) { run(cmd); }
    void c() { String cmd = \"x\"; run(cmd); }
}
";
    let c = cpg(Language::Java, "A.java", src);
    let r = edges(&c, EdgeKind::Ref);
    assert!(r.contains("identifier:cmd@3 -> field:cmd@1"), "{r:#?}");
    assert!(r.contains("identifier:cmd@4 -> param:cmd@4"), "{r:#?}");
    assert!(r.contains("identifier:cmd@5 -> local:cmd@5"), "{r:#?}");
    assert!(!r.contains("identifier:cmd@4 -> field:cmd@1") && !r.contains("identifier:cmd@5 -> field:cmd@1"), "{r:#?}");
}

#[test]
fn symbol_edges_are_exported() {
    use taintless::export::cpg::{select, to_json};
    let c = cpg(Language::Python, "s.py", PY);
    for kind in [EdgeKind::Scope, EdgeKind::Ref, EdgeKind::Inherits] {
        let v = to_json(&c, &select(&c, &[kind], None));
        assert!(!v["edges"].as_array().unwrap().is_empty(), "{}", kind.as_str());
        assert_eq!(EdgeKind::parse(kind.as_str()), Some(kind));
    }
}

#[test]
fn a_class_without_methods_still_inherits() {
    let java = cpg(Language::Java, "A.java", "interface Runner { void run(); }\nclass Base { void wake() {} }\nclass Dog extends Base implements Runner { public void run() {} }\nclass Empty extends Base {}\n");
    assert_eq!(
        edges(&java, EdgeKind::Inherits),
        BTreeSet::from(["type_decl:Dog@3 -> type_decl:Base@2", "type_decl:Dog@3 -> type_decl:Runner@1", "type_decl:Empty@4 -> type_decl:Base@2"].map(String::from))
    );
    let cpp = cpg(Language::Cpp, "a.cpp", "struct Base { void wake() {} };\nstruct Empty : Base {};\n");
    assert_eq!(edges(&cpp, EdgeKind::Inherits), BTreeSet::from(["type_decl:Empty@2 -> type_decl:Base@1".to_string()]));
    let ts = cpg(Language::TypeScript, "a.ts", "class Base { wake() {} }\nclass Empty extends Base {}\n");
    assert_eq!(edges(&ts, EdgeKind::Inherits), BTreeSet::from(["type_decl:Empty@2 -> type_decl:Base@1".to_string()]));
}

#[test]
fn go_types_inherit_what_they_embed_and_the_interfaces_they_satisfy() {
    let src = "package p\n\ntype Runner interface{ Run() }\ntype Waker interface{ Wake(); Run() }\ntype Base struct{}\nfunc (b Base) Wake() {}\ntype Dog struct{ Base }\nfunc (d Dog) Run() {}\ntype Rock struct{}\nfunc (r Rock) Run() {}\ntype Empty struct{ Base }\n";
    let c = cpg(Language::Go, "a.go", src);
    assert_eq!(
        edges(&c, EdgeKind::Inherits),
        BTreeSet::from([
            // embedded types
            "type_decl:Dog@7 -> type_decl:Base@5",
            "type_decl:Empty@11 -> type_decl:Base@5",
            // by shape: Dog has Run itself and Wake from Base; Rock lacks Wake; Empty lacks Run
            "type_decl:Dog@7 -> type_decl:Runner@3",
            "type_decl:Dog@7 -> type_decl:Waker@4",
            "type_decl:Rock@9 -> type_decl:Runner@3",
        ].map(String::from))
    );
}
