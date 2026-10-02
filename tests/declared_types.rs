use std::path::Path;
use taintless::{analysis, lang::{self, Language}};

fn cases() -> Vec<(Language, &'static str, &'static str, &'static str)> {
    vec![
        (Language::Go, "go", "Runner.Run", r#"package p
import "os"
import "os/exec"
type Runner struct{}
func (r Runner) Run(x string) { exec.Command(x).Run() }
type Other struct{}
func (r Other) Run(x string) {}
type Holder struct { worker *Runner }
func (h Holder) Go() { h.worker.Run(os.Args[1]) }
func (h Holder) Local() { var r *Runner = unknown(); r.Run(os.Args[1]) }
"#),
        (Language::Rust, "rs", "Runner::run", r#"struct Runner;
impl Runner { fn run(&self, x: String) { std::process::Command::new(x); } }
struct Other;
impl Other { fn run(&self, x: String) {} }
struct Holder { worker: Box<Runner> }
impl Holder {
 fn go(&self) { self.worker.run(std::env::args().nth(1).unwrap()); }
 fn local(&self) { let r: Box<Runner> = unknown(); r.run(std::env::args().nth(1).unwrap()); }
}
"#),
        (Language::Cpp, "cpp", "Runner::run", r#"class Runner { public: void run(const char* x) { system(x); } };
class Other { public: void run(const char* x) {} };
class Holder { Runner* worker; public:
 void go() { this->worker->run(getenv("CMD")); }
 void local() { Runner* r = unknown(); r->run(getenv("CMD")); }
};
"#),
        (Language::Java, "java", "Runner.run", r#"class Runner { void run(String x) { Runtime.getRuntime().exec(x); } }
class Other { void run(String x) {} }
class Holder { Runner worker;
 void go() { this.worker.run(System.getenv("CMD")); }
 void local() { Runner r = unknown(); r.run(System.getenv("CMD")); }
}
"#),
    ]
}

#[test]
fn declared_locals_and_fields_drive_all_three_analyses() {
    for (lang, ext, sink, src) in cases() {
        let cfgs = lang::build_cfgs(lang, src).unwrap();
        let local = cfgs.iter().find(|c| c.name.ends_with("local") || c.name.ends_with("Local")).unwrap();
        assert!(local.local_types.iter().any(|(n, t)| n == "r" && t == "Runner"), "{lang:?}: {:?}", local.local_types);
        assert!(local.field_types.iter().any(|(n, t)| n == "worker" && t == "Runner"), "{lang:?}: {:?}", local.field_types);
        let file = format!("example.{ext}");
        let path = Path::new(&file);
        let cg = analysis::callgraph::build_refs(&[(path, lang, &cfgs)], None);
        for n in cg.graph.node_indices().filter(|&n| cg.graph[n].name == local.name || cg.graph[n].name.ends_with(".Go") || cg.graph[n].name.ends_with(".go") || cg.graph[n].name.ends_with("::go")) {
            let called: Vec<_> = cg.graph.neighbors(n).map(|t| cg.graph[t].name.as_str()).collect();
            assert!(called.contains(&sink) && !called.iter().any(|n| n.starts_with("Other")), "{lang:?}: {} -> {called:?}", cg.graph[n].name);
        }
        let found = analysis::check_file(lang, path, &cfgs);
        assert!(found.iter().any(|f| f.function == sink && f.rule == "command-injection"), "{lang:?}: {found:?}");
        let project = [analysis::ProjectFile { lang, file: path, cfgs: &cfgs, imports: &[] }];
        let df = analysis::dataflow::build(&project, false);
        let sink_params: Vec<_> = df.graph.node_indices().filter(|&n| df.functions[df.graph[n].func].name == sink && df.graph[n].var == "x").collect();
        assert!(sink_params.iter().any(|&n| df.graph.neighbors_directed(n, petgraph::Direction::Incoming).next().is_some()), "{lang:?}");
    }
}

#[test]
fn nested_generic_wrappers_and_whitespace() {
    for t in ["Box<Option<Runner>>", "Optional<Runner>", "std::shared_ptr < Runner >", "&'a mut Box<Runner>", "typing.Optional[Runner]", "std::optional < Runner >"] {
        assert_eq!(lang::common::type_name(t), "Runner", "{t}");
    }
}

#[test]
fn ordinary_generic_containers_keep_their_type() {
    assert_eq!(lang::common::type_name("std::vector<Runner>"), "vector");
    assert_eq!(lang::common::type_name("Map<String, Runner>"), "Map");
}

#[test]
fn declared_field_chain_resolves_even_with_many_same_named_methods() {
    let src = r#"
class Runner { void run(String x) { Runtime.getRuntime().exec(x); } }
class Other1 { void run(String x) {} }
class Other2 { void run(String x) {} }
class Other3 { void run(String x) {} }
class Inner { Runner worker; void noop() {} }
class Holder { Inner inner; void go() { this.inner.worker.run(System.getenv("CMD")); } }
"#;
    let cfgs = lang::build_cfgs(Language::Java, src).unwrap();
    let found = analysis::check_file(Language::Java, Path::new("A.java"), &cfgs);
    assert!(found.iter().any(|f| f.function == "Runner.run" && f.rule == "command-injection"), "{found:?}");
}

#[test]
fn clean_declared_target_does_not_pick_an_unrelated_sink() {
    let src = r#"
class Safe { void run(String x) {} }
class Dangerous { void run(String x) { Runtime.getRuntime().exec(x); } }
class Holder { Safe worker; void go() { this.worker.run(System.getenv("CMD")); } }
"#;
    let cfgs = lang::build_cfgs(Language::Java, src).unwrap();
    let found = analysis::check_file(Language::Java, Path::new("A.java"), &cfgs);
    assert!(!found.iter().any(|f| f.rule == "command-injection"), "{found:?}");
}
