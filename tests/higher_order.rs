use std::path::Path;
use taintless::{analysis, lang::{self, Language}};

fn findings(lang: Language, src: &str) -> Vec<analysis::Finding> {
    let cfgs = lang::build_cfgs(lang, src).unwrap();
    analysis::check_file(lang, Path::new("example"), &cfgs)
}

#[test]
fn callbacks_in_containers_and_unknown_methods() {
    for src in [
        "import os\nclass Worker:\n def handler(self, x): os.system(x)\ndef apply(fn, x): fn(x)\ndef run(obj): apply(obj.handler, input())\n",
        "import os\ndef sink(x): os.system(x)\ndef dispatch(handlers, x): handlers[0](x)\ndef relay(h, x): dispatch(h, x)\ndef run(): relay([sink], input())\n",
        "import os\ndef sink(x): os.system(x)\nclass Box:\n def fire(self, x): self.cb(x)\ndef run():\n b = Box()\n b.cb = sink\n b.fire(input())\n",
        "import os\ndef sink(x): os.system(x)\ndef dispatch(b, x): b.cb(x)\ndef run(b):\n b.cb = sink\n dispatch(b, input())\n",
        "import os\ndef sink(x): os.system(x)\ndef run(a):\n b = a\n b.cb = sink\n a.cb(input())\n",
        "import os\ndef sink(x): os.system(x)\ndef install(b, f): b.cb = f\ndef relay(b, f): install(b, f)\ndef run(b):\n relay(b, sink)\n b.cb(input())\n",
        "import os\ndef sink(x): os.system(x)\ndef build(): return [sink]\ndef dispatch(h, x): h[0](x)\ndef run(): dispatch(build(), input())\n",
    ] {
        assert!(findings(Language::Python, src).iter().any(|f| f.rule == "command-injection"), "{src}");
    }
}

#[test]
fn nested_closures_and_deferred_writes() {
    for src in [
        "import os\ndef outer(cmd):\n def middle():\n  def inner(): os.system(cmd)\n  inner()\n middle()\nouter(input())\n",
        "import os\ndef outer():\n def middle(cmd):\n  def inner(): os.system(cmd)\n  inner()\n middle(input())\nouter()\n",
        "import os\ndef setup():\n cmd = ''\n def write():\n  nonlocal cmd\n  cmd = input()\n def read(): os.system(cmd)\n register(write)\n register(read)\n",
    ] {
        assert!(findings(Language::Python, src).iter().any(|f| f.rule == "command-injection"), "{src}");
    }
}

#[test]
fn java_and_cpp_captures() {
    for (lang, src) in [
        (Language::Java, "class A { static void f(String cmd) { Runnable r = () -> { Runtime.getRuntime().exec(cmd); }; r.run(); } static void main(String[] args) { f(args[0]); } }"),
        (Language::Cpp, "void f() { auto r = [cmd = getenv(\"CMD\")]() { system(cmd); }; r(); }"),
        (Language::Cpp, "void f(char* cmd) { auto r = [cmd]() { system(cmd); }; r(); } int main() { f(getenv(\"CMD\")); }"),
        (Language::Java, "class A { static void f() { String[] box = new String[]{\"\"}; Runnable r = () -> { box[0] = System.getenv(\"CMD\"); }; r.run(); Runtime.getRuntime().exec(box[0]); } }"),
        (Language::Cpp, "void f() { const char* cmd = \"\"; auto w = [&cmd]() { cmd = getenv(\"CMD\"); }; w(); system(cmd); }"),
    ] {
        assert!(findings(lang, src).iter().any(|f| f.rule == "command-injection"), "{src}");
    }
}

#[test]
fn clean_callbacks_and_value_captures_stay_clean() {
    for (lang, src) in [
        (Language::Python, "import os\ndef sink(x): os.system(x)\ndef clean(x): pass\ndef dispatch(h, x): h[0](x)\ndef run():\n dispatch([sink], 'safe')\n dispatch([clean], input())\n"),
        (Language::Cpp, "void f() { const char* cmd = \"\"; auto w = [cmd]() mutable { cmd = getenv(\"CMD\"); }; w(); system(cmd); }"),
        (Language::Cpp, "void f() { const char* cmd = \"\"; auto w = [&]() { const char* cmd; cmd = getenv(\"CMD\"); }; w(); system(cmd); }"),
        (Language::Python, "import os\ndef setup():\n cmd = ''\n def unused():\n  nonlocal cmd\n  cmd = input()\n os.system(cmd)\n"),
    ] {
        assert!(!findings(lang, src).iter().any(|f| f.rule == "command-injection"), "{src}");
    }
}

#[test]
fn dataflow_links_registries_and_other_objects() {
    for (lang, src) in [
        (Language::JavaScript, "const handlers = {run: sink}; function sink(x) { eval(x); } function dispatch(user) { handlers.run(user); }"),
        (Language::JavaScript, "class Worker { handler(x) { eval(x); } } function apply(fn, user) { fn(user); } function run(obj, user) { apply(obj.handler, user); }"),
        (Language::Python, "def sink(x): pass\nclass Box:\n def fire(self, x): self.cb(x)\ndef run(user):\n b = Box()\n b.cb = sink\n b.fire(user)\n"),
        (Language::Python, "def sink(x): pass\ndef install(b, f): b.cb = f\ndef relay(b, f): install(b, f)\ndef run(b, user):\n relay(b, sink)\n b.cb(user)\n"),
        (Language::Python, "def sink(x): pass\ndef dispatch(h, user): h[0](user)\ndef run(user): dispatch([sink], user)\n"),
    ] {
        let cfgs = lang::build_cfgs(lang, src).unwrap();
        let files = [analysis::ProjectFile { lang, file: Path::new("example"), cfgs: &cfgs, imports: &[] }];
        let graph = analysis::dataflow::build(&files, false).unwrap();
        let reachable = graph.slice_from("user");
        assert!(reachable.iter().any(|&n| graph.graph[n].var == "x" && matches!(graph.functions[graph.graph[n].func].name.as_str(), "sink" | "Worker.handler")), "{src}");
    }
}

#[test]
fn escaped_writers_share_cells_with_sibling_handlers() {
    for (lang, src, rule) in [
        (Language::JavaScript, "function setup(req, events) { let code = ''; events.load = () => { code = req.query.q; }; events.run = () => eval(code); }", "code-injection"),
        (Language::Python, "import os\ndef setup(cmd):\n out = ''\n def write():\n  nonlocal out\n  out = cmd\n def read(): os.system(out)\n register(write)\n register(read)\nsetup(input())\n", "command-injection"),
        (Language::Cpp, "void f() { const char* cmd = \"\"; register_handler([&cmd]() { cmd = getenv(\"CMD\"); }); register_handler([&cmd]() { system(cmd); }); }", "command-injection"),
        (Language::Java, "class A { void f() { String[] box = new String[]{\"\"}; register(() -> { box[0] = System.getenv(\"CMD\"); }); register(() -> { Runtime.getRuntime().exec(box[0]); }); } }", "command-injection"),
    ] {
        assert!(findings(lang, src).iter().any(|f| f.rule == rule), "{src}");
    }
}

#[test]
fn bound_callback_returns_receiver_state() {
    let src = "import os\nclass Worker:\n def handler(self, x): return self.cmd\ndef apply(fn, x): return fn(x)\ndef run(obj):\n obj.cmd = input()\n os.system(apply(obj.handler, 'safe'))\n";
    assert!(findings(Language::Python, src).iter().any(|f| f.rule == "command-injection"));
}

#[test]
fn callable_containers_cross_file_boundaries() {
    let helper = "import os\ndef sink(value): os.system(value)\ndef dispatch(handlers, value): handlers[0](value)\n";
    let app = "from helper import sink, dispatch\ndef run(): dispatch([sink], input())\n";
    let sources = [("helper.py", helper), ("app.py", app)];
    let cfgs: Vec<_> = sources.iter().map(|(_, s)| lang::build_cfgs(Language::Python, s).unwrap()).collect();
    let imports: Vec<_> = sources.iter().map(|(_, s)| lang::imports(Language::Python, s).unwrap()).collect();
    let project: Vec<_> = sources.iter().enumerate().map(|(i, (path, _))| analysis::ProjectFile {
        lang: Language::Python, file: Path::new(path), cfgs: &cfgs[i], imports: &imports[i],
    }).collect();
    let found = analysis::check_project(&project, &|| {});
    assert!(found.iter().any(|f| f.rule == "command-injection" && f.file == Path::new("helper.py")));
    let graph = analysis::dataflow::build(&project, false).unwrap();
    assert!(graph.slice_from("input").iter().any(|&n| graph.graph[n].var == "value" && graph.functions[graph.graph[n].func].name == "sink"));
}

#[test]
fn deeply_nested_closures_retain_outer_parameters() {
    let mut src = String::from("import os\ndef outer(cmd):\n");
    for depth in 1..=6 {
        src.push_str(&format!("{}def nested{depth}():\n", " ".repeat(depth)));
    }
    src.push_str("       os.system(cmd)\n");
    for depth in (1..=6).rev() {
        src.push_str(&format!("{}nested{depth}()\n", " ".repeat(depth)));
    }
    src.push_str("outer(input())\n");
    assert!(findings(Language::Python, &src).iter().any(|f| f.rule == "command-injection"));
}
