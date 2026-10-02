mod common;
use common::taintless;

fn flow(args: &[&str]) -> String {
    let out = taintless(&[&["flow"], args].concat());
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn values_flow_inside_and_across_functions() {
    let t = flow(&["tests/interproc", "--format", "text"]);
    // inside a function: assignment <- call <- free variable
    assert!(t.contains("data:7 <- request.args.get():7"), "{t}");
    assert!(t.contains("request.args.get():7 <- request.args"), "{t}");
    // argument -> parameter, and return -> call, across functions
    assert!(t.contains("param cmd <- data:7 [main], param c [nested]"), "{t}");
    assert!(t.contains("build():9 <- data:7, return:9 [build]"), "{t}");
    // a helper that ignores its argument: nothing flows into its return
    assert!(t.contains("\n  return:21\n"), "{t}");
}

#[test]
fn from_follows_a_name_and_function_restricts() {
    let t = flow(&["tests/interproc", "--format", "text", "--from", "request.args"]);
    assert!(t.contains("param name <- data:7 [main]"), "{t}");
    assert!(!t.contains("read_input"), "{t}");
    let only = flow(&["tests/interproc", "--format", "text", "--function", "run_cmd"]);
    assert!(only.starts_with("run_cmd"), "{only}");
    assert!(!only.contains("\nmain"), "{only}");
}

#[test]
fn dot_and_json_are_well_formed() {
    let dot = flow(&["tests/interproc"]);
    assert!(dot.starts_with("digraph dataflow") && dot.trim_end().ends_with('}'));
    assert!(dot.contains("style=dashed"));
    let json: serde_json::Value = serde_json::from_str(&flow(&["tests/interproc", "--format", "json"])).unwrap();
    assert!(json["nodes"].as_array().unwrap().len() > 10);
    assert!(json["edges"].as_array().unwrap().iter().any(|e| e["kind"] == "arg"));
}

#[test]
fn fields_are_separate_and_shared_between_methods() {
    let t = flow(&["tests/flow", "--format", "text"]);
    // a read of self.cmd sees what __init__ stored in it, not self.name
    assert!(t.contains("os.system():10 <- field Job.cmd [Job.__init__], os"), "{t}");
    assert!(t.contains("print():11 <- field Job.name [Job.__init__]"), "{t}");
    assert!(t.contains("field Job.cmd <- self.cmd:6"), "{t}");
    // a reassignment replaces the earlier definition
    assert!(t.contains("print():19 <- x:18"), "{t}");
}

#[test]
fn aliases_typed_receivers_and_callbacks() {
    let t = flow(&["tests/flow", "--format", "text"]);
    // b = a; b.cmd = user  =>  a.cmd holds user
    assert!(t.contains("os.system():26 <- a:23, b.cmd:25, os"), "{t}");
    // j = Job(..); j.run()  =>  the receiver reaches Job.run's self
    assert!(t.contains("param self <- j:15 [main], j:42 [method_on_var]"), "{t}");
    // apply(shout, user): shout is called with user and its result comes back
    assert!(t.contains("param s <- param user [callback]"), "{t}");
    assert!(t.contains("apply():38 <- param user, return:30 [apply], return:34 [shout], shout"), "{t}");
}

#[test]
fn lambdas_are_callbacks() {
    let t = flow(&["tests/flow/fields.js", "--format", "text"]);
    // [user].forEach((v) => exec(v)): the array's elements reach the lambda's parameter
    assert!(t.contains("param v <- param user [run]"), "{t}");
}

#[test]
fn callbacks_stored_in_variables() {
    let t = flow(&["tests/flow/fields.js", "--format", "text"]);
    // const cb = (v) => ..; xs.forEach(cb)
    assert!(t.contains("param v <- param user [stored]"), "{t}");
    // const h = sink; h(user)
    assert!(t.contains("param x <- param user [named]"), "{t}");
}

#[test]
fn closures_and_python_lambdas_see_captured_variables() {
    let js = flow(&["tests/flow/fields.js", "--format", "text"]);
    assert!(js.contains("cmd <- cmd:20 [capture]"), "{js}");
    let py = flow(&["tests/flow/lambdas.py", "--format", "text"]);
    assert!(py.contains("param v <- param user [run]"), "{py}");
    assert!(py.contains("param w <- param user [run]"), "{py}");
}

#[test]
fn control_shows_which_branch_decides() {
    let plain = flow(&["tests/flow/branches.py", "--format", "text"]);
    assert!(!plain.contains("if flag"), "branches only with --control: {plain}");
    let t = flow(&["tests/flow/branches.py", "--format", "text", "--control"]);
    // the branch reads its condition, and the statement it guards depends on it
    assert!(t.contains("if flag > 0 <- param flag"), "{t}");
    assert!(t.contains("cmd:7 <- if flag > 0, param user"), "{t}");
    assert!(t.contains("os.system():9 <- cmd:5, cmd:7, if user, os"), "{t}");
    // a statement nothing decides stays free of branches
    assert!(t.contains("\n  cmd:5\n"), "{t}");
    let json: serde_json::Value =
        serde_json::from_str(&flow(&["tests/flow/branches.py", "--format", "json", "--control"])).unwrap();
    let edges = json["edges"].as_array().unwrap();
    assert!(edges.iter().any(|e| e["kind"] == "control" && e["param"] == "true"));
    let dot = flow(&["tests/flow/branches.py", "--control"]);
    assert!(dot.contains("shape=diamond") && dot.contains("style=dotted"));
}

#[test]
fn callbacks_stored_in_fields_containers_and_reassigned_variables() {
    let t = flow(&["tests/flow/stored.py", "--format", "text"]);
    let line = |prefix: &str| t.lines().find(|l| l.trim_start().starts_with(prefix)).unwrap_or_else(|| panic!("{prefix}: {t}")).to_string();
    let cmd = line("param cmd <-");
    // module-level dict and list, a field set in __init__, a list field, a local table and a list element
    for from in [
        "param user [registry]",
        "param user [queue]",
        "param x [Bus.fire]",
        "param x [Bus.fire_all]",
        "param user [local_table]",
        "param user [passed]",
    ] {
        assert!(cmd.contains(from), "{from}: {cmd}");
    }
    // `f = log; f = run; f(user)` calls only run; `f = run; f = log` only log
    assert!(cmd.contains("param user [reassigned]") && !cmd.contains("[rebound_away]"), "{cmd}");
    let msg = line("param msg <-");
    assert!(msg.contains("param user [rebound_away]") && !msg.contains("[reassigned]"), "{msg}");
    // storing a function in a list is not calling it
    assert!(!cmd.contains("QUEUE"), "{cmd}");
}

#[test]
fn javascript_registries_and_fields() {
    let t = flow(&["tests/flow/stored.js", "--format", "text"]);
    let x = t.lines().find(|l| l.trim_start().starts_with("param x <-")).expect(&t);
    for from in ["param user [dispatch]", "param user [reassign]", "param x [Bus.fire]"] {
        assert!(x.contains(from), "{from}: {x}");
    }
    let y = t.lines().find(|l| l.trim_start().starts_with("param y <-"));
    assert!(y.is_none_or(|l| !l.contains("[reassign]")), "{t}");
}

#[test]
fn aliases_through_calls_fields_elements_and_returned_arguments() {
    let t = flow(&["tests/flow/alias2.py", "--format", "text"]);
    // fill(a) assigns o.d: the call defines a.d, and the later read depends on it
    assert!(t.contains("fill():20 <- a:19, o.d:15 [fill]"), "{t}");
    assert!(t.contains("os.system():21 <- a:19, fill():20"), "{t}");
    // h.r = a, then h.r.d = ..: a.d
    assert!(t.contains("os.system():29 <- a:25, h.r.d:28"), "{t}");
    // xs = [a], then xs[0].d = ..: a.d
    assert!(t.contains("xs.d:35"), "{t}");
    assert!(t.contains("os.system():36 <- a:33") && t.lines().any(|l| l.contains("os.system():36") && l.contains("xs.d:35")), "{t}");
    // b = identity(a), then b.d = ..: a.d
    assert!(t.contains("os.system():47 <- a:44, b.d:46"), "{t}");
    // an unrelated object stays unrelated
    let line = t.lines().find(|l| l.contains("os.system():54")).unwrap();
    assert!(!line.contains("b.d"), "{t}");
}

#[test]
fn go_interface_calls_link_arguments_to_the_types_that_satisfy_them() {
    // through a parameter and through a field
    let t = flow(&["tests/iface/param", "--format", "text"]);
    assert!(t.contains("param cmd <- os.Args[1] [use]"), "{t}");
    let t = flow(&["tests/iface/field", "--format", "text"]);
    assert!(t.contains("param cmd <- os.Args[1] [Svc.work]"), "{t}");
    // `Other.Exec` / `Shell.Exec` lack the interface's `Run`: nothing flows into them
    let t = flow(&["tests/iface/param", "--format", "text"]);
    let other = t.split("Other.Exec").nth(1).unwrap().lines().take(3).collect::<String>();
    assert!(!other.contains("os.Args"), "{t}");
    let t = flow(&["tests/iface/clean", "--format", "text"]);
    let shell = t.split("Shell.Exec").nth(1).unwrap().lines().take(3).collect::<String>();
    assert!(!shell.contains("os.Args"), "{t}");
}

/// The text of one function's block in `flow` output.
fn function_block<'a>(t: &'a str, name: &str) -> Vec<&'a str> {
    t.lines().skip_while(|l| !l.starts_with(&format!("{name} ("))).skip(1).take_while(|l| l.starts_with("  ")).collect()
}

#[test]
fn literal_keys_keep_elements_apart_in_flow() {
    let t = flow(&["tests/elements/elements.py", "--format", "text"]);
    let sink = |f: &str| function_block(&t, f).into_iter().find(|l| l.trim_start().starts_with("os.system()")).unwrap().to_string();
    // `xs = ["ls", input()]`: element 0 is clean, element 1 holds `input()`
    assert!(sink("clean_element_of_a_literal").contains("xs[0]:5") && !sink("clean_element_of_a_literal").contains("xs[1]"), "{t}");
    assert!(sink("tainted_element_of_a_literal").contains("xs[1]:10"), "{t}");
    assert!(function_block(&t, "tainted_element_of_a_literal").iter().any(|l| l.trim_start().starts_with("xs[1]:10 <- input()")), "{t}");
    // `xs[1] = input()` leaves element 0 on its first definition
    let later = sink("element_written_later");
    assert!(later.contains("xs[0]:15") && !later.contains(":16"), "{later}");
    // an unknown index reads every element
    let any = sink("unknown_index_sees_every_element");
    assert!(any.contains("xs[0]:21") && any.contains("xs[1]:21"), "{any}");
}

#[test]
fn dict_keys_keep_entries_apart_in_flow() {
    let t = flow(&["tests/elements/containers.py", "--format", "text"]);
    let sink = |f: &str| function_block(&t, f).into_iter().find(|l| l.trim_start().starts_with("os.system()")).unwrap().to_string();
    assert!(sink("dict_literal_clean").contains("d['a']:5") && !sink("dict_literal_clean").contains("d['b']"), "{t}");
    assert!(sink("dict_literal_tainted").contains("d['b']:10") && !sink("dict_literal_tainted").contains("d['a']"), "{t}");
    let later = sink("dict_write_later");
    assert!(later.contains("d['a']:15") && !later.contains(":16"), "{later}");
    // a dynamic key may be any entry
    let any = sink("dict_dynamic_key_reads_all");
    assert!(any.contains("d['a']") && any.contains("d['b']"), "{any}");
    // instances of one class stay apart, and so do values from an unknown factory
    assert!(!sink("instances_apart").contains("a:"), "{t}");
    assert!(sink("instances_same").contains("a:"), "{t}");
}

#[test]
fn js_and_go_literal_keys_keep_entries_apart_in_flow() {
    for (file, clean, tainted, sink, safe, unsafe_key) in [
        ("tests/elements/objects.js", "cleanDot", "taintedDot", "child_process.exec()", "d.a", "d.b"),
        ("tests/elements/objects.ts", "cleanDot", "taintedDot", "child_process.exec()", "d.a", "d.b"),
        ("tests/elements/composites.go", "cleanMap", "taintedMap", "exec.Command()", "d['a']", "d['b']"),
    ] {
        let t = flow(&[file, "--format", "text"]);
        let clean_block = function_block(&t, clean);
        let tainted_block = function_block(&t, tainted);
        let clean_sink = clean_block.iter().find(|l| l.contains(sink)).unwrap();
        let tainted_sink = tainted_block.iter().find(|l| l.contains(sink)).unwrap();
        assert!(clean_sink.contains(safe) && !clean_sink.contains(unsafe_key), "{file}: {t}");
        assert!(tainted_sink.contains(unsafe_key) && !tainted_sink.contains(safe), "{file}: {t}");
    }
}
