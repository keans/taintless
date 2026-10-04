mod common;

fn json(args: &[&str]) -> serde_json::Value {
    let out = common::taintless(args);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn taint_findings_in_kotlin() {
    let v = json(&["--no-cache", "security", "tests/kotlin", "--format", "json"]);
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    let has = |rule: &str, function: &str| found.iter().any(|(r, f)| r == rule && f == function);
    assert!(has("sql-injection", "UserHandler.find"), "{found:?}");
    assert!(has("command-injection", "UserHandler.run"));
    assert!(has("path-traversal", "UserHandler.read"));
    // a field written in one method and used in another
    assert!(has("command-injection", "Holder.useLast"));
    // a lambda stored in a variable and called with untrusted data
    assert!(has("command-injection", "UserHandler.lambdas.run"));
    // `readLine()`, an `if` expression, `try`, `when` and a `for` loop
    let control = found.iter().filter(|(r, f)| r == "command-injection" && f == "UserHandler.control").count();
    assert_eq!(control, 3, "{found:?}");
    // the constant path is not a finding
    assert_eq!(found.iter().filter(|(r, f)| r == "path-traversal" && f == "UserHandler.read").count(), 1);
    assert_eq!(found.len(), 8, "{found:?}");
}

#[test]
fn call_graph_and_control_flow_of_kotlin() {
    let v = json(&["--no-cache", "calls", "tests/kotlin", "--format", "json"]);
    let names: Vec<&str> = v["functions"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    for want in ["UserHandler.find", "UserHandler.lambdas", "UserHandler.lambdas.run", "UserHandler.control", "Holder.remember", "main"] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    let out = common::taintless(&["--no-cache", "cfg", "tests/kotlin/Vuln.kt", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let control = v[0]["functions"].as_array().unwrap().iter().find(|f| f["name"] == "UserHandler.control").expect("control");
    let edges: Vec<&str> = control["edges"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
    for want in ["true", "false", "back", "exception"] {
        assert!(edges.contains(&want), "{want} in {edges:?}");
    }
}

#[test]
fn kotlin_calls_java_and_the_other_way() {
    // Kotlin and Java share a family: `Util.helper()` in Kotlin reaches the Java method
    let dir = std::env::temp_dir().join(format!("taintless-kt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Util.java"), "class Util { static void helper(String c) { Runtime.getRuntime().exec(c); } }\n").unwrap();
    std::fs::write(dir.join("Main.kt"), "fun go(req: javax.servlet.http.HttpServletRequest) { Util.helper(req.getParameter(\"c\")) }\n").unwrap();
    let v = json(&["--no-cache", "security", dir.to_str().unwrap(), "--format", "json"]);
    let _ = std::fs::remove_dir_all(&dir);
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    assert_eq!(found, [("command-injection".to_string(), "Util.helper".to_string())], "{found:?}");
}
