mod common;

fn json(args: &[&str]) -> serde_json::Value {
    let out = common::taintless(args);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn taint_findings_in_csharp() {
    let v = json(&["--no-cache", "security", "tests/csharp", "--format", "json"]);
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    let has = |rule: &str, function: &str| found.iter().any(|(r, f)| r == rule && f == function);
    assert!(has("sql-injection", "UserController.Find"), "{found:?}");
    assert!(has("command-injection", "UserController.Run"));
    assert!(has("path-traversal", "UserController.Read"));
    assert!(has("weak-crypto", "UserController.Main"));
    // `Path.GetFileName` sanitizes the second read, and `int.Parse` the number in `Main`
    assert_eq!(found.iter().filter(|(r, f)| r == "path-traversal" && f == "UserController.Read").count(), 1);
    assert!(!found.iter().any(|(r, f)| r == "command-injection" && f == "UserController.Main"));
    assert_eq!(found.len(), 4, "{found:?}");
}

#[test]
fn call_graph_and_dependencies_of_csharp() {
    let v = json(&["--no-cache", "calls", "tests/csharp", "--format", "json"]);
    let names: Vec<&str> = v["functions"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    for want in ["UserController.UserController", "UserController.Find", "UserController.Main", "UserController.Clean", "UserController.Local", "UserController.Local.Wrap", "UserController.Local.f"] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    // `Process.Start(Clean(input))`: an edge from `Local` to the method it calls
    let calls: Vec<(u64, u64)> = v["calls"].as_array().unwrap().iter().map(|c| (c["from"].as_u64().unwrap(), c["to"].as_u64().unwrap())).collect();
    let id = |n: &str| v["functions"].as_array().unwrap().iter().find(|f| f["name"] == n).unwrap()["id"].as_u64().unwrap();
    assert!(calls.contains(&(id("UserController.Local"), id("UserController.Clean"))), "{calls:?}");

    let out = common::taintless(&["--no-cache", "deps", "tests/csharp", "--external", "--format", "text"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for ns in ["System.Data.SqlClient", "System.Security.Cryptography", "Microsoft.AspNetCore.Mvc"] {
        assert!(text.contains(ns), "{ns}: {text}");
    }
}

#[test]
fn control_flow_of_csharp_statements() {
    let out = common::taintless(&["--no-cache", "cfg", "tests/csharp/Vuln.cs", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let funcs = v[0]["functions"].as_array().unwrap();
    let local = funcs.iter().find(|f| f["name"] == "UserController.Local").expect("Local");
    let edges: Vec<&str> = local["edges"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
    // `try` / `catch`, `foreach`, `switch` and `using` give branches, back edges and exceptions
    for want in ["true", "false", "back", "exception", "break"] {
        assert!(edges.contains(&want), "{want} in {edges:?}");
    }
}
