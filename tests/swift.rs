mod common;

fn json(args: &[&str]) -> serde_json::Value {
    let out = common::taintless(args);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn taint_findings_in_swift() {
    let v = json(&["--no-cache", "security", "tests/swift", "--format", "json"]);
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    let has = |rule: &str, function: &str| found.iter().any(|(r, f)| r == rule && f == function);
    assert!(has("command-injection", "direct"), "{found:?}");
    assert!(has("path-traversal", "fromArguments"));
    assert!(has("command-injection", "branches"));
    assert!(has("insecure-deserialization", "rescued"));
    // `if let name = raw` and `guard let other = readLine()` bind the untrusted value
    assert_eq!(found.iter().filter(|(r, f)| r == "command-injection" && f == "bindings").count(), 2, "{found:?}");
    // `Runner(cmd: readLine()!)` and a method that reads `cmd`
    assert!(has("command-injection", "Runner.run"));
    // `Int(name)` sanitizes
    assert!(!found.iter().any(|(_, f)| f == "safe"), "{found:?}");
}

#[test]
fn call_graph_of_swift() {
    let v = json(&["--no-cache", "calls", "tests/swift", "--format", "json"]);
    let names: Vec<&str> = v["functions"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    for want in ["Runner.init", "Runner.run", "stored", "bindings"] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    let id = |n: &str| v["functions"].as_array().unwrap().iter().find(|f| f["name"] == n).unwrap()["id"].as_u64().unwrap();
    let calls: Vec<(u64, u64)> = v["calls"].as_array().unwrap().iter().map(|c| (c["from"].as_u64().unwrap(), c["to"].as_u64().unwrap())).collect();
    assert!(calls.contains(&(id("stored"), id("Runner.init"))) && calls.contains(&(id("stored"), id("Runner.run"))), "{calls:?}");
}

#[test]
fn control_flow_of_swift_statements() {
    let out = common::taintless(&["--no-cache", "cfg", "tests/swift/App.swift", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let funcs = v[0]["functions"].as_array().unwrap();
    let edges = |name: &str| -> Vec<String> { funcs.iter().find(|f| f["name"] == name).unwrap()["edges"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect() };
    // `do` / `catch` gives an exception edge, `if` a true and a false one
    assert!(edges("rescued").iter().any(|k| k == "exception"));
    let b = edges("branches");
    assert!(b.iter().any(|k| k == "true") && b.iter().any(|k| k == "false"), "{b:?}");
}

#[test]
fn swift_crypto_inventory() {
    let v = json(&["--no-cache", "crypto", "tests/swift_crypto", "--format", "json"]);
    let calls = v["calls"].as_array().unwrap();
    let at = |line: u64| -> Vec<&serde_json::Value> { calls.iter().filter(|c| c["line"] == line).collect() };
    let issues = |c: &serde_json::Value| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(at(8)[0]["reason"], "MD5");
    assert_eq!(at(9)[0]["reason"], "SHA-1");
    assert_eq!(at(10)[0]["weak"], false);
    assert_eq!(at(11)[0]["reason"], "MD5");
    assert!(issues(at(16)[0]).contains(&"hardcoded key".to_string()));
    assert_eq!(at(19)[0]["reason"], "DES");
    assert_eq!(at(20)[0]["weak"], false);
    assert!(issues(at(21)[0]).contains(&"hardcoded key".to_string()));
    assert!(issues(at(30)[0]).iter().any(|i| i.starts_with("low PBKDF2 iterations")));
    assert!(issues(at(31)[0]).is_empty());
    assert!(!at(25).is_empty() && !at(26).is_empty(), "generic HMAC calls");
    let libs: Vec<&str> = v["libraries"].as_array().unwrap().iter().map(|l| l["library"].as_str().unwrap()).collect();
    for want in ["CryptoKit", "CommonCrypto", "CryptoSwift"] {
        assert!(libs.contains(&want), "{want} in {libs:?}");
    }
}
