mod common;

fn json(args: &[&str]) -> serde_json::Value {
    let out = common::taintless(args);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn taint_findings_in_php() {
    let v = json(&["--no-cache", "security", "tests/php", "--format", "json"]);
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    let has = |rule: &str, function: &str| found.iter().any(|(r, f)| r == rule && f == function);
    assert!(has("command-injection", "direct"), "{found:?}");
    assert!(has("sql-injection", "sql"));
    assert!(has("xss", "page"));
    assert!(has("code-injection", "page"), "include of a request value");
    assert!(has("insecure-deserialization", "loops"));
    assert!(has("code-injection", "loops"));
    assert!(has("command-injection", "branches"));
    // an object built with `new Runner($_GET['c'])` and a method that reads `$this->cmd`
    assert!(has("command-injection", "Runner.run"), "{found:?}");
    // `escapeshellarg` sanitizes
    assert!(!found.iter().any(|(_, f)| f == "safe"), "{found:?}");
}

#[test]
fn call_graph_and_dependencies_of_php() {
    let v = json(&["--no-cache", "calls", "tests/php", "--format", "json"]);
    let names: Vec<&str> = v["functions"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    for want in ["Runner.__construct", "Runner.run", "stored", "cleanup"] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    let id = |n: &str| v["functions"].as_array().unwrap().iter().find(|f| f["name"] == n).unwrap()["id"].as_u64().unwrap();
    let calls: Vec<(u64, u64)> = v["calls"].as_array().unwrap().iter().map(|c| (c["from"].as_u64().unwrap(), c["to"].as_u64().unwrap())).collect();
    assert!(calls.contains(&(id("stored"), id("Runner.__construct"))) && calls.contains(&(id("stored"), id("Runner.run"))), "{calls:?}");
    assert!(calls.contains(&(id("loops"), id("cleanup"))), "a function of a required file");
    let out = common::taintless(&["--no-cache", "deps", "tests/php", "--format", "text"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("helper.php"));
}

#[test]
fn control_flow_of_php_statements() {
    let out = common::taintless(&["--no-cache", "cfg", "tests/php/app.php", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let funcs = v[0]["functions"].as_array().unwrap();
    let edges = |name: &str| -> Vec<String> { funcs.iter().find(|f| f["name"] == name).unwrap()["edges"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect() };
    // `try` / `catch` / `finally`, `foreach`, `if` / `else`
    for want in ["exception", "back"] {
        assert!(edges("loops").iter().any(|k| k == want), "{want}");
    }
    let b = edges("branches");
    assert!(b.iter().any(|k| k == "true") && b.iter().any(|k| k == "false"), "{b:?}");
}

#[test]
fn php_crypto_inventory() {
    let v = json(&["--no-cache", "crypto", "tests/php_crypto", "--format", "json"]);
    let calls = v["calls"].as_array().unwrap();
    let at = |line: u64| -> Vec<&serde_json::Value> { calls.iter().filter(|c| c["line"] == line).collect() };
    let issues = |c: &serde_json::Value| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(at(9)[0]["reason"], "MD5");
    assert_eq!(at(11)[0]["weak"], false);
    assert_eq!(at(12)[0]["reason"], "MD5");
    assert_eq!(at(13)[0]["algorithm"], "(by name)");
    assert_eq!(at(19)[0]["reason"], "ECB mode");
    assert!(issues(at(19)[0]).contains(&"hardcoded key".to_string()));
    assert_eq!(at(22)[0]["reason"], "1024-bit key");
    assert_eq!(at(24)[0]["reason"], "ECB mode");
    assert!(issues(at(29)[0]).contains(&"hardcoded key".to_string()));
    assert!(issues(at(35)[0]).iter().any(|i| i.starts_with("low PBKDF2 iterations")));
    assert!(issues(at(37)[0]).iter().any(|i| i.starts_with("low bcrypt cost")));
    assert!(issues(at(38)[0]).is_empty());
    assert!(at(44)[0]["reason"].as_str().unwrap().contains("alg none"));
    let libs: Vec<&str> = v["libraries"].as_array().unwrap().iter().map(|l| l["library"].as_str().unwrap()).collect();
    assert!(libs.contains(&"firebase/php-jwt") && libs.contains(&"phpseclib"), "{libs:?}");
}
