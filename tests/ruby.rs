mod common;

fn json(args: &[&str]) -> serde_json::Value {
    let out = common::taintless(args);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn taint_findings_in_ruby() {
    let v = json(&["--no-cache", "security", "tests/ruby", "--format", "json"]);
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    let has = |rule: &str, function: &str| found.iter().any(|(r, f)| r == rule && f == function);
    // `gets` and `params` reach `system` / `File.read`; `ARGV` reaches `eval` through both branches
    assert!(has("command-injection", "direct"), "{found:?}");
    assert!(has("path-traversal", "through_helper"));
    assert!(has("code-injection", "branches"));
    assert!(has("insecure-deserialization", "rescued"));
    // an object built with `Runner.new(gets)` and a method that reads `@cmd`
    assert!(has("command-injection", "Runner.run"));
    // `Shellwords.escape` sanitizes
    assert!(!found.iter().any(|(_, f)| f == "safe"), "{found:?}");
}

#[test]
fn call_graph_and_dependencies_of_ruby() {
    let v = json(&["--no-cache", "calls", "tests/ruby", "--format", "json"]);
    let names: Vec<&str> = v["functions"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    for want in ["Runner.initialize", "Runner.run", "stored", "blocks.<block>", "util"] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }
    // `Runner.new(..)` calls the constructor, `r.run` the method
    let id = |n: &str| v["functions"].as_array().unwrap().iter().find(|f| f["name"] == n).unwrap()["id"].as_u64().unwrap();
    let calls: Vec<(u64, u64)> = v["calls"].as_array().unwrap().iter().map(|c| (c["from"].as_u64().unwrap(), c["to"].as_u64().unwrap())).collect();
    assert!(calls.contains(&(id("stored"), id("Runner.initialize"))) && calls.contains(&(id("stored"), id("Runner.run"))), "{calls:?}");
    // `require_relative 'helper'`
    let out = common::taintless(&["--no-cache", "deps", "tests/ruby", "--format", "text"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("helper.rb"));
}

#[test]
fn control_flow_of_ruby_statements() {
    let out = common::taintless(&["--no-cache", "cfg", "tests/ruby/app.rb", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let funcs = v[0]["functions"].as_array().unwrap();
    let rescued = funcs.iter().find(|f| f["name"] == "rescued").expect("rescued");
    let edges: Vec<&str> = rescued["edges"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
    // `begin` / `rescue` / `ensure` give an exception edge
    assert!(edges.contains(&"exception"), "{edges:?}");
    let branches = funcs.iter().find(|f| f["name"] == "branches").expect("branches");
    let edges: Vec<&str> = branches["edges"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert!(edges.contains(&"true") && edges.contains(&"false"), "{edges:?}");
}

#[test]
fn ruby_crypto_inventory() {
    let v = json(&["--no-cache", "crypto", "tests/ruby_crypto", "--format", "json"]);
    let calls = v["calls"].as_array().unwrap();
    let at = |line: u64| -> Vec<&serde_json::Value> { calls.iter().filter(|c| c["line"] == line).collect() };
    let issues = |c: &serde_json::Value| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(at(10)[0]["reason"], "MD5");
    assert_eq!(at(11)[0]["weak"], false);
    assert_eq!(at(12)[0]["reason"], "SHA-1");
    assert_eq!(at(13)[0]["algorithm"], "(by name)");
    assert_eq!(at(18)[0]["reason"], "ECB mode");
    assert_eq!(at(22)[0]["reason"], "DES");
    assert_eq!(at(23)[0]["reason"], "1024-bit key");
    // hardcoded keys, a low work factor, an unsigned JWT
    assert!(issues(at(28)[0]).contains(&"hardcoded key".to_string()));
    assert!(issues(at(33)[0]).iter().any(|i| i.starts_with("low PBKDF2 iterations")));
    assert!(issues(at(35)[0]).iter().any(|i| i.starts_with("low bcrypt cost")));
    assert!(issues(at(36)[0]).is_empty());
    assert!(at(41)[0]["reason"].as_str().unwrap().contains("alg none"));
    let libs: Vec<&str> = v["libraries"].as_array().unwrap().iter().map(|l| l["library"].as_str().unwrap()).collect();
    for want in ["OpenSSL", "Digest", "bcrypt-ruby", "ruby-jwt", "SecureRandom"] {
        assert!(libs.contains(&want), "{want} in {libs:?}");
    }
}
