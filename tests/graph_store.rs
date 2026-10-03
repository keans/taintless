//! The stored graph: `index`, `query` and `export-graph`.
mod common;

fn run(db: &str, args: &[&str]) -> (String, String) {
    let mut all = vec!["--cache", db];
    all.extend(args);
    let out = common::taintless(&all);
    (String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

#[test]
fn index_query_and_export() {
    let dir = std::env::temp_dir().join(format!("taintless-graph-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("a.py"),
        "import os\ndef run(cmd):\n    os.system(cmd)\ndef main():\n    x = input()\n    run(x)\n",
    )
    .unwrap();
    let (db, tree) = (dir.join("db.sqlite"), dir.to_str().unwrap().to_string());
    let db = db.to_str().unwrap();

    // nothing stored yet: a hint, not an empty answer
    assert!(run(db, &["query", "callers", "run"]).1.contains("taintless index"));
    assert!(run(db, &["index", &tree]).1.contains("stored"));
    assert!(run(db, &["index", &tree]).1.contains("up to date"));

    let (callers, _) = run(db, &["query", "callers", "run"]);
    assert!(callers.contains("main") && callers.contains("calls run"), "{callers}");
    let (callees, _) = run(db, &["query", "callees", "main"]);
    assert!(callees.contains("calls run"), "{callees}");
    let (reach, _) = run(db, &["query", "reach", "input()", "os.system"]);
    assert!(reach.contains("os.system(cmd)") && reach.contains("via"), "{reach}");
    let (json, _) = run(db, &["query", "reach", "input()", "os.system", "--format", "json"]);
    let rows: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(rows[0]["path"].as_array().unwrap().len() >= 2, "{json}");

    // a changed file replaces the graph
    std::fs::write(dir.join("a.py"), "def main():\n    pass\n").unwrap();
    assert!(run(db, &["index", &tree]).1.contains("stored"));
    assert!(run(db, &["query", "callers", "run"]).0.is_empty());

    let out = dir.join("neo");
    run(db, &["export-graph", "--format", "neo4j", "--out", out.to_str().unwrap()]);
    assert!(std::fs::read_to_string(out.join("nodes.csv")).unwrap().starts_with("id:ID,"));
    assert!(std::fs::read_to_string(out.join("edges.csv")).unwrap().starts_with(":START_ID,"));
    assert!(run(db, &["export-graph", "--format", "graphml"]).0.contains("<graphml"));
    let _ = std::fs::remove_dir_all(&dir);
}
