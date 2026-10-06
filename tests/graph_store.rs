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

#[test]
fn a_changed_file_rewrites_only_the_files_whose_rows_change() {
    let dir = std::env::temp_dir().join(format!("taintless-graph-incr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
    write("lib.py", "def helper(x):\n    return x\n");
    write("use.py", "from lib import helper\ndef go(v):\n    return helper(v)\n");
    write("other.py", "def alone():\n    return 1\n");
    let tree = dir.to_str().unwrap().to_string();
    let db = dir.join("db.sqlite");
    let db = db.to_str().unwrap();
    let (_, first) = run(db, &["index", &tree]);
    assert!(first.contains("3 of 3 files rewritten"), "{first}");

    // an edit inside one function of one file that touches nothing else: only that file
    write("other.py", "def alone():\n    return 2\n");
    let (_, second) = run(db, &["index", &tree]);
    assert!(second.contains("1 of 3 files rewritten"), "{second}");

    // the stored graph is what a fresh index of the same tree gives
    write("lib.py", "def helper(x, y=0):\n    return x\n\ndef extra():\n    return 3\n");
    let (_, third) = run(db, &["index", &tree]);
    assert!(third.contains("stored") && !third.contains("3 of 3"), "{third}");
    let fresh = dir.join("fresh.sqlite");
    run(fresh.to_str().unwrap(), &["index", &tree]);
    for format in ["graphml", "dot"] {
        let a = run(db, &["export-graph", "--format", format]).0;
        let b = run(fresh.to_str().unwrap(), &["export-graph", "--format", format]).0;
        assert_eq!(a, b, "{format} export differs");
    }
    // a removed file leaves nothing behind
    std::fs::remove_file(dir.join("other.py")).unwrap();
    let (_, fourth) = run(db, &["index", &tree]);
    assert!(fourth.contains("stored"), "{fourth}");
    assert!(run(db, &["query", "callers", "alone"]).0.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
