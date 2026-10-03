//! `security --store` records findings; triaged ones stop being reported.
use std::path::Path;

mod common;

fn run(db: &str, args: &[&str]) -> (String, String) {
    let mut all = vec!["--cache", db];
    all.extend(args);
    let out = common::taintless(&all);
    (String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

#[test]
fn triaged_findings_are_hidden_and_history_lists_them() {
    let dir = std::env::temp_dir().join(format!("taintless-triage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.py"), "import os\ndef f(x):\n    os.system(input())\n").unwrap();
    let db = dir.join("db.sqlite");
    let (db, tree) = (db.to_str().unwrap(), dir.to_str().unwrap());

    // the id is printed with the finding, so it can be triaged without looking it up
    let (out, err) = run(db, &["security", tree, "--store"]);
    assert!(err.contains("1 findings"), "{err}");
    let id = out.split("id=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    let (history, _) = run(db, &["history"]);
    assert!(history.starts_with(&id) && history.contains("open"), "{history}");

    run(db, &["triage", "accepted", &id, "--reason", "internal tool"]);
    let (_, err) = run(db, &["security", tree, "--store"]);
    assert!(err.contains("0 findings") && err.contains("triaged"), "{err}");
    let (history, _) = run(db, &["history"]);
    assert!(history.contains("accepted") && history.contains("internal tool"), "{history}");

    // SARIF still lists it, as suppressed
    let (sarif, _) = run(db, &["security", tree, "--store", "--format", "sarif"]);
    assert!(sarif.contains("\"suppressions\"") && sarif.contains("internal tool") && sarif.contains(&id), "{sarif}");

    // the fix is noticed: the finding is no longer present
    std::fs::write(dir.join("a.py"), "def f(x):\n    pass\n").unwrap();
    run(db, &["security", tree, "--store"]);
    assert!(run(db, &["history"]).0.is_empty());
    assert!(run(db, &["history", "--all"]).0.contains("(fixed)"));

    // it comes back: open again, whatever it was triaged as
    std::fs::write(dir.join("a.py"), "import os\ndef f(x):\n    os.system(input())\n").unwrap();
    let (out, _) = run(db, &["security", tree, "--store"]);
    assert!(out.contains(&id), "{out}");
    assert!(run(db, &["history"]).0.contains("open"));

    // bulk triage by rule, and a selector is required
    let (_, err) = run(db, &["triage", "false-positive", "--rule", "command-injection"]);
    assert!(err.contains("1 finding"), "{err}");
    assert!(run(db, &["triage", "open"]).1.contains("name findings"));

    let status = run(db, &["cache-status"]).0;
    assert!(status.contains("parsed files") && status.contains("findings history"), "{status}");
    assert!(!Path::new(tree).join(".taintless").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
