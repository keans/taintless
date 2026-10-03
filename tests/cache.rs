//! A warm run on a changing tree must give exactly the output of a clean `--no-cache` run.
use std::path::Path;

mod common;

fn scan(dir: &Path, cache: Option<&Path>, cmd: &str) -> String {
    let tree = dir.to_str().unwrap();
    let mut args = vec![];
    match cache {
        Some(db) => args.extend(["--cache", db.to_str().unwrap()]),
        None => args.push("--no-cache"),
    }
    args.extend([cmd, "--format", "json", tree]);
    String::from_utf8(common::taintless(&args).stdout).unwrap()
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

#[test]
fn warm_runs_match_clean_runs() {
    let tmp = std::env::temp_dir().join(format!("taintless-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let tree = tmp.join("tree");
    for fixture in ["interproc", "imports", "link", "callgraph"] {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join(fixture);
        copy(&src, &tree.join(fixture));
    }
    let db = tmp.join("db.sqlite");
    let compare = |step: &str| {
        for cmd in ["security", "calls", "flow", "cfg"] {
            let warm = scan(&tree, Some(&db), cmd);
            let clean = scan(&tree, None, cmd);
            assert!(!clean.is_empty(), "{step}/{cmd}: no output");
            assert_eq!(warm, clean, "{step}/{cmd}");
        }
    };
    compare("cold");
    compare("warm");
    // change one file, add another, delete a third
    let mut files: Vec<_> = walk(&tree);
    files.sort();
    let edited = &files[0];
    let text = std::fs::read_to_string(edited).unwrap();
    std::fs::write(edited, format!("{text}\n\n")).unwrap();
    std::fs::write(tree.join("added.py"), "import os\ndef f(x):\n    os.system(x)\n").unwrap();
    std::fs::remove_file(&files[1]).unwrap();
    compare("changed");
    // a configuration appearing, changing and disappearing is noticed too
    let config = tree.join(".taintless.toml");
    std::fs::write(&config, "disable = [\"command-injection\"]\n").unwrap();
    compare("config added");
    std::fs::write(&config, "disable = [\"unreachable-code\"]\n").unwrap();
    compare("config changed");
    std::fs::remove_file(&config).unwrap();
    compare("config removed");
    let _ = std::fs::remove_dir_all(&tmp);
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    ignore::WalkBuilder::new(dir)
        .build()
        .flatten()
        .map(|e| e.into_path())
        .filter(|p| p.is_file() && taintless::lang::Language::detect(p).is_some())
        .collect()
}
