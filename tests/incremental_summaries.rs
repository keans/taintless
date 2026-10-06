//! Summaries kept between runs: after any edit the findings equal those of a run without the
//! cache, and the functions an edit cannot affect are not analyzed again.
mod common;

use std::path::Path;

fn put_file(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
}

/// `(findings as JSON, stderr)` of `security` over `dir`, with the cache in `dir` or without it.
fn scan(dir: &Path, cached: bool) -> (serde_json::Value, String) {
    let tree = dir.to_str().unwrap();
    let db = dir.join("db.sqlite");
    let mut args = vec![];
    if cached {
        args.extend(["--cache", db.to_str().unwrap()]);
    } else {
        args.push("--no-cache");
    }
    args.extend(["security", tree, "--format", "json"]);
    let out = common::taintless(&args);
    (serde_json::from_slice(&out.stdout).unwrap_or_default(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn analyzed(stderr: &str) -> Option<(usize, usize)> {
    let rest = stderr.split("analyzed ").nth(1)?;
    let mut it = rest.split_whitespace();
    let done = it.next()?.parse().ok()?;
    let all = it.nth(1)?.parse().ok()?;
    Some((done, all))
}

/// Run both ways and require the same findings.
fn same(dir: &Path) -> String {
    let (cached, stderr) = scan(dir, true);
    let (plain, _) = scan(dir, false);
    assert_eq!(cached, plain, "findings differ after the edit\n{stderr}");
    stderr
}

#[test]
fn edits_give_the_findings_of_a_cold_run_and_reuse_what_they_cannot_touch() {
    let dir = std::env::temp_dir().join(format!("taintless-incr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    put_file(&dir, "lib.py", "import os\n\ndef sink(x):\n    os.system(x)\n");
    put_file(&dir, "mid.py", "from lib import sink\n\ndef mid(y):\n    sink(y)\n");
    put_file(&dir, "top.py", "from mid import mid\n\ndef top():\n    mid(input())\n");
    put_file(&dir, "box.py", "import os\n\nclass Box:\n    def put(self):\n        self.cmd = input()\n\n    def run(self):\n        os.system(self.cmd)\n");
    let filler: String = (0..12).map(|i| format!("def f{i}(a):\n    b = a\n    return b\n\n")).collect();
    put_file(&dir, "other.py", &filler);

    let cold = same(&dir);
    assert!(analyzed(&cold).is_none(), "the first run has nothing to reuse: {cold}");
    assert!(scan(&dir, true).0.as_array().unwrap().len() >= 2, "the fixture must have findings");

    let total = 5 + 12;

    // an edit that leaves every summary as it was: only the file's own functions are analyzed again
    put_file(&dir, "other.py", &filler.replace("b = a", "b = a + 1"));
    assert_eq!(analyzed(&same(&dir)), Some((12, total)));

    // a callee changes without changing its summary: nothing that calls it is analyzed again
    put_file(&dir, "lib.py", "import os\n\ndef sink(x):\n    os.system(x )\n");
    assert_eq!(analyzed(&same(&dir)), Some((1, total)));

    // a callee changes its summary: it and its callers are, up the chain, and no others
    put_file(&dir, "lib.py", "import os\n\ndef sink(x):\n    print(x)\n");
    let (done, all) = analyzed(&same(&dir)).unwrap();
    assert_eq!(all, total);
    assert!((3..=5).contains(&done), "sink, mid and top, not the 14 others: {done}");
    put_file(&dir, "lib.py", "import os\n\ndef sink(x):\n    os.system(x)\n");
    same(&dir);

    // a function appears: names changed, so everything is analyzed again
    put_file(&dir, "lib.py", "import os\n\ndef sink(x):\n    os.system(x)\n\ndef extra():\n    return 1\n");
    let (done, all) = analyzed(&same(&dir)).unwrap();
    assert_eq!(done, all);

    // a stored field changes what a method of the class reads
    put_file(&dir, "box.py", "import os\n\nclass Box:\n    def put(self):\n        self.cmd = 'ls'\n\n    def run(self):\n        os.system(self.cmd)\n");
    same(&dir);
    put_file(&dir, "box.py", "import os\n\nclass Box:\n    def put(self):\n        self.cmd = input()\n\n    def run(self):\n        os.system(self.cmd)\n");
    same(&dir);

    // a function is renamed, a file is removed
    put_file(&dir, "top.py", "from mid import mid\n\ndef top2():\n    mid(input())\n");
    same(&dir);
    std::fs::remove_file(dir.join("other.py")).unwrap();
    same(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

fn copy_tree(from: &Path, to: &Path) -> Vec<std::path::PathBuf> {
    let mut files = vec![];
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        let target = to.join(e.file_name());
        if p.is_dir() {
            files.extend(copy_tree(&p, &target));
        } else if std::fs::metadata(&p).is_ok_and(|m| m.len() < 300_000) && std::fs::copy(&p, &target).is_ok() {
            files.push(target);
        }
    }
    files
}

/// Every fixture project: store what it gives, change one file the way that keeps its functions
/// (a trailing newline), and require the cached run after that to equal an uncached one. This takes
/// the stored summaries of every kind the fixtures produce through a round trip.
#[test]
fn every_fixture_project_gives_the_same_findings_from_stored_summaries() {
    let root = std::env::temp_dir().join(format!("taintless-incr-fixtures-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (mut checked, mut reused) = (0, 0);
    let mut dirs: Vec<_> = std::fs::read_dir("tests").unwrap().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    for dir in dirs {
        let work = root.join(dir.file_name().unwrap());
        let files = copy_tree(&dir, &work);
        let Some(victim) = files.iter().find(|f| matches!(f.extension().and_then(|e| e.to_str()), Some("py" | "js" | "java" | "go" | "rs" | "c" | "cpp" | "cs" | "kt" | "ts"))) else { continue };
        let _ = scan(&work, true);
        let mut text = std::fs::read_to_string(victim).unwrap_or_default();
        text.push('\n');
        std::fs::write(victim, text).unwrap();
        let (cached, stderr) = scan(&work, true);
        let (plain, _) = scan(&work, false);
        assert_eq!(cached, plain, "{}: findings differ with stored summaries\n{stderr}", dir.display());
        checked += 1;
        reused += usize::from(analyzed(&stderr).is_some_and(|(done, all)| done < all));
    }
    assert!(checked > 20, "{checked} projects checked");
    assert!(reused * 2 > checked, "only {reused} of {checked} projects reused anything");
    let _ = std::fs::remove_dir_all(&root);
}
