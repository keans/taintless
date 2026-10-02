use taintless::analysis::{self, Finding, baseline::Baseline, suppress};
use taintless::lang;
use std::path::{Path, PathBuf};
mod common;
use common::taintless;

/// `(file name, line, rule, severity)` of every finding reported as JSON.
fn findings(args: &[&str]) -> Vec<(String, u64, String, String)> {
    let mut a = vec!["security"];
    a.extend_from_slice(args);
    a.extend(["--format", "json"]);
    let out = taintless(&a);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    v.as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let file = Path::new(f["file"].as_str().unwrap()).file_name().unwrap().to_string_lossy().into_owned();
            (file, f["line"].as_u64().unwrap(), f["rule"].as_str().unwrap().into(), f["severity"].as_str().unwrap().into())
        })
        .collect()
}

#[test]
fn suppression_comments() {
    let f = findings(&["tests/suppress"]);
    // a: same line; b: line above, right rule; c: wrong rule; d: nothing; e: the marker covers only the next line
    let lines: Vec<u64> = f.iter().filter(|x| x.0 == "app.py").map(|x| x.1).collect();
    assert_eq!(lines, [14, 18, 24], "{f:?}");
    // `taintless: ignore-file[rule]` silences the whole file
    assert!(!f.iter().any(|x| x.0 == "ignored.py"));
    // the audit switch shows everything
    let all = findings(&["tests/suppress", "--no-suppress"]);
    assert_eq!(all.len(), 6, "{all:?}");
}

#[test]
fn custom_sources_sinks_sanitizers_and_entry_points() {
    // nothing is known about `myapp` without a configuration
    assert!(findings(&["tests/config/app.py"]).is_empty());
    let f = findings(&["tests/config/app.py", "--config", "tests/config/custom.toml"]);
    let lines: Vec<u64> = f.iter().map(|x| x.1).collect();
    // line 6: configured source -> configured sink; line 12: entry-point parameter `data`
    assert_eq!(lines, [6, 12], "{f:?}");
    assert!(f.iter().all(|x| x.2 == "sql-injection" && x.3 == "high"));
    // line 8 is sanitized, line 13 is a parameter that was not listed
}

#[test]
fn disable_severity_and_exclude() {
    let plain = findings(&["tests/vuln"]);
    assert!(plain.iter().any(|x| x.2 == "weak-crypto") && plain.iter().any(|x| x.0 == "app.js"));
    let f = findings(&["tests/vuln", "--config", "tests/config/filter.toml"]);
    assert!(!f.iter().any(|x| x.2 == "weak-crypto" || x.2 == "unreachable-code"));
    assert!(!f.iter().any(|x| x.0 == "app.js" || x.0 == "app.go"));
    let cmd: Vec<_> = f.iter().filter(|x| x.2 == "command-injection").collect();
    assert!(!cmd.is_empty() && cmd.iter().all(|x| x.3 == "medium"), "{cmd:?}");
    assert!(f.iter().any(|x| x.0 == "app.py"), "other files are still analyzed");
}

#[test]
fn configuration_is_discovered_and_validated() {
    // `.taintless.toml` in the scanned directory is picked up automatically
    let out = taintless(&["security", "tests/config_auto"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("using configuration"));
    // mistakes are errors, not silently ignored
    for (file, needle) in [("bad_rule.toml", "unknown rule"), ("bad_field.toml", "disbale")] {
        let out = taintless(&["security", "tests/config/app.py", "--config", &format!("tests/config/{file}")]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains(needle), "{file}: {}", String::from_utf8_lossy(&out.stderr));
    }
}

fn load(path: &str) -> Vec<Finding> {
    let p = PathBuf::from(path);
    let src = std::fs::read_to_string(&p).unwrap();
    let l = lang::Language::detect(&p).unwrap();
    let cfgs = lang::build_cfgs(l, &src).unwrap();
    analysis::check_file(l, &p, &cfgs)
}

#[test]
fn baseline_hides_known_findings_and_survives_line_shifts() {
    let f = load("tests/vuln/app.py");
    assert!(f.len() > 5);
    let base = Baseline::from_findings(&f);
    // the same findings, moved around by an edit above them: all known
    let moved: Vec<Finding> = f.iter().cloned().map(|mut x| (x.line += 40, x).1).collect();
    let (new, known) = base.filter(moved.clone());
    assert!(new.is_empty() && known == f.len());
    // a new finding, or one more of an existing kind, is reported
    let mut more = moved;
    let mut extra = more[0].clone();
    extra.message = "something new".into();
    more.push(extra);
    more.push(more[1].clone());
    let (new, _) = base.filter(more);
    assert_eq!(new.len(), 2);
}

#[test]
fn baseline_survives_renamed_functions_and_moved_files() {
    let f = load("tests/vuln/app.py");
    let base = Baseline::from_findings(&f);
    let renamed: Vec<Finding> = f.iter().cloned().map(|mut x| (x.function = format!("renamed_{}", x.function), x).1).collect();
    let (new, known) = base.filter(renamed);
    assert!(new.is_empty() && known == f.len(), "{new:?}");
    let moved: Vec<Finding> = f.iter().cloned().map(|mut x| (x.file = PathBuf::from("src/elsewhere/app.py"), x).1).collect();
    let (new, known) = base.filter(moved.clone());
    assert!(new.is_empty() && known == f.len(), "{new:?}");
    // moving does not hide an additional finding of the same kind
    let mut more = moved;
    more.push(more[0].clone());
    assert_eq!(base.filter(more).0.len(), 1);
}

#[test]
fn suppressions_expire() {
    let mk = |line: usize| Finding {
        rule: "xss",
        cwe: "CWE-79",
        severity: analysis::Severity::Medium,
        message: String::new(),
        file: PathBuf::from("x.js"),
        function: "f".into(),
        line,
        col: 1,
        origin: None,
    };
    let src = "a(); // taintless: ignore[xss] until=2026-06-30\n// taintless: ignore until 2027-01-01\nb();\nc(); // taintless: ignore[xss] until=not-a-date\n";
    let run = |today: &str| suppress::apply_on(vec![mk(1), mk(3), mk(4)], &|_| Some(src.to_string()), today);
    let (kept, dropped, expired) = run("2026-06-30");
    assert!(kept.is_empty() && dropped == 3 && expired == 0, "the last day still counts");
    let (kept, dropped, expired) = run("2026-07-01");
    assert_eq!(kept.iter().map(|f| f.line).collect::<Vec<_>>(), [1]);
    assert_eq!((dropped, expired), (2, 1));
    let (kept, _, expired) = run("2027-01-02");
    assert_eq!(kept.iter().map(|f| f.line).collect::<Vec<_>>(), [1, 3]);
    assert_eq!(expired, 2);
    assert_eq!(suppress::today().len(), 10);
}

#[test]
fn baseline_cli_round_trip() {
    let file = tmp("baseline.json");
    let file = file.to_str().unwrap();
    let write = taintless(&["security", "tests/vuln/app.py", "--write-baseline", file]);
    assert_eq!(write.status.code(), Some(0));
    // everything in app.py is known now
    let out = taintless(&["security", "tests/vuln/app.py", "--baseline", file]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already in the baseline"));
    // but the other files of the directory are new
    let dir = findings(&["tests/vuln", "--baseline", file]);
    assert!(!dir.is_empty() && dir.iter().all(|x| x.0 != "app.py"));
}

#[test]
fn comment_markers_in_other_syntaxes() {
    let mk = |line: usize| Finding {
        rule: "xss",
        cwe: "CWE-79",
        severity: analysis::Severity::Medium,
        message: String::new(),
        file: PathBuf::from("x.js"),
        function: "f".into(),
        line,
        col: 1,
        origin: None,
    };
    let src = "a();\n/* taintless: ignore[xss] */\nb();\nc(); // taintless: ignore\nd();\n";
    let (kept, dropped) = suppress::apply(vec![mk(3), mk(4), mk(5)], &|_| Some(src.to_string()));
    assert_eq!(dropped, 2);
    assert_eq!(kept.iter().map(|f| f.line).collect::<Vec<_>>(), [5]);
}

#[test]
fn java_main_args_are_untrusted_by_default() {
    let src = "class M { static void main(String[] args) {\n Runtime.getRuntime().exec(args[0]);\n } void other(String[] args) {\n Runtime.getRuntime().exec(args[0]);\n } }";
    let l = lang::Language::Java;
    let cfgs = lang::build_cfgs(l, src).unwrap();
    let f = analysis::check_file(l, Path::new("M.java"), &cfgs);
    assert_eq!(f.iter().map(|x| x.line).collect::<Vec<_>>(), [2], "only main's `args` are command-line input: {f:?}");
}

#[test]
fn extends_nested_configs_rule_excludes_and_source_messages() {
    let out = taintless(&["security", "tests/cfgdirs", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    let f: Vec<(String, String, String, Option<String>)> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["file"].as_str().unwrap().replace("tests/cfgdirs/", ""),
                f["rule"].as_str().unwrap().into(),
                f["severity"].as_str().unwrap().into(),
                f["origin"].as_str().map(String::from),
            )
        })
        .collect();
    let has = |file: &str, rule: &str| f.iter().find(|x| x.0 == file && x.1 == rule);
    // root config: `weak-crypto` disabled by the file it extends, severity overridden on top of it
    assert!(f.iter().all(|x| x.1 != "weak-crypto"), "{f:?}");
    assert_eq!(has("app.py", "command-injection").unwrap().2, "medium");
    // sub/.taintless.toml disables command-injection below sub/ and excludes deep/skip.py
    assert!(f.iter().all(|x| !x.0.starts_with("sub/")), "{f:?}");
    // [rule.sql-injection] exclude is per rule: other/q.py keeps its other findings
    assert!(has("other/q.py", "sql-injection").is_none(), "{f:?}");
    let cmd = has("other/q.py", "command-injection").expect("myapp.read() is a source");
    assert!(cmd.3.as_deref().unwrap().contains("comes from the HTTP layer"), "{cmd:?}");
}

#[test]
fn config_errors_in_extends() {
    let dir = tmp("cfg_loop");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.toml"), "extends = [\"b.toml\"]\n").unwrap();
    std::fs::write(dir.join("b.toml"), "extends = [\"a.toml\"]\n").unwrap();
    let out = taintless(&["security", "tests/config/app.py", "--config", dir.join("a.toml").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("extends itself"), "{}", String::from_utf8_lossy(&out.stderr));
    // analysis tables are not allowed in nested configs
    let nested = dir.join("proj/sub");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join(".taintless.toml"), "[[sanitizer]]\ncall = \"x\"\n").unwrap();
    std::fs::write(nested.join("a.py"), "x = 1\n").unwrap();
    let out = taintless(&["security", dir.join("proj").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("root configuration"));
}

#[test]
fn baseline_fingerprints_survive_rename_and_move_together() {
    let dir = tmp("fingerprints");
    std::fs::create_dir_all(dir.join("moved")).unwrap();
    let old = dir.join("a.py");
    let new = dir.join("moved/b.py");
    std::fs::write(&old, "import os\n\n\ndef handler():\n    os.system(input())\n").unwrap();
    // another function, another file, and the line indented differently (whitespace is normalized)
    std::fs::write(&new, "import os\n\n# moved\n\ndef renamed():\n        os.system(input())\n").unwrap();
    let read = |p: &Path| std::fs::read_to_string(p).ok();
    let before = load(old.to_str().unwrap());
    assert_eq!(before.len(), 1);
    let base = Baseline::build(&before, &read, None);
    assert!(base.findings[0].fingerprint.is_some());
    let after = load(new.to_str().unwrap());
    assert_eq!(after.len(), 1);
    // without fingerprints (old baselines, `filter`) a rename plus a move is a new finding
    assert_eq!(Baseline::from_findings(&before).filter(after.clone()).0.len(), 1);
    let (new_findings, known, _) = base.filter_on(after, &read, &suppress::today());
    assert!(new_findings.is_empty() && known == 1, "{new_findings:?}");
    // a different line of code is not the same finding
    std::fs::write(&new, "import os\n\ndef renamed():\n    os.system(input() + 'x')\n").unwrap();
    let other = load(new.to_str().unwrap());
    assert_eq!(base.filter_on(other, &read, &suppress::today()).0.len(), 1);
}

#[test]
fn baseline_entries_have_review_dates() {
    let f = load("tests/vuln/app.py");
    let read = |p: &Path| std::fs::read_to_string(p).ok();
    let mut base = Baseline::build(&f, &read, Some(30));
    let due = base.findings[0].review_by.clone().unwrap();
    assert_eq!(due.len(), 10);
    // before the date everything is hidden; after it the findings are back, and counted
    let (new, known, expired) = base.filter_on(f.clone(), &read, &suppress::today());
    assert!(new.is_empty() && known == f.len() && expired == 0);
    let (new, known, expired) = base.filter_on(f.clone(), &read, "9999-01-01");
    assert_eq!((new.len(), known, expired), (f.len(), 0, f.len()));
    // only the entries past their date stop hiding
    base.findings[0].review_by = Some("2000-01-01".into());
    let (_, _, expired) = base.filter_on(f, &read, &suppress::today());
    assert_eq!(expired, base.findings[0].count);
    // the CLI writes the dates
    let file = tmp("baseline_review.json");
    let out = taintless(&["security", "tests/vuln/app.py", "--write-baseline", file.to_str().unwrap(), "--review-after", "30"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(std::fs::read_to_string(&file).unwrap().contains("review_by"));
}

/// A scratch path private to this test run, so concurrent `cargo test` runs don't share files.
fn tmp(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{name}", std::process::id()))
}
