//! Preprocessor macros in C / C++: expanded, conditionals resolved, and headers of the project
//! included.

mod common;

use std::path::Path;

fn functions(args: &[&str]) -> Vec<String> {
    let mut a = vec!["security"];
    a.extend_from_slice(args);
    a.extend(["--format", "json"]);
    let out = common::taintless(&a);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
    let mut f: Vec<String> = v.as_array().unwrap().iter().map(|f| f["function"].as_str().unwrap().to_string()).collect();
    f.sort();
    f
}

#[test]
fn macros_from_headers_are_expanded() {
    let f = functions(&["--no-cache", "tests/c_macros"]);
    // a function-like macro, an object-like alias and token pasting all end up calling system()
    for want in ["via_header_macro", "via_header_alias", "via_paste"] {
        assert!(f.iter().any(|x| x == want), "{want} in {f:?}");
    }
    // `#if MODE == 2` takes the first branch (MODE comes from the header); `#if 0` is dropped
    assert!(f.iter().any(|x| x == "selected"), "{f:?}");
    assert!(!f.iter().any(|x| x == "dropped" || x == "disabled"), "{f:?}");
    // a literal command is not a finding
    assert!(!f.iter().any(|x| x == "safe"), "{f:?}");
}

#[test]
fn unknown_conditions_keep_both_branches_and_cpp_is_known() {
    let f = functions(&["--no-cache", "tests/c_macros"]);
    assert!(f.iter().any(|x| x == "cpp_only"), "{f:?}");
    assert!(!f.iter().any(|x| x == "c_only"), "{f:?}");
    assert!(f.iter().any(|x| x == "windows") && f.iter().any(|x| x == "posix"), "{f:?}");
}

#[test]
fn a_changed_header_invalidates_the_cached_results() {
    let dir = std::env::temp_dir().join(format!("taintless-cmacros-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.h"), "#define CMD system\n").unwrap();
    std::fs::write(dir.join("a.c"), "#include \"a.h\"\nint f(int argc, char **argv) { CMD(argv[1]); return 0; }\n").unwrap();
    let db = dir.join("db.sqlite");
    let run = || {
        let (d, c) = (dir.to_string_lossy().to_string(), db.to_string_lossy().to_string());
        let out = common::taintless(&["--cache", &c, "security", &d, "--format", "json"]);
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap().as_array().unwrap().len()
    };
    assert_eq!(run(), 1);
    assert_eq!(run(), 1, "from the cache");
    // the macro now names a harmless function: same a.c, different results
    std::fs::write(dir.join("a.h"), "#define CMD puts\n").unwrap();
    assert_eq!(run(), 0);
    assert!(Path::new(&db).exists());
    let _ = std::fs::remove_dir_all(&dir);
}
