//! Pruning of unused entries and where the default cache lives.
use taintless::store::Store;

mod common;

#[test]
fn unused_entries_are_pruned_and_used_ones_kept() {
    let dir = std::env::temp_dir().join(format!("taintless-prune-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut db = Store::open(&dir.join("db.sqlite")).unwrap();
    db.begin_run().unwrap();
    db.put_all(&[("old".into(), vec![1]), ("used".into(), vec![2])], &[]).unwrap();
    for _ in 0..40 {
        db.begin_run().unwrap();
        db.put_all(&[], &["used".into()]).unwrap();
    }
    assert!(db.get_raw("old").unwrap().is_none());
    assert!(db.get_raw("used").unwrap().is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn default_cache_sits_in_the_project_root() {
    let root = std::env::temp_dir().join(format!("taintless-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src/deep")).unwrap();
    std::fs::write(root.join("src/deep/a.py"), "def f():\n    pass\n").unwrap();
    // scanning a subdirectory, from somewhere else, uses the cache at the root
    common::taintless(&["security", root.join("src/deep").to_str().unwrap()]);
    assert!(root.join(".taintless/db.sqlite").exists());
    assert!(!root.join("src/deep/.taintless").exists());
    let _ = std::fs::remove_dir_all(&root);
}
