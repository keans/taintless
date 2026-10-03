//! Record the files an analysis reads besides the sources (configuration, package
//! manifests), so a stored result can be checked against what is on disk now.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// A recorded input: the file (or `dir:`-prefixed listing) and a hash of what it held;
/// `None` when it was absent.
pub type Input = (PathBuf, Option<String>);

static ENABLED: AtomicBool = AtomicBool::new(false);
static LOG: Mutex<BTreeMap<PathBuf, Option<String>>> = Mutex::new(BTreeMap::new());

fn hash(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// Start recording reads; without it (`--no-cache`) they cost nothing.
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

fn record(path: &Path, h: Option<String>) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if let Ok(mut log) = LOG.lock() {
        log.insert(path.to_path_buf(), h);
    }
}

/// Pass the result of reading `path` through, remembering what it held (or that it was
/// missing): `inputs::note(&p, std::fs::read_to_string(&p))`.
pub fn note(path: &Path, res: std::io::Result<String>) -> std::io::Result<String> {
    if ENABLED.load(Ordering::Relaxed) {
        record(path, res.as_ref().ok().map(|s| hash(s)));
    }
    res
}

/// The subdirectories of `dir` a workspace pattern can match, sorted; `None` when it cannot be listed.
pub fn subdirs(dir: &Path) -> Option<Vec<PathBuf>> {
    let mut subs: Vec<PathBuf> =
        std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir() && !p.ends_with("node_modules")).collect();
    subs.sort();
    Some(subs)
}

fn listing_hash(subs: &[PathBuf]) -> String {
    hash(&subs.iter().map(|p| format!("{}\n", p.display())).collect::<String>())
}

/// Remember the subdirectories found when expanding a pattern under `dir`.
pub fn record_listing(dir: &Path, subs: &[PathBuf]) {
    record(&PathBuf::from(format!("dir:{}", dir.display())), Some(listing_hash(subs)));
}

/// Remember that `dir` could not be listed.
pub fn record_missing_listing(dir: &Path) {
    record(&PathBuf::from(format!("dir:{}", dir.display())), None);
}

/// Everything recorded so far.
pub fn snapshot() -> Vec<Input> {
    LOG.lock().map(|l| l.iter().map(|(p, h)| (p.clone(), h.clone())).collect()).unwrap_or_default()
}

/// Whether every input still holds what it did when recorded.
pub fn unchanged(inputs: &[Input]) -> bool {
    inputs.iter().all(|(p, h)| match p.to_str().and_then(|s| s.strip_prefix("dir:")) {
        Some(dir) => subdirs(Path::new(dir)).map(|subs| listing_hash(&subs)) == *h,
        None => std::fs::read_to_string(p).ok().map(|s| hash(&s)) == *h,
    })
}
