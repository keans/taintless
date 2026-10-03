//! Stamp the build with a hash of the sources, so the cache of stored results is
//! invalidated by any change to the analysis code, however the binary was produced.

use std::path::Path;

fn walk(dir: &Path, hasher: &mut blake3::Hasher) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk(&p, hasher);
        } else if let Ok(bytes) = std::fs::read(&p) {
            hasher.update(p.to_string_lossy().as_bytes());
            hasher.update(&bytes);
        }
    }
}

fn main() {
    let mut hasher = blake3::Hasher::new();
    walk(Path::new("src"), &mut hasher);
    for file in ["Cargo.toml", "Cargo.lock"] {
        hasher.update(&std::fs::read(file).unwrap_or_default());
    }
    println!("cargo:rustc-env=TAINTLESS_BUILD={}", hasher.finalize().to_hex());
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
}
