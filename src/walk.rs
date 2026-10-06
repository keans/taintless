//! The directory walk shared by file discovery and configuration discovery: it honors
//! `.gitignore` / `.ignore` and the `--exclude` globs.

use anyhow::Result;
use ignore::WalkBuilder;
use ignore::overrides::{Override, OverrideBuilder};
use std::path::Path;
use std::sync::OnceLock;

static EXCLUDES: OnceLock<Override> = OnceLock::new();

/// Leave out what these `.gitignore`-style globs match (relative to the working directory) in
/// every later [`walker`]. Call once, before walking.
pub fn set_excludes(globs: &[String]) -> Result<()> {
    let mut o = OverrideBuilder::new(std::env::current_dir()?);
    for g in globs {
        // an override glob with `!` ignores what it matches
        o.add(&format!("!{g}"))?;
    }
    let _ = EXCLUDES.set(o.build()?);
    Ok(())
}

/// A walk over `path`.
pub fn walker(path: &Path) -> WalkBuilder {
    let mut w = WalkBuilder::new(path);
    if let Some(o) = EXCLUDES.get() {
        w.overrides(o.clone());
    }
    w
}
