//! Security analysis over the CFGs: taint tracking from untrusted sources to
//! dangerous calls, rule-based findings and unreachable code.

pub mod baseline;
pub mod callgraph;
pub mod config;
pub mod dataflow;
pub mod deps;
pub mod link;
pub mod manifest;
pub mod rules;
pub mod suppress;
pub(crate) mod taint;
pub(crate) mod values;
mod unreachable;

use crate::ir::Cfg;
use crate::lang::Language;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn escalate(self) -> Self {
        match self {
            Self::Low => Self::Medium,
            _ => Self::High,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    pub cwe: &'static str,
    pub severity: Severity,
    pub message: String,
    pub file: PathBuf,
    /// Qualified name of the enclosing function.
    pub function: String,
    pub line: usize,
    pub col: usize,
    /// Where the untrusted data came from, e.g. `input() (line 3)`.
    pub origin: Option<String>,
}

/// A path as shown to users and matched by `exclude` / baselines: relative to
/// the working directory when possible, forward slashes, no leading `./`.
pub fn rel_path(p: &Path) -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    let p = p.strip_prefix(&cwd).unwrap_or(p);
    let s = p.to_string_lossy().replace('\\', "/");
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

/// One analyzed source file.
pub struct ProjectFile<'a> {
    pub lang: Language,
    pub file: &'a Path,
    pub cfgs: &'a [Cfg],
    /// What the file imports; lets calls to same-named functions resolve to the
    /// one it can actually see. May be empty.
    pub imports: &'a [crate::lang::common::Import],
}

/// Number of functions `check_project` will analyze (for progress reporting).
pub fn function_count(files: &[ProjectFile]) -> usize {
    files.iter().map(|f| f.cfgs.len()).sum()
}

/// Run every analysis over a whole project, so that data flowing between
/// functions (and files) is followed. `progress` is called once per function.
/// Findings are deduplicated (a `finally` body is copied onto several paths)
/// and sorted by position.
pub fn check_project(files: &[ProjectFile], progress: &(dyn Fn() + Sync)) -> Vec<Finding> {
    use rayon::prelude::*;
    let fns: Vec<taint::FnInfo> = files
        .iter()
        .enumerate()
        .flat_map(|(fi, f)| {
            let rules = rules::rules_for(f.lang);
            f.cfgs.iter().map(move |cfg| taint::FnInfo { file_idx: fi, lang: f.lang, file: f.file, cfg, rules })
        })
        .collect();
    let dep_files: Vec<deps::DepFile> = files
        .iter()
        .map(|f| deps::DepFile { path: f.file, lang: f.lang, imports: f.imports.to_vec(), cfgs: f.cfgs })
        .collect();
    let visible = (!files.iter().all(|f| f.imports.is_empty())).then(|| deps::visibility(&dep_files));
    let mut out = taint::analyze_project(&fns, visible, progress);
    out.par_extend(fns.par_iter().flat_map(|f| {
        let mut v = vec![];
        unreachable::analyze(f.cfg, f.file, &mut v);
        v
    }));

    // The same sink can be reached several ways: keep the most severe report,
    // preferring one that names where the untrusted data came from.
    out.sort_by(|a, b| {
        (&a.file, a.line, a.col, a.rule, &a.function)
            .cmp(&(&b.file, b.line, b.col, b.rule, &b.function))
            .then(b.severity.cmp(&a.severity))
            .then(b.origin.is_some().cmp(&a.origin.is_some()))
            .then(a.origin.cmp(&b.origin))
    });
    out.dedup_by(|a, b| (&a.file, a.line, a.col, a.rule, &a.function) == (&b.file, b.line, b.col, b.rule, &b.function));
    match config::installed() {
        Some(active) => active.filter(out),
        None => out,
    }
}

/// Analyze a single file on its own.
pub fn check_file(lang: Language, file: &Path, cfgs: &[Cfg]) -> Vec<Finding> {
    check_project(&[ProjectFile { lang, file, cfgs, imports: &[] }], &|| {})
}
