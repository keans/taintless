//! Project configuration (`.taintless.toml`): turn rules off, change severities,
//! skip paths and teach the analysis about the project's own sources, sinks,
//! sanitizers and entry points.
//!
//! ```toml
//! extends = ["../base.toml"]            # configs (relative to this file) merged underneath this one
//! disable = ["weak-crypto"]             # rule ids
//! exclude = ["tests/**", "vendor/**"]   # findings in these paths are dropped
//!
//! [severity]
//! unreachable-code = "medium"
//!
//! [rule.command-injection]              # per rule: skip findings in these paths
//! exclude = ["scripts/**"]
//!
//! [[source]]                            # untrusted data
//! language = "python"                   # optional; default: every language
//! call = "myapp.read_request"           # a call whose result is untrusted ...
//! # path = "ctx.params"                 # ... or a variable / member path
//! message = "comes from the HTTP layer" # optional: shown with the finding's origin
//!
//! [[sanitizer]]
//! call = "myapp.clean"
//!
//! [[sink]]                              # a dangerous call
//! call = "myapp.db.raw_query"
//! rule = "sql-injection"                # a built-in rule id: gives CWE, message
//! arg = 0                               # optional: only this argument counts
//!
//! [[entry]]                             # parameters of these functions are untrusted
//! function = "handle_*"
//! params = ["data"]                     # optional: only these
//! ```
//!
//! `implicit_flows = true` (top level, off by default) also follows implicit flows: a branch on
//! untrusted data taints the variables assigned under it (`if secret: x = 1` taints `x`).
//!
//! A `.taintless.toml` in a subdirectory of the scanned path adds to the root one for
//! the files below it: `disable` and `exclude` (matched relative to that
//! directory) accumulate, `severity` overrides. It cannot define sources, sinks,
//! sanitizers or entry points, which are the same for the whole run.

use crate::lang::Language;
use super::rules::{self, ArgSel, CallRule, Entry, Mode, RULE_INFO};
use super::{Finding, Severity};
use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default)]
    pub rule: BTreeMap<String, RuleCfg>,
    #[serde(default)]
    pub disable: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub severity: BTreeMap<String, String>,
    #[serde(default)]
    pub source: Vec<SourceCfg>,
    #[serde(default)]
    pub sanitizer: Vec<SanitizerCfg>,
    #[serde(default)]
    pub sink: Vec<SinkCfg>,
    #[serde(default)]
    pub entry: Vec<EntryCfg>,
    /// Also follow implicit flows: what a branch on untrusted data decides taints the
    /// variables assigned under it (`if secret: x = 1` taints `x`).
    #[serde(default)]
    pub implicit_flows: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCfg {
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Config {
    /// `self` on top of `base`: lists add up, the more specific severity wins.
    fn on_top_of(mut self, mut base: Config) -> Config {
        base.disable.extend(self.disable);
        base.exclude.extend(self.exclude);
        base.severity.append(&mut self.severity);
        for (id, r) in self.rule {
            base.rule.entry(id).or_default().exclude.extend(r.exclude);
        }
        base.source.extend(self.source);
        base.sanitizer.extend(self.sanitizer);
        base.sink.extend(self.sink);
        base.entry.extend(self.entry);
        base.implicit_flows |= self.implicit_flows;
        base
    }

    fn defines_analysis_tables(&self) -> bool {
        self.implicit_flows || !(self.source.is_empty() && self.sanitizer.is_empty() && self.sink.is_empty() && self.entry.is_empty())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCfg {
    pub message: Option<String>,
    pub language: Option<String>,
    pub call: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizerCfg {
    pub language: Option<String>,
    pub call: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkCfg {
    pub language: Option<String>,
    pub call: String,
    pub rule: String,
    pub arg: Option<usize>,
    pub severity: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryCfg {
    pub language: Option<String>,
    pub function: String,
    pub params: Option<Vec<String>>,
}

/// The `disable` / `exclude` / `severity` settings of one config file.
struct Scope {
    /// Directory the settings apply below, relative like findings' paths (`""`: everywhere).
    dir: String,
    disable: Vec<String>,
    exclude: GlobSet,
    rule_exclude: BTreeMap<String, GlobSet>,
    severity: BTreeMap<String, Severity>,
}

impl Scope {
    fn new(dir: String, config: &Config) -> Result<Self> {
        for id in config.disable.iter().chain(config.rule.keys()) {
            known_rule(id)?;
        }
        let mut severity = BTreeMap::new();
        for (id, s) in &config.severity {
            known_rule(id)?;
            severity.insert(id.clone(), parse_severity(s).with_context(|| format!("[severity] {id}"))?);
        }
        let globs = |list: &[String], what: &str| -> Result<GlobSet> {
            let mut b = GlobSetBuilder::new();
            for g in list {
                b.add(Glob::new(g).with_context(|| format!("{what} pattern `{g}`"))?);
            }
            Ok(b.build()?)
        };
        let mut rule_exclude = BTreeMap::new();
        for (id, r) in &config.rule {
            rule_exclude.insert(id.clone(), globs(&r.exclude, &format!("[rule.{id}] exclude"))?);
        }
        Ok(Self { dir, disable: config.disable.clone(), exclude: globs(&config.exclude, "exclude")?, rule_exclude, severity })
    }

    /// `path` below this scope's directory, if it is.
    fn within<'p>(&self, path: &'p str) -> Option<&'p str> {
        if self.dir.is_empty() {
            return Some(path);
        }
        path.strip_prefix(&self.dir)?.strip_prefix('/')
    }
}

/// A validated configuration, installed once per process.
pub struct Active {
    pub config: Config,
    /// The root config first, then the ones found in subdirectories.
    scopes: Vec<Scope>,
}

static ACTIVE: OnceLock<Active> = OnceLock::new();

/// The installed configuration, if any.
pub fn installed() -> Option<&'static Active> {
    ACTIVE.get()
}

/// Whether the installed configuration turns on implicit flows (`implicit_flows = true`).
pub fn implicit_flows() -> bool {
    installed().is_some_and(|a| a.config.implicit_flows)
}

/// Make `config` apply to every analysis in this process.
pub fn install(config: Config) -> Result<()> {
    install_with(config, vec![])
}

/// Like `install`, with the configs found in subdirectories (their directory, relative to
/// the working directory, and contents).
pub fn install_with(config: Config, nested: Vec<(String, Config)>) -> Result<()> {
    let active = Active::new(config, nested)?;
    ACTIVE.set(active).map_err(|_| anyhow::anyhow!("configuration already installed"))
}

pub fn parse_severity(s: &str) -> Result<Severity> {
    Ok(match s {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        other => bail!("unknown severity `{other}` (use low, medium or high)"),
    })
}

/// Language name -> language family (`None` = every language).
pub fn family_of(name: &Option<String>) -> Result<Option<u8>> {
    let Some(n) = name else { return Ok(None) };
    match Language::from_name(n) {
        Some(l) => Ok(Some(l.family())),
        None => bail!("unknown language `{n}` (python, javascript, typescript, rust, go, java, c, cpp)"),
    }
}

fn known_rule(id: &str) -> Result<()> {
    if RULE_INFO.iter().any(|(r, _, _)| *r == id) {
        return Ok(());
    }
    let ids: Vec<&str> = RULE_INFO.iter().map(|(r, _, _)| *r).collect();
    bail!("unknown rule `{id}`; known rules: {}", ids.join(", "))
}

impl Active {
    fn new(config: Config, nested: Vec<(String, Config)>) -> Result<Self> {
        for s in &config.source {
            family_of(&s.language)?;
            if s.call.is_none() == s.path.is_none() {
                bail!("[[source]] needs exactly one of `call` or `path`");
            }
        }
        for s in &config.sanitizer {
            family_of(&s.language)?;
        }
        for s in &config.sink {
            family_of(&s.language)?;
            known_rule(&s.rule).with_context(|| format!("[[sink]] call = \"{}\"", s.call))?;
            if let Some(sev) = &s.severity {
                parse_severity(sev)?;
            }
        }
        for e in &config.entry {
            family_of(&e.language)?;
        }
        let mut scopes = vec![Scope::new(String::new(), &config)?];
        let mut nested = nested;
        nested.sort_by(|a, b| a.0.cmp(&b.0)); // parents before children
        for (dir, c) in &nested {
            if c.defines_analysis_tables() {
                bail!("{dir}/.taintless.toml: implicit_flows, [[source]], [[sanitizer]], [[sink]] and [[entry]] belong in the root configuration");
            }
            scopes.push(Scope::new(dir.clone(), c).with_context(|| format!("{dir}/.taintless.toml"))?);
        }
        Ok(Self { scopes, config })
    }

    /// Apply `disable`, `severity`, `exclude` and rule-level `exclude` to findings.
    pub fn filter(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter_map(|mut f| {
                let path = super::rel_path(&f.file);
                for sc in &self.scopes {
                    let Some(rel) = sc.within(&path) else { continue };
                    if sc.disable.iter().any(|d| d == f.rule)
                        || sc.exclude.is_match(rel)
                        || sc.rule_exclude.get(f.rule).is_some_and(|g| g.is_match(rel))
                    {
                        return None;
                    }
                    if let Some(&s) = sc.severity.get(f.rule) {
                        f.severity = s;
                    }
                }
                Some(f)
            })
            .collect()
    }
}

/// `.taintless.toml` next to the scanned path, else in the working directory.
pub fn discover(scanned: &Path) -> Option<PathBuf> {
    let dir = if scanned.is_dir() { scanned } else { scanned.parent().unwrap_or(Path::new(".")) };
    [dir.join(".taintless.toml"), PathBuf::from(".taintless.toml")].into_iter().find(|p| p.is_file())
}

/// Read a config file together with the ones it `extends`.
pub fn load(path: &Path) -> Result<Config> {
    load_chain(path, &mut vec![])
}

fn load_chain(path: &Path, seen: &mut Vec<PathBuf>) -> Result<Config> {
    let canon = path.canonicalize().with_context(|| format!("reading {}", path.display()))?;
    if seen.contains(&canon) {
        bail!("{} extends itself (through {})", path.display(), seen.last().map_or(String::new(), |p| p.display().to_string()));
    }
    seen.push(canon);
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut config: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut merged = Config::default();
    for e in std::mem::take(&mut config.extends) {
        let base = load_chain(&dir.join(&e), seen).with_context(|| format!("{} extends {e}", path.display()))?;
        merged = base.on_top_of(merged);
    }
    seen.pop();
    Ok(config.on_top_of(merged))
}

/// `.taintless.toml` files below the scanned directory (other than `root`), as
/// `(directory relative to the working directory, config)`.
pub fn discover_nested(scanned: &Path, root: Option<&Path>) -> Result<Vec<(String, Config)>> {
    if !scanned.is_dir() {
        return Ok(vec![]);
    }
    let root = root.and_then(|r| r.canonicalize().ok());
    let mut out = vec![];
    for entry in ignore::WalkBuilder::new(scanned).hidden(false).build().flatten() {
        if entry.file_name() != ".taintless.toml" || !entry.path().is_file() {
            continue;
        }
        if root.is_some() && entry.path().canonicalize().ok() == root {
            continue;
        }
        let dir = entry.path().parent().unwrap_or(Path::new("."));
        out.push((super::rel_path(dir), load(entry.path())?));
    }
    out.retain(|(d, _)| !d.is_empty() && d != ".");
    Ok(out)
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

fn leak_slice<T>(v: Vec<T>) -> &'static [T] {
    Box::leak(v.into_boxed_slice())
}

/// The built-in rules of `base` extended with the configured ones for family `fam`.
pub(super) fn extend(base: &'static rules::RuleSet, fam: u8, cfg: &Config) -> &'static rules::RuleSet {
    let mine = |l: &Option<String>| family_of(l).ok().flatten().is_none_or(|f| f == fam);
    let mut rule_list = base.rules.to_vec();
    for s in cfg.sink.iter().filter(|s| mine(&s.language)) {
        // inherit CWE / severity / message from the built-in rule of that id
        let proto = rules::all_rules().find(|r| r.id == s.rule);
        let (id, cwe, sev, msg) = RULE_INFO
            .iter()
            .find(|(r, _, _)| *r == s.rule)
            .map(|(id, title, cwe)| (*id, *cwe, proto.map_or(Severity::High, |p| p.severity), proto.map_or(*title, |p| p.message)))
            .expect("validated");
        rule_list.push(CallRule {
            pattern: leak(&s.call),
            id,
            cwe,
            severity: s.severity.as_deref().and_then(|x| parse_severity(x).ok()).unwrap_or(sev),
            message: s.message.as_deref().map_or(msg, leak),
            mode: Mode::Tainted(s.arg.map_or(ArgSel::Any, ArgSel::At)),
            except: &[],
        });
    }
    let mut calls = base.source_calls.to_vec();
    let mut paths = base.source_paths.to_vec();
    let mut notes = base.source_notes.to_vec();
    for s in cfg.source.iter().filter(|s| mine(&s.language)) {
        if let Some(c) = &s.call {
            calls.push(leak(c));
            if let Some(m) = &s.message {
                notes.push((true, leak(c), leak(m)));
            }
        }
        if let Some(p) = &s.path {
            paths.push(leak(p));
            if let Some(m) = &s.message {
                notes.push((false, leak(p), leak(m)));
            }
        }
    }
    let mut sanitizers = base.sanitizers.to_vec();
    sanitizers.extend(cfg.sanitizer.iter().filter(|s| mine(&s.language)).map(|s| leak(&s.call)));
    let mut entries = base.entries.to_vec();
    for e in cfg.entry.iter().filter(|e| mine(&e.language)) {
        let params: Vec<&'static str> = e.params.iter().flatten().map(|p| leak(p)).collect();
        entries.push(Entry { pattern: leak(&e.function), params: leak_slice(params) });
    }
    Box::leak(Box::new(rules::RuleSet {
        entries: leak_slice(entries),
        rules: leak_slice(rule_list),
        source_calls: leak_slice(calls),
        source_paths: leak_slice(paths),
        sanitizers: leak_slice(sanitizers),
        source_notes: leak_slice(notes),
    }))
}
