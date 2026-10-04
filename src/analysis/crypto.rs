//! Cryptography inventory: which crypto libraries a project imports and which
//! crypto functions it calls. Purely name-based: imports are matched against
//! library prefixes, normalized callees against the same patterns as the
//! security rules (`hashlib.md5`, `*.createHash`), plus `name*` for C-style
//! prefixes (`EVP_*`).

pub mod tables;
mod der;
mod object;

use self::tables::{Call, active};
use super::rules;
use crate::ir::{CallFlow, Cfg, Flow};
use crate::lang::{Language, common::{Import, simple_name as simple}};
use std::collections::{BTreeMap, BTreeSet};
use petgraph::visit::NodeIndexable;
use std::path::{Path, PathBuf};

const PY: u8 = 0;
const JS: u8 = 1;
const RS: u8 = 2;
const GO: u8 = 3;
const JAVA: u8 = 4;
const C: u8 = 5;
const CS: u8 = 6;

fn call_matches(pattern: &str, callee: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) if !prefix.ends_with('.') => callee.rsplit('.').next().is_some_and(|last| last.starts_with(prefix)),
        _ => rules::matches(pattern, callee),
    }
}

fn module_matches(prefix: &str, module: &str) -> bool {
    let m = module.trim_start_matches("./");
    m.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '/', ':']))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Import,
    Call,
    /// Key material, a keystore, or a TLS / cipher setting in a configuration file (a PEM block inside
    /// source code counts too).
    File,
    /// A method called on an object a crypto call created (`c = Cipher.getInstance(..); c.doFinal(..)`)
    /// or on the result of one (`Fernet(k).encrypt(d)`).
    Method,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct CryptoUse {
    pub file: PathBuf,
    pub line: usize,
    pub col: usize,
    pub kind: Kind,
    /// The module (imports) or callee (calls) as it appears in the code.
    pub name: String,
    /// The library an import belongs to; empty for calls.
    pub library: String,
    /// `hash`, `cipher`, `mac`, `kdf`, `signature`, `tls`, ... (empty for imports).
    pub primitive: String,
    pub algorithm: String,
    /// A broken or deprecated algorithm, mode or key size (MD5, SHA-1, DES, RC4, ECB, RSA-1024, ...).
    pub weak: bool,
    /// Why it is weak (empty unless `weak`).
    pub reason: String,
    /// Other problems the arguments show: hardcoded keys, static IVs and salts, low iteration
    /// counts, constant PRNG seeds, ...
    pub issues: Vec<String>,
    /// The call's arguments as written (calls only, shortened).
    pub args: String,
    /// Methods: the line of the call that created the object (0 when it is not known).
    pub origin_line: usize,
    /// `vulnerable` to a quantum computer (RSA, ECC, DH, DSA), `safe` (ML-KEM, ML-DSA, SLH-DSA, ...) or empty.
    pub quantum: String,
    /// Enclosing function (calls only).
    pub function: String,
}

/// What a crypto call or object was created with, kept for the methods called on it.
#[derive(Clone)]
struct Origin {
    line: usize,
    primitive: &'static str,
    algorithm: String,
    reason: String,
}

/// Every scanned file's source, so a constant defined in another file can be resolved
/// (`Config.ALGO` for a name defined once in the project).
#[derive(Default)]
pub struct Project {
    sources: Vec<(u8, std::sync::Arc<str>)>,
    cache: std::sync::Mutex<std::collections::HashMap<(u8, String), Option<String>>>,
    summaries: std::sync::Mutex<Summaries>,
    /// The index of each file's first function in the call graph's `files x functions` order.
    node_base: std::sync::Mutex<std::collections::HashMap<PathBuf, usize>>,
    next_node: std::sync::atomic::AtomicUsize,
    /// `(caller function, line, col)` of a call -> the functions the call graph says it reaches.
    targets: std::sync::Mutex<Option<CallTargets>>,
    /// The calls each function is reached by: `(caller function, line, col, callee as written)`.
    callers: std::sync::Mutex<Callers>,
    /// The source of each function's file, by the function's index.
    node_sources: Vec<std::sync::Arc<str>>,
    /// A crypto argument was a parameter: the callers' arguments are worth reading.
    needs_callers: std::sync::atomic::AtomicBool,
}

/// The calls each function is reached by: `(caller function, line, col, callee as written)`.
type Callers = std::collections::HashMap<usize, Vec<(usize, usize, usize, String)>>;

/// `(caller function, line, col)` of a call -> the functions the call graph says it reaches.
type CallTargets = std::collections::HashMap<(usize, usize, usize), Vec<usize>>;

/// A method called on a parameter inside a function, listed where a crypto object is passed in.
#[derive(Clone)]
struct ParamSite {
    file: PathBuf,
    line: usize,
    col: usize,
    callee: String,
    function: String,
    args: String,
}

/// What the project's functions do with crypto objects: which return one, and which call methods
/// on their parameters. Filled while scanning, read by the next scan. Functions are identified by
/// their index in the call graph's order.
#[derive(Default)]
struct Summaries {
    registered: BTreeSet<usize>,
    /// Functions per language family and simple name, for calls the call graph does not resolve.
    by_name: BTreeMap<(u8, String), Vec<usize>>,
    /// The object a function returns; `None` when it returns something else, or different objects.
    returns: BTreeMap<usize, Option<Origin>>,
    /// Per parameter: the methods called on it.
    params: BTreeMap<usize, Vec<Vec<ParamSite>>>,
    /// Per parameter: the calls it is passed on in, so that methods called further down count.
    forwards: BTreeMap<usize, Vec<Vec<Forward>>>,
}

/// A parameter passed on as an argument of another call.
#[derive(Clone)]
struct Forward {
    line: usize,
    col: usize,
    callee: String,
    /// The argument position in that call.
    arg: usize,
}

impl Summaries {
    /// The one function with this simple name, when there is exactly one.
    fn unique(&self, fam: u8, name: &str) -> Option<usize> {
        match self.by_name.get(&(fam, name.to_string()))?.as_slice() {
            [n] if name.len() >= 4 => Some(*n),
            _ => None,
        }
    }
}

impl Project {
    /// From `(language, path, functions)` of every scanned file. A file without functions (only
    /// constants, say) has no retained source and is read again.
    pub fn new<'a>(files: impl Iterator<Item = (Language, &'a Path, &'a [Cfg])>) -> Self {
        let mut sources = vec![];
        let mut node_sources: Vec<std::sync::Arc<str>> = vec![];
        let mut node_base = std::collections::HashMap::new();
        let mut nodes = 0;
        for (lang, path, cfgs) in files {
            node_base.insert(path.to_path_buf(), nodes);
            nodes += cfgs.len();
            let src = cfgs.iter().map(|c| c.source.clone()).find(|s| !s.is_empty()).or_else(|| std::fs::read_to_string(path).ok().map(Into::into));
            node_sources.extend(std::iter::repeat_n(src.clone().unwrap_or_else(|| "".into()), cfgs.len()));
            sources.extend(src.map(|s| (lang.family(), s)));
        }
        Self { sources, node_sources, node_base: node_base.into(), next_node: nodes.into(), ..Self::default() }
    }

    /// The call graph index of the first function of `file` (new indexes for a file the project
    /// was not built from).
    fn base_of(&self, file: &Path, functions: usize) -> usize {
        let Ok(mut map) = self.node_base.lock() else { return 0 };
        *map.entry(file.to_path_buf()).or_insert_with(|| self.next_node.fetch_add(functions, std::sync::atomic::Ordering::Relaxed))
    }

    /// Whether any function returns a crypto object or calls methods on a parameter, so that
    /// resolving calls precisely is worth building the call graph.
    fn has_summaries(&self) -> bool {
        self.summaries.lock().is_ok_and(|s| s.returns.values().any(Option::is_some) || !s.params.is_empty() || !s.forwards.is_empty())
    }

    fn set_targets(&self, targets: CallTargets, callers: Callers) {
        if let Ok(mut t) = self.targets.lock() {
            *t = Some(targets);
        }
        if let Ok(mut c) = self.callers.lock() {
            *c = callers;
        }
    }

    /// The literal every caller passes for parameter `index` of function `node`, when they agree
    /// (`hash("MD5")` for `def hash(alg)`): a quoted string with its quotes, or a number.
    fn param_value(&self, node: usize, index: usize) -> Option<String> {
        self.needs_callers.store(true, std::sync::atomic::Ordering::Relaxed);
        let callers = self.callers.lock().ok()?;
        let sites = callers.get(&node).filter(|s| !s.is_empty() && s.len() <= 6)?;
        let mut value: Option<String> = None;
        for (caller, line, col, callee) in sites {
            let src = self.node_sources.get(*caller).filter(|s| !s.is_empty())?;
            let args = call_args(src, *line, *col, callee)?;
            let arg = args.get(index)?.trim();
            if named_arg(arg).is_some() {
                return None;
            }
            let v = if literal_text(arg).is_some() || arg.parse::<i64>().is_ok() {
                arg.to_string()
            } else if arg.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') && !arg.is_empty() {
                match const_lookup(src, arg.rsplit('.').next().unwrap_or(arg)) {
                    Lookup::Found(v) => v,
                    _ => return None,
                }
            } else {
                return None;
            };
            match &value {
                Some(old) if *old != v => return None,
                _ => value = Some(v),
            }
        }
        value
    }

    /// The functions a call reaches: what the call graph resolved, else the one function with the
    /// callee's simple name.
    fn targets_of(&self, sum: &Summaries, fam: u8, at: Option<(usize, usize, usize)>, callee: &str) -> Vec<usize> {
        if let Some(key) = at
            && let Ok(t) = self.targets.lock()
            && let Some(found) = t.as_ref().and_then(|m| m.get(&key))
            && !found.is_empty()
        {
            return found.clone();
        }
        sum.unique(fam, simple(callee)).into_iter().collect()
    }

    /// The object the project function a call reaches returns, when they all return the same kind.
    fn returned(&self, fam: u8, at: Option<(usize, usize, usize)>, callee: &str) -> Option<Origin> {
        let sum = self.summaries.lock().ok()?;
        let nodes = self.targets_of(&sum, fam, at, callee);
        let mut found: Option<Origin> = None;
        for n in nodes {
            let o = sum.returns.get(&n)?.as_ref()?;
            match &found {
                Some(f) if (f.primitive, &f.algorithm, &f.reason) != (o.primitive, &o.algorithm, &o.reason) => return None,
                _ => found = Some(o.clone()),
            }
        }
        found
    }

    /// The methods called on parameter `index` of the project functions a call reaches, and on what
    /// they pass it on to (a few calls deep).
    fn param_sites(&self, fam: u8, at: Option<(usize, usize, usize)>, callee: &str, index: usize) -> Vec<ParamSite> {
        let Ok(sum) = self.summaries.lock() else { return vec![] };
        let mut out: Vec<ParamSite> = vec![];
        let mut seen = BTreeSet::new();
        for n in self.targets_of(&sum, fam, at, callee) {
            self.collect_sites(&sum, fam, n, index, 0, &mut seen, &mut out);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_sites(&self, sum: &Summaries, fam: u8, node: usize, index: usize, depth: usize, seen: &mut BTreeSet<(usize, usize)>, out: &mut Vec<ParamSite>) {
        if depth > 3 || !seen.insert((node, index)) {
            return;
        }
        for site in sum.params.get(&node).and_then(|p| p.get(index)).into_iter().flatten() {
            if !out.iter().any(|o| (&o.file, o.line, o.col) == (&site.file, site.line, site.col)) {
                out.push(site.clone());
            }
        }
        for f in sum.forwards.get(&node).and_then(|p| p.get(index)).into_iter().flatten() {
            for next in self.targets_of(sum, fam, Some((node, f.line, f.col)), &f.callee) {
                self.collect_sites(sum, fam, next, f.arg, depth + 1, seen, out);
            }
        }
    }

    /// Record what `cfg` (function `node`) returns and which methods it calls on its parameters (the
    /// first time it is seen).
    fn register(&self, sc: &Scan, node: usize, cfg: &Cfg, objs: &BTreeMap<String, Option<Origin>>, fields: &BTreeMap<String, Option<Origin>>, entry_of: &dyn Fn(&str) -> Option<(&'static Call, String)>) {
        let Ok(mut sum) = self.summaries.lock() else { return };
        if !sum.registered.insert(node) {
            return;
        }
        sum.by_name.entry((sc.fam, simple(&cfg.name).to_string())).or_default().push(node);
        // what it returns: the same crypto object on every return
        let mut returned: Vec<Option<Origin>> = vec![];
        for r in cfg.graph.node_weights().flat_map(|b| &b.stmts).filter_map(|s| s.ret.as_ref()) {
            returned.push(match r {
                Flow::Call(c) => entry_of(&c.callee).map(|(e, n)| {
                    let u = describe(sc, cfg, c, e, &n);
                    Origin { line: c.line, primitive: &e.primitive, algorithm: u.algorithm, reason: u.reason }
                }),
                Flow::Path(p) => objs.get(p).or_else(|| fields.get(p)).cloned().flatten(),
                _ => None,
            });
        }
        let same = |a: &Origin, b: &Origin| (a.primitive, &a.algorithm, &a.reason) == (b.primitive, &b.algorithm, &b.reason);
        let origin = match returned.split_first() {
            Some((Some(first), rest)) if rest.iter().all(|o| o.as_ref().is_some_and(|o| same(first, o))) => Some(first.clone()),
            _ => None,
        };
        sum.returns.insert(node, origin);
        // methods called on its parameters
        let mut per_param: Vec<Vec<ParamSite>> = vec![vec![]; cfg.params.len()];
        for call in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.calls) {
            let Some((recv, _)) = call.callee.split_once('.') else { continue };
            let Some(i) = cfg.params.iter().position(|p| p.iter().any(|n| n == recv)) else { continue };
            let args = call_args(sc.source(), call.line, call.col, &call.callee).unwrap_or_default();
            per_param[i].push(ParamSite { file: sc.file.to_path_buf(), line: call.line, col: call.col, callee: call.callee.clone(), function: cfg.name.clone(), args: shorten(&args.join(", ")) });
        }
        if per_param.iter().any(|p| !p.is_empty()) {
            sum.params.insert(node, per_param);
        }
        // parameters passed on to other calls
        let mut forwards: Vec<Vec<Forward>> = vec![vec![]; cfg.params.len()];
        for call in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.calls) {
            for (arg, flow) in call.args.iter().enumerate() {
                if let Flow::Path(p) = flow
                    && let Some(i) = cfg.params.iter().position(|ps| ps.iter().any(|n| n == p))
                {
                    forwards[i].push(Forward { line: call.line, col: call.col, callee: call.callee.clone(), arg });
                }
            }
        }
        if forwards.iter().any(|f| !f.is_empty()) {
            sum.forwards.insert(node, forwards);
        }
    }

    /// The `{...}` / `[...]` `name` is defined as in the files of the family that define it, when
    /// they agree.
    fn object(&self, fam: u8, name: &str) -> Option<String> {
        let mut found: Option<String> = None;
        for (_, src) in self.sources.iter().filter(|(f, _)| *f == fam).filter(|(_, src)| src.contains(name)) {
            if let Some(text) = object_text(src, name) {
                match &found {
                    Some(f) if *f != text => return None,
                    _ => found = Some(text),
                }
            }
        }
        found
    }

    /// The literal function `name` returns in every file of the family that defines it, when they
    /// agree (`def algorithm(): return "md5"` in another module).
    fn returned_value(&self, fam: u8, name: &str) -> Option<String> {
        if self.sources.is_empty() {
            return None;
        }
        let key = (fam, format!("{name}()"));
        if let Some(hit) = self.cache.lock().ok()?.get(&key) {
            return hit.clone();
        }
        let mut value: Option<String> = None;
        let mut ok = true;
        for (_, src) in self.sources.iter().filter(|(f, _)| *f == fam).filter(|(_, src)| src.contains(&format!("{name}("))) {
            match returned_literal(src, name) {
                Lookup::Missing => {}
                Lookup::Unknown => ok = false,
                Lookup::Found(v) => match &value {
                    Some(old) if *old != v => ok = false,
                    _ => value = Some(v),
                },
            }
        }
        let result = if ok { value } else { None };
        self.cache.lock().ok()?.insert(key, result.clone());
        result
    }

    /// The literal `name` is defined as in every file of the language family that defines it, when
    /// they agree. Only names written like constants (`ALGO`, `Algo`) are looked up.
    fn lookup(&self, fam: u8, name: &str) -> Option<String> {
        if !name.chars().next().is_some_and(char::is_uppercase) || self.sources.is_empty() {
            return None;
        }
        let key = (fam, name.to_string());
        if let Some(hit) = self.cache.lock().ok()?.get(&key) {
            return hit.clone();
        }
        let mut value: Option<String> = None;
        let mut ok = true;
        for (_, src) in self.sources.iter().filter(|(f, _)| *f == fam) {
            match const_lookup(src, name) {
                Lookup::Missing => {}
                Lookup::Unknown => ok = false,
                Lookup::Found(v) => match &value {
                    Some(old) if *old != v => ok = false,
                    _ => value = Some(v),
                },
            }
        }
        let result = if ok { value } else { None };
        self.cache.lock().ok()?.insert(key, result.clone());
        result
    }
}

struct Scan<'a> {
    project: &'a Project,
    fam: u8,
    file: &'a Path,
    cfgs: &'a [Cfg],
    src: std::cell::OnceCell<String>,
    /// The function being scanned: its index in the call graph and the name of each parameter.
    current: std::cell::RefCell<Option<(usize, Vec<String>)>>,
}

impl Scan<'_> {
    fn enter(&self, node: usize, cfg: &Cfg) {
        *self.current.borrow_mut() = Some((node, cfg.params.iter().map(|p| p.first().cloned().unwrap_or_default()).collect()));
    }

    fn source(&self) -> &str {
        self.src.get_or_init(|| self.cfgs.iter().map(|c| c.source.clone()).find(|s| !s.is_empty()).map_or_else(|| std::fs::read_to_string(self.file).unwrap_or_default(), |s| s.to_string()))
    }

    /// The literal a name is defined as in this file (`ALGO = "md5"`), when it has one definition.
    fn resolve(&self, name: &str) -> Option<String> {
        // `{}name` asks for the `{...}` or `[...]` a name is defined as, `name()` for what a function
        // returns
        if let Some(object) = name.strip_prefix("{}") {
            return object_text(self.source(), object).or_else(|| self.project.object(self.fam, object));
        }
        if let Some(function) = name.strip_suffix("()") {
            return match returned_literal(self.source(), function) {
                Lookup::Found(v) => Some(v),
                Lookup::Unknown => None,
                Lookup::Missing => self.project.returned_value(self.fam, function),
            };
        }
        // a parameter is what its callers pass
        if let Some((node, params)) = self.current.borrow().as_ref()
            && let Some(i) = params.iter().position(|p| p == name)
        {
            return self.project.param_value(*node, i);
        }
        match const_lookup(self.source(), name) {
            Lookup::Found(v) => Some(v),
            Lookup::Unknown => None,
            Lookup::Missing => self.project.lookup(self.fam, name),
        }
    }
}

fn plain(file: &Path, kind: Kind, name: &str, function: &str, line: usize, col: usize) -> CryptoUse {
    CryptoUse {
        file: file.to_path_buf(),
        line,
        col,
        kind,
        name: name.to_string(),
        library: String::new(),
        primitive: String::new(),
        algorithm: String::new(),
        weak: false,
        reason: String::new(),
        issues: vec![],
        args: String::new(),
        origin_line: 0,
        quantum: String::new(),
        function: function.to_string(),
    }
}

/// One file's crypto imports and calls.
pub fn scan_file(lang: Language, file: &Path, imports: &[Import], cfgs: &[Cfg]) -> Vec<CryptoUse> {
    scan_file_in(lang, file, imports, cfgs, &Project::default())
}

/// One file to scan with [`scan_project`].
pub struct ScanFile<'a> {
    pub lang: Language,
    pub file: &'a Path,
    pub imports: &'a [Import],
    pub cfgs: &'a [Cfg],
}

/// Every file's crypto imports and calls, with what is known across files: constants defined in
/// another file, objects returned by a function (`c = make_cipher(); c.encrypt(d)`) and objects
/// passed to one (`encrypt(AES.new(..), d)` reports the `c.encrypt` inside it). The files are
/// scanned twice, the first time to collect what each function returns and calls on its parameters.
pub fn scan_project(files: &[ScanFile]) -> Vec<CryptoUse> {
    let project = Project::new(files.iter().map(|f| (f.lang, f.file, f.cfgs)));
    for f in files {
        scan_file_in(f.lang, f.file, f.imports, f.cfgs, &project);
    }
    // calls are resolved by name until the call graph tells which function they reach (classes,
    // overloads, imports); it is only built when some function handles a crypto object
    if project.has_summaries() || project.needs_callers.load(std::sync::atomic::Ordering::Relaxed) {
        let (targets, callers) = call_targets(files);
        project.set_targets(targets, callers);
    }
    let mut out: Vec<CryptoUse> = files.iter().flat_map(|f| scan_file_in(f.lang, f.file, f.imports, f.cfgs, &project)).collect();
    // a method on a parameter declared as a crypto class says only what the class says; where a caller
    // passes a concrete object, that is the better report
    let generic = |u: &CryptoUse| u.kind == Kind::Method && u.origin_line == 0 && u.algorithm.starts_with("(by");
    if out.iter().any(generic) {
        let concrete: BTreeSet<(PathBuf, usize, usize, String)> = out.iter().filter(|u| u.kind == Kind::Method && !generic(u)).map(|u| (u.file.clone(), u.line, u.col, u.name.clone())).collect();
        out.retain(|u| !(generic(u) && concrete.contains(&(u.file.clone(), u.line, u.col, u.name.clone()))));
    }
    // the same method call, reached from several callers
    out.sort();
    out.dedup_by(|a, b| (&a.file, a.line, a.col, a.kind, &a.name, &a.algorithm) == (&b.file, b.line, b.col, b.kind, &b.name, &b.algorithm));
    out
}

/// For every call the call graph resolves to a project function: `(caller index, line, col)` ->
/// the callee indexes, in the graph's `files x functions` order.
fn call_targets(files: &[ScanFile]) -> (CallTargets, Callers) {
    use petgraph::visit::EdgeRef;
    let dep_files: Vec<super::deps::DepFile> = files.iter().map(|f| super::deps::DepFile { path: f.file, lang: f.lang, imports: f.imports.to_vec(), cfgs: f.cfgs }).collect();
    let refs: Vec<(&Path, Language, &[Cfg])> = files.iter().map(|f| (f.file, f.lang, f.cfgs)).collect();
    let graph = super::callgraph::build_refs(&refs, Some(super::deps::visibility(&dep_files)));
    let mut out = CallTargets::new();
    let mut callers = Callers::new();
    for e in graph.graph.edge_references() {
        // a call by name, or a function really invoked through a variable; not one only handed over
        for site in e.weight().call_sites.iter().filter(|s| s.exact && (!s.callback || s.invoked)) {
            out.entry((e.source().index(), site.line, site.col)).or_default().push(e.target().index());
            callers.entry(e.target().index()).or_default().push((e.source().index(), site.line, site.col, site.callee.clone()));
        }
    }
    (out, callers)
}

/// What the first pass learns about the objects of one function.
struct Local {
    objs: BTreeMap<String, Option<Origin>>,
    /// Containers (and variables copied from them) that hold several kinds of objects.
    multi: BTreeMap<String, Vec<Origin>>,
    /// The objects stored under a literal key (`d['a']`).
    keyed: BTreeMap<String, Vec<Origin>>,
    /// What reassigned variables hold at each call: by `(line, column, callee)`.
    at_call: BTreeMap<(usize, usize, String), FlowState>,
}

type EntryFn<'a> = &'a dyn Fn(&str) -> Option<(&'static Call, String)>;

fn same_origin(a: &Origin, b: &Origin) -> bool {
    (a.primitive, &a.algorithm, &a.reason) == (b.primitive, &b.algorithm, &b.reason)
}

/// `found` with the objects that are the same kind listed once.
fn distinct(found: Vec<Origin>) -> Vec<Origin> {
    let mut out: Vec<Origin> = vec![];
    for o in found {
        if !out.iter().any(|x| same_origin(x, &o)) {
            out.push(o);
        }
    }
    out
}

/// The crypto objects a value may be: what a crypto call creates, what a variable or container
/// holds (`multi` for those with several kinds), or every part of a list or dictionary literal.
#[allow(clippy::too_many_arguments)]
fn flow_origins(f: &Flow, sc: &Scan, cfg: &Cfg, entry_of: EntryFn, objs: &BTreeMap<String, Option<Origin>>, fields: &BTreeMap<String, Option<Origin>>, multi: &BTreeMap<String, Vec<Origin>>, state: Option<&FlowState>) -> Vec<Origin> {
    match f {
        Flow::Call(c) => entry_of(&c.callee)
            .filter(|(e, _)| e.primitive != "prng")
            .map(|(e, n)| {
                let u = describe(sc, cfg, c, e, &n);
                Origin { line: c.line, primitive: &e.primitive, algorithm: u.algorithm, reason: u.reason }
            })
            .into_iter()
            .collect(),
        Flow::Path(p) => {
            let base = p.split('[').next().unwrap_or(p);
            if let Some(set) = state.and_then(|s| s.get(base)) {
                return set.iter().flatten().cloned().collect();
            }
            if let Some(set) = multi.get(base) {
                return set.clone();
            }
            objs.get(base).or_else(|| fields.get(base)).cloned().flatten().map(|o| Origin { line: o.line, ..o }).into_iter().collect()
        }
        Flow::Join(parts) if !parts.is_empty() => {
            let each: Vec<Vec<Origin>> = parts.iter().map(|x| flow_origins(x, sc, cfg, entry_of, objs, fields, multi, state)).collect();
            if each.iter().all(|v| !v.is_empty()) { distinct(each.into_iter().flatten().collect()) } else { vec![] }
        }
        _ => vec![],
    }
}

/// What each reassigned variable may hold at a point: every kind of object some assignment that
/// reaches it makes (`None`: something that is not a crypto object).
type FlowState = BTreeMap<String, Vec<Option<Origin>>>;

fn merge_sets(a: &mut Vec<Option<Origin>>, b: &[Option<Origin>]) {
    for o in b {
        let known = a.iter().any(|x| match (x, o) {
            (None, None) => true,
            (Some(x), Some(o)) => same_origin(x, o),
            _ => false,
        });
        if !known {
            a.push(o.clone());
        }
    }
}

fn merge_states(into: &mut Option<FlowState>, from: &FlowState, tracked: &BTreeSet<&str>) -> bool {
    let Some(cur) = into else {
        *into = Some(from.clone());
        return true;
    };
    let before: Vec<usize> = tracked.iter().map(|t| cur.get(*t).map_or(1, Vec::len)).collect();
    for t in tracked {
        let other = from.get(*t).cloned().unwrap_or_else(|| vec![None]);
        let mine = cur.entry((*t).to_string()).or_insert_with(|| vec![None]);
        merge_sets(mine, &other);
    }
    before != tracked.iter().map(|t| cur.get(*t).map_or(1, Vec::len)).collect::<Vec<_>>()
}

/// Like [`scan_file`], resolving constants defined in other files of `project` too.
pub fn scan_file_in(lang: Language, file: &Path, imports: &[Import], cfgs: &[Cfg], project: &Project) -> Vec<CryptoUse> {
    let fam = lang.family();
    let sc = Scan { project, fam, file, cfgs, src: Default::default(), current: Default::default() };
    let base = project.base_of(file, cfgs.len());
    let mut out = vec![];
    let mut imported: BTreeSet<&str> = BTreeSet::new();
    for imp in imports {
        let mut mods = vec![imp.module.clone()];
        // `from cryptography import fernet`, Go grouped imports, `use ring::{digest, hmac}`
        mods.extend(imp.names.iter().map(|n| format!("{}.{n}", imp.module)));
        if let Some(lib) = active().library.iter().find(|l| l.lang.family() == fam && mods.iter().any(|m| module_matches(&l.module, m))) {
            imported.insert(lib.name.as_str());
            let mut u = plain(file, Kind::Import, &imp.module, "", imp.line, 0);
            u.library = lib.name.clone();
            out.push(u);
        }
    }
    let has_import = |m: &str| imports.iter().any(|i| i.module == m);
    let binds = if imports.is_empty() { Bindings::default() } else { bindings(fam, imports, sc.source()) };
    // the table entry for a callee, and the name it matched under: as written, or with an alias or
    // a `from m import *` module resolved (`h.md5` for `import hashlib as h` is `hashlib.md5`)
    let entry_of = |callee: &str| -> Option<(&'static Call, String)> {
        for name in binds.candidates(callee) {
            if let Some(e) = active().call.iter().find(|c| c.lang.family() == fam && call_matches(&c.pattern, &name) && c.library.as_deref().is_none_or(|l| imported.contains(l))) {
                return Some((e, name));
            }
            let prng = active().prng.iter().any(|p| {
                p.lang.family() == fam && call_matches(&p.pattern, &name) && p.with_import.as_deref().is_none_or(has_import) && !p.without_import.as_deref().is_some_and(has_import)
            });
            if prng {
                return Some((prng_call(), name));
            }
        }
        None
    };
    // The same statement can be copied onto several paths (`finally`): count each site once.
    let mut seen = BTreeSet::new();
    // objects created by crypto calls and kept in a field (`self.c = Cipher.getInstance(..)`): file-wide
    let mut fields: BTreeMap<String, Option<Origin>> = BTreeMap::new();
    let mut locals: Vec<Local> = vec![];
    for (ci, cfg) in cfgs.iter().enumerate() {
        sc.enter(base + ci, cfg);
        let mut objs: BTreeMap<String, Option<Origin>> = BTreeMap::new();
        // containers that hold several kinds of crypto objects, and what is stored under each key
        let mut multi: BTreeMap<String, Vec<Origin>> = BTreeMap::new();
        let mut keyed: BTreeMap<String, Vec<Origin>> = BTreeMap::new();
        let mut elem_sets: BTreeMap<String, Vec<Origin>> = BTreeMap::new();
        let mut assigned: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
        for stmt in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
            for a in stmt.assigns.iter().filter(|a| !a.target.contains('[')) {
                assigned.entry(&a.target).or_default().insert(stmt.line);
                let origin = match &a.value {
                    Flow::Call(c) => entry_of(&c.callee).filter(|(e, _)| e.primitive != "prng").map(|(e, n)| (c, e, n)),
                    _ => None,
                };
                // `c = make_cipher()`: a project function that returns a crypto object
                if origin.is_none()
                    && let Flow::Call(c) = &a.value
                    && let Some(o) = project.returned(fam, Some((base + ci, c.line, c.col)), &c.callee)
                {
                    let map = if a.target.contains('.') { &mut fields } else { &mut objs };
                    let o = Origin { line: c.line, ..o };
                    if map.insert(a.target.clone(), Some(o)).is_some() {
                        map.insert(a.target.clone(), None);
                    }
                    continue;
                }
                let Some((call, e, name)) = origin else { continue };
                let u = describe(&sc, cfg, call, e, &name);
                let o = Origin { line: call.line, primitive: &e.primitive, algorithm: u.algorithm, reason: u.reason };
                let map = if a.target.contains('.') { &mut fields } else { &mut objs };
                let prev = map.insert(a.target.clone(), Some(o));
                if prev.is_some() {
                    map.insert(a.target.clone(), None);
                }
            }
        }
        // copies (`b = a`, `c = xs[0]`, `for h in xs`), list literals of crypto objects, and objects
        // put into a container (`ys.append(AES.new(..))`): the container holds the object
        let same = |a: &Origin, b: &Origin| (a.primitive, &a.algorithm, &a.reason) == (b.primitive, &b.algorithm, &b.reason);
        for _ in 0..2 {
            for stmt in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
                for a in stmt.assigns.iter().filter(|a| !a.target.contains('[')) {
                    let found = flow_origins(&a.value, &sc, cfg, &entry_of, &objs, &fields, &multi, None);
                    let map = if a.target.contains('.') { &mut fields } else { &mut objs };
                    match found.len() {
                        0 => {}
                        1 => {
                            map.entry(a.target.clone()).or_insert(Some(found[0].clone()));
                        }
                        _ => {
                            multi.entry(a.target.clone()).or_insert(found);
                        }
                    }
                }
                // `d["a"] = DES.new(..)`, `xs = [AES.new(..), DES.new(..)]`: what is stored under a key, and in the container
                for e in &stmt.elems {
                    let found = flow_origins(&e.value, &sc, cfg, &entry_of, &objs, &fields, &multi, None);
                    if found.is_empty() {
                        continue;
                    }
                    let base = e.target.split('[').next().unwrap_or(&e.target).to_string();
                    keyed.entry(e.target.clone()).or_default().extend(found.iter().cloned());
                    elem_sets.entry(base).or_default().extend(found);
                }
                for c in &stmt.calls {
                    let Some((container, method)) = c.callee.rsplit_once('.') else { continue };
                    if !matches!(method, "append" | "add" | "push" | "push_back" | "insert" | "put" | "offer" | "extend" | "setdefault") {
                        continue;
                    }
                    let put = c.args.iter().find_map(|f| match f {
                        Flow::Call(x) => entry_of(&x.callee).filter(|(e, _)| e.primitive != "prng").map(|(e, n)| {
                            let u = describe(&sc, cfg, x, e, &n);
                            Origin { line: x.line, primitive: &e.primitive, algorithm: u.algorithm, reason: u.reason }
                        }),
                        _ => None,
                    });
                    if let Some(o) = put {
                        let map = if container.contains('.') { &mut fields } else { &mut objs };
                        match map.get(container) {
                            Some(Some(old)) if !same(old, &o) => {
                                let old = old.clone();
                                map.insert(container.to_string(), None);
                                multi.entry(container.to_string()).or_default().extend([old, o]);
                            }
                            Some(_) => {
                                if let Some(m) = multi.get_mut(container) {
                                    m.push(o);
                                }
                            }
                            None => {
                                map.insert(container.to_string(), Some(o));
                            }
                        }
                    }
                }
            }
        }
        // a parameter or local declared with a crypto class (`Cipher c`) is an object of that class
        for (name, class) in cfg.param_types.iter().chain(&cfg.local_types) {
            if let Some(o) = typed_origin(fam, class, &imported) {
                objs.entry(name.clone()).or_insert(Some(o));
            }
        }
        // a variable assigned in several places is not one object
        for (t, lines) in &assigned {
            if lines.len() > 1 {
                if let Some(o) = objs.get_mut(*t) {
                    *o = None;
                }
                if let Some(o) = fields.get_mut(*t) {
                    *o = None;
                }
            }
        }
        // containers holding several kinds of objects
        for (base_name, set) in elem_sets {
            let set = distinct(set);
            if set.len() > 1 {
                multi.insert(base_name, set);
            }
        }
        for set in multi.values_mut() {
            *set = distinct(std::mem::take(set));
        }
        // what a reassigned variable holds where it is used: the kinds of every assignment that reaches
        let tracked: BTreeSet<&str> = assigned.iter().filter(|(_, l)| l.len() > 1).map(|(t, _)| *t).collect();
        let mut at_call: BTreeMap<(usize, usize, String), FlowState> = BTreeMap::new();
        let any_known = cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns).any(|a| tracked.contains(a.target.as_str()) && !flow_origins(&a.value, &sc, cfg, &entry_of, &objs, &fields, &multi, None).is_empty());
        if any_known {
            let step = |stmt: &crate::ir::Stmt, st: &mut FlowState| {
                for a in stmt.assigns.iter().filter(|a| a.strong && tracked.contains(a.target.as_str())) {
                    let found = flow_origins(&a.value, &sc, cfg, &entry_of, &objs, &fields, &multi, Some(&*st));
                    st.insert(a.target.clone(), if found.is_empty() { vec![None] } else { found.into_iter().map(Some).collect() });
                }
            };
            let bound = cfg.graph.node_bound();
            let mut inn: Vec<Option<FlowState>> = vec![None; bound];
            inn[cfg.entry.index()] = Some(FlowState::new());
            let mut work: std::collections::VecDeque<_> = std::collections::VecDeque::from([cfg.entry]);
            let mut queued = vec![false; bound];
            queued[cfg.entry.index()] = true;
            let mut budget = bound * 40 + 500;
            while let Some(b) = work.pop_front() {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                queued[b.index()] = false;
                let mut st = inn[b.index()].clone().unwrap_or_default();
                for stmt in &cfg.graph[b].stmts {
                    step(stmt, &mut st);
                }
                for succ in cfg.graph.neighbors(b) {
                    if merge_states(&mut inn[succ.index()], &st, &tracked) && !queued[succ.index()] {
                        queued[succ.index()] = true;
                        work.push_back(succ);
                    }
                }
            }
            for b in cfg.graph.node_indices() {
                let Some(start) = &inn[b.index()] else { continue };
                let mut st = start.clone();
                for stmt in &cfg.graph[b].stmts {
                    for c in &stmt.calls {
                        let slot = at_call.entry((c.line, c.col, c.callee.clone())).or_default();
                        for (var, set) in &st {
                            merge_sets(slot.entry(var.clone()).or_default(), set);
                        }
                    }
                    step(stmt, &mut st);
                }
            }
        }
        project.register(&sc, base + ci, cfg, &objs, &fields, &|callee: &str| entry_of(callee).filter(|(e, _)| e.primitive != "prng"));
        locals.push(Local { objs, multi, keyed, at_call });
    }
    for (ci, (cfg, local)) in cfgs.iter().zip(&locals).enumerate() {
        let objs = &local.objs;
        sc.enter(base + ci, cfg);
        // `aes.Key = key;` / `aes.IV = new byte[16];` on a crypto object: a hardcoded key or static IV
        for stmt in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
            for a in stmt.assigns.iter().filter(|a| a.strong) {
                let Some((obj, prop)) = a.target.rsplit_once('.') else { continue };
                let role = match prop {
                    "Key" | "key" => "key",
                    "IV" | "iv" | "Nonce" | "nonce" => "iv",
                    _ => continue,
                };
                let Some(o) = objs.get(obj).or_else(|| fields.get(obj)).cloned().flatten() else { continue };
                let Some(value) = stmt.text.split_once('=').map(|(_, v)| v.trim().trim_end_matches(';').trim().to_string()) else { continue };
                let resolve = |n: &str| sc.resolve(n);
                let Some(issue) = issue_for(role, &hardcoded(&value, &resolve)) else { continue };
                if !seen.insert((stmt.line, stmt.col, a.target.clone())) {
                    continue;
                }
                let mut u = plain(file, Kind::Method, &format!("{} =", a.target), &cfg.name, stmt.line, stmt.col);
                u.primitive = o.primitive.to_string();
                u.algorithm = o.algorithm.clone();
                u.issues.push(issue);
                u.origin_line = o.line;
                u.args = shorten(&value);
                out.push(u);
            }
        }
        for call in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.calls) {
            if !seen.insert((call.line, call.col, call.callee.clone())) {
                continue;
            }
            if let Some((e, name)) = entry_of(&call.callee) {
                out.push(describe(&sc, cfg, call, e, &name));
                continue;
            }
            // a crypto object passed to a project function that calls methods on that parameter
            for (i, arg) in call.args.iter().enumerate() {
                let origin = match arg {
                    Flow::Call(c) => entry_of(&c.callee).filter(|(e, _)| e.primitive != "prng").map(|(e, n)| {
                        let u = describe(&sc, cfg, c, e, &n);
                        Origin { line: c.line, primitive: &e.primitive, algorithm: u.algorithm, reason: u.reason }
                    }),
                    Flow::Path(p) => objs.get(p).or_else(|| fields.get(p)).cloned().flatten(),
                    _ => None,
                };
                let Some(o) = origin else { continue };
                for site in project.param_sites(fam, Some((base + ci, call.line, call.col)), &call.callee, i) {
                    let mut u = plain(&site.file, Kind::Method, &site.callee, &site.function, site.line, site.col);
                    u.primitive = o.primitive.to_string();
                    u.quantum = quantum(o.primitive, &o.algorithm, &site.callee).to_string();
                    u.algorithm = o.algorithm.clone();
                    u.weak = !o.reason.is_empty();
                    u.reason = o.reason.clone();
                    u.origin_line = call.line;
                    u.args = site.args.clone();
                    out.push(u);
                }
            }
            let Some((recv, method)) = call.callee.rsplit_once('.') else { continue };
            // putting an object into a container is not a use of it
            if matches!(method, "append" | "add" | "push" | "push_back" | "insert" | "put" | "offer" | "extend" | "setdefault") {
                continue;
            }
            // a method of an object a crypto call created: by variable, by field, or directly on the call;
            // of a reassigned variable, every kind that reaches the call; of an element, the kind under that key
            let key = call.callee_key.as_deref().and_then(|k| k.rsplit_once('.')).map(|(r, _)| r);
            let flow: Vec<Origin> = local.at_call.get(&(call.line, call.col, call.callee.clone())).and_then(|st| st.get(recv)).map(|set| set.iter().flatten().cloned().collect()).unwrap_or_default();
            let known: Vec<Origin> = if !flow.is_empty() {
                flow
            } else if let Some(set) = key.and_then(|k| local.keyed.get(k)) {
                distinct(set.clone())
            } else if let Some(set) = local.multi.get(recv) {
                set.clone()
            } else {
                objs.get(recv).or_else(|| fields.get(recv)).cloned().flatten().into_iter().collect()
            };
            let origins: Vec<Origin> = if known.is_empty() {
                let direct = entry_of(recv).filter(|(e, _)| e.primitive != "prng").map(|(e, _)| Origin { line: 0, primitive: &e.primitive, algorithm: e.algorithm.clone(), reason: if e.weak { e.algorithm.clone() } else { String::new() } });
                direct.or_else(|| project.returned(fam, None, recv).map(|o| Origin { line: call.line, ..o })).into_iter().collect()
            } else {
                known
            };
            let args = call_args(sc.source(), call.line, call.col, &call.callee).unwrap_or_default();
            for o in origins {
                // a method on the result of `X.Create(name)` says nothing the call itself did not
                if o.line == 0 && o.algorithm.starts_with("(by") {
                    continue;
                }
                let mut u = plain(file, Kind::Method, &call.callee, &cfg.name, call.line, call.col);
                u.primitive = o.primitive.to_string();
                u.quantum = quantum(o.primitive, &o.algorithm, &call.callee).to_string();
                u.algorithm = o.algorithm;
                u.weak = !o.reason.is_empty();
                u.reason = o.reason;
                u.origin_line = if o.line == usize::MAX { 0 } else { o.line };
                if let Some(r) = key_size_issue(o.primitive, method, &args, &|n: &str| sc.resolve(n)) {
                    u.reason = if u.reason.is_empty() { r } else { format!("{}, {r}", u.reason) };
                    u.weak = true;
                }
                u.args = shorten(&args.join(", "));
                out.push(u);
            }
        }
    }
    out.sort();
    out
}

impl CryptoUse {
    /// How serious the finding is: `None` for something that is not flagged. A disabled
    /// certificate check, committed key material and a hardcoded key or secret are `high`; weak
    /// algorithms, modes and protocols, static IVs and salts, small keys and low work factors
    /// `medium`; SHA-1 and a plain non-cryptographic PRNG `low`.
    pub fn severity(&self) -> Option<super::Severity> {
        use super::Severity::{High, Low, Medium};
        if !self.flagged() {
            return None;
        }
        let mut level = Low;
        for issue in &self.issues {
            let l = match issue.as_str() {
                i if i.starts_with("hardcoded") || i == "all-zero key" => High,
                "non-cryptographic PRNG" | "non-cryptographic hash" => Low,
                _ => Medium,
            };
            level = level.max(l);
        }
        if self.weak {
            let l = match self.reason.as_str() {
                "certificate verification disabled" => High,
                "SHA-1" => Low,
                _ => Medium,
            };
            level = level.max(l);
        }
        Some(level)
    }

    /// A weak algorithm or a problem in the arguments. A non-cryptographic PRNG or hash is only a hint.
    pub fn flagged(&self) -> bool {
        self.weak || self.issues.iter().any(|i| !matches!(i.as_str(), "non-cryptographic PRNG" | "non-cryptographic hash"))
    }
}

/// `vulnerable` for public-key algorithms a quantum computer breaks, `safe` for the post-quantum
/// standards, empty for everything else.
fn quantum(primitive: &str, algorithm: &str, callee: &str) -> &'static str {
    let words = tokens(&format!("{algorithm} {callee}"));
    let has = |names: &[&str]| words.iter().any(|w| names.contains(&w.as_str()));
    if has(&["MLKEM", "KYBER", "MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS", "FALCON", "XMSS", "LMS"]) || words.windows(2).any(|w| matches!((w[0].as_str(), w[1].as_str()), ("ML", "KEM" | "DSA") | ("SLH", "DSA"))) {
        return "safe";
    }
    let named = has(&["RSA", "ECDSA", "ECDH", "ECC", "EC", "DH", "DSA", "ED25519", "X25519", "ECIES", "ELGAMAL", "SECP256R1", "SECP384R1", "P256", "P384"]);
    if matches!(primitive, "asymmetric" | "key-exchange") || (named && matches!(primitive, "signature" | "key" | "cipher")) {
        return "vulnerable";
    }
    ""
}

/// One crypto call, with what its arguments show.
fn describe(sc: &Scan, cfg: &Cfg, call: &CallFlow, entry: &Call, matched: &str) -> CryptoUse {
    let (primitive, algorithm, weak, library) = (entry.primitive.as_str(), entry.algorithm.as_str(), entry.weak, entry.library.as_deref());
    let args = call_args(sc.source(), call.line, call.col, &call.callee).unwrap_or_default();
    let resolve = |n: &str| sc.resolve(n);
    let d = inspect(sc.fam, matched, primitive, &args, &resolve);
    let algorithm = match d.literal {
        Some(l) if algorithm.starts_with('(') => l,
        None if algorithm.starts_with("(by") && !d.classes.is_empty() => d.classes.join(", "),
        _ => algorithm.to_string(),
    };
    let reason = if weak && primitive != "prng" { algorithm.clone() } else { d.weak.unwrap_or_default() };
    let mut issues = secret_issues(sc.fam, matched, &args, &resolve);
    issues.extend(limit_issues(sc.fam, matched, &args, &resolve));
    if primitive != "prng" && algorithm.contains("non-cryptographic") {
        issues.push("non-cryptographic hash".to_string());
    }
    if primitive == "prng" {
        let seeds = matched == "Random" || matched.ends_with("seed") || matched.ends_with("srand") || matched.ends_with("srandom") || matched.ends_with("NewSource");
        let constant = args.first().is_some_and(|a| is_literal_number_or_string(a, &resolve));
        issues.push(if seeds && constant { "constant PRNG seed".to_string() } else { "non-cryptographic PRNG".to_string() });
    }
    let mut u = plain(sc.file, Kind::Call, &call.callee, &cfg.name, call.line, call.col);
    u.library = library.unwrap_or_default().to_string();
    u.quantum = quantum(primitive, &algorithm, matched).to_string();
    u.primitive = primitive.to_string();
    u.algorithm = algorithm;
    u.weak = !reason.is_empty();
    u.reason = reason;
    u.issues = issues;
    u.args = shorten(&args.join(", "));
    u
}

/// A crypto library a manifest declares.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Declared {
    pub manifest: PathBuf,
    pub line: usize,
    /// The dependency as written in the manifest.
    pub name: String,
    pub library: String,
    /// Some scanned file imports this library.
    pub used: bool,
    /// Found in a lock file (so possibly a transitive dependency), not in a manifest.
    pub lock: bool,
}

fn dependency_library(fam: u8, name: &str) -> Option<&'static str> {
    let name = name.trim();
    let lower = name.to_ascii_lowercase();
    // NuGet and PyPI names are case-insensitive
    if let Some(d) = active().dependency.iter().find(|d| {
        let dn = d.name.to_ascii_lowercase();
        d.lang.family() == fam && dn.strip_suffix('*').map_or(dn == lower, |pre| lower.starts_with(pre))
    }) {
        return Some(&d.library);
    }
    let module = if fam == RS { name.replace('-', "_") } else { name.to_string() };
    active().library.iter().find(|l| l.lang.family() == fam && fam != PY && module_matches(&l.module, &module)).map(|l| l.name.as_str())
}

/// Dependency names with the line they are on, for the manifest kinds this knows:
/// `Cargo.toml`, `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `pom.xml`,
/// `build.gradle(.kts)`. `None` for any other file.
fn dependency_names(file_name: &str, text: &str) -> Option<(u8, Vec<String>)> {
    let strings = |v: Option<&toml::Value>| -> Vec<String> { v.and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.as_str()).map(pep508_name).collect() };
    let keys = |v: Option<&toml::Value>| -> Vec<String> {
        v.and_then(|v| v.as_table())
            .into_iter()
            .flatten()
            .map(|(k, v)| v.get("package").and_then(|p| p.as_str()).unwrap_or(k).to_string())
            .collect()
    };
    match file_name {
        "Cargo.toml" => {
            let t = text.parse::<toml::Table>().ok()?;
            let mut names = vec![];
            let mut tables = vec![t.get("dependencies"), t.get("dev-dependencies"), t.get("build-dependencies")];
            tables.push(t.get("workspace").and_then(|w| w.get("dependencies")));
            for target in t.get("target").and_then(|t| t.as_table()).into_iter().flatten() {
                tables.extend(["dependencies", "dev-dependencies", "build-dependencies"].map(|k| target.1.get(k)));
            }
            for tb in tables {
                names.extend(keys(tb));
            }
            Some((RS, names))
        }
        "package.json" => {
            let v: serde_json::Value = serde_json::from_str(text).ok()?;
            let names = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
                .iter()
                .filter_map(|k| v.get(*k)?.as_object())
                .flat_map(|o| o.keys().cloned())
                .collect();
            Some((JS, names))
        }
        "pyproject.toml" => {
            let t = text.parse::<toml::Table>().ok()?;
            let mut names = strings(t.get("project").and_then(|p| p.get("dependencies")));
            for extra in t.get("project").and_then(|p| p.get("optional-dependencies")).and_then(|o| o.as_table()).into_iter().flat_map(|o| o.values()) {
                names.extend(strings(Some(extra)));
            }
            let poetry = t.get("tool").and_then(|t| t.get("poetry"));
            names.extend(keys(poetry.and_then(|p| p.get("dependencies"))).into_iter().filter(|n| n != "python"));
            names.extend(keys(poetry.and_then(|p| p.get("dev-dependencies"))));
            for group in poetry.and_then(|p| p.get("group")).and_then(|g| g.as_table()).into_iter().flat_map(|g| g.values()) {
                names.extend(keys(group.get("dependencies")));
            }
            Some((PY, names))
        }
        "Cargo.lock" | "poetry.lock" => {
            let t = text.parse::<toml::Table>().ok()?;
            let names = t.get("package")?.as_array()?.iter().filter_map(|p| p.get("name")?.as_str()).map(str::to_string).collect();
            Some((if file_name == "Cargo.lock" { RS } else { PY }, names))
        }
        "package-lock.json" => {
            let v: serde_json::Value = serde_json::from_str(text).ok()?;
            let mut names: Vec<String> = v.get("packages").and_then(|p| p.as_object()).into_iter().flat_map(|p| p.keys()).filter_map(|k| k.rsplit_once("node_modules/").map(|(_, n)| n.to_string())).collect();
            names.extend(v.get("dependencies").and_then(|d| d.as_object()).into_iter().flat_map(|d| d.keys().cloned()));
            Some((JS, names))
        }
        "Pipfile.lock" => {
            let v: serde_json::Value = serde_json::from_str(text).ok()?;
            let names = ["default", "develop"].iter().filter_map(|k| v.get(*k)?.as_object()).flat_map(|o| o.keys().cloned()).collect();
            Some((PY, names))
        }
        "go.sum" => {
            let names = text.lines().filter_map(|l| l.split_whitespace().next()).map(str::to_string).collect();
            Some((GO, names))
        }
        "go.mod" => {
            let mut names = vec![];
            let mut block = false;
            for l in text.lines() {
                let l = l.split("//").next().unwrap_or("").trim();
                if block {
                    if l == ")" {
                        block = false;
                    } else if let Some(m) = l.split_whitespace().next() {
                        names.push(m.to_string());
                    }
                } else if let Some(r) = l.strip_prefix("require") {
                    let r = r.trim();
                    if r.starts_with('(') {
                        block = true;
                    } else if let Some(m) = r.split_whitespace().next() {
                        names.push(m.to_string());
                    }
                }
            }
            Some((GO, names))
        }
        "pom.xml" => {
            let mut names = vec![];
            for tag in ["groupId", "artifactId"] {
                let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
                names.extend(text.split(&open).skip(1).filter_map(|r| r.split_once(&close)).map(|(n, _)| n.trim().to_string()));
            }
            Some((JAVA, names))
        }
        n if n.starts_with("build.gradle") => {
            let mut names = vec![];
            for q in text.split(['"', '\'']).skip(1).step_by(2) {
                let mut parts = q.split(':');
                if let (Some(g), Some(a), Some(_)) = (parts.next(), parts.next(), parts.next()) {
                    names.extend([g.to_string(), a.to_string()]);
                }
            }
            Some((JAVA, names))
        }
        n if n.ends_with(".csproj") || matches!(n, "Directory.Packages.props" | "Directory.Build.props") => {
            // `<PackageReference Include="Name" Version=".." />`, `<PackageVersion Include=".." />`
            let names = text.lines().filter(|l| l.contains("PackageReference") || l.contains("PackageVersion")).filter_map(|l| xml_attribute(l, "Include").or_else(|| xml_attribute(l, "Update"))).collect();
            Some((CS, names))
        }
        "packages.config" => {
            let names = text.lines().filter(|l| l.contains("<package ")).filter_map(|l| xml_attribute(l, "id")).collect();
            Some((CS, names))
        }
        "setup.py" => {
            // `install_requires=[".."]`, `extras_require`, `setup_requires`, `tests_require`
            let mut names = vec![];
            for key in ["install_requires", "setup_requires", "tests_require", "extras_require"] {
                for (at, _) in text.match_indices(key) {
                    let rest = &text[at + key.len()..];
                    let Some(open) = rest.find(['[', '{']) else { continue };
                    let (mut depth, mut end) = (0i32, rest.len());
                    for (i, c) in rest[open..].char_indices() {
                        match c {
                            '[' | '{' => depth += 1,
                            ']' | '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    end = open + i;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    names.extend(quoted_strings(&rest[open..end]).into_iter().map(|q| pep508_name(&q)).filter(|n| !n.is_empty()));
                }
            }
            Some((PY, names))
        }
        "setup.cfg" => {
            // `install_requires =` followed by one requirement per indented line
            let mut names = vec![];
            let mut inside = false;
            for l in text.lines() {
                let t = l.trim();
                if inside && (l.starts_with(' ') || l.starts_with('\t')) {
                    names.push(pep508_name(t));
                } else {
                    inside = ["install_requires", "setup_requires", "tests_require"].iter().any(|k| t.starts_with(k) && t.contains('='));
                    if inside && let Some((_, rest)) = t.split_once('=') && !rest.trim().is_empty() {
                        names.push(pep508_name(rest));
                    }
                }
            }
            Some((PY, names.into_iter().filter(|n| !n.is_empty()).collect()))
        }
        "Pipfile" => {
            let t = text.parse::<toml::Table>().ok()?;
            let mut names = keys(t.get("packages"));
            names.extend(keys(t.get("dev-packages")));
            Some((PY, names))
        }
        "libs.versions.toml" => {
            // `[libraries]`: `a = "group:artifact:1.0"`, `{ module = "group:artifact" }` or `{ group, name }`
            let t = text.parse::<toml::Table>().ok()?;
            let mut names = vec![];
            for lib in t.get("libraries").and_then(|l| l.as_table()).into_iter().flat_map(|l| l.values()) {
                let coordinate = lib.as_str().or_else(|| lib.get("module").and_then(|m| m.as_str()));
                if let Some(c) = coordinate {
                    names.extend(c.split(':').take(2).map(str::to_string));
                } else if let Some(g) = lib.get("group").and_then(|g| g.as_str()) {
                    names.push(g.to_string());
                    names.extend(lib.get("name").and_then(|n| n.as_str()).map(str::to_string));
                }
            }
            Some((JAVA, names))
        }
        "conanfile.txt" => {
            let mut names = vec![];
            let mut inside = false;
            for l in text.lines().map(str::trim) {
                if l.starts_with('[') {
                    inside = matches!(l, "[requires]" | "[build_requires]" | "[tool_requires]");
                } else if inside && !l.is_empty() && !l.starts_with('#') {
                    names.push(l.split(['/', '@']).next().unwrap_or(l).to_string());
                }
            }
            Some((C, names))
        }
        "conanfile.py" => {
            let names = text.lines().filter(|l| l.contains("requires")).flat_map(quoted_strings).filter(|q| q.contains('/')).map(|q| q.split(['/', '@']).next().unwrap_or("").to_string()).collect();
            Some((C, names))
        }
        "vcpkg.json" => {
            let v: serde_json::Value = serde_json::from_str(text).ok()?;
            let names = v.get("dependencies")?.as_array()?.iter().filter_map(|d| d.as_str().or_else(|| d.get("name").and_then(|n| n.as_str()))).map(str::to_string).collect();
            Some((C, names))
        }
        "CMakeLists.txt" => {
            // `find_package(OpenSSL REQUIRED)` and imported targets such as `OpenSSL::Crypto`
            let mut names = vec![];
            for l in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
                if let Some(rest) = l.strip_prefix("find_package(") {
                    names.extend(rest.split_whitespace().next().map(|n| n.trim_end_matches(')').to_string()));
                }
                names.extend(l.split(|c: char| c.is_whitespace() || c == '(' || c == ')').filter_map(|w| w.split_once("::").map(|(p, _)| p.to_string())));
            }
            Some((C, names))
        }
        n if n.starts_with("requirements") && n.ends_with(".txt") => {
            let names = text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty() && !l.starts_with('-')).map(pep508_name).collect();
            Some((PY, names))
        }
        _ => None,
    }
}

/// The value of `attr="value"` in an XML line.
fn xml_attribute(line: &str, attr: &str) -> Option<String> {
    let at = line.find(&format!("{attr}=\""))?;
    let rest = &line[at + attr.len() + 2..];
    rest.split_once('"').map(|(v, _)| v.to_string())
}

/// The contents of the string literals in `text` (single or double quoted).
fn quoted_strings(text: &str) -> Vec<String> {
    let mut out = vec![];
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if matches!(c, '"' | '\'') {
            let s: String = chars.by_ref().take_while(|x| *x != c).collect();
            out.push(s);
        }
    }
    out
}

/// `requests[security]>=2.0; python_version < "3"` -> `requests`.
fn pep508_name(spec: &str) -> String {
    spec.trim().chars().take_while(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.')).collect()
}

/// The crypto libraries a manifest declares (empty for files that are not manifests). Whether an
/// import uses them is set later by [`mark_used`].
pub fn scan_manifest(path: &Path, text: &str) -> Vec<Declared> {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else { return vec![] };
    let Some((fam, names)) = dependency_names(file_name, text) else { return vec![] };
    let lock = file_name.ends_with(".lock") || file_name.ends_with("-lock.json") || file_name == "go.sum";
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<Declared> = names
        .into_iter()
        .filter_map(|name| {
            let library = dependency_library(fam, &name)?;
            let line = lines.iter().position(|l| l.contains(name.as_str())).map_or(1, |i| i + 1);
            Some(Declared { manifest: path.to_path_buf(), line, name, library: library.to_string(), used: false, lock })
        })
        .collect();
    out.sort();
    // a Maven / Gradle coordinate gives both its group and its artifact: one library
    out.dedup_by(|a, b| (&a.manifest, a.line, &a.library) == (&b.manifest, b.line, &b.library));
    out
}

/// Set `used` on every declared library that some import in `uses` refers to.
pub fn mark_used(declared: &mut Vec<Declared>, uses: &[CryptoUse]) {
    // a lock file entry for something a manifest declares adds nothing
    let direct: BTreeSet<(String, String)> = declared.iter().filter(|d| !d.lock).map(|d| (d.name.clone(), d.library.clone())).collect();
    declared.retain(|d| !d.lock || !direct.contains(&(d.name.clone(), d.library.clone())));
    let imported: BTreeSet<&str> = uses.iter().filter(|u| u.kind == Kind::Import).map(|u| u.library.as_str()).collect();
    for d in declared.iter_mut() {
        d.used = imported.contains(d.library.as_str());
    }
}

/// The text inside a string literal (`"AES"`, `b'k'`, `'x'`), or None for anything else.
fn literal_text(v: &str) -> Option<String> {
    let folded = fold_concat(v.trim());
    let v = folded.trim_start_matches(['b', 'B', 'r', 'R', 'u', 'U', '@', '$']);
    let q = v.chars().next().filter(|c| matches!(c, '"' | '\'' | '`'))?;
    let inner = v[1..].strip_suffix(q)?;
    // `"a" + x` is not a literal
    if inner.contains(q) && !inner.contains(['\\']) {
        return None;
    }
    Some(inner.to_string())
}

/// Joins string literals added together: `"MD" + "5"` becomes `"MD5"`. Anything else is kept.
fn fold_concat(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let literal_end = |start: usize| -> Option<usize> {
        let q = chars[start];
        let mut i = start + 1;
        while i < chars.len() {
            match chars[i] {
                '\\' => i += 1,
                c if c == q => return Some(i),
                _ => {}
            }
            i += 1;
        }
        None
    };
    let (mut out, mut i) = (String::new(), 0);
    while i < chars.len() {
        if !matches!(chars[i], '"' | '\'' | '`') {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let Some(mut end) = literal_end(i) else {
            out.extend(&chars[i..]);
            break;
        };
        let mut body: String = chars[i + 1..end].iter().collect();
        loop {
            let mut j = end + 1;
            while chars.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            if chars.get(j) != Some(&'+') {
                break;
            }
            j += 1;
            while chars.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            if !chars.get(j).is_some_and(|c| matches!(c, '"' | '\'' | '`')) {
                break;
            }
            let Some(next_end) = literal_end(j) else { break };
            body.extend(&chars[j + 1..next_end]);
            end = next_end;
        }
        out.push(chars[i]);
        out.push_str(&body);
        out.push(chars[i]);
        i = end + 1;
    }
    out
}

/// The `{...}` or `[...]` that `name` is defined as (`ALGS = {"fast": "md5"}`), when every
/// definition in the text is the same.
fn object_text(src: &str, name: &str) -> Option<String> {
    let defined = defined_object(src, name);
    let (keyed, is_list) = filled_entries(src, name);
    if keyed.is_empty() {
        return defined;
    }
    // a literal plus what is stored into it afterwards
    let mut entries: Vec<(String, String)> = match &defined {
        Some(d) => {
            let items = flow_settings(d, 1, "");
            if d.starts_with('[') != is_list && !items.is_empty() {
                return None;
            }
            items.into_iter().map(|(_, k, v)| (k, v)).collect()
        }
        None => vec![],
    };
    entries.extend(keyed);
    let body: Vec<String> = entries.iter().map(|(k, v)| if is_list { format!("{v:?}") } else { format!("{k:?}: {v:?}") }).collect();
    Some(if is_list { format!("[{}]", body.join(", ")) } else { format!("{{{}}}", body.join(", ")) })
}

/// What is stored into `name` after it is created: `NAME["k"] = "v"`, `NAME.k = "v"` (a dictionary
/// or object) or `NAME.append("v")` / `push` / `add` (a list), when every one is a literal.
fn filled_entries(src: &str, name: &str) -> (Vec<(String, String)>, bool) {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let (mut entries, mut list) = (vec![], false);
    for (i, _) in src.match_indices(name) {
        if src[..i].chars().next_back().is_some_and(|c| word(c) || c == '.') {
            continue;
        }
        let rest = &src[i + name.len()..];
        let line = rest.split('\n').next().unwrap_or("").trim_end_matches(';').trim();
        let literal = |v: &str| literal_text(v).or_else(|| v.trim().parse::<i64>().ok().map(|n| n.to_string()));
        if let Some(call) = ["append(", "push(", "add("].iter().find_map(|m| line.strip_prefix('.').and_then(|l| l.strip_prefix(m)))
            && let Some(v) = call.strip_suffix(')').and_then(literal)
        {
            entries.push((String::new(), v));
            list = true;
        } else if let Some(r) = line.strip_prefix('[')
            && let Some((k, v)) = r.split_once("]")
            && let Some(v) = v.trim_start().strip_prefix('=').filter(|v| !v.starts_with('=')).map(str::trim).and_then(literal)
            && let Some(k) = literal_text(k)
        {
            entries.push((k, v));
        } else if let Some(r) = line.strip_prefix('.')
            && let Some((k, v)) = r.split_once('=')
            && !v.starts_with('=')
            && k.trim().chars().all(word)
            && let Some(v) = literal(v)
        {
            entries.push((k.trim().to_string(), v));
        }
    }
    (entries, list)
}

fn defined_object(src: &str, name: &str) -> Option<String> {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let mut found: Option<String> = None;
    for (i, _) in src.match_indices(name) {
        if src[..i].chars().next_back().is_some_and(|c| word(c) || c == '.') || src[i + name.len()..].chars().next().is_some_and(word) {
            continue;
        }
        let rest = &src[i + name.len()..];
        let Some(eq) = rest.split('\n').next().and_then(|l| l.find('=')) else { continue };
        let (between, after) = (&rest[..eq], rest[eq + 1..].trim_start());
        if between.len() > 40 || between.contains(['(', ')', ',', ';', '"', '\'', '+', '[', '.']) || after.starts_with(['=', '>']) || !after.starts_with(['{', '[']) {
            continue;
        }
        let (mut depth, mut quote, mut end) = (0i32, None::<char>, None);
        let mut chars = after.char_indices();
        while let Some((j, c)) = chars.next() {
            if j > 4000 {
                break;
            }
            if let Some(q) = quote {
                if c == '\\' {
                    chars.next();
                } else if c == q {
                    quote = None;
                }
                continue;
            }
            match c {
                '"' | '\'' | '`' => quote = Some(c),
                '{' | '[' | '(' => depth += 1,
                '}' | ']' | ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let text = after[..end?].to_string();
        match &found {
            Some(f) if *f != text => return None,
            _ => found = Some(text),
        }
    }
    found
}

/// The top-level comma separated parts of `s` (brackets and quotes respected).
fn split_top(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth, mut quote) = (vec![], String::new(), 0i32, None::<char>);
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            cur.push(c);
            if c == '\\' {
                cur.extend(chars.next());
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => {
                quote = Some(c);
                cur.push(c);
            }
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => out.push(std::mem::take(&mut cur).trim().to_string()),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// `value` laid out by a printf or Python format spec: width, `-` / `<` / `>` alignment, `0` fill
/// and precision (which cuts a string).
fn pad(value: &str, spec: &str) -> String {
    let left = spec.starts_with(['-', '<']);
    let spec = spec.trim_start_matches(['-', '<', '>', '^', '+', ' ', '#']);
    let zero = spec.starts_with('0') && value.parse::<i64>().is_ok();
    let (width, precision) = spec.split_once('.').map_or((spec, ""), |(w, p)| (w, p));
    let digits = |t: &str| t.trim_start_matches('0').trim_end_matches(|c: char| c.is_alphabetic()).parse::<usize>().ok();
    let mut v: String = value.to_string();
    if let Some(p) = digits(precision).filter(|_| value.parse::<i64>().is_err()) {
        v = v.chars().take(p).collect();
    }
    let width = digits(width).unwrap_or(0);
    let fill = width.saturating_sub(v.chars().count());
    match (left, zero) {
        (true, _) => format!("{v}{}", " ".repeat(fill)),
        (false, true) => format!("{}{v}", "0".repeat(fill)),
        (false, false) => format!("{}{v}", " ".repeat(fill)),
    }
}

/// A string made by formatting: `"sha%s" % BITS`, `"sha%d%s" % (1, "")`, `"sha{}".format(X)`,
/// `"sha{n}".format(n=1)`, `String.format("SHA-%d", 1)`, `fmt.Sprintf(..)`, `string.Format("SHA{0}", 1)`,
/// as the quoted result, when the template is a literal and every value resolves to a literal or
/// a number.
fn format_literal(a: &str, resolve: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let value = |v: &str| -> Option<String> {
        let v = v.trim();
        literal_text(v).or_else(|| v.parse::<i64>().ok().map(|n| n.to_string())).or_else(|| {
            let id = v.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') && !v.is_empty();
            let r = id.then(|| resolve(v.rsplit('.').next().unwrap_or(v))).flatten()?;
            literal_text(&r).or_else(|| r.parse::<i64>().ok().map(|n| n.to_string()))
        })
    };
    let (template, values): (String, Vec<String>) = if let Some((l, r)) = a.split_once(" % ") {
        let r = r.trim();
        let inner = r.strip_prefix('(').and_then(|r| r.strip_suffix(')')).unwrap_or(r);
        (literal_text(l)?, split_top(inner))
    } else if let Some((at, text)) = a.find(".format(").filter(|_| a.ends_with(')')).and_then(|at| Some((at, literal_text(&a[..at])?))) {
        (text, split_top(&a[at + 8..a.len() - 1]))
    } else if let Some((head, rest)) = a.split_once('(').filter(|_| a.ends_with(')')) {
        let last = head.rsplit('.').next().unwrap_or(head);
        if !matches!(last, "format" | "Format" | "Sprintf" | "sprintf" | "format!") {
            return None;
        }
        let parts = split_top(&rest[..rest.len() - 1]);
        (literal_text(parts.first()?)?, parts[1..].to_vec())
    } else {
        return None;
    };
    let (mut out, mut next, mut chars) = (String::new(), 0usize, template.chars().peekable());
    let positional = |i: usize| values.get(i).filter(|v| !v.contains('=') || v.starts_with(['"', '\''])).and_then(|v| value(v));
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                // flags, width and precision: `%5d`, `%-8s`, `%05d`, `%.3s`
                let mut spec = String::new();
                while chars.peek().is_some_and(|c| matches!(c, '-' | '+' | ' ' | '#' | '0'..='9' | '.')) {
                    spec.extend(chars.next());
                }
                match chars.next()? {
                    '%' if spec.is_empty() => out.push('%'),
                    'b' | 'c' | 'd' | 'i' | 'o' | 's' | 'r' | 'v' | 'x' | 'X' | 'u' => {
                        out.push_str(&pad(&positional(next)?, &spec));
                        next += 1;
                    }
                    _ => return None,
                }
            }
            '{' => {
                let field: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let (key, spec) = field.split_once(':').unwrap_or((&field, ""));
                let key = key.split('!').next().unwrap_or("");
                let v = if key.is_empty() {
                    next += 1;
                    positional(next - 1)?
                } else if let Ok(i) = key.parse::<usize>() {
                    positional(i)?
                } else {
                    let named = values.iter().find_map(|v| v.split_once('=').filter(|(k, _)| k.trim() == key).map(|(_, v)| v.to_string()))?;
                    value(&named)?
                };
                out.push_str(&pad(&v, spec));
            }
            c => out.push(c),
        }
    }
    Some(format!("\"{out}\""))
}

/// An argument with the values it reads spelled out: `ALGS["fast"]` and `ALGS.fast` as the entry of
/// a dictionary or list the file defines, and an interpolated string (`f"sha{BITS}"`,
/// `` `sha${BITS}` ``) with the constants it names filled in. Anything that cannot be resolved
/// completely is returned as it is.
fn expand(arg: &str, resolve: &dyn Fn(&str) -> Option<String>) -> String {
    let a = arg.trim();
    let ident = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_') && !s.starts_with(|c: char| c.is_ascii_digit());
    let quoted = |v: &str| if v.parse::<i64>().is_ok() { v.to_string() } else { format!("\"{v}\"") };
    // `NAME[key]`, `NAME[0]`, `NAME.key`
    let entry = if let Some((name, rest)) = a.split_once('[') {
        rest.strip_suffix(']').map(|k| (name, k.trim()))
    } else {
        a.split_once('.').filter(|(n, k)| ident(n) && ident(k))
    };
    if let Some((name, key)) = entry
        && ident(name)
        && let Some(object) = resolve(&format!("{{}}{name}"))
    {
        let key = literal_text(key).unwrap_or_else(|| key.to_string());
        let items = flow_settings(&object, 1, "");
        let value = if object.starts_with('[') { key.parse::<usize>().ok().and_then(|i| items.get(i)).map(|(_, _, v)| v.clone()) } else { {
            // a key stored with different values in several places has no single value
            let mut all = items.iter().filter(|(_, k, _)| *k == key).map(|(_, _, v)| v);
            all.next().filter(|first| all.all(|v| v == *first)).cloned()
        } };
        if let Some(v) = value {
            return quoted(&v);
        }
    }
    if let Some(formatted) = format_literal(a, resolve) {
        return formatted;
    }
    // an interpolated string
    let body = a.strip_prefix(['f', 'F', '$']).unwrap_or(a);
    if let Some(q) = body.chars().next().filter(|c| matches!(c, '"' | '\'' | '`'))
        && let Some(inner) = body[1..].strip_suffix(q)
        && (a.starts_with(['f', 'F', '$']) || q == '`')
        && inner.contains('{')
    {
        let (mut out, mut rest) = (String::new(), inner);
        while let Some(at) = rest.find('{') {
            out.push_str(rest[..at].trim_end_matches('$'));
            let Some(end) = rest[at..].find('}') else { return a.to_string() };
            let name = rest[at + 1..at + end].trim();
            let Some(v) = ident(name).then(|| resolve(name)).flatten().and_then(|v| literal_text(&v).or_else(|| v.parse::<i64>().ok().map(|n| n.to_string()))) else { return a.to_string() };
            out.push_str(&v);
            rest = &rest[at + end + 1..];
        }
        out.push_str(rest);
        return format!("\"{out}\"");
    }
    a.to_string()
}

/// The literal every `return` of function `name` gives (`def alg(): return "MD5"`, `fn alg() ->
/// &str { "MD5" }`), when they agree.
fn returned_literal(src: &str, name: &str) -> Lookup {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let lines: Vec<&str> = src.lines().collect();
    let mut found: Option<String> = None;
    for (n, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let Some(at) = trimmed.find(&format!("{name}(")) else { continue };
        let before = &trimmed[..at];
        if before.chars().next_back().is_some_and(|c| word(c) || c == '.') && !before.ends_with(' ') {
            continue;
        }
        let defines = ["def ", "fn ", "function ", "func ", "fun "].iter().any(|k| before.contains(k)) || (!before.is_empty() && !before.contains(['=', '(', ';']) && trimmed.ends_with('{'));
        if !defines || !trimmed.ends_with(['{', ':']) {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let mut returns = vec![];
        for body in &lines[n + 1..] {
            let t = body.trim();
            if t.is_empty() {
                continue;
            }
            if body.len() - body.trim_start().len() <= indent {
                break;
            }
            if let Some(r) = t.strip_prefix("return ") {
                returns.push(r.trim_end_matches(';').trim().to_string());
            } else if literal_text(t).is_some() {
                returns.push(t.to_string());
            }
        }
        let value = (!returns.is_empty() && returns.iter().all(|r| literal_text(r).is_some() && *r == returns[0])).then(|| fold_concat(&returns[0]));
        let Some(value) = value else { return Lookup::Unknown };
        match &found {
            Some(f) if *f != value => return Lookup::Unknown,
            _ => found = Some(value),
        }
    }
    found.map_or(Lookup::Missing, Lookup::Found)
}

/// What a source file says a name is defined as.
enum Lookup {
    /// No definition.
    Missing,
    /// A definition that is not a literal, or several different ones.
    Unknown,
    Found(String),
}

/// What `src` says `name` is defined as (`NAME = "x"`, `static final String NAME = "x";`,
/// `const NAME: &str = "x";`, `NAME := 1024`): a quoted string with its quotes, or a number.
fn const_lookup(src: &str, name: &str) -> Lookup {
    const_lookup_at(src, name, 0)
}

fn const_lookup_at(src: &str, name: &str, depth: usize) -> Lookup {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let mut found: Option<String> = None;
    for (i, _) in src.match_indices(name) {
        if src[..i].chars().next_back().is_some_and(word) || src[i + name.len()..].chars().next().is_some_and(word) {
            continue;
        }
        let rest = &src[i + name.len()..];
        let line = rest.split('\n').next().unwrap_or("");
        let Some(eq) = line.find('=') else { continue };
        let (between, after) = (&line[..eq], &line[eq + 1..]);
        if between.len() > 40 || between.contains(['(', ')', ',', ';', '"', '\'', '+', '-', '*', '/', '%', '|', '^', '!', '<', '>', '.', '[']) || after.starts_with(['=', '>']) {
            continue;
        }
        let folded = fold_concat(after.trim_start());
        let after = folded.as_str();
        let lit = {
            let t = after.trim_start_matches(['b', 'B', 'r', 'R', 'u', 'U']);
            match t.chars().next() {
                Some(q @ ('"' | '\'' | '`')) => {
                    let mut end = None;
                    let mut esc = false;
                    for (j, c) in t.char_indices().skip(1) {
                        if esc {
                            esc = false;
                        } else if c == '\\' {
                            esc = true;
                        } else if c == q {
                            end = Some(j);
                            break;
                        }
                    }
                    // `"a" + x` is an expression, not a literal
                    end.filter(|j| !t[j + 1..].trim_start().starts_with('+')).map(|j| t[..=j].to_string())
                }
                Some(c) if c.is_ascii_digit() => Some(t.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect::<String>().replace('_', "")),
                _ => None,
            }
        };
        // a key written as a call over a literal (`Encoding.UTF8.GetBytes("k")`, `new byte[] { 1, 2 }`)
        let lit = lit.or_else(|| {
            let expr = after.trim().trim_end_matches(';').trim();
            (!expr.is_empty() && hardcoded(expr, &|_| None) != Hard::No).then(|| expr.to_string())
        });
        // `alg2 = alg1`: the value of another constant, a few hops deep
        let lit = lit.or_else(|| {
            let expr = after.trim().trim_end_matches(';').trim();
            let plain = !expr.is_empty() && expr.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') && !expr.starts_with(|c: char| c.is_ascii_digit());
            let last = expr.rsplit('.').next().unwrap_or(expr);
            match (plain && depth < 3 && last != name && !matches!(last, "null" | "nil" | "None" | "true" | "false" | "this" | "self")).then(|| const_lookup_at(src, last, depth + 1)) {
                Some(Lookup::Found(v)) => Some(v),
                _ => None,
            }
        });
        // `aes.Key = Key;` assigns a member of that name: not a definition of the constant
        let member = src[..i].ends_with('.');
        let Some(lit) = lit else {
            if member {
                continue;
            }
            return Lookup::Unknown;
        };
        match &found {
            Some(f) if *f != lit => return Lookup::Unknown,
            _ => found = Some(lit),
        }
    }
    found.map_or(Lookup::Missing, Lookup::Found)
}

fn is_literal_number_or_string(arg: &str, resolve: &dyn Fn(&str) -> Option<String>) -> bool {
    let a = arg.trim();
    a.parse::<i64>().is_ok() || literal_text(a).is_some() || resolve(a).is_some_and(|v| v.parse::<i64>().is_ok() || literal_text(&v).is_some())
}

/// The number an argument stands for (a literal, or a constant of the file).
fn arg_number(arg: &str, resolve: &dyn Fn(&str) -> Option<String>) -> Option<u64> {
    let a = arg.trim();
    let a = a.rsplit_once('=').filter(|(k, _)| k.chars().all(|c| c.is_alphanumeric() || c == '_')).map_or(a, |(_, v)| v.trim());
    if let Ok(n) = a.replace('_', "").parse::<u64>() {
        return Some(n);
    }
    // `8 * 1024`, `1 << 16`, `64 << 20`
    if let Some((l, r)) = a.split_once('*') {
        return arg_number(l, resolve)?.checked_mul(arg_number(r, resolve)?);
    }
    if let Some((l, r)) = a.split_once("<<") {
        return arg_number(l, resolve)?.checked_shl(u32::try_from(arg_number(r, resolve)?).ok()?);
    }
    let last = a.rsplit('.').next()?;
    // libsodium's presets: `crypto_pwhash_MEMLIMIT_INTERACTIVE`, `MEMLIMIT_MIN`, `OPSLIMIT_MODERATE`
    let preset = last.strip_prefix("crypto_pwhash_argon2id_").or_else(|| last.strip_prefix("crypto_pwhash_argon2i_")).or_else(|| last.strip_prefix("crypto_pwhash_")).unwrap_or(last);
    match preset {
        "MinCost" => Some(4),
        "DefaultCost" => Some(10),
        "MaxCost" => Some(31),
        "MEMLIMIT_MIN" => Some(8192),
        "MEMLIMIT_INTERACTIVE" => Some(64 << 20),
        "MEMLIMIT_MODERATE" => Some(256 << 20),
        "MEMLIMIT_SENSITIVE" => Some(1024 << 20),
        "OPSLIMIT_MIN" => Some(1),
        "OPSLIMIT_INTERACTIVE" => Some(2),
        "OPSLIMIT_MODERATE" => Some(3),
        "OPSLIMIT_SENSITIVE" => Some(4),
        _ => resolve(last)?.parse().ok(),
    }
}

#[derive(PartialEq)]
enum Hard {
    No,
    Yes,
    Zero,
}

/// Is this argument a literal (a string, a byte array, a constant defined as one)? All zeros count as `Zero`.
fn hardcoded(arg: &str, resolve: &dyn Fn(&str) -> Option<String>) -> Hard {
    let a = arg.trim();
    let resolved;
    let a = if a.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') && !a.is_empty() {
        match resolve(a.rsplit('.').next().unwrap_or(a)) {
            Some(v) => {
                resolved = v;
                resolved.as_str()
            }
            None => return Hard::No,
        }
    } else {
        a
    };
    let mut core = a;
    for w in ["Encoding.UTF8.GetBytes(", "Encoding.ASCII.GetBytes(", "Encoding.Default.GetBytes(", "Encoding.Unicode.GetBytes(", "Convert.FromBase64String(", "Convert.FromHexString(", "bytes(", "bytearray(", "Buffer.from(", "[]byte(", "unhexlify(", "binascii.unhexlify(", "bytes.fromhex(", "b64decode(", "base64.b64decode(", "atob(", "hex::decode(", "String::from("] {
        if let Some(inner) = core.strip_prefix(w) {
            core = inner.trim_end_matches(')').trim();
        }
    }
    for suffix in [".toByteArray", ".getBytes", ".encode", ".as_bytes", ".to_vec", ".into", ".to_owned", ".to_string", ".toCharArray"] {
        if let Some(i) = core.find(suffix) {
            core = core[..i].trim();
        }
    }
    if let Some(inner) = literal_text(core) {
        let zero = !inner.is_empty() && inner.replace("\\x00", "").replace("\\0", "").is_empty();
        return if zero { Hard::Zero } else if inner.is_empty() { Hard::No } else { Hard::Yes };
    }
    // `ByteArray(16)` (Kotlin) and `new byte[16]` are sixteen zero bytes
    if core.strip_prefix("ByteArray(").and_then(|r| r.strip_suffix(')')).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) {
        return Hard::Zero;
    }
    // `byteArrayOf(1, 2, 3)`
    if let Some(inner) = core.strip_prefix("byteArrayOf(").and_then(|r| r.strip_suffix(')')) {
        let nums: Vec<&str> = inner.split(',').map(str::trim).collect();
        if !nums.is_empty() && nums.iter().all(|n| n.trim_start_matches("0x").chars().all(|c| c.is_ascii_hexdigit()) && !n.is_empty()) {
            return if nums.iter().all(|n| n.trim_start_matches("0x").trim_start_matches('0').is_empty()) { Hard::Zero } else { Hard::Yes };
        }
    }
    // `new byte[16]` is sixteen zero bytes
    if core.strip_prefix("new byte[").and_then(|r| r.strip_suffix(']')).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) {
        return Hard::Zero;
    }
    // byte array literals: `[1, 2]`, `&[0u8; 16]`, `new byte[]{1, 2}`, `[]byte{1, 2}`
    let body = core.trim_start_matches('&');
    if body.starts_with(['[', '{']) || body.starts_with("new byte[") || body.starts_with("[]byte{") {
        let cleaned = body.replace("u8", "").replace("byte", "").replace("new", "").replace("0x", "").replace("0X", "");
        let letters_ok = cleaned.chars().all(|c| !c.is_alphabetic() || c.is_ascii_hexdigit());
        let has_digit = cleaned.chars().any(|c| c.is_ascii_digit());
        if letters_ok && has_digit {
            let nonzero = body.replace("u8", "").split(|c: char| !c.is_ascii_alphanumeric()).any(|t| !t.is_empty() && !t.trim_start_matches("0x").trim_start_matches('0').is_empty() && t != "x");
            return if nonzero { Hard::Yes } else { Hard::Zero };
        }
    }
    Hard::No
}

/// The `key=value` form of an argument (Python keyword arguments, JS object properties are not matched).
fn named_arg(arg: &str) -> Option<(&str, &str)> {
    let (k, v) = arg.split_once('=')?;
    let k = k.trim();
    (!v.starts_with('=') && !k.is_empty() && k.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some((k, v.trim()))
}

fn issue_for(role: &str, h: &Hard) -> Option<String> {
    Some(match (role, h) {
        (_, Hard::No) => return None,
        ("iv", Hard::Zero) => "zero IV".into(),
        ("iv", _) => "static IV".into(),
        ("salt", Hard::Zero) => "zero salt".into(),
        ("salt", _) => "static salt".into(),
        ("secret", _) => "hardcoded secret".into(),
        (_, Hard::Zero) => "all-zero key".into(),
        _ => "hardcoded key".into(),
    })
}

/// Hardcoded keys, IVs, salts and secrets among the arguments: by position for the functions in
/// the `secret` table, by keyword name (`key=`, `iv=`, `nonce=`, `salt=`, `password=`) for any crypto call.
fn secret_issues(fam: u8, callee: &str, args: &[String], resolve: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out = vec![];
    let positional = active().secret.iter().find(|x| x.lang.family() == fam && call_matches(&x.pattern, callee)).map_or(&[][..], |x| x.args.as_slice());
    for (i, a) in args.iter().enumerate() {
        let role = match named_arg(a) {
            Some((k, _)) => match k.to_ascii_lowercase().as_str() {
                "key" | "secret_key" | "secretkey" => Some("key"),
                "iv" | "nonce" => Some("iv"),
                "salt" => Some("salt"),
                "secret" | "password" | "passphrase" | "pwd" => Some("secret"),
                _ => None,
            },
            None => positional.iter().find(|a| a.index == i).map(|a| a.role.as_str()),
        };
        let Some(role) = role else { continue };
        let value = named_arg(a).map_or(a.as_str(), |(_, v)| v);
        if let Some(issue) = issue_for(role, &hardcoded(value, resolve))
            && !out.contains(&issue)
        {
            out.push(issue);
        }
    }
    out
}

/// Iteration counts and costs below their minimum.
fn limit_issues(fam: u8, callee: &str, args: &[String], resolve: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out = vec![];
    for l in active().limit.iter().filter(|l| l.lang.family() == fam && call_matches(&l.pattern, callee)) {
        let (what, min) = (&l.what, l.min);
        let by_position = l.index.and_then(|i| args.get(i));
        let by_keyword = args.iter().filter(|a| named_arg(a).is_some_and(|(k, _)| l.keywords.iter().any(|w| w == k)));
        // an options object (`{ memoryCost: 4096 }`): the property of that name
        let objects: Vec<String> = args.iter().filter_map(|a| if a.trim_start().starts_with('{') { Some(a.clone()) } else { resolve(&format!("{{}}{}", a.trim())).filter(|o| o.starts_with('{')) }).collect();
        let by_property: Vec<String> = objects.iter().flat_map(|a| flow_settings(a, 1, "")).filter(|(_, k, _)| l.keywords.iter().any(|w| w == k)).map(|(_, _, v)| v).collect();
        for a in by_position.into_iter().chain(by_keyword).chain(&by_property) {
            if let Some(n) = arg_number(a, resolve)
                && n < min
            {
                out.push(format!("low {what} ({n}, at least {min} recommended)"));
                break;
            }
        }
    }
    out
}

/// Local names an import gives to modules and members (`import hashlib as h`, `from hashlib import
/// md5`, `const { createHash: ch } = require('crypto')`, `use md5 as m`, `import static ...`),
/// and modules whose members are all in scope (`from hashlib import *`).
#[derive(Default)]
pub struct Bindings {
    names: Vec<(String, String)>,
    wildcards: Vec<String>,
}

impl Bindings {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.wildcards.is_empty()
    }

    /// The names `callee` can also be matched under: with an alias or a wildcard module resolved
    /// (`h.md5` is `hashlib.md5`). Empty when the callee does not start with an imported name.
    pub fn alternatives(&self, callee: &str) -> Vec<String> {
        let mut all = self.candidates(callee);
        all.remove(0);
        all
    }

    /// The callee as written, then with an alias or a wildcard module resolved.
    fn candidates(&self, callee: &str) -> Vec<String> {
        let mut out = vec![callee.to_string()];
        let (head, rest) = callee.split_once('.').map_or((callee, ""), |(h, r)| (h, r));
        for (local, full) in &self.names {
            if local == head {
                out.push(if rest.is_empty() { full.clone() } else { format!("{full}.{rest}") });
            }
        }
        if !callee.contains('.') {
            out.extend(self.wildcards.iter().map(|w| format!("{w}.{callee}")));
        }
        out.dedup();
        out
    }
}

/// The source of the statement that starts on `line`: up to the line that closes its brackets.
fn statement(src: &str, line: usize) -> String {
    let mut text = String::new();
    let mut depth = 0i32;
    for l in src.lines().skip(line.saturating_sub(1)).take(12) {
        let l = l.split("//").next().unwrap_or("");
        let l = if l.trim_start().starts_with('#') { "" } else { l.split(" #").next().unwrap_or("") };
        text.push_str(l);
        text.push(' ');
        depth += l.chars().map(|c| match c { '(' | '{' | '[' => 1, ')' | '}' | ']' => -1, _ => 0 }).sum::<i32>();
        if depth <= 0 && !l.trim_end().ends_with(['\\', ',']) {
            break;
        }
    }
    text
}

/// The names a Rust `use` tree binds, nested groups included
/// (`use a::{b::{C as D, E}, f::*}`): `D` is `a.b.C`, `E` is `a.b.E`, `a.f` is a wildcard.
fn use_tree(tree: &str, prefix: &str, b: &mut Bindings) {
    let tree = tree.trim();
    let join = |name: &str| if prefix.is_empty() { name.replace("::", ".") } else { format!("{prefix}.{}", name.replace("::", ".")) };
    if let Some(open) = tree.find('{') {
        let Some(close) = tree.rfind('}') else { return };
        let inner_prefix = join(tree[..open].trim_end_matches("::").trim());
        let inner_prefix = inner_prefix.trim_matches('.');
        // split the group at its top-level commas
        let (mut depth, mut start) = (0usize, open + 1);
        let group = &tree[..close];
        for (i, c) in group.char_indices().skip(open + 1).chain([(close, ',')]) {
            match c {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    use_tree(&tree[start..i], inner_prefix, b);
                    start = i + 1;
                }
                _ => {}
            }
        }
        return;
    }
    match tree {
        "" => {}
        "*" => b.wildcards.push(prefix.to_string()),
        "self" => {
            if let Some(last) = prefix.rsplit('.').next().filter(|l| !l.is_empty()) {
                b.names.push((last.to_string(), prefix.to_string()));
            }
        }
        item if item.ends_with("::*") => b.wildcards.push(join(item.trim_end_matches("::*"))),
        item => match item.split_once(" as ") {
            Some((n, alias)) => b.names.push((alias.trim().to_string(), join(n.trim()))),
            None => b.names.push((item.rsplit("::").next().unwrap_or(item).to_string(), join(item))),
        },
    }
}

fn ident(s: &str) -> Option<&str> {
    let s = s.trim();
    (!s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$')).then_some(s)
}

/// The import bindings of a file (`None` when it has none worth resolving). The source is the
/// retained one of the functions, else the file itself.
pub fn file_bindings(lang: Language, file: &Path, imports: &[Import], cfgs: &[Cfg]) -> Option<Bindings> {
    if imports.is_empty() {
        return None;
    }
    let from_cfg = cfgs.iter().map(|c| &c.source).find(|s| !s.is_empty());
    let read;
    let src: &str = match from_cfg {
        Some(s) => s,
        None => {
            read = std::fs::read_to_string(file).unwrap_or_default();
            &read
        }
    };
    let b = bindings(lang.family(), imports, src);
    (!b.is_empty()).then_some(b)
}

fn bindings(fam: u8, imports: &[Import], src: &str) -> Bindings {
    let mut b = Bindings::default();
    let mut seen = BTreeSet::new();
    for imp in imports.iter().filter(|i| seen.insert((i.line, i.module.clone()))) {
        let text = statement(src, imp.line);
        let t = text.trim();
        match fam {
            PY => {
                let flat = t.replace(['(', ')', '\\'], " ");
                if let Some(rest) = flat.strip_prefix("from ") {
                    let Some((module, items)) = rest.split_once(" import ") else { continue };
                    let module = module.trim();
                    if module.starts_with('.') {
                        continue;
                    }
                    for item in items.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                        match item.split_once(" as ") {
                            _ if item == "*" => b.wildcards.push(module.to_string()),
                            Some((name, alias)) => b.names.push((alias.trim().to_string(), format!("{module}.{}", name.trim()))),
                            None => b.names.push((item.to_string(), format!("{module}.{item}"))),
                        }
                    }
                } else if let Some(rest) = flat.strip_prefix("import ") {
                    for item in rest.split(',') {
                        if let Some((name, alias)) = item.split_once(" as ") {
                            b.names.push((alias.trim().to_string(), name.trim().to_string()));
                        }
                    }
                }
            }
            JS => {
                // the name the call patterns use for this module, when it has one (`CryptoJS`)
                let alias = active().library.iter().find(|l| l.lang.family() == JS && l.alias.is_some() && module_matches(&l.module, &imp.module)).and_then(|l| l.alias.as_deref());
                let module = alias.unwrap_or(imp.module.as_str());
                let pre = if let Some(i) = t.find("require(") {
                    let head = &t[..i];
                    head.rsplit_once('=').map_or(head, |(h, _)| h).trim_start_matches("const ").trim_start_matches("let ").trim_start_matches("var ").to_string()
                } else if let Some(rest) = t.strip_prefix("import ") {
                    rest.rsplit_once(" from ").map_or(rest, |(h, _)| h).trim_start_matches("type ").to_string()
                } else {
                    continue;
                };
                let (inner, outer) = match (pre.find('{'), pre.rfind('}')) {
                    (Some(i), Some(j)) if j > i => (pre[i + 1..j].to_string(), format!("{}{}", &pre[..i], &pre[j + 1..])),
                    _ => (String::new(), pre.clone()),
                };
                for item in inner.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                    let item = item.trim_start_matches("type ");
                    let (name, alias) = item.split_once(" as ").or_else(|| item.split_once(':')).map_or((item, item), |(n, a)| (n.trim(), a.trim()));
                    if let (Some(n), Some(a)) = (ident(name), ident(alias)) {
                        b.names.push((a.to_string(), format!("{module}.{n}")));
                    }
                }
                for item in outer.split(',') {
                    let item = item.trim().trim_start_matches("* as ").trim();
                    if let Some(a) = ident(item) {
                        b.names.push((a.to_string(), module.to_string()));
                    }
                }
            }
            GO => {
                let t = t.trim_start_matches("import").trim();
                if let Some((alias, _)) = t.split_once('"')
                    && let Some(alias) = ident(alias)
                    && alias != "_"
                {
                    let mut segs = imp.module.rsplit('/');
                    let last = segs.next().unwrap_or("");
                    let pkg = if last.len() > 1 && last.starts_with('v') && last[1..].chars().all(|c| c.is_ascii_digit()) { segs.next().unwrap_or(last) } else { last };
                    b.names.push((alias.to_string(), pkg.to_string()));
                }
            }
            RS => {
                let Some(rest) = t.strip_prefix("use ").or_else(|| t.strip_prefix("pub use ")) else { continue };
                use_tree(rest.trim().trim_end_matches(';').trim(), "", &mut b);
            }
            CS => {
                // `using Alias = A.B;` binds Alias; `using static A.B;` brings its members into scope
                let t = t.strip_prefix("global ").unwrap_or(t);
                let Some(rest) = t.strip_prefix("using ") else { continue };
                let rest = rest.trim().trim_end_matches(';').trim();
                if let Some(path) = rest.strip_prefix("static ") {
                    b.wildcards.push(path.trim().to_string());
                } else if let Some((alias, target)) = rest.split_once('=')
                    && let Some(a) = ident(alias)
                {
                    b.names.push((a.to_string(), target.trim().to_string()));
                }
            }
            JAVA => {
                // Kotlin: `import a.b.C as D` binds D
                if let Some(rest) = t.strip_prefix("import ").filter(|r| !r.starts_with("static ")) {
                    if let Some((path, alias)) = rest.trim().trim_end_matches(';').split_once(" as ")
                        && let Some(a) = ident(alias)
                    {
                        b.names.push((a.to_string(), path.trim().to_string()));
                    }
                    continue;
                }
                let Some(path) = t.strip_prefix("import static ") else { continue };
                let path = path.trim().trim_end_matches(';').trim();
                match path.strip_suffix(".*") {
                    Some(class) => b.wildcards.push(class.to_string()),
                    None => {
                        if let Some((_, method)) = path.rsplit_once('.') {
                            b.names.push((method.to_string(), path.to_string()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    b
}

const KEYSTORE_EXTENSIONS: &[&str] = &["jks", "jceks", "keystore", "p12", "pfx", "bks", "kdb"];
const CONFIG_EXTENSIONS: &[&str] = &["conf", "cnf", "cfg", "ini", "yaml", "yml", "properties", "toml", "config", "xml", "json"];
const CONFIG_NAMES: &[&str] = &["sshd_config", "ssh_config", "java.security"];

fn file_use(file: &Path, line: usize, name: &str, primitive: &str, algorithm: &str) -> CryptoUse {
    let mut u = plain(file, Kind::File, name, "", line, 1);
    u.primitive = primitive.to_string();
    u.algorithm = algorithm.to_string();
    u
}

/// Algorithms recognized by their constants: `(name, primitive, weak, groups)`. A group is a set
/// of 32-bit (or, with 16 hex digits, 64-bit) words; a file has the algorithm when it holds
/// every word of some group. Byte groups (`bytes`) are searched as written.
struct Fingerprint {
    name: &'static str,
    primitive: &'static str,
    weak: bool,
    words: &'static [u64],
    /// A table of byte values (written as `0x63, 0x7c, ...` in source) or a string.
    bytes: &'static [u8],
    table: bool,
}

const FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint { name: "SHA-1", primitive: "hash", weak: true, words: &[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], bytes: &[], table: false },
    Fingerprint { name: "MD5", primitive: "hash", weak: true, words: &[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xd76aa478], bytes: &[], table: false },
    Fingerprint { name: "SHA-256", primitive: "hash", weak: false, words: &[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a], bytes: &[], table: false },
    Fingerprint { name: "SHA-256 round constants", primitive: "hash", weak: false, words: &[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5], bytes: &[], table: false },
    Fingerprint { name: "SHA-512", primitive: "hash", weak: false, words: &[0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b], bytes: &[], table: false },
    Fingerprint { name: "Blowfish", primitive: "cipher", weak: true, words: &[0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344], bytes: &[], table: false },
    Fingerprint { name: "AES S-box", primitive: "cipher", weak: false, words: &[], bytes: &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b], table: true },
    Fingerprint { name: "ChaCha / Salsa20", primitive: "cipher", weak: false, words: &[], bytes: b"expand 32-byte k", table: false },
    Fingerprint { name: "SHA-224", primitive: "hash", weak: false, words: &[0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939], bytes: &[], table: false },
    Fingerprint { name: "SHA-384", primitive: "hash", weak: false, words: &[0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17], bytes: &[], table: false },
    Fingerprint { name: "SHA-3 / Keccak", primitive: "hash", weak: false, words: &[0x8082, 0x800000000000808a, 0x8000000080008000, 0x808b], bytes: &[], table: false },
    Fingerprint { name: "SM3", primitive: "hash", weak: false, words: &[0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600], bytes: &[], table: false },
    Fingerprint { name: "Camellia", primitive: "cipher", weak: false, words: &[0xa09e667f3bcc908b, 0xb67ae8584caa73b2, 0xc6ef372fe94f82be], bytes: &[], table: false },
    Fingerprint { name: "AES S-box (inverse)", primitive: "cipher", weak: false, words: &[], bytes: &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e], table: true },
    Fingerprint { name: "SM4 S-box", primitive: "cipher", weak: false, words: &[], bytes: &[0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7], table: true },
    Fingerprint { name: "RC2", primitive: "cipher", weak: true, words: &[], bytes: &[0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79], table: true },
    Fingerprint { name: "Twofish", primitive: "cipher", weak: false, words: &[], bytes: &[0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78], table: true },
    Fingerprint { name: "Serpent", primitive: "cipher", weak: false, words: &[], bytes: &[3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12], table: true },
    Fingerprint { name: "Whirlpool", primitive: "hash", weak: false, words: &[], bytes: &[0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5], table: true },
    Fingerprint { name: "Threefish / Skein", primitive: "cipher", weak: false, words: &[0x1bd11bdaa9fc1a22], bytes: &[], table: false },
    Fingerprint { name: "Serpent", primitive: "cipher", weak: false, words: &[], bytes: &[15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4], table: true },
    Fingerprint { name: "Serpent", primitive: "cipher", weak: false, words: &[], bytes: &[8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2], table: true },
    Fingerprint { name: "DES", primitive: "cipher", weak: true, words: &[], bytes: &[58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4], table: true },
];

/// Hand-rolled or embedded implementations: the constants of well-known algorithms in source
/// text (`0x6a09e667`) or in a binary (either byte order).
fn embedded_constants(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    if bytes.len() > 4 << 20 || bytes.len() < 16 {
        return vec![];
    }
    let mut out = vec![];
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            let lower = text.to_ascii_lowercase();
            let hex = number_literals(&lower);
            for f in FINGERPRINTS {
                let found = if !f.words.is_empty() {
                    let at: Vec<Option<usize>> = f.words.iter().map(|w| hex.iter().find(|(_, h)| h == w).map(|(l, _)| *l)).collect();
                    // SHA-1 / MD5 share four words: the last one tells them apart; the shared words alone are not enough
                    at.iter().all(Option::is_some).then(|| at[0].unwrap_or(1))
                } else if f.table {
                    let seq: Vec<u64> = f.bytes.iter().map(|b| u64::from(*b)).collect();
                    hex.windows(seq.len()).find(|w| w.iter().map(|(_, v)| *v).eq(seq.iter().copied())).map(|w| w[0].0)
                } else {
                    lower.find(&String::from_utf8_lossy(f.bytes).to_string()).map(|i| lower[..i].matches('\n').count() + 1)
                };
                if let Some(line) = found {
                    out.push(constants_use(path, line, f));
                }
            }
        }
        Err(_) => {
            let has = |needle: &[u8]| bytes.windows(needle.len()).position(|w| w == needle);
            for f in FINGERPRINTS {
                let found = if !f.words.is_empty() {
                    let wide = f.words.iter().any(|w| *w > u64::from(u32::MAX));
                    let enc = |w: u64, be: bool| -> Vec<u8> {
                        match (wide, be) {
                            (true, true) => w.to_be_bytes().to_vec(),
                            (true, false) => w.to_le_bytes().to_vec(),
                            (false, true) => (w as u32).to_be_bytes().to_vec(),
                            (false, false) => (w as u32).to_le_bytes().to_vec(),
                        }
                    };
                    [true, false].iter().any(|be| f.words.iter().all(|w| has(&enc(*w, *be)).is_some()))
                } else {
                    has(f.bytes).is_some()
                };
                if found {
                    out.push(constants_use(path, 1, f));
                }
            }
        }
    }
    // an algorithm with several tables (Serpent) is listed once
    let mut names = BTreeSet::new();
    out.retain(|u| names.insert(u.algorithm.clone()));
    out
}

/// Integer literals in order with their lines: hex (`0x6a09e667`, `0x..ULL`) and decimal
/// (`1732584193`, `58`), so a table is found however it is written.
fn number_literals(lower: &str) -> Vec<(usize, u64)> {
    let mut out = vec![];
    for (line, l) in lower.lines().enumerate() {
        for tok in l.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()) {
            let value = match tok.strip_prefix("0x") {
                Some(h) => {
                    let digits: String = h.chars().take_while(char::is_ascii_hexdigit).collect();
                    u64::from_str_radix(&digits, 16).ok()
                }
                None => {
                    let digits = tok.trim_end_matches(['u', 'l']);
                    (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())).then(|| digits.parse().ok()).flatten()
                }
            };
            if let Some(v) = value {
                out.push((line + 1, v));
            }
        }
    }
    out
}

fn constants_use(path: &Path, line: usize, f: &Fingerprint) -> CryptoUse {
    let mut u = file_use(path, line, "embedded or hand-rolled implementation", f.primitive, f.name);
    u.weak = f.weak;
    if f.weak {
        u.reason = f.name.to_string();
    }
    u
}

/// `kpg.initialize(1024)`, `keyGen.init(64)`: a key size given to a method of a key generator.
fn key_size_issue(primitive: &str, method: &str, args: &[String], resolve: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if !matches!(method, "initialize" | "init") {
        return None;
    }
    let bits = args.iter().find_map(|a| arg_number(a, resolve))?;
    let small = match primitive {
        "asymmetric" | "key-exchange" => (256..2048).contains(&bits),
        "key" => (1..128).contains(&bits),
        _ => false,
    };
    small.then(|| format!("{bits}-bit key"))
}

/// Switched-off certificate checks and old protocol minimums in source code and scripts:
/// `InsecureSkipVerify: true`, `verify=False`, `rejectUnauthorized: false`, `curl -k`,
/// `MinVersion: tls.VersionTLS10`, `danger_accept_invalid_certs(true)`.
fn tls_settings(path: &Path, text: &str) -> Vec<CryptoUse> {
    const SOURCE: &[&str] = &["py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "go", "rs", "java", "kt", "cs", "c", "cc", "cpp", "cxx", "h", "hpp", "sh", "bash", "yml", "yaml", "mk"];
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    if !SOURCE.contains(&ext.as_str()) && !name.starts_with("dockerfile") && name != "makefile" {
        return vec![];
    }
    let compact = |l: &str| l.replace(' ', "");
    let mut out = vec![];
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with(['#', '*']) || line.starts_with("//") {
            continue;
        }
        let c = compact(line);
        let hit = [
            ("InsecureSkipVerify:true", "InsecureSkipVerify"),
            ("InsecureSkipVerify=true", "InsecureSkipVerify"),
            ("verify=False", "verify=False"),
            ("rejectUnauthorized:false", "rejectUnauthorized"),
            ("rejectUnauthorized=false", "rejectUnauthorized"),
            ("NODE_TLS_REJECT_UNAUTHORIZED=0", "NODE_TLS_REJECT_UNAUTHORIZED"),
            ("NODE_TLS_REJECT_UNAUTHORIZED='0'", "NODE_TLS_REJECT_UNAUTHORIZED"),
            ("NODE_TLS_REJECT_UNAUTHORIZED=\"0\"", "NODE_TLS_REJECT_UNAUTHORIZED"),
            ("NODE_TLS_REJECT_UNAUTHORIZED']='0'", "NODE_TLS_REJECT_UNAUTHORIZED"),
            ("ssl.CERT_NONE", "ssl.CERT_NONE"),
            ("check_hostname=False", "check_hostname=False"),
            ("NoopHostnameVerifier", "NoopHostnameVerifier"),
            ("ALLOW_ALL_HOSTNAME_VERIFIER", "ALLOW_ALL_HOSTNAME_VERIFIER"),
            ("TrustAllStrategy", "TrustAllStrategy"),
            ("danger_accept_invalid_certs(true)", "danger_accept_invalid_certs"),
            ("danger_accept_invalid_hostnames(true)", "danger_accept_invalid_hostnames"),
            ("CURLOPT_SSL_VERIFYPEER,0", "CURLOPT_SSL_VERIFYPEER"),
            ("CURLOPT_SSL_VERIFYPEER,false", "CURLOPT_SSL_VERIFYPEER"),
            ("http.sslVerifyfalse", "http.sslVerify"),
            ("--no-check-certificate", "--no-check-certificate"),
        ]
        .iter()
        .find(|(p, _)| c.contains(p))
        .map(|(_, n)| n.to_string())
        .or_else(|| (line.contains("curl ") && line.split_whitespace().any(|w| w == "-k" || w == "--insecure")).then(|| "curl --insecure".to_string()));
        let weak_version = ["VersionTLS10", "VersionTLS11", "VersionSSL30"].iter().find(|v| c.contains(&format!("MinVersion:tls.{v}")));
        // .NET: `CipherMode.ECB`, `SslProtocols.Tls`, `ServerCertificateValidationCallback = (..) => true`
        let dotnet = if c.contains("CipherMode.ECB") {
            Some(("CipherMode.ECB", "ECB mode"))
        } else if c.contains("DangerousAcceptAnyServerCertificateValidator") || (c.contains("ValidationCallback") && c.contains("=>true")) {
            Some(("ServerCertificateValidationCallback", "certificate verification disabled"))
        } else if c.contains("SslProtocols.Ssl3") || c.contains("SslProtocols.Ssl2") || c.contains("SecurityProtocolType.Ssl3") {
            Some(("SslProtocols.Ssl3", "SSLV3"))
        } else if weak_tls_enum(&c, "SslProtocols.Tls") || weak_tls_enum(&c, "SecurityProtocolType.Tls") {
            Some(("SslProtocols.Tls", "TLS 1.0/1.1"))
        } else {
            None
        };
        let (name, reason) = match (hit, weak_version, dotnet) {
            (Some(n), _, _) => (n, "certificate verification disabled".to_string()),
            (None, Some(_), _) => ("MinVersion".to_string(), "TLS 1.0/1.1".to_string()),
            (None, None, Some((n, r))) => (n.to_string(), r.to_string()),
            _ => continue,
        };
        let mut u = file_use(path, i + 1, &name, "tls-config", &shorten(line));
        u.weak = true;
        u.reason = reason;
        out.push(u);
    }
    out
}

/// What a declared class says about an object: the table entry that creates it (`Cipher.getInstance`
/// for `Cipher`, `Fernet` for `Fernet`), with whatever algorithm that entry names.
fn typed_origin(fam: u8, class: &str, imported: &BTreeSet<&str>) -> Option<Origin> {
    let class = simple(class);
    let e = active().call.iter().find(|c| {
        c.lang.family() == fam
            && c.primitive != "prng"
            && !c.pattern.contains('*')
            && c.library.as_deref().is_none_or(|l| imported.contains(l))
            && c.pattern.split('.').next() == Some(class)
    })?;
    // `usize::MAX`: declared, not created anywhere we can see
    Some(Origin { line: usize::MAX, primitive: &e.primitive, algorithm: e.algorithm.clone(), reason: if e.weak { e.algorithm.clone() } else { String::new() } })
}

/// A key, certificate or DH parameter set found in a file, from its PEM label (or the label its DER
/// shape suggests) and what was read from it. None for a label that is no key material.
fn material_use(path: &Path, line: usize, label: &str, encoding: &str, info: Option<der::KeyInfo>) -> Option<CryptoUse> {
    let name = format!("{label}{encoding}");
    let algorithm = ["RSA", "EC", "DSA", "OPENSSH", "PGP", "ENCRYPTED", "DH"].iter().find(|a| label.contains(*a)).copied().unwrap_or("PKCS#8");
    let mut u = if label.ends_with("PRIVATE KEY") || label.ends_with("PRIVATE KEY BLOCK") {
        let mut u = file_use(path, line, &name, "key-material", algorithm);
        u.issues.push(if label.contains("ENCRYPTED") { "hardcoded private key (encrypted)" } else { "hardcoded private key" }.into());
        u
    } else if label.contains("PUBLIC KEY") {
        file_use(path, line, &name, "key-material", algorithm)
    } else if label.contains("CERTIFICATE") {
        file_use(path, line, &name, "certificate", "X.509")
    } else if label == "DH PARAMETERS" {
        file_use(path, line, &name, "key-material", "DH")
    } else {
        return None;
    };
    u.quantum = quantum("key-material", algorithm, "").to_string();
    if matches!(algorithm, "RSA" | "EC" | "DSA" | "DH") {
        u.quantum = "vulnerable".into();
    }
    if let Some(info) = info {
        u.algorithm = info.algorithm;
        if !info.weak.is_empty() {
            u.weak = true;
            u.reason = info.weak.join(", ");
        }
        if ["RSA", "EC ", "DSA", "DH", "25519"].iter().any(|a| u.algorithm.contains(a)) {
            u.quantum = "vulnerable".into();
        }
    }
    Some(u)
}

/// A key in a binary DER file (`.der`, `.crt`, `.key`, `.p8`).
fn der_file(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    if !["der", "crt", "cer", "key", "p8", "pk8"].contains(&ext.as_str()) || bytes.first() != Some(&0x30) {
        return vec![];
    }
    let Some((label, info)) = der::guess(bytes) else { return vec![] };
    material_use(path, 1, label, " (DER)", Some(info)).into_iter().collect()
}

/// Base64 DER on one line (`PRIVATE_KEY=MIIEvQIBADANBgkq...`): a run of base64 that starts like a
/// DER sequence and decodes to a key, certificate or public key.
fn base64_keys(path: &Path, text: &str) -> Vec<CryptoUse> {
    let mut out = vec![];
    let mut attempts = 0;
    for (i, line) in text.lines().enumerate() {
        let mut from = 0;
        while let Some(at) = line[from..].find("MI") {
            let start = from + at;
            let run: String = line[start..].chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')).collect();
            from = start + run.len().max(2);
            if run.len() < 100 || start > 0 && line[..start].chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            attempts += 1;
            if attempts > 20 {
                return out;
            }
            if let Some((label, info)) = der::base64(&run).and_then(|b| der::guess(&b)) {
                out.extend(material_use(path, i + 1, label, " (base64)", Some(info)));
            }
        }
    }
    out
}

/// JSON Web Keys: `{ "kty": "RSA", "n": .., "d": .. }`, alone or in a `keys` array.
fn jwk_keys(path: &Path, text: &str) -> Vec<CryptoUse> {
    if !text.contains("\"kty\"") {
        return vec![];
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else { return vec![] };
    let mut keys = vec![];
    fn collect<'a>(v: &'a serde_json::Value, out: &mut Vec<&'a serde_json::Map<String, serde_json::Value>>) {
        match v {
            serde_json::Value::Object(m) if m.contains_key("kty") => out.push(m),
            serde_json::Value::Object(m) => m.values().for_each(|x| collect(x, out)),
            serde_json::Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
            _ => {}
        }
    }
    collect(&value, &mut keys);
    let lines: Vec<usize> = text.lines().enumerate().filter(|(_, l)| l.contains("\"kty\"")).map(|(i, _)| i + 1).collect();
    let mut out = vec![];
    for (n, k) in keys.iter().enumerate() {
        let get = |name: &str| k.get(name).and_then(|v| v.as_str());
        let private = k.contains_key("d");
        let (algorithm, weak, kind) = match get("kty") {
            Some("RSA") => {
                let bits = get("n").and_then(der::base64url).map(|b| der::bits_of(&b));
                (bits.map_or("RSA".to_string(), |b| format!("RSA {b}-bit")), bits.filter(|b| *b < 2048).map(|b| format!("{b}-bit key")), "RSA")
            }
            Some("EC") => {
                let crv = get("crv").unwrap_or("");
                (format!("EC {crv}"), None, "EC")
            }
            Some("OKP") => (get("crv").unwrap_or("OKP").to_string(), None, "OKP"),
            Some("oct") => {
                let bits = get("k").and_then(der::base64url).map(|b| b.len() as u32 * 8);
                (bits.map_or("symmetric".to_string(), |b| format!("symmetric {b}-bit")), bits.filter(|b| *b < 128).map(|b| format!("{b}-bit key")), "oct")
            }
            _ => continue,
        };
        let line = lines.get(n).copied().unwrap_or(1);
        let mut u = file_use(path, line, "JSON Web Key", "key-material", &algorithm);
        if private || kind == "oct" {
            u.issues.push(if kind == "oct" { "hardcoded key" } else { "hardcoded private key" }.into());
        }
        if let Some(w) = weak {
            u.weak = true;
            u.reason = w;
        }
        if kind != "oct" && kind != "OKP" || algorithm.contains("25519") {
            u.quantum = "vulnerable".into();
        }
        out.push(u);
    }
    out
}

/// Whether `bytes` start like an executable, shared library or Java class file.
fn is_object_file(bytes: &[u8]) -> bool {
    matches!(bytes.get(..4), Some([0x7f, b'E', b'L', b'F'] | [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xce] | [0xfe, 0xed, 0xfa, 0xcf] | [0xca, 0xfe, 0xba, 0xbe]))
        || bytes.starts_with(b"MZ")
}

/// Go standard library packages that are crypto, as they appear in a compiled Go program.
const GO_PACKAGES: &[(&str, &str, bool)] = &[
    ("crypto/md5", "MD5", true),
    ("crypto/sha1", "SHA-1", true),
    ("crypto/des", "DES", true),
    ("crypto/rc4", "RC4", true),
    ("crypto/sha256", "SHA-256", false),
    ("crypto/sha512", "SHA-512", false),
    ("crypto/aes", "AES", false),
    ("crypto/cipher", "block cipher modes", false),
    ("crypto/hmac", "HMAC", false),
    ("crypto/rsa", "RSA", false),
    ("crypto/ecdsa", "ECDSA", false),
    ("crypto/ed25519", "Ed25519", false),
    ("crypto/tls", "TLS", false),
    ("crypto/x509", "X.509", false),
];

/// Linked libraries by the file names that appear in an import table: `(prefix, library)`.
const LINKED: &[(&str, &str)] = &[
    ("libcrypto", "OpenSSL"),
    ("libssl", "OpenSSL"),
    ("libsodium", "libsodium"),
    ("libgcrypt", "libgcrypt"),
    ("libmbedcrypto", "mbedTLS"),
    ("libmbedtls", "mbedTLS"),
    ("libgnutls", "GnuTLS"),
    ("libnettle", "Nettle"),
    ("libwolfssl", "wolfSSL"),
    ("libbotan", "Botan"),
    ("libcryptopp", "Crypto++"),
    ("bcrypt.dll", "Windows CNG"),
    ("ncrypt.dll", "Windows CNG"),
    ("crypt32.dll", "Windows CryptoAPI"),
];

/// Crypto in a compiled program: the library functions it imports (`EVP_md5`), the crypto libraries
/// it links, Go's crypto packages and, in a Java class file, the algorithm names it passes to
/// `getInstance`. Found by reading the printable strings of the file, which is where symbol tables
/// and import tables keep their names, so it works on ELF, Mach-O, PE, Go and `.class` files alike.
fn binary_symbols(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    if bytes.len() > 4 << 20 || !is_object_file(bytes) {
        return vec![];
    }
    // a Java class has its version (45 or more) where a fat Mach-O header has a small count
    let java_class = bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && bytes.get(6..8).is_some_and(|v| u16::from_be_bytes([v[0], v[1]]) >= 45);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = vec![];
    // the symbol and import tables say what is imported; the strings of the file also hold messages
    // and debug names. Without a table (a Java class, a stripped or unusual file) the strings are all there is.
    let table = object::symbols(bytes);
    if let Some(t) = &table {
        for lib in &t.libraries {
            symbol_uses(path, lib, false, false, &mut seen, &mut out);
        }
        for name in &t.names {
            if out.len() >= 300 {
                break;
            }
            if let Some(parts) = object::demangle_rust(name) {
                rust_symbol(path, &parts, &mut seen, &mut out);
            } else {
                symbol_uses(path, name, false, false, &mut seen, &mut out);
            }
        }
    }
    // imports by number are named by the exports of the DLL, when it is next to the file
    if let Some(t) = &table {
        let mut exports: BTreeMap<String, Option<BTreeMap<usize, String>>> = BTreeMap::new();
        for (dll, ordinal) in t.ordinals.iter().take(512) {
            let names = exports.entry(dll.to_ascii_lowercase()).or_insert_with(|| sibling_file(path, dll).and_then(|b| object::pe_exports(&b)));
            if let Some(name) = names.as_ref().and_then(|n| n.get(ordinal)) {
                symbol_uses(path, name, false, false, &mut seen, &mut out);
            }
        }
    }
    let go_only = table.is_some();
    let mut run: Vec<u8> = vec![];
    let mut flush = |run: &mut Vec<u8>, out: &mut Vec<CryptoUse>| {
        if (if java_class { 3 } else { 4 }..=120).contains(&run.len()) && out.len() < 300 {
            symbol_uses(path, &String::from_utf8_lossy(run), java_class, go_only, &mut seen, out);
        }
        run.clear();
    };
    for &b in bytes {
        if (0x21..=0x7e).contains(&b) {
            run.push(b);
        } else {
            flush(&mut run, &mut out);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// The crates a Rust symbol names (libraries of the tables), and the crypto function it is: `Md5.update`
/// for `<md5::Md5 as Digest>::update` or `md5::Md5::update`.
fn rust_symbol(path: &Path, sym: &object::RustSymbol, seen: &mut BTreeSet<String>, out: &mut Vec<CryptoUse>) {
    let mut library: Option<&str> = None;
    for krate in &sym.crates {
        let Some(lib) = active().library.iter().find(|l| l.lang.family() == RS && module_matches(&l.module, krate)) else { continue };
        library.get_or_insert(lib.name.as_str());
        if seen.insert(format!("crate:{krate}")) {
            let mut u = file_use(path, 1, &format!("linked Rust crate {krate}"), "library", &lib.name);
            u.library = lib.name.clone();
            let reason = weak_word(&tokens(krate)).unwrap_or_default();
            u.weak = !reason.is_empty();
            u.reason = reason;
            out.push(u);
        }
    }
    let Some(library) = library else { return };
    let named: Vec<&String> = sym.names.iter().filter(|p| !p.starts_with('{') && !p.starts_with('<')).collect();
    let Some(last) = named.last() else { return };
    // a type and a method (`Md5.new`), or a longer tail of the path
    let mut candidates: Vec<String> = named[..named.len() - 1].iter().map(|n| format!("{n}.{last}")).collect();
    for n in [2usize, 3] {
        if let Some(from) = named.len().checked_sub(n) {
            candidates.push(named[from..].iter().map(|p| p.as_str()).collect::<Vec<_>>().join("."));
        }
    }
    for tail in candidates {
        if let Some(e) = active().call.iter().find(|c| c.lang.family() == RS && c.pattern.contains('.') && call_matches(&c.pattern, &tail))
            && seen.insert(format!("rsfn:{tail}"))
        {
            let mut u = file_use(path, 1, &tail, &e.primitive, &e.algorithm);
            u.library = library.to_string();
            if e.weak {
                u.weak = true;
                u.reason = e.algorithm.clone();
            }
            out.push(u);
            break;
        }
    }
}

/// The contents of the file called `name` (any case) in the directory of `from`: the entry is picked
/// from the directory listing, so the name only selects it.
fn sibling_file(from: &Path, name: &str) -> Option<Vec<u8>> {
    let dir = from.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let entry = std::fs::read_dir(dir).ok()?.filter_map(Result::ok).find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name))?;
    let meta = entry.metadata().ok()?;
    (meta.is_file() && meta.len() < 32 << 20).then(|| std::fs::read(entry.path()).ok()).flatten()
}

fn symbol_uses(path: &Path, token: &str, java_class: bool, go_only: bool, seen: &mut BTreeSet<String>, out: &mut Vec<CryptoUse>) {
    let lower = token.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);
    if let Some((_, lib)) = LINKED.iter().find(|(p, _)| file_name.starts_with(p) && file_name.len() < 60).filter(|_| !go_only) {
        if seen.insert(format!("lib:{lib}")) {
            let mut u = file_use(path, 1, "linked library", "library", lib);
            u.library = (*lib).to_string();
            out.push(u);
        }
        return;
    }
    // Go: `crypto/md5.New`, `crypto/sha1.(*digest).Write`
    if let Some((pkg, rest)) = token.split_once('.') && let Some((_, name, weak)) = GO_PACKAGES.iter().find(|(p, _, _)| *p == pkg) && !rest.is_empty() {
        if seen.insert(format!("go:{pkg}")) {
            let mut u = file_use(path, 1, &format!("linked Go package {pkg}"), "library", name);
            u.weak = *weak;
            if *weak {
                u.reason = (*name).to_string();
            }
            out.push(u);
        }
        // the function: `crypto/md5.Sum` is `md5.Sum` of the tables (methods like `(*digest).Write` are not)
        let short = pkg.rsplit('/').next().unwrap_or(pkg);
        let call = format!("{short}.{rest}");
        if !rest.contains(['(', '*', '{'])
            && let Some(e) = active().call.iter().find(|c| c.lang.family() == GO && call_matches(&c.pattern, &call))
            && seen.insert(format!("gofn:{call}"))
        {
            let mut u = file_use(path, 1, &call, &e.primitive, &e.algorithm);
            if e.weak {
                u.weak = true;
                u.reason = e.algorithm.clone();
            }
            out.push(u);
        }
        return;
    }
    if go_only {
        return;
    }
    if java_class {
        // classes and algorithm names in the constant pool
        let algorithm = ["MD5", "MD2", "SHA-1", "SHA1", "SHA", "DES", "DESede", "RC4", "ARCFOUR", "Blowfish", "RC2"].contains(&token) || token.starts_with("AES/ECB") || token.starts_with("DES/") || token.starts_with("DESede/") || token == "AES";
        if algorithm && seen.insert(format!("alg:{token}")) {
            let mut u = file_use(path, 1, "algorithm name", "hash-or-cipher", token);
            // a bare `AES` may be a key algorithm as well as a transformation: not a finding by itself
            let reason = weak_word(&tokens(token)).unwrap_or_default();
            u.weak = !reason.is_empty();
            u.reason = reason;
            out.push(u);
        }
        return;
    }
    // C: an imported function, with Mach-O's leading underscore dropped
    let symbol = token.strip_prefix('_').filter(|r| r.chars().next().is_some_and(char::is_alphabetic)).unwrap_or(token);
    if !symbol.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || !symbol.contains('_') {
        return;
    }
    if let Some(e) = active().call.iter().find(|c| c.lang.family() == C && c.pattern.contains('_') && call_matches(&c.pattern, symbol))
        && seen.insert(format!("sym:{symbol}"))
    {
        let mut u = file_use(path, 1, symbol, &e.primitive, &e.algorithm);
        if e.weak {
            u.weak = true;
            u.reason = e.algorithm.clone();
        }
        out.push(u);
    }
}

/// Key material and TLS settings outside the code the scanner parses: PEM blocks (in any text file,
/// including source code), keystore files, weak protocols and ciphers in configuration files
/// (nginx, Apache, sshd, `.properties`, YAML, ...) and small keys in shell scripts and Dockerfiles.
pub fn scan_artifact(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let mut out = vec![];
    if KEYSTORE_EXTENSIONS.contains(&ext.as_str()) {
        let mut u = file_use(path, 1, "keystore file", "key-material", &ext.to_ascii_uppercase());
        u.issues.push("hardcoded keystore".into());
        out.push(u);
        out.extend(jks_certificates(path, bytes));
        out.extend(pkcs12_contents(path, bytes));
        out.extend(certificates(path, bytes));
    }
    if matches!(ext.as_str(), "jar" | "war" | "ear" | "aar") {
        out.extend(jar_contents(path, bytes));
    }
    out.extend(embedded_constants(path, bytes));
    out.extend(binary_symbols(path, bytes));
    if bytes.len() > 1 << 20 {
        return out;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        out.extend(der_file(path, bytes));
        return out;
    };
    out.extend(pem_blocks(path, text));
    out.extend(base64_keys(path, text));
    out.extend(jwk_keys(path, text));
    out.extend(tls_settings(path, text));
    let lower = name.to_ascii_lowercase();
    if CONFIG_EXTENSIONS.contains(&ext.as_str()) || CONFIG_NAMES.contains(&lower.as_str()) {
        out.extend(config_settings(path, text));
    }
    if ext == "sh" || ext == "bash" || lower.starts_with("dockerfile") || lower == "makefile" || ext == "mk" {
        out.extend(script_keys(path, text));
    }
    out.sort();
    out
}

/// The crypto libraries and weak algorithm classes among the entry names of a `.jar` (the classes
/// are compressed, so only the names are read): `org/bouncycastle/...`, `.../MD5Digest.class`.
fn jar_contents(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    let u16le = |at: usize| bytes.get(at..at + 2).map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])));
    let u32le = |at: usize| bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let Some(end) = (0..bytes.len().saturating_sub(21)).rev().take(70_000).find(|&i| bytes[i..].starts_with(&[0x50, 0x4b, 0x05, 0x06])) else { return vec![] };
    let (Some(count), Some(mut at)) = (u16le(end + 10), u32le(end + 16)) else { return vec![] };
    let (mut libraries, mut classes): (BTreeSet<&str>, BTreeSet<String>) = (BTreeSet::new(), BTreeSet::new());
    // (offset of the local header, method, compressed size) of each class, the project's own first
    let mut class_entries: Vec<(usize, usize, usize)> = vec![];
    for _ in 0..count.min(20_000) {
        if bytes.get(at..at + 4) != Some(&[0x50, 0x4b, 0x01, 0x02]) {
            break;
        }
        let (Some(n), Some(extra), Some(comment)) = (u16le(at + 28), u16le(at + 30), u16le(at + 32)) else { break };
        let Some(name) = bytes.get(at + 46..at + 46 + n).and_then(|b| std::str::from_utf8(b).ok()) else { break };
        let (package, file) = name.rsplit_once('/').unwrap_or(("", name));
        let dotted = package.replace('/', ".");
        if let Some(l) = active().library.iter().find(|l| l.lang.family() == JAVA && module_matches(&l.module, &dotted)) {
            libraries.insert(l.name.as_str());
        }
        if name.ends_with(".class")
            && class_entries.len() < 400
            && !name.starts_with("org/bouncycastle/")
            && let (Some(method), Some(compressed)) = (u16le(at + 10), u32le(at + 20))
        {
            class_entries.push((at + 42, method, compressed));
        }
        if let Some(class) = file.strip_suffix(".class")
            && ["MD5Digest", "MD4Digest", "MD2Digest", "SHA1Digest", "DESEngine", "DESedeEngine", "RC4Engine", "RC2Engine", "BlowfishEngine"].contains(&class)
        {
            classes.insert(class.to_string());
        }
        at += 46 + n + extra + comment;
    }
    let mut out = vec![];
    // the algorithm names in the classes
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    for (class_at, method, compressed) in class_entries {
        let Some(local) = u32le(class_at) else { continue };
        let (Some(n), Some(extra)) = (u16le(local + 26), u16le(local + 28)) else { continue };
        let Some(data) = bytes.get(local + 30 + n + extra..local + 30 + n + extra + compressed) else { continue };
        let class = match method {
            0 => Some(data.to_vec()),
            8 => object::inflate(data, 1 << 20),
            _ => None,
        };
        let Some(class) = class else { continue };
        for u in binary_symbols(path, &class) {
            if found.insert((u.name.clone(), u.algorithm.clone())) && found.len() < 200 {
                out.push(u);
            }
        }
    }
    for lib in libraries {
        let mut u = file_use(path, 1, "library in jar", "library", lib);
        u.library = lib.to_string();
        out.push(u);
    }
    for class in classes {
        let mut u = file_use(path, 1, &format!("class {class} in jar"), "hash-or-cipher", &class);
        let reason = weak_word(&tokens(class.trim_end_matches("Digest").trim_end_matches("Engine"))).unwrap_or_default();
        u.weak = !reason.is_empty();
        u.reason = reason;
        out.push(u);
    }
    out
}

/// What a PKCS#12 file shows without its password: the certificates in bags that are not
/// encrypted, the algorithms that protect the rest, and the digest of its MAC.
fn pkcs12_contents(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    let Some(info) = der::pkcs12(bytes) else { return vec![] };
    let mut out = vec![];
    for cert in &info.certs {
        if let Some((label, k)) = der::guess(cert)
            && let Some(u) = material_use(path, 1, label, " (PKCS#12)", Some(k))
        {
            out.push(u);
        }
    }
    for alg in &info.encryption {
        let mut u = file_use(path, 1, "keystore encryption", "key-protection", alg);
        let mut reasons: Vec<&str> = vec![];
        for (needle, why) in [("RC4", "RC4"), ("RC2", "RC2"), ("TripleDES", "3DES")] {
            if alg.contains(needle) {
                reasons.push(why);
            }
        }
        if alg.contains("DES-CBC") && !alg.contains("Triple") {
            reasons.push("DES");
        }
        if alg.contains("40Bit") {
            reasons.push("40-bit key");
        }
        let reason = reasons.join(", ");
        u.weak = !reason.is_empty();
        u.reason = reason;
        out.push(u);
    }
    if let Some(mac) = &info.mac {
        let mut u = file_use(path, 1, "keystore MAC", "mac", mac);
        let reason = weak_word(&tokens(mac)).unwrap_or_default();
        u.weak = !reason.is_empty();
        u.reason = reason;
        out.push(u);
    }
    out
}

/// A reader over big-endian keystore bytes (JKS, JCEKS, BKS): numbers, `writeUTF` strings, slices.
struct BigEndian<'a>(&'a [u8]);

impl<'a> BigEndian<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    fn u32(&mut self) -> Option<usize> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize)
    }
    fn utf(&mut self) -> Option<String> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize;
        Some(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    /// A BKS certificate: its type, then the bytes.
    fn cert(&mut self) -> Option<&'a [u8]> {
        self.utf()?;
        let n = self.u32()?;
        self.take(n)
    }
}

/// The certificates of a BouncyCastle keystore (`.bks`): entry type, alias, date, then the entry.
/// Key entries are read as far as their certificate chain; sealed and secret entries end the reading.
fn certificates(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    let mut r = BigEndian(bytes);
    let mut out = vec![];
    if !matches!(r.u32(), Some(1 | 2)) {
        return out;
    }
    // salt, iteration count
    let Some(salt) = r.u32().filter(|n| *n < 256) else { return out };
    if r.take(salt).is_none() || r.u32().is_none() {
        return out;
    }
    for _ in 0..256 {
        let Some(kind) = r.take(1).map(|b| b[0]) else { break };
        if kind == 0 {
            break;
        }
        let entry = (|| {
            let alias = r.utf()?;
            r.take(8)?;
            let mut certs = vec![];
            match kind {
                1 => certs.push(r.cert()?),
                2 => {
                    // key: type, format, algorithm, name, encoded bytes; then the chain
                    r.take(1)?;
                    r.utf()?;
                    r.utf()?;
                    r.utf()?;
                    let n = r.u32()?;
                    r.take(n)?;
                    for _ in 0..r.u32()?.min(16) {
                        certs.push(r.cert()?);
                    }
                }
                _ => return None,
            }
            Some((alias, kind, certs))
        })();
        let Some((alias, kind, certs)) = entry else { break };
        for (i, der) in certs.into_iter().enumerate() {
            let what = if kind == 2 && i == 0 { "private key" } else { "certificate" };
            if let Some((label, info)) = der::guess(der)
                && let Some(u) = material_use(path, 1, label, &format!(" (BKS {what} `{alias}`)"), Some(info))
            {
                out.push(u);
            }
        }
    }
    out
}

/// The certificates of a Java keystore (`.jks`): the key sizes and curves of what it holds. Private
/// keys are encrypted, so a key entry shows through the certificate chain that comes with it.
fn jks_certificates(path: &Path, bytes: &[u8]) -> Vec<CryptoUse> {
    let mut r = BigEndian(bytes);
    let mut out = vec![];
    // JCEKS has the layout of JKS, with secret key entries (tag 3) that are serialized objects
    if !matches!(r.u32(), Some(0xFEED_FEED | 0xCECE_CECE)) || !matches!(r.u32(), Some(1 | 2)) {
        return out;
    }
    let Some(count) = r.u32() else { return out };
    for _ in 0..count.min(256) {
        let entry = (|| {
            let tag = r.u32()?;
            let alias = r.utf()?;
            r.take(8)?;
            let mut certs = vec![];
            let chain = match tag {
                1 => {
                    let n = r.u32()?;
                    r.take(n)?;
                    r.u32()?
                }
                2 => 1,
                _ => return None,
            };
            for _ in 0..chain.min(16) {
                r.utf()?;
                let n = r.u32()?;
                certs.push(r.take(n)?);
            }
            Some((tag, alias, certs))
        })();
        let Some((tag, alias, certs)) = entry else { break };
        for (i, der) in certs.into_iter().enumerate() {
            // the first certificate of a key entry belongs to the key
            let kind = if tag == 1 && i == 0 { "private key" } else { "certificate" };
            let Some((label, info)) = der::guess(der) else { continue };
            let name = format!("{label} (JKS {kind} `{alias}`)");
            if let Some(u) = material_use(path, 1, label, &name[label.len()..], Some(info)) {
                out.push(u);
            }
        }
    }
    out
}

/// `-----BEGIN RSA PRIVATE KEY-----` and friends, when key data follows (not just a mention in docs).
fn pem_blocks(path: &Path, text: &str) -> Vec<CryptoUse> {
    let mut out = vec![];
    let mut offset = 0;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let line_start = offset;
        offset += line.len();
        let line = line.trim_end_matches(['\n', '\r']);
        let Some(at) = line.find("-----BEGIN ") else { continue };
        let rest = &line[at + 11..];
        let Some(end) = rest.find("-----") else { continue };
        let label = &rest[..end];
        let after = rest[end + 5..].trim_start_matches(['\\', 'n', 'r', ' ', '"', '\'', ',']);
        let next = text.lines().nth(i + 1).unwrap_or("").trim();
        let data = if after.is_empty() { next } else { after };
        let base64 = |s: &str| s.len() >= 20 && s.chars().take(20).all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
        if !(base64(data) || data.starts_with("Proc-Type") || data.starts_with("Version:") || label.contains("PGP")) {
            continue;
        }
        let kind = label.trim();
        // the algorithm and size, read from the key itself
        let body = &text[(line_start + at + 11 + end + 5).min(text.len())..];
        let info = der::decode_body(body).and_then(|bytes| der::key_info(kind, &bytes));
        let Some(u) = material_use(path, i + 1, kind, "", info) else { continue };
        out.push(u);
    }
    out
}

/// A setting that names protocols or ciphers, with the weak ones among its values. Deny lists
/// (`jdk.tls.disabledAlgorithms`) and negated entries (`!RC4`, `-SSLv3`) are what you want to see.
fn config_settings(path: &Path, text: &str) -> Vec<CryptoUse> {
    config_settings_in(path, text, 0)
}

/// `config_settings` that also reads the files a setting includes (`include conf.d/*.conf;`,
/// `Include /etc/ssh/sshd_config.d/*.conf`), up to three levels deep. What an included file holds
/// is reported at its own place.
fn config_settings_in(path: &Path, text: &str, depth: usize) -> Vec<CryptoUse> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let mut out = vec![];
    for (line, key, value) in settings_of(&ext, text) {
        if depth < 3 && matches!(key.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str(), "include" | "includeoptional") {
            for file in included_files(path, &value) {
                if file == path || file.metadata().is_ok_and(|m| m.len() > 1 << 20) {
                    continue;
                }
                if let Some(inner) = read_included(&file) {
                    out.extend(config_settings_in(&file, &inner, depth + 1));
                }
            }
            continue;
        }
        let reasons = weak_setting(&key, &value);
        if reasons.is_empty() {
            continue;
        }
        let mut u = file_use(path, line, &key, "tls-config", &value);
        u.weak = true;
        u.reason = reasons.join(", ");
        out.push(u);
    }
    out
}

/// The text of an included file, by its canonical path (which drops `..` and symlink tricks).
fn read_included(file: &Path) -> Option<String> {
    let real = file.canonicalize().ok()?;
    std::fs::read_to_string(real).ok()
}

/// The files an `include` names: relative to the including file, with `*` in the file name.
fn included_files(from: &Path, spec: &str) -> Vec<PathBuf> {
    let spec = spec.split_whitespace().next().unwrap_or("").trim_matches(['"', '\'', ';']);
    if spec.is_empty() {
        return vec![];
    }
    let target = from.parent().unwrap_or(Path::new("")).join(spec);
    let Some(name) = target.file_name().and_then(|n| n.to_str()).map(str::to_string) else { return vec![] };
    if !name.contains('*') {
        return if target.is_file() { vec![target] } else { vec![] };
    }
    let (pre, post) = name.split_once('*').unwrap_or((&name, ""));
    let Ok(dir) = std::fs::read_dir(target.parent().unwrap_or(Path::new("."))) else { return vec![] };
    let mut files: Vec<PathBuf> = dir.filter_map(Result::ok).map(|e| e.path()).filter(|f| f.is_file() && f.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.len() >= pre.len() + post.len() && n.starts_with(pre) && n.ends_with(post))).collect();
    files.sort();
    files
}

fn is_comment(line: &str) -> bool {
    line.is_empty() || line.starts_with(['#', ';', '/']) || line.starts_with("<!--")
}

/// `key = value`, `key: value` or `key value`, with the key and value cleaned up.
fn key_value(line: &str) -> Option<(String, String)> {
    let split = line.find(|c: char| c == '=' || c == ':' || c.is_whitespace())?;
    let key = line[..split].trim_matches(['"', '\'', '-', ' ']).to_string();
    let value = line[split..].trim_start_matches(|c: char| c == '=' || c == ':' || c.is_whitespace()).trim().trim_end_matches([';', ',']).trim_matches(['"', '\'']).to_string();
    Some((key, value))
}

/// A YAML key that opens a block: its indent, its name, and the anchor it carries with the number
/// of settings found before it.
type YamlKey = (usize, String, Option<(String, usize)>);

/// The `(line, key, value)` settings of a configuration file. The key is the full path in nested
/// formats (`tls.min_version` for YAML under `tls:`, a TOML `[tls]` section, nested JSON, an INI
/// section), and a value may continue on the next lines (`\`, a YAML list, an XML text node).
fn settings_of(ext: &str, text: &str) -> Vec<(usize, String, String)> {
    let mut out = vec![];
    match ext {
        "xml" => {
            // attributes, and element text: `<tag>text</tag>`, or the text on the lines after `<tag>`
            let mut open: Option<(usize, String, String)> = None;
            for (i, raw) in text.lines().enumerate() {
                let line = raw.trim();
                if is_comment(line) {
                    continue;
                }
                out.extend(xml_attributes(line).into_iter().map(|(k, v)| (i + 1, k, v)));
                if let Some(rest) = line.strip_prefix('<').filter(|r| !r.starts_with(['/', '?', '!'])) {
                    let tag: String = rest.chars().take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')).collect();
                    let after = rest[tag.len()..].split_once('>').map(|(_, a)| a);
                    match after {
                        Some(a) if a.contains(&format!("</{tag}")) => {
                            let text = a.split("</").next().unwrap_or("").trim();
                            out.push((i + 1, tag, text.to_string()));
                        }
                        Some(a) if !rest.contains("/>") => open = Some((i + 1, tag, a.trim().to_string())),
                        _ => {}
                    }
                } else if let Some((line_no, tag, mut value)) = open.take() {
                    if line.starts_with("</") {
                        out.push((line_no, tag, value));
                    } else {
                        if !value.is_empty() {
                            value.push(' ');
                        }
                        value.push_str(line);
                        open = Some((line_no, tag, value));
                    }
                }
            }
        }
        "json" => out.extend(flow_settings(text, 1, "")),
        "yaml" | "yml" => {
            let lines: Vec<&str> = text.lines().collect();
            // what each anchor (`&tls`) stands for, relative to the node that carries it
            let mut anchors: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
            // (indent, key, the anchor the key carries and where its settings start)
            let mut stack: Vec<YamlKey> = vec![];
            let join = |stack: &[YamlKey], key: &str| stack.iter().map(|(_, k, _)| k.as_str()).chain((!key.is_empty()).then_some(key)).collect::<Vec<_>>().join(".");
            let close = |stack: &mut Vec<YamlKey>, out: &[(usize, String, String)], anchors: &mut BTreeMap<String, Vec<(String, String)>>| {
                let base = join(stack, "");
                if let Some((_, _, Some((name, start)))) = stack.pop() {
                    let rel = out[start..].iter().map(|(_, k, v)| (k.strip_prefix(base.as_str()).unwrap_or(k).trim_start_matches('.').to_string(), v.clone())).collect();
                    anchors.insert(name, rel);
                }
            };
            let mut i = 0;
            while i < lines.len() {
                let (raw, no) = (lines[i], i + 1);
                i += 1;
                let line = raw.trim();
                if is_comment(line) {
                    continue;
                }
                let indent = raw.len() - raw.trim_start().len();
                while stack.last().is_some_and(|(n, ..)| *n >= indent) {
                    close(&mut stack, &out, &mut anchors);
                }
                // a flow collection (`{a: 1, b: [x]}`) may run over several lines
                if let Some(rest) = flow_start(line) {
                    let mut flow = rest.to_string();
                    while flow.matches(['{', '[']).count() > flow.matches(['}', ']']).count() && i < lines.len() {
                        flow.push('\n');
                        flow.push_str(lines[i]);
                        i += 1;
                    }
                    let key = if line.starts_with("- ") { String::new() } else { line.split_once(':').map(|(k, _)| k.trim().trim_matches(['"', '\'']).to_string()).unwrap_or_default() };
                    out.extend(flow_settings(&flow, no, &join(&stack, &key)));
                    continue;
                }
                let path = |stack: &[YamlKey], key: &str| join(stack, key);
                if let Some(item) = line.strip_prefix("- ") {
                    match key_value(item) {
                        Some((k, v)) if item.contains(':') => out.push((no, path(&stack, &k), v)),
                        _ => out.push((no, path(&stack, ""), item.trim_matches(['"', '\'']).to_string())),
                    }
                    continue;
                }
                let (key, rest) = match line.split_once(':') {
                    Some((k, r)) if r.is_empty() || r.starts_with(' ') => (k.trim().trim_matches(['"', '\'']).to_string(), r.trim()),
                    _ => {
                        if let Some((k, v)) = key_value(line) {
                            out.push((no, path(&stack, &k), v));
                        }
                        continue;
                    }
                };
                if let Some(name) = rest.strip_prefix('*') {
                    // `<<: *tls` merges the anchored settings here, `key: *tls` puts them under the key
                    let base = if key == "<<" { path(&stack, "") } else { path(&stack, &key) };
                    for (rel, v) in anchors.get(name.trim()).cloned().unwrap_or_default() {
                        out.push((no, [base.as_str(), rel.as_str()].iter().filter(|p| !p.is_empty()).copied().collect::<Vec<_>>().join("."), v));
                    }
                } else if let Some(anchored) = rest.strip_prefix('&') {
                    let (name, value) = anchored.split_once(' ').map_or((anchored, ""), |(n, v)| (n, v.trim()));
                    if value.is_empty() {
                        stack.push((indent, key, Some((name.to_string(), out.len()))));
                    } else {
                        let value = value.trim_matches(['"', '\'']).to_string();
                        out.push((no, path(&stack, &key), value.clone()));
                        anchors.insert(name.to_string(), vec![(String::new(), value)]);
                    }
                } else if rest.is_empty() {
                    stack.push((indent, key, None));
                } else {
                    let value = rest.trim_end_matches([';', ',']).trim_matches(['"', '\'']).to_string();
                    out.push((no, path(&stack, &key), value));
                }
            }
            while !stack.is_empty() {
                close(&mut stack, &out, &mut anchors);
            }
        }
        _ => {
            // `key = value` lines, joined across a trailing backslash, under `[section]` headers
            let sections = matches!(ext, "toml" | "ini" | "cfg" | "cnf");
            let mut section = String::new();
            let mut lines = text.lines().enumerate();
            while let Some((i, raw)) = lines.next() {
                let mut line = raw.trim().to_string();
                while line.ends_with('\\') {
                    line.pop();
                    match lines.next() {
                        Some((_, next)) => line.push_str(next.trim()),
                        None => break,
                    }
                }
                if is_comment(&line) {
                    continue;
                }
                if sections && line.starts_with('[') && line.ends_with(']') {
                    section = line.trim_matches(['[', ']', ' ']).to_string();
                    continue;
                }
                if let Some((k, v)) = key_value(&line) {
                    let key = if section.is_empty() { k } else { format!("{section}.{k}") };
                    out.push((i + 1, key, v));
                }
            }
        }
    }
    out.dedup();
    out
}

/// `key="value"` pairs of an XML element (`<Connector sslProtocol="TLSv1" ciphers="..."/>`).
fn xml_attributes(line: &str) -> Vec<(String, String)> {
    if !line.starts_with('<') {
        return vec![];
    }
    let parts: Vec<&str> = line.split('"').collect();
    let mut out = vec![];
    for (i, value) in parts.iter().enumerate().skip(1).step_by(2) {
        let before = parts[i - 1].trim_end();
        if let Some(key) = before.strip_suffix('=').and_then(|k| k.split(|c: char| c.is_whitespace() || c == '<').next_back())
            && !key.is_empty()
        {
            out.push((key.to_string(), (*value).to_string()));
        }
    }
    out
}

/// `"key": "value"` pairs of a JSON line, several to a line included.
/// The `{...}` or `[...]` a YAML line opens (`key: {a: 1}`, `- [x, y]`).
fn flow_start(line: &str) -> Option<&str> {
    let open = |r: &&str| r.starts_with(['{', '[']);
    line.split_once(':').map(|(_, r)| r.trim()).filter(open).or_else(|| line.strip_prefix("- ").map(str::trim).filter(open))
}

/// The `(line, path, value)` scalars of a JSON document or a YAML flow collection
/// (`{min: TLSv1, protocols: [a, b]}`), under `prefix`. `first_line` is the line the text starts on.
fn flow_settings(text: &str, first_line: usize, prefix: &str) -> Vec<(usize, String, String)> {
    struct Flow {
        chars: Vec<char>,
        at: usize,
        line: usize,
        out: Vec<(usize, String, String)>,
    }
    impl Flow {
        fn flow_skip(&mut self) {
            while let Some(c) = self.chars.get(self.at).filter(|c| c.is_whitespace()) {
                self.line += usize::from(*c == '\n');
                self.at += 1;
            }
        }
        fn flow_quoted(&mut self) -> String {
            let q = self.chars[self.at];
            self.at += 1;
            let mut s = String::new();
            while let Some(&c) = self.chars.get(self.at) {
                self.at += 1;
                self.line += usize::from(c == '\n');
                if c == '\\' {
                    s.extend(self.chars.get(self.at));
                    self.at += 1;
                } else if c == q {
                    break;
                } else {
                    s.push(c);
                }
            }
            s
        }
        fn flow_key(&mut self) -> String {
            self.flow_skip();
            if self.chars.get(self.at).is_some_and(|c| matches!(c, '"' | '\'')) {
                return self.flow_quoted();
            }
            let mut s = String::new();
            while let Some(&c) = self.chars.get(self.at) {
                let colon = c == ':' && self.chars.get(self.at + 1).is_none_or(|n| n.is_whitespace());
                if colon || matches!(c, ',' | '}' | ']') {
                    break;
                }
                s.push(c);
                self.at += 1;
            }
            s.trim().to_string()
        }
        fn flow_value(&mut self, path: &str, depth: usize) {
            self.flow_skip();
            let Some(&c) = self.chars.get(self.at) else { return };
            let join = |key: &str| if path.is_empty() { key.to_string() } else { format!("{path}.{key}") };
            match c {
                '{' | '[' if depth < 32 => {
                    self.at += 1;
                    loop {
                        self.flow_skip();
                        match self.chars.get(self.at) {
                            None => return,
                            Some('}' | ']') => {
                                self.at += 1;
                                return;
                            }
                            Some(',') => self.at += 1,
                            Some(_) => {
                                let before = self.at;
                                if c == '{' {
                                    let key = self.flow_key();
                                    self.flow_skip();
                                    if self.chars.get(self.at) == Some(&':') {
                                        self.at += 1;
                                    }
                                    self.flow_value(&join(&key), depth + 1);
                                } else {
                                    self.flow_value(path, depth + 1);
                                }
                                if self.at == before {
                                    self.at += 1;
                                }
                            }
                        }
                    }
                }
                '"' | '\'' => {
                    let line = self.line;
                    let v = self.flow_quoted();
                    self.out.push((line, path.to_string(), v));
                }
                _ => {
                    let line = self.line;
                    let mut s = String::new();
                    while let Some(&c) = self.chars.get(self.at) {
                        if matches!(c, ',' | '}' | ']' | '\n') {
                            break;
                        }
                        s.push(c);
                        self.at += 1;
                    }
                    // `&anchor value`
                    let v = match s.trim().strip_prefix('&') {
                        Some(r) => r.split_once(' ').map_or("", |(_, v)| v),
                        None => s.trim(),
                    };
                    if !v.is_empty() {
                        self.out.push((line, path.to_string(), v.to_string()));
                    }
                }
            }
        }
    }
    let mut flow = Flow { chars: text.chars().collect(), at: 0, line: first_line, out: vec![] };
    flow.flow_value(prefix, 0);
    flow.out
}

/// The weak protocols and ciphers a setting's value names, when its key is about TLS or ciphers.
fn weak_setting(key: &str, value: &str) -> Vec<String> {
    let k = key.to_ascii_lowercase();
    let relevant = ["ssl", "tls", "cipher", "macs", "kex", "protocol", "algorithm"].iter().any(|w| k.contains(w));
    let denies = ["disabled", "blacklist", "blocklist", "deny", "exclude", "insecure", "legacy"].iter().any(|w| k.contains(w));
    if !relevant || denies || value.is_empty() {
        return vec![];
    }
    let tls_key = k.contains("tls") || k.contains("ssl");
    let mut reasons: Vec<String> = vec![];
    for item in value.split(|c: char| c.is_whitespace() || matches!(c, ',' | ':' | '"' | '\'' | '[' | ']' | ';')).filter(|t| !t.is_empty()) {
        if item.starts_with(['!', '-', '+']) && !item.starts_with("-----") {
            continue; // `!RC4`, `-SSLv3`: switched off
        }
        let words = tokens(item);
        let mut reason = weak_word(&words);
        // `..._CBC_SHA` names the MAC of a cipher suite; the suite is not a SHA-1 use as such
        if reason.as_deref() == Some("SHA-1") && words.len() > 2 && words.last().is_some_and(|w| w == "SHA") {
            reason = None;
        }
        if reason.is_none() && tls_key && matches!(item.trim_start_matches(['v', 'V']), "1.0" | "1.1" | "1") && (k.contains("version") || k.contains("protocol")) {
            reason = Some("TLS 1.0/1.1".into());
        }
        if reason.is_none() && words.iter().any(|w| matches!(w.as_str(), "NULL" | "ANULL" | "ENULL" | "EXPORT" | "EXP" | "ANON" | "ADH" | "AECDH" | "RC4" | "RC2")) {
            reason = Some(format!("weak cipher {item}"));
        }
        if let Some(r) = reason
            && !reasons.contains(&r)
        {
            reasons.push(r);
        }
    }
    reasons
}

/// `SslProtocols.Tls` and `SslProtocols.Tls11` (TLS 1.0 / 1.1), not `Tls12` or `Tls13`.
fn weak_tls_enum(compact: &str, prefix: &str) -> bool {
    compact.match_indices(prefix).any(|(i, _)| {
        let rest = &compact[i + prefix.len()..];
        rest.starts_with("11") || !rest.starts_with(|c: char| c.is_ascii_digit())
    })
}

/// `openssl genrsa 1024`, `-newkey rsa:1024`, `ssh-keygen -b 1024`, `keytool -keysize 1024`.
fn script_keys(path: &Path, text: &str) -> Vec<CryptoUse> {
    let mut out = vec![];
    for (i, line) in text.lines().enumerate() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let small = |n: &str| n.parse::<u32>().is_ok_and(|n| (256..2048).contains(&n));
        let mut bits = None;
        if line.contains("openssl") {
            bits = words.iter().find_map(|w| w.strip_prefix("rsa:").filter(|n| small(n))).or_else(|| (line.contains("genrsa")).then(|| words.last().filter(|n| small(n)).copied()).flatten());
        }
        if bits.is_none() && (line.contains("ssh-keygen") || line.contains("keytool")) {
            bits = words.windows(2).find(|w| matches!(w[0], "-b" | "-keysize") && small(w[1])).map(|w| w[1]);
        }
        if let Some(b) = bits {
            let mut u = file_use(path, i + 1, "key generation", "asymmetric", "RSA");
            u.weak = true;
            u.reason = format!("{b}-bit key");
            u.args = shorten(line);
            u.quantum = "vulnerable".into();
            out.push(u);
        }
    }
    out
}

fn shorten(s: &str) -> String {
    let s: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() > 80 { format!("{}...", s.chars().take(77).collect::<String>()) } else { s }
}

/// The top-level arguments of the call at `line`:`col` (1-based, the start of the call expression),
/// as written. None when the source does not look like `callee(..)` there.
fn call_args(src: &str, line: usize, col: usize, callee: &str) -> Option<Vec<String>> {
    let mut off = 0;
    for l in src.split_inclusive('\n').take(line.checked_sub(1)?) {
        off += l.len();
    }
    let tail = src.get(off + col.checked_sub(1)?..)?;
    let last = callee.rsplit('.').next()?;
    let mut rest = tail[tail.find(last)? + last.len()..].trim_start();
    if let Some(t) = rest.strip_prefix("::<") {
        rest = t.split_once('>')?.1.trim_start();
    }
    let rest = rest.strip_prefix('(')?;
    let (mut args, mut cur, mut depth, mut quote) = (vec![], String::new(), 0usize, None::<char>);
    let mut chars = rest.chars().take(4000);
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            cur.push(c);
            if c == '\\' {
                cur.extend(chars.next());
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => {
                quote = Some(c);
                cur.push(c);
            }
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '}' if depth == 0 => {
                if !cur.trim().is_empty() {
                    args.push(cur.trim().to_string());
                }
                return Some(args);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => args.push(std::mem::take(&mut cur).trim().to_string()),
            _ => cur.push(c),
        }
    }
    None
}

#[derive(Default)]
struct Detail {
    /// The first string literal argument (`"AES/ECB/PKCS5Padding"`, `'sha1'`).
    literal: Option<String>,
    /// Class-like names in the arguments (`AES`, `CBC` of `Cipher(algorithms.AES(k), modes.CBC(iv))`).
    classes: Vec<String>,
    weak: Option<String>,
}

/// What the arguments of a crypto call say about the algorithm: broken algorithms and modes,
/// small RSA / DH keys and Java's default ECB mode.
fn inspect(fam: u8, callee: &str, primitive: &str, args: &[String], resolve: &dyn Fn(&str) -> Option<String>) -> Detail {
    let mut d = Detail::default();
    let mut words: Vec<String> = vec![];
    let mut const_literal: Option<String> = None;
    let mut bits = None;
    for a in args {
        // string literals (their words count), then the identifiers left over
        let a = &fold_concat(&expand(a, resolve));
        let (mut other, mut chars) = (String::new(), a.chars());
        while let Some(c) = chars.next() {
            if matches!(c, '"' | '\'' | '`') {
                let mut lit = String::new();
                for x in chars.by_ref() {
                    if x == c {
                        break;
                    }
                    lit.push(x);
                }
                // `"SHA-" + mode` names only a part of the algorithm
                let partial = chars.as_str().trim_start().starts_with('+') || other.trim_end().ends_with('+') || other.ends_with('[');
                if !partial {
                    words.extend(tokens(&lit));
                    d.literal.get_or_insert(lit);
                }
                other.push(' ');
            } else {
                other.push(c);
            }
        }
        for ident in other.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.')).filter(|i| !i.is_empty()) {
            // a constant defined in the file stands for its value (`ALGO = "md5"`, `BITS = 1024`)
            let last_part = ident.rsplit('.').next().unwrap_or(ident);
            let called = a.contains(&format!("{last_part}("));
            if !ident.chars().next().is_some_and(|c| c.is_ascii_digit())
                && let Some(v) = if called { resolve(&format!("{last_part}()")) } else { resolve(last_part) }
            {
                if let Some(lit) = literal_text(&v) {
                    words.extend(tokens(&lit));
                    // a constant stands for the algorithm only when no literal names it
                    const_literal.get_or_insert(lit);
                    continue;
                }
                if let Ok(n) = v.parse::<u32>() {
                    if matches!(n, 512 | 768 | 1024 | 1536) && matches!(primitive, "asymmetric" | "key-exchange" | "key") {
                        bits = Some(n);
                    }
                    continue;
                }
            }
            if let Ok(n) = ident.parse::<u32>() {
                if matches!(n, 512 | 768 | 1024 | 1536) && matches!(primitive, "asymmetric" | "key-exchange" | "key") {
                    bits = Some(n);
                }
                continue;
            }
            let last = ident.rsplit('.').next().unwrap_or(ident);
            let upper_const = last.chars().any(char::is_uppercase) && !last.chars().any(char::is_lowercase);
            if last.chars().next().is_some_and(char::is_uppercase) && (ident.contains('.') || upper_const || last.chars().any(char::is_lowercase)) {
                if !upper_const && !d.classes.contains(&last.to_string()) {
                    d.classes.push(last.to_string());
                }
                words.extend(tokens(last));
            }
        }
    }
    if d.literal.is_none() {
        d.literal = const_literal;
    }
    d.weak = weak_word(&words).or_else(|| bits.map(|b| format!("{b}-bit key")));
    if d.weak.is_none()
        && fam == JAVA
        && callee.ends_with("Cipher.getInstance")
        && let Some(l) = &d.literal
        && !l.contains('/')
        && matches!(l.to_ascii_uppercase().as_str(), "AES" | "DES" | "DESEDE" | "BLOWFISH")
    {
        d.weak = Some("default ECB mode".into());
    }
    d
}

/// `secp192r1`, `prime192v1`, `sect163k1`: named curves below 224 bits.
fn weak_curve(t: &str) -> bool {
    let digits = |prefix: &str| t.strip_prefix(prefix).map(|r| r.chars().take_while(char::is_ascii_digit).collect::<String>());
    ["SECP", "PRIME", "SECT", "C2PNB", "BRAINPOOLP"].iter().any(|p| digits(p).and_then(|d| d.parse::<u32>().ok()).is_some_and(|n| (100..224).contains(&n)))
}

fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).map(str::to_ascii_uppercase).collect()
}

fn weak_word(words: &[String]) -> Option<String> {
    for (i, w) in words.iter().enumerate() {
        let hit = match w.as_str() {
            "MD2" | "MD4" | "MD5" | "RC2" | "RC4" | "ARC4" | "ARCFOUR" | "DES" | "DESEDE" | "3DES" | "TRIPLEDES" | "BLOWFISH" => w.clone(),
            "ECB" => "ECB mode".into(),
            "SHA1" => "SHA-1".into(),
            "SSLV2" | "SSLV3" | "SSLV2HELLO" => w.clone(),
            "TLSV1" if words.get(i + 1).is_none_or(|n| n == "0" || n == "1") => "TLS 1.0/1.1".into(),
            "VERSIONTLS10" | "VERSIONTLS11" | "VERSIONSSL30" => w.clone(),
            "TLS1" if words.get(i + 1).is_none_or(|n| n == "0" || n == "1") => "TLS 1.0/1.1".into(),
            c if weak_curve(c) => format!("EC curve {}", c.to_ascii_lowercase()),
            "SHA" if words.get(i + 1).is_none_or(|n| n == "1") => "SHA-1".into(),
            _ => continue,
        };
        return Some(hit);
    }
    None
}

fn prng_call() -> &'static Call {
    static PRNG: std::sync::OnceLock<Call> = std::sync::OnceLock::new();
    PRNG.get_or_init(|| Call { lang: tables::Lang::C, pattern: String::new(), primitive: "prng".into(), algorithm: "non-cryptographic PRNG".into(), weak: false, library: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_prefixes() {
        assert!(module_matches("crypto", "crypto"));
        assert!(module_matches("crypto", "crypto/sha256"));
        assert!(module_matches("javax.crypto", "javax.crypto.Cipher"));
        assert!(module_matches("ring", "ring::digest"));
        assert!(!module_matches("ring", "string"));
        assert!(!module_matches("crypto", "cryptography"));
    }

    #[test]
    fn major_library_calls_are_classified() {
        let cases = [
            (Language::Python, "import nacl.secret\nfrom cryptography.hazmat.primitives.kdf.hkdf import HKDF\ndef f():\n    nacl.secret.SecretBox(key)\n    HKDF(algorithm, 32, salt, info)\n", "nacl.secret.SecretBox", "XSalsa20-Poly1305"),
            (Language::JavaScript, "import forge from 'node-forge';\nfunction f() { forge.md.sha256.create(); forge.cipher.createCipher('AES-GCM', key); }\n", "forge.md.sha256.create", "SHA-256"),
            (Language::Rust, "use hkdf::Hkdf;\nfn f() { Hkdf::<Sha256>::new(None, key); Aes256GcmSiv::new(key); }\n", "Hkdf.new", "HKDF"),
            (Language::Go, "package p\nimport \"github.com/cloudflare/circl/kem/schemes\"\nfunc f() { schemes.ByName(\"Kyber512\") }\n", "schemes.ByName", "KEM (by name)"),
            (Language::Java, "import org.conscrypt.Conscrypt;\nclass A { void f() { Conscrypt.newProvider(); SCrypt.generate(p, s, 2, 8, 1, 32); } }\n", "Conscrypt.newProvider", "Conscrypt"),
            (Language::C, "#include <bearssl.h>\n#include <monocypher.h>\nvoid f() { br_sha256_init(c); crypto_aead_lock(c, m, k, n, p, s); }\n", "br_sha256_init", "SHA-256"),
        ];
        for (lang, src, name, algorithm) in cases {
            let cfgs = crate::lang::build_cfgs(lang, src).unwrap();
            let imports = crate::lang::imports(lang, src).unwrap();
            let uses = scan_file(lang, Path::new("example"), &imports, &cfgs);
            assert!(uses.iter().any(|u| u.kind == Kind::Call && u.name == name && u.algorithm == algorithm), "{lang:?}: {uses:?}");
        }
    }

    #[test]
    fn short_names_need_their_library_import() {
        let cases = [
            (Language::JavaScript, "import { sha256 } from '@noble/hashes/sha2.js';\nfunction f() { sha256(data); }\n", "function f() { sha256(data); }\n", "sha256", "noble"),
            (Language::Go, "package p\nimport \"github.com/tink-crypto/tink-go/v2/keyset\"\nfunc f() { keyset.NewHandle(template) }\n", "package p\nfunc f() { keyset.NewHandle(template) }\n", "keyset.NewHandle", "Tink"),
            (Language::Rust, "use aws_lc_rs::digest;\nfn f() { digest::digest(&digest::SHA256, data); }\n", "fn f() { digest::digest(&digest::SHA256, data); }\n", "digest.digest", "aws-lc-rs"),
            (Language::C, "#include <nettle/sha2.h>\nvoid f() { nettle_sha256_init(ctx); }\n", "void f() { nettle_sha256_init(ctx); }\n", "nettle_sha256_init", "Nettle"),
        ];
        for (lang, with_import, without_import, name, library) in cases {
            for (source, expected) in [(with_import, true), (without_import, false)] {
                let cfgs = crate::lang::build_cfgs(lang, source).unwrap();
                let imports = crate::lang::imports(lang, source).unwrap();
                let uses = scan_file(lang, Path::new("example"), &imports, &cfgs);
                assert_eq!(uses.iter().any(|u| u.kind == Kind::Call && u.name == name && u.library == library), expected, "{lang:?}: {uses:?}");
            }
        }
    }

    #[test]
    fn argument_details() {
        let src = "x = AES.new(key, AES.MODE_ECB)\nCipher.getInstance(\"AES/CBC/PKCS5Padding\")\n";
        let a = call_args(src, 1, 5, "AES.new").unwrap();
        assert_eq!(a, ["key", "AES.MODE_ECB"]);
        assert_eq!(inspect(PY, "AES.new", "cipher", &a, &|_| None).weak.as_deref(), Some("ECB mode"));
        let a = call_args(src, 2, 1, "Cipher.getInstance").unwrap();
        assert_eq!(inspect(JAVA, "Cipher.getInstance", "cipher", &a, &|_| None).literal.as_deref(), Some("AES/CBC/PKCS5Padding"));
        let a = vec!["\"AES\"".to_string()];
        assert_eq!(inspect(JAVA, "Cipher.getInstance", "cipher", &a, &|_| None).weak.as_deref(), Some("default ECB mode"));
        let a = vec!["data_des".to_string(), "self.des_key".to_string()];
        assert_eq!(inspect(PY, "hashlib.sha256", "hash", &a, &|_| None).weak, None);
        let a = vec!["\"SHA-256\"".to_string()];
        assert_eq!(inspect(JAVA, "MessageDigest.getInstance", "hash", &a, &|_| None).weak, None);
        let a = vec!["\"SHA\"".to_string()];
        assert_eq!(inspect(JAVA, "MessageDigest.getInstance", "hash", &a, &|_| None).weak.as_deref(), Some("SHA-1"));
    }

    #[test]
    fn manifests() {
        let cargo = "[dependencies]\nsha2 = \"0.10\"\nserde = \"1\"\naes-gcm = { version = \"0.10\" }\n";
        let d = scan_manifest(Path::new("Cargo.toml"), cargo);
        let libs: Vec<_> = d.iter().map(|d| (d.name.as_str(), d.library.as_str(), d.line)).collect();
        assert_eq!(libs, [("sha2", "RustCrypto sha2", 2), ("aes-gcm", "RustCrypto aes-gcm", 4)]);
        let d = scan_manifest(Path::new("requirements-dev.txt"), "# c\npycryptodome==3.1\nrequests>=2 ; x\n");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].library, "PyCryptodome");
        let d = scan_manifest(Path::new("go.mod"), "module m\nrequire (\n\tgolang.org/x/crypto v0.1.0\n\tgithub.com/x/y v1\n)\n");
        assert_eq!(d.len(), 1);
        let d = scan_manifest(Path::new("package.json"), r#"{"dependencies":{"crypto-js":"4","left-pad":"1"}}"#);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn alias_bindings() {
        let py = "import hashlib as h\nfrom hashlib import md5, sha256 as s2\nfrom hashlib import *\n";
        let imports = crate::lang::imports(Language::Python, py).unwrap();
        let b = bindings(PY, &imports, py);
        assert!(b.candidates("h.md5").contains(&"hashlib.md5".to_string()));
        assert!(b.candidates("md5").contains(&"hashlib.md5".to_string()));
        assert!(b.candidates("s2").contains(&"hashlib.sha256".to_string()));
        assert!(b.candidates("sha1").contains(&"hashlib.sha1".to_string()));
        let js = "const { createHash: ch } = require('crypto');\nimport * as cr from 'node:crypto';\nimport { createHash as ch2, randomBytes } from 'crypto';\n";
        let imports = crate::lang::imports(Language::JavaScript, js).unwrap();
        let b = bindings(JS, &imports, js);
        assert!(b.candidates("ch").contains(&"crypto.createHash".to_string()));
        assert!(b.candidates("cr.createHash").contains(&"node:crypto.createHash".to_string()));
        assert!(b.candidates("ch2").contains(&"crypto.createHash".to_string()));
        assert!(b.candidates("randomBytes").contains(&"crypto.randomBytes".to_string()));
        let go = "package p\nimport (\n  m \"crypto/md5\"\n  r \"github.com/x/y/v2\"\n)\n";
        let imports = crate::lang::imports(Language::Go, go).unwrap();
        let b = bindings(GO, &imports, go);
        assert!(b.candidates("m.Sum").contains(&"md5.Sum".to_string()));
        assert!(b.candidates("r.F").contains(&"y.F".to_string()));
        let rs = "use md5 as m;\nuse sha2::{Sha256 as S, Digest};\n";
        let imports = crate::lang::imports(Language::Rust, rs).unwrap();
        let b = bindings(RS, &imports, rs);
        assert!(b.candidates("m.compute").contains(&"md5.compute".to_string()));
        assert!(b.candidates("S.digest").contains(&"sha2.Sha256.digest".to_string()));
        let java = "import static java.security.MessageDigest.getInstance;\n";
        let imports = crate::lang::imports(Language::Java, java).unwrap();
        let b = bindings(JAVA, &imports, java);
        assert!(b.candidates("getInstance").contains(&"java.security.MessageDigest.getInstance".to_string()));
    }

    #[test]
    fn nested_use_groups_and_default_import_names() {
        let rs = "use std::{process::{Command as Cmd}, io::{self, Read}};\nuse ring::{digest, hmac::{self, Key}, aead::*};\n";
        let imports = crate::lang::imports(Language::Rust, rs).unwrap();
        let b = bindings(RS, &imports, rs);
        assert!(b.candidates("Cmd.new").contains(&"std.process.Command.new".to_string()));
        assert!(b.candidates("io.stdin").contains(&"std.io.stdin".to_string()));
        assert!(b.candidates("Read.read").contains(&"std.io.Read.read".to_string()));
        assert!(b.candidates("digest.digest").contains(&"ring.digest.digest".to_string()));
        assert!(b.candidates("hmac.sign").contains(&"ring.hmac.sign".to_string()));
        assert!(b.candidates("Key.new").contains(&"ring.hmac.Key.new".to_string()));
        assert!(b.candidates("seal").contains(&"ring.aead.seal".to_string()), "a wildcard inside a group");
        let js = "import CJ from 'crypto-js';\nimport { AES } from 'crypto-js';\nconst forge = require('node-forge');\n";
        let imports = crate::lang::imports(Language::JavaScript, js).unwrap();
        let b = bindings(JS, &imports, js);
        assert!(b.candidates("CJ.AES.encrypt").contains(&"CryptoJS.AES.encrypt".to_string()));
        assert!(b.candidates("AES.encrypt").contains(&"CryptoJS.AES.encrypt".to_string()));
        assert!(b.candidates("forge.md.sha1.create").contains(&"forge.md.sha1.create".to_string()));
    }

    #[test]
    fn call_patterns() {
        assert!(call_matches("EVP_*", "EVP_EncryptInit_ex"));
        assert!(!call_matches("EVP_*", "my.EVP"));
        assert!(call_matches("*.createHash", "crypto.createHash"));
        assert!(call_matches("hashlib.md5", "hashlib.md5"));
        assert!(!call_matches("MD5", "MD5_Init"));
    }
}
