//! File-level dependencies: which file imports / includes / calls into which.
//!
//! Imports are resolved to scanned files by path (there is no package
//! manager here): relative paths exactly, module names by matching the end of
//! the path. Anything that does not resolve is reported as external.

use super::callgraph::{self, CallGraph};
use super::manifest::Manifests;
use crate::lang::family;
use crate::ir::Cfg;
use crate::lang::{
    Language,
    common::{Import, ImportKind},
};
use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

pub struct DepFile<'a> {
    pub path: &'a Path,
    pub lang: Language,
    pub imports: Vec<Import>,
    pub cfgs: &'a [Cfg],
}

#[derive(Default, Clone)]
pub struct DepEdge {
    /// `(line, module as written)` for each import that resolved to the target.
    pub imports: Vec<(usize, String)>,
    /// Number of call sites from the source file into the target file.
    pub calls: usize,
    /// A few `caller -> callee` pairs.
    pub examples: Vec<String>,
}

pub struct DepGraph {
    /// Node weight: the file (or directory, see [`DepGraph::by_dir`]).
    pub graph: DiGraph<PathBuf, DepEdge>,
    /// Modules that did not resolve to a scanned file -> files that use them.
    pub external: BTreeMap<String, BTreeSet<usize>>,
}

fn family(l: Language) -> u8 {
    l.family()
}

/// Lexically resolve `.` and `..`.
fn norm(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            c => out.push(c.as_os_str()),
        }
    }
    out
}

fn segments(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

struct Index<'a> {
    files: &'a [DepFile<'a>],
    by_path: HashMap<PathBuf, usize>,
    /// Path without extension, every suffix (`a/b/c`, `b/c`, `c`); `__init__` /
    /// `index` / `mod` stand for their directory.
    by_stem: HashMap<String, Vec<usize>>,
    /// Path with extension, every suffix.
    by_name: HashMap<String, Vec<usize>>,
    /// Directory of the file, every suffix.
    by_dir: HashMap<String, Vec<usize>>,
    /// Files in the same directory.
    by_parent: HashMap<PathBuf, Vec<usize>>,
    manifests: Manifests,
}

impl<'a> Index<'a> {
    fn new(files: &'a [DepFile<'a>]) -> Self {
        let mut ix = Self {
            files,
            by_path: HashMap::new(),
            by_stem: HashMap::new(),
            by_name: HashMap::new(),
            by_dir: HashMap::new(),
            by_parent: HashMap::new(),
            manifests: Manifests::discover(files.iter().map(|f| f.path)),
        };
        for (i, f) in files.iter().enumerate() {
            let p = norm(f.path);
            let segs = segments(&p);
            ix.by_path.insert(p.clone(), i);
            for k in 0..segs.len() {
                ix.by_name.entry(segs[k..].join("/")).or_default().push(i);
            }
            let stem = p.with_extension("");
            let mut s = segments(&stem);
            // only the name that stands for its directory in the file's language
            let dir_name = match family(f.lang) {
                0 => "__init__",
                1 => "index",
                2 => "mod",
                _ => "",
            };
            if s.last().is_some_and(|l| l == dir_name) {
                s.pop();
            }
            for k in 0..s.len() {
                ix.by_stem.entry(s[k..].join("/")).or_default().push(i);
            }
            ix.by_parent.entry(p.parent().unwrap_or(Path::new("")).to_path_buf()).or_default().push(i);
            let d = segments(p.parent().unwrap_or(Path::new("")));
            for k in 0..d.len() {
                ix.by_dir.entry(d[k..].join("/")).or_default().push(i);
            }
        }
        ix
    }

    fn same_family(&self, importer: usize, cand: usize) -> bool {
        family(self.files[importer].lang) == family(self.files[cand].lang)
    }

    /// Of several candidates keep the ones closest to the importer.
    fn nearest(&self, importer: usize, candidates: &[usize]) -> Vec<usize> {
        let mut c: Vec<usize> = candidates.iter().copied().filter(|&x| x != importer && self.same_family(importer, x)).collect();
        c.sort_unstable();
        c.dedup();
        let me = segments(self.files[importer].path.parent().unwrap_or(Path::new("")));
        let score = |x: usize| {
            let other = segments(self.files[x].path.parent().unwrap_or(Path::new("")));
            me.iter().zip(&other).take_while(|(a, b)| a == b).count()
        };
        let best = c.iter().map(|&x| score(x)).max().unwrap_or(0);
        c.retain(|&x| score(x) == best);
        c.truncate(3);
        c
    }

    fn file(&self, p: PathBuf, importer: usize) -> Option<usize> {
        self.by_path.get(&norm(&p)).copied().filter(|&x| x != importer)
    }

    fn resolve(&self, importer: usize, imp: &Import) -> Vec<usize> {
        let f = &self.files[importer];
        let dir = f.path.parent().unwrap_or(Path::new("")).to_path_buf();
        match family(f.lang) {
            family::PYTHON => self.python(importer, &dir, imp),
            family::JAVASCRIPT => self.javascript(importer, &dir, imp),
            family::RUST => self.rust(importer, imp),
            family::GO => self.go(importer, imp),
            family::JAVA => self.java(importer, imp),
            family::RUBY => self.ruby(importer, &dir, imp),
            family::PHP => self.php(importer, &dir, imp),
            // Swift modules are not files: the files of one directory see each other
            family::SWIFT => vec![],
            _ => self.c(importer, &dir, imp),
        }
    }

    fn python(&self, importer: usize, dir: &Path, imp: &Import) -> Vec<usize> {
        let dots = imp.module.chars().take_while(|&c| c == '.').count();
        let rest = imp.module[dots..].replace('.', "/");
        let mut out = vec![];
        let mut keys = vec![rest.clone()];
        keys.extend(imp.names.iter().filter(|n| *n != "*").map(|n| if rest.is_empty() { n.clone() } else { format!("{rest}/{n}") }));
        if dots > 0 {
            // relative: `.` is this package, `..` its parent
            let mut base = dir.to_path_buf();
            for _ in 1..dots {
                base.pop();
            }
            for k in keys.iter().filter(|k| !k.is_empty()) {
                for cand in [base.join(format!("{k}.py")), base.join(k).join("__init__.py")] {
                    out.extend(self.file(cand, importer));
                }
            }
            if rest.is_empty() {
                out.extend(self.file(base.join("__init__.py"), importer));
            }
            return out;
        }
        for k in keys.iter().filter(|k| !k.is_empty()) {
            // a configured source root (`src/`, `package-dir`, ..) names the file exactly
            let exact = self
                .manifests
                .py_roots
                .iter()
                .rev()
                .flat_map(|r| [r.join(format!("{k}.py")), r.join(k).join("__init__.py")])
                .find_map(|c| self.file(c, importer));
            if let Some(x) = exact {
                out.push(x);
            } else if let Some(v) = self.by_stem.get(k) {
                out.extend(self.nearest(importer, v));
            }
        }
        out
    }

    fn javascript(&self, importer: usize, dir: &Path, imp: &Import) -> Vec<usize> {
        let m = &imp.module;
        if !(m.starts_with("./") || m.starts_with("../") || m.starts_with('/') || m == "." || m == "..") {
            // a package, unless tsconfig `paths` / `baseUrl` or a workspace package map it into the project
            let ts = self.manifests.tsconfig(dir).into_iter().flat_map(|ts| ts.candidates(m)).find_map(|b| self.js_file(b, importer));
            return ts.or_else(|| self.js_package(importer, m)).into_iter().collect();
        }
        let base = if m.starts_with('/') { PathBuf::from(m) } else { dir.join(m) };
        self.js_file(base, importer).into_iter().collect()
    }

    /// `@scope/pkg/sub` -> a workspace package's file, through `exports` or `main`.
    fn js_package(&self, importer: usize, m: &str) -> Option<usize> {
        let segs: Vec<&str> = m.split('/').collect();
        let n = if m.starts_with('@') { 2 } else { 1 };
        if segs.len() < n {
            return None;
        }
        let pkg = self.manifests.js_packages.get(&segs[..n].join("/"))?;
        pkg.candidates(&segs[n..].join("/")).into_iter().find_map(|b| self.js_file(b, importer))
    }

    /// The file a JS / TS module path `base` stands for (extensions and `index` are optional).
    fn js_file(&self, base: PathBuf, importer: usize) -> Option<usize> {
        let exts = ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];
        let mut cands = vec![base.clone()];
        let s = base.to_string_lossy().into_owned();
        // TypeScript writes `./x.js` for `x.ts`
        if let Some(stem) = s.strip_suffix(".js").or_else(|| s.strip_suffix(".jsx")).or_else(|| s.strip_suffix(".mjs")) {
            cands.extend(["ts", "tsx", "mts"].iter().map(|e| PathBuf::from(format!("{stem}.{e}"))));
        }
        for e in exts {
            cands.push(PathBuf::from(format!("{s}.{e}")));
            cands.push(base.join(format!("index.{e}")));
        }
        cands.into_iter().find_map(|c| self.file(c, importer))
    }

    /// `require_relative 'x'` (a path from the file) and `require 'a/b'` (a path below a load path,
    /// matched by its end), with or without `.rb`.
    fn ruby(&self, importer: usize, dir: &Path, imp: &Import) -> Vec<usize> {
        let m = imp.module.trim_end_matches(".rb");
        if m.starts_with('.') {
            return self.file(dir.join(format!("{m}.rb")), importer).into_iter().collect();
        }
        self.by_stem.get(m).map(|v| self.nearest(importer, v)).unwrap_or_default()
    }

    /// `require 'lib/x.php'` (a path from the file, or below an include path, matched by its end) and
    /// `use App\Models\User` (the namespace as a path, matched by its end like a PSR-4 autoload).
    fn php(&self, importer: usize, dir: &Path, imp: &Import) -> Vec<usize> {
        let m = &imp.module;
        if m.ends_with(".php") || m.ends_with(".inc") || m.starts_with('.') {
            if m.starts_with('.') {
                return self.file(dir.join(m), importer).into_iter().collect();
            }
            return self.by_name.get(m.as_str()).map(|v| self.nearest(importer, v)).unwrap_or_default();
        }
        self.by_stem.get(m.as_str()).map(|v| self.nearest(importer, v)).unwrap_or_default()
    }

    fn java(&self, importer: usize, imp: &Import) -> Vec<usize> {
        let mut segs: Vec<&str> = imp.module.split('.').collect();
        if segs.last() == Some(&"*") {
            segs.pop();
            return self.by_dir.get(&segs.join("/")).map(|v| self.nearest(importer, v)).unwrap_or_default();
        }
        // `a.b.C`, or `a.b.C.member` for static / nested imports: drop trailing parts
        while segs.len() >= 2 {
            if let Some(v) = self.by_stem.get(&segs.join("/")) {
                return self.nearest(importer, v);
            }
            segs.pop();
        }
        vec![]
    }

    /// Importable files of a Go package: another directory, not a test file, same language family.
    fn go_candidates(&self, importer: usize, files: impl Iterator<Item = usize>, other_dir: impl Fn(usize) -> bool) -> Vec<usize> {
        files
            .filter(|&x| other_dir(x))
            .filter(|&x| !self.files[x].path.to_string_lossy().ends_with("_test.go"))
            .filter(|&x| self.same_family(importer, x))
            .collect()
    }

    fn go(&self, importer: usize, imp: &Import) -> Vec<usize> {
        let mods = &self.manifests.go_modules;
        if !mods.is_empty() {
            // go.mod known: an import is in the project iff it starts with a module path
            let best = mods
                .iter()
                .filter(|(m, _)| imp.module == *m || imp.module.strip_prefix(m.as_str()).is_some_and(|r| r.starts_with('/')))
                .max_by_key(|(m, _)| m.len());
            let Some((m, dir)) = best else { return vec![] };
            let target = norm(&dir.join(imp.module[m.len()..].trim_start_matches('/')));
            let importer_dir = self.files[importer].path.parent().map(norm);
            return self.go_candidates(importer, self.by_parent.get(&target).into_iter().flatten().copied(), |x| {
                self.files[x].path.parent().map(norm) != importer_dir
            });
        }
        let mut segs: Vec<&str> = imp.module.split('/').collect();
        // `github.com/me/app/pkg/util` -> the scanned directory `.../pkg/util`
        while !segs.is_empty() {
            if let Some(v) = self.by_dir.get(&segs.join("/")) {
                let importer_dir = self.files[importer].path.parent();
                let c = self.go_candidates(importer, v.iter().copied(), |x| self.files[x].path.parent() != importer_dir);
                if !c.is_empty() {
                    return c;
                }
            }
            segs.remove(0);
            if segs.len() < 2 && !imp.module.contains('/') {
                break;
            }
        }
        vec![]
    }

    fn c(&self, importer: usize, dir: &Path, imp: &Import) -> Vec<usize> {
        if imp.kind == ImportKind::LocalInclude
            && let Some(x) = self.file(dir.join(&imp.module), importer)
        {
            return vec![x];
        }
        self.by_name.get(&imp.module).map(|v| self.nearest(importer, v)).unwrap_or_default()
    }

    /// Directory a Rust file's child modules live in.
    fn module_dir(&self, importer: usize) -> PathBuf {
        let p = self.files[importer].path;
        if self.is_rust_root(p) {
            return p.parent().unwrap_or(Path::new("")).to_path_buf();
        }
        let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let dir = p.parent().unwrap_or(Path::new("")).to_path_buf();
        if matches!(stem.as_str(), "lib" | "main" | "mod") { dir } else { dir.join(stem) }
    }

    fn is_rust_root(&self, p: &Path) -> bool {
        let p = norm(p);
        self.manifests.rust_roots.iter().any(|r| norm(r) == p)
    }

    /// The root file (`[lib] path`, `[[bin]] path`, `lib.rs`, `main.rs`) of the crate the file is in.
    fn crate_root_file(&self, importer: usize) -> Option<PathBuf> {
        let p = norm(self.files[importer].path);
        let dir = p.parent()?.to_path_buf();
        self.manifests
            .rust_roots
            .iter()
            .map(|r| norm(r))
            .filter(|r| self.by_path.contains_key(r) && r.parent().is_some_and(|rd| dir.starts_with(rd)))
            .max_by_key(|r| r.components().count())
    }

    fn crate_root(&self, importer: usize) -> PathBuf {
        if let Some(r) = self.crate_root_file(importer) {
            return r.parent().unwrap_or(Path::new("")).to_path_buf();
        }
        let mut d = self.files[importer].path.parent().unwrap_or(Path::new("")).to_path_buf();
        loop {
            if self.by_path.contains_key(&norm(&d.join("lib.rs"))) || self.by_path.contains_key(&norm(&d.join("main.rs"))) {
                return d;
            }
            if !d.pop() {
                return self.files[importer].path.parent().unwrap_or(Path::new("")).to_path_buf();
            }
        }
    }

    fn rust(&self, importer: usize, imp: &Import) -> Vec<usize> {
        let segs: Vec<&str> = imp.module.split("::").filter(|s| !s.is_empty()).collect();
        let mut crate_hop = false;
        let (base, rest): (PathBuf, Vec<&str>) = if imp.kind == ImportKind::ModDecl {
            (self.module_dir(importer), segs.clone())
        } else {
            match segs.first().copied() {
                Some("crate") => (self.crate_root(importer), segs[1..].to_vec()),
                Some("self") => (self.module_dir(importer), segs[1..].to_vec()),
                Some("super") => {
                    let mut b = self.module_dir(importer);
                    let mut r = &segs[..];
                    while r.first() == Some(&"super") {
                        b.pop();
                        r = &r[1..];
                    }
                    (b, r.to_vec())
                }
                // 2015-style / local module: `use foo::bar` where `foo` is a module of this crate
                Some(first) => {
                    let root = self.crate_root(importer);
                    let is_local = self.by_path.contains_key(&norm(&root.join(format!("{first}.rs"))))
                        || self.by_path.contains_key(&norm(&root.join(first).join("mod.rs")));
                    if !is_local {
                        // another crate of the project (`use mylib::x`), or std / an external crate
                        let Some(lib) = self.manifests.crates.get(first) else { return vec![] };
                        crate_hop = true;
                        (lib.parent().unwrap_or(Path::new("")).to_path_buf(), segs[1..].to_vec())
                    } else {
                        (root, segs.clone())
                    }
                }
                None => return vec![],
            }
        };
        // `use a::{b, c}`: b and c may themselves be modules
        let mut tails: Vec<Vec<&str>> = vec![rest.clone()];
        for n in imp.names.iter().filter(|n| *n != "*") {
            let mut r = rest.clone();
            r.push(n);
            tails.push(r);
        }
        let mut out = vec![];
        for mut r in tails {
            // longest prefix that is a file
            while !r.is_empty() {
                let p = base.join(r.join("/"));
                let found = [PathBuf::from(format!("{}.rs", p.display())), p.join("mod.rs")]
                    .into_iter()
                    .find_map(|c| self.file(c, importer));
                if let Some(x) = found {
                    out.push(x);
                    break;
                }
                r.pop();
            }
        }
        if out.is_empty() && (rest.is_empty() || crate_hop) {
            // `use crate::Item;` -> the crate root file
            if crate_hop && let Some(r) = self.manifests.crates.get(segs[0]) {
                out.extend(self.file(r.clone(), importer));
            } else if let Some(r) = self.crate_root_file(importer) {
                out.extend(self.file(r, importer));
            }
            for root in ["lib.rs", "main.rs"] {
                out.extend(self.file(base.join(root), importer));
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// For each file, the files whose functions it can call without it being a
/// guess: itself, what it imports (and what those import, to see through
/// re-exporting `__init__` / `index` / `mod` files), its own package in Go and
/// Java, and the source file standing behind an included C header.
pub fn visibility(files: &[DepFile]) -> Vec<HashSet<usize>> {
    visibility_in(&Index::new(files), files)
}

fn visibility_in(ix: &Index, files: &[DepFile]) -> Vec<HashSet<usize>> {
    let direct: Vec<HashSet<usize>> =
        files.iter().enumerate().map(|(i, f)| f.imports.iter().flat_map(|imp| ix.resolve(i, imp)).collect()).collect();
    (0..files.len())
        .map(|i| {
            let mut v: HashSet<usize> = HashSet::from([i]);
            v.extend(&direct[i]);
            for &j in &direct[i] {
                v.extend(&direct[j]);
            }
            let parent = norm(files[i].path).parent().unwrap_or(Path::new("")).to_path_buf();
            match family(files[i].lang) {
                family::GO | family::JAVA | family::SWIFT => v.extend(ix.by_parent.get(&parent).into_iter().flatten()),
                5 => {
                    // util.h stands for util.c next to it
                    for j in v.clone() {
                        let p = norm(files[j].path);
                        let (dir, stem) = (p.parent().map(Path::to_path_buf), p.file_stem().map(|s| s.to_os_string()));
                        for &k in dir.and_then(|d| ix.by_parent.get(&d)).into_iter().flatten() {
                            if norm(files[k].path).file_stem().map(|s| s.to_os_string()) == stem {
                                v.insert(k);
                            }
                        }
                    }
                }
                _ => {}
            }
            v.retain(|&j| family(files[j].lang) == family(files[i].lang));
            v
        })
        .collect()
}

pub fn build(files: &[DepFile]) -> DepGraph {
    resolve(files).deps
}

/// Everything the project's imports and calls resolve to, from one pass: the file dependencies,
/// the call graph they select with (`visible`), and what each of them needs of the other.
pub struct Resolved {
    pub deps: DepGraph,
    /// The call graph with import-based visibility, which the call counts of `deps` come from.
    pub calls: CallGraph,
    /// Per file, the files whose functions it can call without it being a guess.
    pub visible: Vec<HashSet<usize>>,
}

/// Resolve imports and calls once (the file index is built once, the call graph once).
pub fn resolve(files: &[DepFile]) -> Resolved {
    let ix = Index::new(files);
    let visible = visibility_in(&ix, files);
    let refs: Vec<(&Path, Language, &[Cfg])> = files.iter().map(|f| (f.path, f.lang, f.cfgs)).collect();
    let calls = callgraph::build_refs(&refs, Some(visible.clone()));
    let deps = build_from(&ix, files, &calls);
    Resolved { deps, calls, visible }
}

fn build_from(ix: &Index, files: &[DepFile], cg: &CallGraph) -> DepGraph {
    let mut graph: DiGraph<PathBuf, DepEdge> = DiGraph::new();
    for f in files {
        graph.add_node(f.path.to_path_buf());
    }
    let mut external: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    let mut edges: HashMap<(usize, usize), DepEdge> = HashMap::new();

    for (i, f) in files.iter().enumerate() {
        for imp in &f.imports {
            let targets = ix.resolve(i, imp);
            if targets.is_empty() {
                external.entry(imp.module.clone()).or_default().insert(i);
            }
            for t in targets {
                edges.entry((i, t)).or_default().imports.push((imp.line, imp.module.clone()));
            }
        }
    }

    // calls that cross files, from the call graph
    let by_file: HashMap<&Path, usize> = files.iter().enumerate().map(|(i, f)| (f.path, i)).collect();
    for e in cg.graph.edge_indices() {
        let (a, b) = cg.graph.edge_endpoints(e).expect("edge");
        let (fa, fb) = (&cg.graph[a], &cg.graph[b]);
        let (Some(&ia), Some(&ib)) = (by_file.get(fa.file.as_path()), by_file.get(fb.file.as_path())) else { continue };
        if ia == ib {
            continue;
        }
        let w = &cg.graph[e];
        let edge = edges.entry((ia, ib)).or_default();
        edge.calls += w.sites;
        if edge.examples.len() < 3 {
            edge.examples.push(format!("{} → {}", fa.name, fb.name));
        }
    }

    let mut sorted: Vec<_> = edges.into_iter().collect();
    sorted.sort_by_key(|((a, b), _)| (*a, *b));
    for ((a, b), mut e) in sorted {
        e.imports.sort();
        e.imports.dedup();
        graph.add_edge(NodeIndex::new(a), NodeIndex::new(b), e);
    }
    DepGraph { graph, external }
}

impl DepGraph {
    /// Files that depend on each other (directly or not).
    pub fn cycles(&self) -> Vec<Vec<NodeIndex>> {
        let mut v: Vec<Vec<NodeIndex>> = tarjan_scc(&self.graph).into_iter().filter(|c| c.len() > 1).collect();
        for c in &mut v {
            c.sort();
        }
        v.sort();
        v
    }

    /// Collapse files into their directories; edges within a directory vanish.
    pub fn by_dir(&self) -> DepGraph {
        let mut graph: DiGraph<PathBuf, DepEdge> = DiGraph::new();
        let mut ids: HashMap<PathBuf, NodeIndex> = HashMap::new();
        let dir_of = |p: &Path| p.parent().map(Path::to_path_buf).filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| PathBuf::from("."));
        let mut node = |g: &mut DiGraph<PathBuf, DepEdge>, d: PathBuf| *ids.entry(d.clone()).or_insert_with(|| g.add_node(d));
        let mapping: Vec<NodeIndex> = self.graph.node_weights().map(|p| node(&mut graph, dir_of(p))).collect();
        let mut merged: BTreeMap<(usize, usize), DepEdge> = BTreeMap::new();
        for e in self.graph.edge_indices() {
            let (a, b) = self.graph.edge_endpoints(e).expect("edge");
            let (da, db) = (mapping[a.index()], mapping[b.index()]);
            if da == db {
                continue;
            }
            let w = &self.graph[e];
            let m = merged.entry((da.index(), db.index())).or_default();
            m.imports.extend(w.imports.iter().cloned());
            m.calls += w.calls;
            if m.examples.len() < 3 {
                m.examples.extend(w.examples.iter().take(3 - m.examples.len()).cloned());
            }
        }
        for ((a, b), e) in merged {
            graph.add_edge(NodeIndex::new(a), NodeIndex::new(b), e);
        }
        let mut external: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        for (m, users) in &self.external {
            for &u in users {
                external.entry(m.clone()).or_default().insert(mapping[u].index());
            }
        }
        DepGraph { graph, external }
    }
}
