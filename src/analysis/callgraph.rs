//! Which function calls which: a project-wide call graph built from the
//! per-function call facts. Calls use inferred types where available; ambiguous
//! names are linked only when few functions share them.

use super::values::Values;
mod keys;
use keys::KeyFacts;
use crate::ir::{Cfg, Flow};
use crate::lang::Language;
use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A name shared by more functions than this is too ambiguous to link.
const MAX_AMBIGUITY: usize = 3;

pub struct FnNode {
    pub file: PathBuf,
    pub name: String,
    pub line: usize,
}

/// One call expression that links a caller to a callee.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// 1-based position of the call expression in the caller's file.
    pub line: usize,
    pub col: usize,
    /// The callee as the call writes it (normalized), which is not always the callee's own name.
    pub callee: String,
    /// The callee is handed over or called through a variable, not called by name.
    pub callback: bool,
    /// The callee is really called here, through a variable or container, so the arguments
    /// and the result flow; false where it is only handed over (`register(handler)`).
    pub invoked: bool,
    /// The callee follows from a declared or inferred class, a held function or a qualified name;
    /// false where only the method name matched an arbitrary object (a guess).
    pub exact: bool,
}

#[derive(Default)]
pub struct CallEdge {
    /// Every call expression behind this edge, in the caller's source order.
    pub call_sites: Vec<CallSite>,
    /// How many call sites.
    pub sites: usize,
    /// First call site (line in the caller's file).
    pub line: usize,
    /// Every call site, sorted.
    pub lines: Vec<usize>,
    /// The sites where the function is not called by name but handed over or
    /// called through a variable (`register(handler)`, `f = handler; f()`).
    pub callback_lines: Vec<usize>,
}

/// The class a method belongs to: its qualified name without the last segment.
pub fn class_of(name: &str) -> Option<String> {
    let q = dotted(name);
    let (c, _) = q.rsplit_once('.')?;
    (!c.is_empty()).then(|| c.to_string())
}

pub struct CallGraph {
    pub graph: DiGraph<FnNode, CallEdge>,
    /// Calls that did not resolve to a scanned function (libraries, builtins).
    pub external: HashMap<String, usize>,
}

/// Function names use `::` (Rust, C++) or `.`; compare them as dotted paths.
fn dotted(name: &str) -> String {
    name.replace("::", ".")
}

/// The part after the last `.` (the method of `recv.method`).
pub fn last_segment(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

pub use crate::lang::common::simple_name;

/// The functions a call may refer to. `exact` is false when the match is only
/// a method name on an unknown receiver, which may well be a library method.
#[derive(Clone)]
pub struct Resolved {
    pub ids: Vec<usize>,
    pub exact: bool,
}

/// Resolves a call's normalized callee to the functions it may refer to.
/// Functions are identified by their position in the flattened
/// `files x cfgs` order, which is also their `NodeIndex` in [`CallGraph`].
pub struct Resolver {
    /// dotted suffix of a qualified name -> functions (`K.step`, `step`, ...)
    by_suffix: HashMap<String, Vec<usize>>,
    by_exact: HashMap<String, Vec<usize>>,
    by_simple: HashMap<String, Vec<usize>>,
    file_of: Vec<usize>,
    family_of: Vec<u8>,
    /// Language family of each file, by file index.
    file_family: HashMap<usize, u8>,
    /// Per file, the files it can see (see `deps::visibility`); used to choose
    /// between several functions with the same name.
    visible: Option<Vec<HashSet<usize>>>,
    /// simple class name -> qualified (dotted) classes
    class_by_simple: HashMap<String, Vec<String>>,
    parents: HashMap<String, Vec<String>>,
    children: HashMap<String, Vec<String>>,
}

impl Resolver {
    /// `fns` yields `(file index, language family, function name)` in function-id order.
    pub fn new<'a>(fns: impl Iterator<Item = (usize, u8, &'a str)>) -> Self {
        let mut r = Self {
            by_suffix: HashMap::new(),
            by_exact: HashMap::new(),
            by_simple: HashMap::new(),
            file_of: vec![],
            family_of: vec![],
            file_family: HashMap::new(),
            visible: None,
            class_by_simple: HashMap::new(),
            parents: HashMap::new(),
            children: HashMap::new(),
        };
        for (id, (file, fam, name)) in fns.enumerate() {
            r.file_of.push(file);
            r.family_of.push(fam);
            r.file_family.insert(file, fam);
            let q = dotted(name);
            let segs: Vec<&str> = q.split('.').collect();
            for i in 0..segs.len() {
                r.by_suffix.entry(segs[i..].join(".")).or_default().push(id);
            }
            r.by_simple.entry(last_segment(&q).to_string()).or_default().push(id);
            r.by_exact.entry(q).or_default().push(id);
        }
        r
    }

    /// Prefer, among same-named functions, the ones in files the caller can see.
    pub fn with_visibility(mut self, visible: Option<Vec<HashSet<usize>>>) -> Self {
        self.visible = visible;
        self
    }

    /// Teach the resolver the class hierarchy: `(function name, bases of its class)` for every function.
    pub fn with_hierarchy<'a>(mut self, fns: impl Iterator<Item = (&'a str, &'a [String])>) -> Self {
        let fns: Vec<(&str, &[String])> = fns.collect();
        for (name, _) in &fns {
            if let Some(c) = class_of(name) {
                let v = self.class_by_simple.entry(last_segment(&c).to_string()).or_default();
                if !v.contains(&c) {
                    v.push(c);
                }
            }
        }
        for (name, bases) in &fns {
            let Some(c) = class_of(name) else { continue };
            for b in bases.iter() {
                for base in self.class_by_simple.get(last_segment(&dotted(b))).cloned().unwrap_or_default() {
                    if base == c {
                        continue;
                    }
                    let p = self.parents.entry(c.clone()).or_default();
                    if !p.contains(&base) {
                        p.push(base.clone());
                        self.children.entry(base).or_default().push(c.clone());
                    }
                }
            }
        }
        self
    }

    /// Add declared Go structs even if they define no methods of their own.
    pub fn with_class_decls<'a>(mut self, decls: impl Iterator<Item = &'a (String, Vec<String>)>) -> Self {
        let decls: Vec<_> = decls.collect();
        for (name, _) in &decls {
            let classes = self.class_by_simple.entry(simple_name(name).to_string()).or_default();
            if !classes.contains(name) {
                classes.push(name.clone());
            }
        }
        for (name, bases) in decls {
            for base in bases {
                for parent in self.class_by_simple.get(simple_name(base)).cloned().unwrap_or_default() {
                    if parent == *name {
                        continue;
                    }
                    let parents = self.parents.entry(name.clone()).or_default();
                    if !parents.contains(&parent) {
                        parents.push(parent.clone());
                        self.children.entry(parent).or_default().push(name.clone());
                    }
                }
            }
        }
        self
    }

    /// The class a declared type names, if exactly one scanned class has that name.
    pub fn class_named(&self, simple: &str) -> Option<&str> {
        match self.class_by_simple.get(simple)?.as_slice() {
            [c] => Some(c),
            _ => None,
        }
    }

    /// The classes of the caller's language that define every one of `methods`:
    /// the types that structurally satisfy an interface used through those methods.
    pub fn implementers(&self, methods: &std::collections::BTreeSet<String>, caller_file: usize) -> Vec<String> {
        let mut out = vec![];
        for classes in self.class_by_simple.values() {
            for c in classes {
                // defined by the type itself or promoted from what it embeds / extends
                let has = |m: &String| !self.method_of(c, m, caller_file, false).ids.is_empty();
                if !methods.is_empty() && methods.iter().all(has) {
                    out.push(c.clone());
                }
            }
        }
        out.sort();
        out
    }

    /// The direct bases of `class`.
    pub fn bases_of(&self, class: &str) -> &[String] {
        self.parents.get(&dotted(class)).map_or(&[], |v| v.as_slice())
    }

    /// A method of a known class, e.g. `Req.run` for `r.run()` where `r` is a `Req`:
    /// the class's own method or the one it inherits, and the overrides in subclasses
    /// (the object may be any of them).
    pub fn resolve_method(&self, class: &str, method: &str, caller_file: usize) -> Resolved {
        self.method_of(class, method, caller_file, true)
    }

    /// `super.method()`: what `class` inherits, without overrides below it.
    pub fn resolve_inherited(&self, class: &str, method: &str, caller_file: usize) -> Resolved {
        self.method_of(class, method, caller_file, false)
    }

    fn method_of(&self, class: &str, method: &str, caller_file: usize, overrides: bool) -> Resolved {
        let fam = self.file_family.get(&caller_file).copied();
        let find = |c: &str| -> Vec<usize> {
            self.by_exact
                .get(&format!("{c}.{method}"))
                .into_iter()
                .flatten()
                .copied()
                .filter(|&n| fam.is_none_or(|f| self.family_of[n] == f))
                .collect()
        };
        let class = dotted(class);
        let mut ids = vec![];
        // up: the nearest definition on each path through the bases
        let mut seen: HashSet<String> = HashSet::new();
        let mut queue = vec![class.clone()];
        while let Some(c) = queue.pop() {
            if !seen.insert(c.clone()) {
                continue;
            }
            let own = find(&c);
            if own.is_empty() {
                queue.extend(self.parents.get(&c).cloned().unwrap_or_default());
            } else {
                ids.extend(own);
            }
        }
        // down: overrides in every subclass
        if overrides {
            let mut seen: HashSet<String> = HashSet::from([class.clone()]);
            let mut queue = vec![class];
            while let Some(c) = queue.pop() {
                for d in self.children.get(&c).into_iter().flatten() {
                    if seen.insert(d.clone()) {
                        ids.extend(find(d));
                        queue.push(d.clone());
                    }
                }
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Resolved { ids, exact: true }
    }

    /// The free function a bare name refers to (not a method), if there is exactly one.
    pub fn free_function(&self, name: &str, caller_file: usize) -> Option<usize> {
        if name.contains('.') {
            return None;
        }
        let fam = self.file_family.get(&caller_file).copied();
        let mut c: Vec<usize> =
            self.by_exact.get(name)?.iter().copied().filter(|&n| fam.is_none_or(|f| self.family_of[n] == f)).collect();
        if c.len() > 1 {
            c.retain(|&n| self.file_of[n] == caller_file || self.visible.as_ref().and_then(|v| v.get(caller_file)).is_some_and(|s| s.contains(&self.file_of[n])));
        }
        (c.len() == 1).then(|| c[0])
    }

    pub fn resolve(&self, callee: &str, caller_file: usize) -> Resolved {
        // `self.step()` / `this.step()` call a method of the same class: treat as `step`
        let callee = ["self.", "this.", "cls.", "super."]
            .iter()
            .find_map(|p| callee.strip_prefix(p))
            .filter(|rest| !rest.contains('.'))
            .unwrap_or(callee);
        let fam = self.file_family.get(&caller_file).copied();
        let same = |v: &Vec<usize>| -> Vec<usize> {
            v.iter().copied().filter(|&n| fam.is_none_or(|f| self.family_of[n] == f)).collect()
        };
        // 1. functions whose qualified name ends with the callee (`K.step` for `step`)
        let mut c: Vec<usize> = self.by_suffix.get(callee).map(same).unwrap_or_default();
        // a method called on an arbitrary object only matches by name: a guess
        let mut exact = true;
        // 2. the callee is qualified more than the function (`pkg.helper` for `helper`)
        if c.is_empty() {
            let mut rest = callee;
            while let Some((_, tail)) = rest.split_once('.') {
                rest = tail;
                if let Some(v) = self.by_exact.get(rest).map(same).filter(|v| !v.is_empty()) {
                    c = v;
                    break;
                }
            }
        }
        // 3. a method on some object: match the method name alone
        if c.is_empty() && callee.contains('.') {
            c = self.by_simple.get(last_segment(callee)).map(same).unwrap_or_default();
            exact = false;
        }
        // 4. constructing an object by its class name: `Job(..)` -> `Job.__init__`,
        //    `new Svc(..)` -> `Svc.Svc`, `new S()` -> `S.constructor`
        if c.is_empty() {
            let l = constructed_class(callee);
            for ctor in CONSTRUCTORS.iter().map(|c| format!("{l}.{c}")).chain([format!("{l}.{l}")]) {
                if let Some(v) = self.by_suffix.get(&ctor).map(same) {
                    c.extend(v);
                }
            }
            // `Job.new(..)` names the class, so the constructor it finds is not a guess
            exact |= !c.is_empty() && l != last_segment(callee);
        }
        if c.len() > 1 {
            let local: Vec<usize> = c.iter().copied().filter(|&n| self.file_of[n] == caller_file).collect();
            if !local.is_empty() {
                c = local;
            } else if let Some(seen) = self.visible.as_ref().and_then(|v| v.get(caller_file)) {
                // several candidates: the imported ones win; if none is imported, keep all
                let visible: Vec<usize> = c.iter().copied().filter(|&n| seen.contains(&self.file_of[n])).collect();
                if !visible.is_empty() {
                    c = visible;
                }
            }
        }
        if c.len() > MAX_AMBIGUITY {
            c.clear();
        }
        c.sort_unstable();
        c.dedup();
        Resolved { ids: c, exact }
    }
}

/// The names a language gives its constructors (Python, JS / TS, Ruby, PHP, Swift); Java-like
/// languages name them after the class.
const CONSTRUCTORS: &[&str] = &["__init__", "constructor", "initialize", "__construct", "init"];

/// Is `simple` the name of a constructor method (or the `new` of `X.new`)?
pub(crate) fn is_constructor_name(simple: &str) -> bool {
    simple == "new" || CONSTRUCTORS.contains(&simple)
}

/// The class a constructor call names: `Job` for `Job(..)` and for Ruby's `Job.new(..)`.
pub(crate) fn constructed_class(callee: &str) -> &str {
    let mut parts = callee.rsplit(['.', ':']).filter(|p| !p.is_empty());
    match (parts.next(), parts.next()) {
        (Some("new"), Some(class)) => class,
        (Some(last), _) => last,
        _ => callee,
    }
}

/// The class a call creates or returns: a constructor, or a function with a declared return class.
pub(crate) fn call_class(resolver: &Resolver, fns: &[(usize, Language, &Cfg)], c: &crate::ir::CallFlow, fi: usize) -> Option<String> {
    let r = resolver.resolve(&c.callee, fi);
    match r.ids.as_slice() {
        [id] if r.exact => {
            let f = fns[*id].2;
            let simple = simple_name(&f.name);
            let class = class_of(&f.name);
            if let Some(cl) = class.as_ref().filter(|cl| is_constructor_name(simple) || simple == simple_name(cl)) {
                return Some(cl.clone());
            }
            f.ret_type.as_deref().and_then(|t| resolver.class_named(t)).map(str::to_string)
        }
        [] => resolver.class_named(constructed_class(&c.callee)).map(str::to_string),
        _ => None,
    }
}

/// The classes of variables and fields, found without running the code: from
/// declared parameter types, constructors (`r = Req()`), return types
/// (`r = make()`), copies of typed variables and `self.f = <typed value>` in
/// methods. A name that gets two different classes is dropped.
pub(crate) struct Types {
    /// Per function: variable -> class.
    pub(crate) locals: Vec<HashMap<String, String>>,
    /// `(class, field)` -> class of the value stored in it.
    fields: HashMap<(String, String), String>,
    /// Per function: parameters declared with a type that is not a scanned class.
    declared: Vec<HashMap<String, String>>,
    /// Go: interface type -> the methods called on values of that type.
    iface_use: HashMap<String, std::collections::BTreeSet<String>>,
    /// Go: `(class, field)` -> the interface the field is declared with.
    field_iface: HashMap<(String, String), String>,
    /// Per function, for the variables that are given different classes: the class each has
    /// before a statement `(block, index)`, where the flow decides (`x = A(); x.run(); x = B(); x.run()`).
    flow: Vec<ClassFlow>,
}

type ClassFlow = HashMap<(usize, usize), Vec<(String, String)>>;

/// `map` as sorted entries, so that it can be hashed or compared as text.
fn sorted_entries<K: Ord + std::fmt::Debug, V: std::fmt::Debug>(map: &HashMap<K, V>) -> String {
    let mut v: Vec<(&K, &V)> = map.iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    format!("{v:?}")
}

impl Types {
    /// What is known about function `f`'s variables, as text: equal text, equal results of the
    /// analysis (for everything that depends on classes of variables).
    pub(crate) fn fingerprint(&self, f: usize) -> String {
        format!("{}|{}|{}", sorted_entries(&self.locals[f]), sorted_entries(&self.declared[f]), sorted_entries(&self.flow[f]))
    }

    /// What is known about classes (field types, Go interfaces), as text.
    pub(crate) fn global_fingerprint(&self) -> String {
        format!("{}|{}|{}", sorted_entries(&self.fields), sorted_entries(&self.iface_use), sorted_entries(&self.field_iface))
    }

    pub(crate) fn infer(fns: &[(usize, Language, &Cfg)], resolver: &Resolver) -> Self {
        let cfg_of = |n: usize| fns[n].2;
        let class_of_call = |c: &crate::ir::CallFlow, fi: usize| call_class(resolver, fns, c, fi);
        let mut locals: Vec<HashMap<String, String>> = vec![];
        let mut declared: Vec<HashMap<String, String>> = vec![];
        let mut flow: Vec<ClassFlow> = vec![];
        for (n, &(fi, _, _)) in fns.iter().enumerate() {
            let cfg = cfg_of(n);
            let mut known: HashMap<String, String> = HashMap::new();
            let mut raw: HashMap<String, String> = HashMap::new();
            // declared parameters and locals (`Runner r;`, `x: Foo = ..`); a name declared with
            // different types in nested scopes is not typed
            let declared_vars = cfg.declared_vars();
            for &(name, t) in &declared_vars {
                match resolver.class_named(t) {
                    Some(c) => drop(known.insert(name.to_string(), c.to_string())),
                    None => drop(raw.insert(name.to_string(), t.to_string())),
                }
            }
            let params: HashSet<&str> = declared_vars.iter().map(|(n, _)| *n).collect();
            let mut conflict: HashSet<String> = HashSet::new();
            // a variable declared in several scopes (shadowing) is one variable per scope: `type_key`
            let assigns = || cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| s.assigns.iter().map(move |a| (s.line, a)));
            // two rounds so that `b = a` after `a = Req()` is seen whatever the order
            for _ in 0..2 {
                for (line, a) in assigns().filter(|(_, a)| !a.target.contains(['.', '[']) && !params.contains(a.target.as_str())) {
                    let key = cfg.type_key(&a.target, line);
                    let class = match &a.value {
                        Flow::Call(c) => class_of_call(c, fi),
                        Flow::Path(p) => known.get(&cfg.type_key(p, line)).cloned(),
                        _ => None,
                    };
                    match class {
                        Some(c) => match known.insert(key.clone(), c.clone()) {
                            Some(old) if old != c => drop(conflict.insert(key)),
                            _ => {}
                        },
                        None => drop(conflict.insert(key)),
                    }
                }
            }
            known.retain(|k, _| !conflict.contains(k));
            flow.push(if conflict.is_empty() { HashMap::new() } else { flow_classes(cfg, fi, &conflict, &known, &class_of_call) });
            locals.push(known);
            declared.push(raw);
        }
        // fields: `self.f = <typed value>` in the methods of a class
        let mut fields: HashMap<(String, String), String> = HashMap::new();
        let mut bad: HashSet<(String, String)> = HashSet::new();
        // declared field types (`private Runner r;`, `r: Runner`, `self.r: Runner`) win over what is assigned
        let mut declared_fields: HashSet<(String, String)> = HashSet::new();
        for n in 0..fns.len() {
            let cfg = cfg_of(n);
            let Some(class) = class_of(&cfg.name) else { continue };
            for (field, t) in &cfg.field_types {
                if let Some(c) = resolver.class_named(t) {
                    let key = (class.clone(), field.clone());
                    fields.insert(key.clone(), c.to_string());
                    declared_fields.insert(key);
                }
            }
        }
        for (n, &(fi, _, _)) in fns.iter().enumerate() {
            let cfg = cfg_of(n);
            let (Some(recv), Some(class)) = (&cfg.receiver, class_of(&cfg.name)) else { continue };
            let prefix = format!("{recv}.");
            for a in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns) {
                let Some(field) = a.target.strip_prefix(&prefix).filter(|f| !f.contains(['.', '['])) else { continue };
                let key = (class.clone(), field.to_string());
                if declared_fields.contains(&key) {
                    continue;
                }
                let value = match &a.value {
                    Flow::Call(c) => class_of_call(c, fi),
                    Flow::Path(p) => locals[n].get(p).cloned(),
                    _ => None,
                };
                match value {
                    Some(v) => match fields.insert(key.clone(), v.clone()) {
                        Some(old) if old != v => drop(bad.insert(key)),
                        _ => {}
                    },
                    None => drop(bad.insert(key)),
                }
            }
        }
        fields.retain(|k, _| !bad.contains(k));
        // Go interfaces: what is called on values of an unknown parameter type
        let mut iface_use: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
        for (n, _) in fns.iter().enumerate() {
            if fns[n].1 != Language::Go {
                continue;
            }
            for call in cfg_of(n).graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.calls) {
                if let Some((v, m)) = call.callee.split_once('.').filter(|(_, m)| !m.contains('.'))
                    && let Some(t) = declared[n].get(v)
                {
                    iface_use.entry(t.clone()).or_default().insert(m.to_string());
                }
            }
        }
        // what the declaration says an interface requires replaces what the calls happen to use
        let mut field_iface = HashMap::new();
        for (n, _) in fns.iter().enumerate().filter(|(n, _)| fns[*n].1 == Language::Go) {
            let cfg = cfg_of(n);
            for (name, methods) in &cfg.iface_methods {
                iface_use.insert(name.clone(), methods.iter().cloned().collect());
            }
            if let Some(class) = class_of(&cfg.name) {
                for (field, t) in &cfg.field_types {
                    if cfg.iface_methods.iter().any(|(i, _)| i == t) {
                        field_iface.insert((class.clone(), field.clone()), t.clone());
                    }
                }
            }
        }
        Self { locals, fields, declared, iface_use, field_iface, flow }
    }

    /// The class `key` (a name, see [`Cfg::type_key`]) of function `n` has before statement
    /// `(block, index)`, where the function gives it different classes at different places.
    pub(crate) fn class_at(&self, n: usize, at: (usize, usize), key: &str) -> Option<&str> {
        self.flow[n].get(&at)?.iter().find(|(k, _)| k == key).map(|(_, c)| c.as_str())
    }

    pub(crate) fn path_class(&self, resolver: &Resolver, cfg: &Cfg, path: &str, local: impl Fn(&str) -> Option<String>) -> Option<String> {
        let mut parts = path.split('.');
        let root = parts.next()?;
        let mut class = if cfg.receiver.as_deref() == Some(root) {
            class_of(&cfg.name)
        } else if let Some(c) = local(root) {
            Some(c)
        } else {
            // a bare name the method never declares is a field of its class (`r.run()` in
            // `Svc::go`, whose class body is in another file)
            let declared = cfg.params.iter().flatten().any(|p| p == root)
                || cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns).any(|a| a.target == root)
                || cfg.declared_vars().iter().any(|(n, _)| *n == root);
            match class_of(&cfg.name) {
                Some(own) if cfg.receiver.is_some() && !declared => self.field(resolver, &own, root),
                _ => None,
            }
        }?;
        for field in parts { class = self.field(resolver, &class, field)?; }
        Some(class)
    }

    /// The class of the value in `class.field`, looking through the bases.
    pub(crate) fn field(&self, resolver: &Resolver, class: &str, field: &str) -> Option<String> {
        let mut seen = HashSet::new();
        let mut queue = vec![class.to_string()];
        while let Some(c) = queue.pop() {
            if !seen.insert(c.clone()) {
                continue;
            }
            if let Some(t) = self.fields.get(&(c.clone(), field.to_string())) {
                return Some(t.clone());
            }
            queue.extend(resolver.bases_of(&c).iter().cloned());
        }
        None
    }

    /// The interface a field of `class` (or of a base) is declared with.
    fn field_interface(&self, resolver: &Resolver, class: &str, field: &str) -> Option<&String> {
        let mut seen = HashSet::new();
        let mut queue = vec![class.to_string()];
        while let Some(c) = queue.pop() {
            if !seen.insert(c.clone()) {
                continue;
            }
            if let Some(t) = self.field_iface.get(&(c.clone(), field.to_string())) {
                return self.iface_use.get_key_value(t).map(|(k, _)| k);
            }
            queue.extend(resolver.bases_of(&c).iter().cloned());
        }
        None
    }

    /// Go: the methods of the types that satisfy the interface `callee` (`r.Run`, `s.r.Run`) is
    /// called through, for a parameter, local or field declared with an interface type.
    pub(crate) fn interface_targets(&self, resolver: &Resolver, func: usize, callee: &str, file: usize, class_at: impl Fn(&str) -> Option<String>) -> Vec<usize> {
        let Some((obj, m)) = callee.rsplit_once('.') else { return vec![] };
        let iface = match obj.rsplit_once('.') {
            None => self.interface_of(func, obj),
            Some((parent, field)) => {
                class_at(parent).and_then(|pc| self.field_interface(resolver, &pc, field))
            }
        };
        let Some(iface) = iface else { return vec![] };
        let mut out = vec![];
        for c in resolver.implementers(&self.iface_use[iface], file) {
            out.extend(resolver.resolve_method(&c, m, file).ids);
        }
        out
    }

    /// The interface type a parameter was declared with, when it has callers' methods recorded.
    fn interface_of(&self, func: usize, var: &str) -> Option<&String> {
        let t = self.declared[func].get(var)?;
        self.iface_use.get_key_value(t).map(|(k, _)| k)
    }
}

/// For the variables of `cfg` that are given different classes (`conflict`, by [`Cfg::type_key`]):
/// the class each has before every statement, found by following the assignments through the
/// control flow. A variable whose paths disagree, or that is assigned something unknown, has none.
fn flow_classes(
    cfg: &Cfg,
    fi: usize,
    conflict: &HashSet<String>,
    known: &HashMap<String, String>,
    class_of_call: &dyn Fn(&crate::ir::CallFlow, usize) -> Option<String>,
) -> HashMap<(usize, usize), Vec<(String, String)>> {
    use petgraph::visit::NodeIndexable;
    // key -> class; `None` when unknown (or paths disagree); absent: not assigned yet
    type State = HashMap<String, Option<String>>;
    let step = |st: &mut State, s: &crate::ir::Stmt| {
        for a in &s.assigns {
            let key = cfg.type_key(&a.target, s.line);
            if !conflict.contains(&key) {
                continue;
            }
            let class = if a.strong && !a.target.contains(['.', '[']) {
                match &a.value {
                    Flow::Call(c) => class_of_call(c, fi),
                    Flow::Path(p) => {
                        let pk = cfg.type_key(p, s.line);
                        st.get(&pk).cloned().unwrap_or_else(|| known.get(&pk).cloned())
                    }
                    _ => None,
                }
            } else {
                None
            };
            st.insert(key, class);
        }
    };
    let bound = cfg.graph.node_bound();
    let mut inn: Vec<Option<State>> = vec![None; bound];
    inn[cfg.entry.index()] = Some(State::new());
    let mut work = std::collections::VecDeque::from([cfg.entry]);
    let mut budget = bound * 20 + 100;
    while let Some(b) = work.pop_front() {
        let mut st = inn[b.index()].clone().expect("queued blocks have a state");
        for s in &cfg.graph[b].stmts {
            step(&mut st, s);
        }
        for succ in cfg.graph.neighbors(b) {
            let changed = match &mut inn[succ.index()] {
                slot @ None => {
                    *slot = Some(st.clone());
                    true
                }
                Some(cur) => {
                    let mut changed = false;
                    for (k, v) in &st {
                        match cur.get(k) {
                            None => {
                                cur.insert(k.clone(), v.clone());
                                changed = true;
                            }
                            Some(old) if old != v && old.is_some() => {
                                cur.insert(k.clone(), None);
                                changed = true;
                            }
                            _ => {}
                        }
                    }
                    changed
                }
            };
            if changed && budget > 0 {
                budget -= 1;
                work.push_back(succ);
            }
        }
    }
    let mut out = HashMap::new();
    for b in cfg.graph.node_indices() {
        let Some(start) = &inn[b.index()] else { continue };
        let mut st = start.clone();
        for (i, s) in cfg.graph[b].stmts.iter().enumerate() {
            let classes: Vec<(String, String)> = st.iter().filter_map(|(k, v)| Some((k.clone(), v.clone()?))).collect();
            if !classes.is_empty() {
                out.insert((b.index(), i), classes);
            }
            step(&mut st, s);
        }
    }
    out
}

pub fn build(files: &[(PathBuf, Language, Vec<Cfg>)]) -> CallGraph {
    let refs: Vec<(&Path, Language, &[Cfg])> = files.iter().map(|(p, l, c)| (p.as_path(), *l, c.as_slice())).collect();
    build_refs(&refs, None)
}

/// Like [`build`], for callers that only hold references, optionally with
/// per-file visibility (`deps::visibility`) to disambiguate same-named functions.
pub fn build_refs(files: &[(&Path, Language, &[Cfg])], visible: Option<Vec<HashSet<usize>>>) -> CallGraph {
    let mut graph = DiGraph::new();
    let mut ids: Vec<(NodeIndex, usize, usize)> = vec![]; // node, file index, cfg index
    for (fi, (file, _, cfgs)) in files.iter().enumerate() {
        for (ci, cfg) in cfgs.iter().enumerate() {
            let n = graph.add_node(FnNode { file: file.to_path_buf(), name: cfg.name.clone(), line: cfg.line });
            ids.push((n, fi, ci));
        }
    }
    let resolver = Resolver::new(ids.iter().map(|&(_, fi, ci)| (fi, files[fi].1.family(), files[fi].2[ci].name.as_str())))
        .with_hierarchy(ids.iter().map(|&(_, fi, ci)| (files[fi].2[ci].name.as_str(), files[fi].2[ci].class_bases.as_slice())))
        .with_class_decls(ids.iter().flat_map(|&(_, fi, ci)| files[fi].2[ci].class_decls.iter()))
        .with_visibility(visible);

    let types = Types::infer(&ids.iter().map(|&(_, fi, ci)| (fi, files[fi].1, &files[fi].2[ci])).collect::<Vec<_>>(), &resolver);

    let flat: Vec<(usize, Language, &Cfg)> = ids.iter().map(|&(_, fi, ci)| (fi, files[fi].1, &files[fi].2[ci])).collect();
    let values = Values::infer(&flat, &resolver);
    let key_facts = KeyFacts::infer(&flat, &resolver);
    let closures: HashMap<(usize, usize, usize), usize> = flat.iter().enumerate()
        .filter(|(_, (_, _, cfg))| cfg.col > 0)
        .map(|(n, (file, _, cfg))| ((*file, cfg.line, cfg.col), n)).collect();
    let field_fns = super::taint::collect_field_fns(flat.iter().map(|(file, _, cfg)| (*file, *cfg)), &resolver, &closures);

    let mut external: HashMap<String, usize> = HashMap::new();
    let mut edges: HashMap<(NodeIndex, NodeIndex), CallEdge> = HashMap::new();
    for (n, &(caller, fi, ci)) in ids.iter().enumerate() {
        let cfg = &files[fi].2[ci];
        let mut written_callbacks: HashMap<String, HashSet<usize>> = HashMap::new();
        for call in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.calls) {
            let resolved = resolver.resolve(&call.callee, fi);
            for target in resolved.ids {
                let params = &flat[target].2.params;
                for (path, refs) in super::taint::callable_writes(&field_fns, target) {
                    let (root, suffix) = path.split_once('.').map_or((path.as_str(), ""), |(r, _)| (r, &path[r.len()..]));
                    if let Some(j) = params.iter().position(|names| names.iter().any(|name| name == root))
                        && let Some(Flow::Path(actual)) = super::taint::arg_for(call, j, params)
                    {
                        written_callbacks.entry(format!("{actual}{suffix}")).or_default().extend(refs);
                    }
                }
            }
        }
        let own_class = cfg.receiver.as_ref().and_then(|_| class_of(&cfg.name));
        let typed: HashMap<&str, &str> = types.locals[n].iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let stmts = || cfg.graph.node_weights().flat_map(|b| &b.stmts);
        // variables assigned somewhere in the function; a bare name that is none of
        // these (or a parameter) and names a free function is a reference to it
        let locals: HashSet<&str> =
            stmts().flat_map(|s| &s.assigns).map(|a| a.target.as_str()).chain(cfg.params.iter().flatten().map(String::as_str)).collect();
        let reference = |p: &str| -> Option<usize> { (!locals.contains(p)).then(|| resolver.free_function(p, fi)).flatten() };
        let mut add = |t: usize, call: &crate::ir::CallFlow, callback: bool, invoked: bool, exact: bool| {
            let line = call.line;
            let e = edges.entry((caller, NodeIndex::new(t))).or_default();
            e.sites += 1;
            e.lines.push(line);
            e.call_sites.push(CallSite { line, col: call.col, callee: call.callee.clone(), callback, invoked, exact });
            if callback {
                e.callback_lines.push(line);
            }
            if e.line == 0 || line < e.line {
                e.line = line;
            }
        };
        let calls: Vec<((usize, usize), &crate::ir::CallFlow)> = cfg
            .graph
            .node_indices()
            .flat_map(|b| cfg.graph[b].stmts.iter().enumerate().flat_map(move |(i, s)| s.calls.iter().map(move |c| ((b.index(), i), c))))
            .collect();
        for (at, call) in calls {
            let mut targets = vec![];
            let mut callback = false;
            let mut exact = true;
            if let Some((v, rest)) = call.callee.split_once('.') {
                let (path, m) = rest.rsplit_once('.').map_or(("", rest), |(a, b)| (a, b));
                if v == "super" && path.is_empty() {
                    for b in own_class.iter().flat_map(|c| resolver.bases_of(c)) {
                        targets.extend(resolver.resolve_inherited(b, m, fi).ids);
                    }
                } else {
                    // `v.f.g.m()`: the type of `v`, then of each field on the way
                    let obj = &call.callee[..call.callee.len() - m.len() - 1];
                    let class_at = |obj: &str| {
                        types.path_class(&resolver, cfg, obj, |root| {
                            if matches!(root, "self" | "this" | "cls") {
                                own_class.clone()
                            } else {
                                // the declaration in effect at this call, not whichever scope declared last
                                cfg.declared_type_at(root, call.line)
                                    .and_then(|t| resolver.class_named(t))
                                    .map(str::to_string)
                                    .or_else(|| {
                                        // a variable declared in several scopes is one per scope; one given
                                        // different classes has the class the flow gives it here
                                        let key = cfg.type_key(root, call.line);
                                        types.class_at(n, at, &key).or_else(|| typed.get(key.as_str()).copied()).map(str::to_string)
                                    })
                            }
                        })
                    };
                    let class = class_at(obj);
                    // `for r in runners: r.run()`: the classes that were put in the container
                    let class = class.map(|c| vec![c]).or_else(|| {
                        let held = match &call.recv {
                            Some(Flow::Path(p)) if super::values::strip_keys(p) == obj => values.lookup(n, p),
                            _ => values.lookup(n, obj),
                        };
                        held.map(|h| h.classes.iter().cloned().collect::<Vec<_>>()).filter(|c| !c.is_empty())
                    });
                    match class {
                        Some(cs) => {
                            for c in cs {
                                targets.extend(resolver.resolve_method(&c, m, fi).ids);
                            }
                        }
                        // a Go interface, known only by the methods called on it
                        None if path.is_empty() => {
                            if let Some(iface) = types.interface_of(n, v) {
                                for c in resolver.implementers(&types.iface_use[iface], fi) {
                                    targets.extend(resolver.resolve_method(&c, m, fi).ids);
                                }
                            }
                        }
                        // a field declared with a Go interface: `s.r.Run()`
                        None => {
                            if let Some((parent, field)) = obj.rsplit_once('.')
                                && let Some(pc) = class_at(parent)
                                && let Some(iface) = types.field_interface(&resolver, &pc, field)
                            {
                                for c in resolver.implementers(&types.iface_use[iface], fi) {
                                    targets.extend(resolver.resolve_method(&c, m, fi).ids);
                                }
                            }
                        }
                    }
                }
            }
            // `handlers[k]()`, `f = handler; f()`, `self.hooks[0]()`: functions held by a variable, container or field
            if targets.is_empty() {
                for path in key_facts.paths(n, cfg, call) {
                    if let Some(h) = values.lookup(n, &path) {
                        targets.extend(h.fns.iter().copied());
                    }
                }
                if !targets.is_empty() {
                    targets.sort_unstable();
                    targets.dedup();
                    callback = true;
                }
            }
            if targets.is_empty() && let Some(refs) = written_callbacks.get(&call.callee) {
                targets.extend(refs);
                callback = true;
            }
            if targets.is_empty() {
                let r = resolver.resolve(&call.callee, fi);
                exact = r.exact;
                targets = r.ids;
            }
            if targets.is_empty() {
                *external.entry(call.callee.clone()).or_default() += 1;
            }
            for t in targets {
                add(t, call, callback, callback, exact);
            }
            // functions handed over as arguments
            for a in &call.args {
                if let Flow::Path(p) = a {
                    if let Some(t) = reference(p) {
                        add(t, call, true, false, true);
                    } else if let Some(h) = values.lookup(n, p) {
                        for &t in &h.fns {
                            add(t, call, true, false, true);
                        }
                    } else if p.contains('.') {
                        // Explicitly handed-over method on an object of unknown class:
                        // visible same-named implementations are possible callbacks.
                        for t in resolver.resolve(p, fi).ids {
                            add(t, call, true, false, false);
                        }
                    }
                }
            }
        }
    }
    let mut sorted: Vec<_> = edges.into_iter().collect();
    sorted.sort_by_key(|((a, b), _)| (a.index(), b.index()));
    for ((a, b), e) in sorted {
        graph.add_edge(a, b, e);
    }
    CallGraph { graph, external }
}

impl CallGraph {
    /// Groups of functions that (indirectly) call each other, plus self-calls.
    pub fn recursive_groups(&self) -> Vec<Vec<NodeIndex>> {
        tarjan_scc(&self.graph)
            .into_iter()
            .filter(|scc| scc.len() > 1 || scc.iter().any(|&n| self.graph.contains_edge(n, n)))
            .collect()
    }

    /// Functions nothing else calls: likely entry points (or dead code).
    pub fn roots(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&n| self.graph.neighbors_directed(n, petgraph::Direction::Incoming).next().is_none())
            .collect()
    }
}
