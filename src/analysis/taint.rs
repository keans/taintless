//! Taint analysis with function summaries and field sensitivity.
//!
//! Each function is analyzed with its parameters seeded as symbolic causes
//! (`Cause::Param(i)`). What those causes reach -- a sink inside the function,
//! its return value, a field of its object -- is recorded in the function's
//! [`Summary`]. Callers apply the summaries of the functions they call: a call
//! returns what its summary says, and an untrusted argument that reaches a
//! sink inside the callee is reported. Functions are processed callees-first
//! over the call graph, with a fixpoint inside recursive groups.
//!
//! State is tracked per access path (`self.a` and `self.b` are different), and
//! untrusted data stored in a field (`self.cmd = input()`) is remembered per
//! class, so that any method of the class that reads the field sees it. That
//! needs the whole project to be re-analyzed until no new tainted fields appear.

use super::callgraph::{Resolver, Types, last_segment, simple_name};
use super::rules::{ArgSel, CallRule, MUTATORS, Mode, RuleSet, ignores_env_sources, is_env_source, matches, wild};
use super::Finding;
use crate::ir::{CallFlow, Cfg, Flow, Stmt};
use crate::cpg::cfg::SNode;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::NodeIndexable;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;

/// Where a tainted value comes from. `Param` sorts first so that when the set
/// has to be truncated, parameters (needed for summaries) survive.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cause {
    Param(usize),
    Source { line: usize, desc: String },
}

pub(crate) type Taint = BTreeSet<Cause>;
/// The abstract state at a program point.
#[derive(Clone, Default, PartialEq)]
struct State {
    /// Tainted access paths (`x`, `self.cmd`, `a.b.c`).
    taint: BTreeMap<String, Taint>,
    /// Paths this function has assigned on every path to here. A field read
    /// from such a path sees what this function stored, not what the rest of
    /// the class stores in that field.
    bound: BTreeSet<String>,
    /// Variables known to hold an instance of a class (`r = Req(..)`).
    types: BTreeMap<String, String>,
    /// Variables that hold the very same object (`b = a`), as variable -> group
    /// representative. Writes through one are seen through the others.
    alias: BTreeMap<String, String>,
    /// Functions a variable, field or container may hold (`h = sink`, `self.cb = f`,
    /// `handlers.append(f)`), so that calling it calls them.
    fnrefs: BTreeMap<String, BTreeSet<usize>>,
}

impl State {
    fn is_bound(&self, p: &str) -> bool {
        let mut end = p.len();
        loop {
            if self.bound.contains(&p[..end]) {
                return true;
            }
            match p[..end].rfind(['.', '[']) {
                Some(i) => end = i,
                None => return false,
            }
        }
    }
}
/// Untrusted data stored in `(class, field)` by some method of the project.
pub(crate) type FieldTaint = BTreeMap<(String, String), Taint>;
/// `(class, field)` written from parameters: `(Class.field) <- params`.
type FieldKey = (String, String);

/// A closure sees the parameters of the function that created it as
/// `Cause::Param(OUTER_PARAM + i)`; sinks they reach go to that function's summary.
const OUTER_PARAM: usize = 1 << 20;
/// Stands for the receiver object (`self` / `this`) in a method's summary.
const RECV_PARAM: usize = usize::MAX;
const MAX_CALLBACKS: usize = 8;
/// Sinks reached from the creating function's parameters, per creating function.
pub(crate) type OuterHits = HashMap<usize, Vec<(usize, Hit)>>;

const MAX_CAUSES: usize = 6;
const MAX_HITS_PER_PARAM: usize = 20;
const MAX_PATH: usize = 6;
const MAX_SCC_ROUNDS: usize = 5;
/// Extra whole-project passes spent on tainted fields.
const MAX_FIELD_ROUNDS: usize = 3;

fn union_into(into: &mut Taint, from: &Taint) {
    into.extend(from.iter().cloned());
    while into.len() > MAX_CAUSES {
        let last = into.iter().next_back().cloned().expect("non-empty");
        into.remove(&last);
    }
}

// ---- state over access paths -------------------------------------------------

/// Taint of the path `p`: what is stored at `p`, at an ancestor (`self` taints
/// `self.x`) or at a descendant (`self.x` taints `self` as a whole).
fn lookup(st: &State, p: &str) -> Taint {
    let mut t = Taint::new();
    // ancestors, including p itself; a path this function assigned on every path
    // (`self.cmd = "ls"`) no longer depends on what its ancestors (`self`) held
    let mut end = p.len();
    loop {
        if let Some(v) = st.taint.get(&p[..end]) {
            union_into(&mut t, v);
        }
        if st.bound.contains(&p[..end]) {
            break;
        }
        match p[..end].rfind(['.', '[']) {
            Some(i) => end = i,
            None => break,
        }
    }
    // descendants: fields and elements
    for (_, v) in below(&st.taint, p) {
        union_into(&mut t, v);
    }
    t
}

/// The entries of `m` for paths below `p`: its fields (`p.f`) and elements (`p[0]`).
fn below<'a, V>(m: &'a BTreeMap<String, V>, p: &str) -> impl Iterator<Item = (&'a String, &'a V)> {
    let len = p.len();
    m.range(p.to_string()..).take_while(move |(k, _)| k.starts_with(p)).filter(move |(k, _)| k[len..].starts_with(['.', '[']))
}


/// Remove `p` and everything below it.
fn kill(st: &mut State, p: &str) {
    st.taint.remove(p);
    let doomed: Vec<String> = below(&st.taint, p).map(|(k, _)| k.clone()).collect();
    for k in doomed {
        st.taint.remove(&k);
    }
}

fn store(st: &mut State, target: &str, t: Taint, strong: bool) {
    if strong {
        kill(st, target);
        st.bound.insert(target.to_string());
    } else {
        // a write to the container as a whole may reach any element: none is known to be clean
        st.bound.retain(|b| !b.strip_prefix(target).is_some_and(|r| r.starts_with('[')));
    }
    if !t.is_empty() {
        union_into(st.taint.entry(target.to_string()).or_default(), &t);
    }
}

/// The variables aliased with `v`, itself included.
fn mates(st: &State, v: &str) -> Vec<String> {
    match st.alias.get(v) {
        Some(rep) => st.alias.iter().filter(|(_, r)| *r == rep).map(|(k, _)| k.clone()).collect(),
        None => vec![v.to_string()],
    }
}

/// `v` stops being the same object as anything else (it is reassigned).
fn leave_group(st: &mut State, v: &str) {
    let Some(rep) = st.alias.remove(v) else { return };
    let rest: Vec<String> = st.alias.iter().filter(|(_, r)| **r == rep).map(|(k, _)| k.clone()).collect();
    match rest.len() {
        0 | 1 => {
            for k in rest {
                st.alias.remove(&k);
            }
        }
        _ => {
            let new_rep = rest.iter().min().cloned().expect("non-empty");
            for k in rest {
                st.alias.insert(k, new_rep.clone());
            }
        }
    }
}

/// `store`, applied to every alias of the target when the write goes through
/// an object (`b.f = x`, `b.append(x)`, `h.r.f = x` with `h.r = b`) rather than
/// rebinding the variable. Alias groups are keyed by access paths (`b`, `h.r`).
fn store_through(st: &mut State, target: &str, t: Taint, strong: bool) {
    if strong {
        // rebinding the path (and with it everything below it) ends its aliasing
        let gone: Vec<String> = st.alias.keys().filter(|k| *k == target || k.strip_prefix(target).is_some_and(|r| r.starts_with(['.', '[']))).cloned().collect();
        for k in gone {
            leave_group(st, &k);
        }
    }
    // the longest prefix of the target that belongs to an alias group
    let dots = target.match_indices('.').map(|(i, _)| i).rev();
    let cut = (!strong).then_some(target.len()).into_iter().chain(dots).find(|&c| st.alias.contains_key(&target[..c]));
    if let Some(c) = cut {
        for m in mates(st, &target[..c]) {
            store(st, &format!("{m}{}", &target[c..]), t.clone(), strong);
        }
        return;
    }
    store(st, target, t, strong);
}

/// A hit: the sink a parameter can reach, with the calls it travels through.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub finding: Finding,
    pub path: Vec<String>,
    /// The sink is reached by this property of the parameter (an options object: `jwt.verify(t, k,
    /// opts)` reads `opts.algorithms`), not by the parameter as a whole.
    pub prop: Option<String>,
}

/// What a function does with its inputs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Summary {
    /// Per parameter: the sinks it reaches (directly or through callees).
    pub param_sinks: Vec<Vec<Hit>>,
    /// Parameters whose value may flow into the return value.
    pub ret_params: BTreeSet<usize>,
    /// Untrusted data that may come out of the return value, described.
    pub ret_source: Option<String>,
    /// Fields of the object (`self.f = param`) that parameters are stored in.
    pub field_writes: BTreeMap<FieldKey, BTreeSet<usize>>,
    /// Sinks the receiver object's state reaches (`self.cmd` read inside the method).
    pub recv_sinks: Vec<Hit>,
    /// The receiver's state may flow into the return value (`return self.cmd`).
    pub ret_recv: bool,
    /// Parameters that are called as functions: what they are called with.
    pub callbacks: Vec<CallbackUse>,
    /// Variables of the enclosing function that a closure assigns, and what flows into them.
    pub captured_writes: BTreeMap<String, ArgDeps>,
    pub ret_fns: BTreeSet<usize>,
    /// What is stored in the fields of an object parameter (`o.d = input()`, `o.d = x`), by
    /// `(parameter, ".field")`: the caller's argument holds that afterwards.
    pub param_writes: BTreeMap<(usize, String), ArgDeps>,
    /// Parameters returned as themselves (`return a`): the result is the same object.
    pub ret_alias: BTreeSet<usize>,
    /// What the properties of a returned object / dictionary hold (`return { algorithms: [x] }`).
    pub ret_props: BTreeMap<String, ArgDeps>,
    /// Callable contents written through an object/container parameter.
    pub callable_writes: BTreeMap<(usize, String), (BTreeSet<usize>, BTreeSet<usize>)>,
}

/// What flows into one argument: parameters of the function, and real sources.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArgDeps {
    pub params: BTreeSet<usize>,
    pub sources: BTreeSet<(usize, String)>,
}

/// `fn(x, 1)` where `fn` is a parameter: the function passed in is called with these arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallbackUse {
    pub param: usize,
    pub args: Vec<ArgDeps>,
    /// The callback's result is (part of) the return value.
    pub ret: bool,
}

fn split_deps(t: &Taint) -> ArgDeps {
    let mut d = ArgDeps::default();
    for k in t {
        match k {
            Cause::Param(j) if *j != RECV_PARAM => {
                d.params.insert(*j);
            }
            Cause::Param(_) => {}
            Cause::Source { line, desc } => {
                d.sources.insert((*line, desc.clone()));
            }
        }
    }
    d
}

pub struct FnInfo<'a> {
    pub file_idx: usize,
    pub lang: crate::lang::Language,
    pub file: &'a Path,
    pub cfg: &'a Cfg,
    pub rules: &'static RuleSet,
    /// What the file's imports call things (`import os as o`, `from os import system`), so rules
    /// written for `os.system` also match `o.system(..)` and `system(..)`.
    pub aliases: Option<&'a super::crypto::Bindings>,
}

/// What one analysis of a function looked at besides its own code, with the values it saw.
/// Analyzing it again gives the same result as long as all of them still hold.
#[derive(Clone, Default)]
struct Reads {
    /// Summaries of other functions, by version (see `run_pass`; 0: not computed yet).
    summaries: Vec<(usize, u64)>,
    /// Single field entries.
    fields: Vec<(FieldKey, Option<Taint>)>,
    /// All fields of a class (a closure's captured scope).
    classes: Vec<(String, Vec<(String, Taint)>)>,
    /// Sinks closures found for the parameters of a function.
    outer: Vec<(usize, Option<Vec<(usize, Hit)>>)>,
}

impl Reads {
    fn still_hold(&self, versions: &[u64], fields: &FieldTaint, outer: &OuterHits) -> bool {
        self.summaries.iter().all(|(f, seen)| versions[*f] == *seen)
            && self.fields.iter().all(|(k, seen)| fields.get(k) == seen.as_ref())
            && self.classes.iter().all(|(c, seen)| class_fields(fields, c).map(|(v, t)| (v.clone(), t.clone())).eq(seen.iter().cloned()))
            && self.outer.iter().all(|(id, seen)| outer.get(id) == seen.as_ref())
    }
}

fn class_fields<'a>(fields: &'a FieldTaint, class: &'a str) -> impl Iterator<Item = (&'a String, &'a Taint)> {
    fields.range((class.to_string(), String::new())..).take_while(move |((c, _), _)| c == class).map(|((_, v), t)| (v, t))
}

/// The results of one group of mutually recursive functions (or of one function) in the
/// previous pass, reused while everything the group read still holds.
#[derive(Clone)]
struct Cached {
    reads: Reads,
    results: Vec<(usize, FnResult)>,
}

struct Env<'a> {
    /// What the function being analyzed has read so far (see [`Reads`]).
    reads: std::cell::RefCell<Reads>,
    fns: &'a [FnInfo<'a>],
    resolver: &'a Resolver,
    types: &'a Types,
    summaries: &'a [Option<Summary>],
    /// Version of each finished summary: equal versions mean equal summaries.
    versions: &'a [u64],
    /// Working summaries of the recursive group being solved.
    overlay: &'a HashMap<usize, Summary>,
    /// Tainted fields found by the previous pass.
    fields: &'a FieldTaint,
    /// Simple class name -> class, for classes with a unique name.
    classes: &'a HashMap<String, String>,
    /// Lambdas and closures by `(file index, line, column)`.
    closures: &'a HashMap<(usize, usize, usize), usize>,
    /// Sinks closures found for the parameters of their creators, from the previous pass.
    outer: &'a OuterHits,
    /// Functions stored in fields of a class, or in module-level variables (keyed `("<module>", "file:var")`).
    field_fns: &'a FieldFns,
    /// Which function created each closure.
    creators: &'a HashMap<usize, usize>,
}

pub(crate) fn parameter_key(id: usize, name: &str) -> FieldKey {
    (format!("<parameter {id}>"), name.to_string())
}

pub(crate) fn writes_key(id: usize) -> String {
    format!("<writes {id}>")
}

pub(crate) fn callable_writes(facts: &FieldFns, id: usize) -> impl Iterator<Item = (&String, &BTreeSet<usize>)> {
    let scope = writes_key(id);
    facts.range((scope.clone(), String::new())..)
        .take_while(move |((key, _), _)| key == &scope)
        .map(|((_, target), refs)| (target, refs))
}

pub(crate) fn return_key(id: usize) -> FieldKey {
    ("<return>".into(), id.to_string())
}

fn stored_values(flow: &Flow, file: usize, locals: &BTreeMap<String, BTreeSet<usize>>, facts: &FieldFns,
    resolver: &Resolver, closures: &HashMap<(usize, usize, usize), usize>) -> BTreeSet<usize> {
    match flow {
        Flow::Path(p) => {
            let root = p.split('.').next().unwrap_or(p);
            let mut out = BTreeSet::new();
            for (path, values) in locals {
                if path == p || path == root || path.strip_prefix(p).is_some_and(|r| r.starts_with('.')) { out.extend(values); }
            }
            if !locals.contains_key(root) {
                out.extend(facts.get(&module_key(file, root)).into_iter().flatten());
                out.extend(fn_value(p, file, resolver, closures));
            }
            out
        }
        Flow::Join(v) => v.iter().flat_map(|f| stored_values(f, file, locals, facts, resolver, closures)).collect(),
        Flow::Call(c) => resolver.resolve(&c.callee, file).ids.into_iter()
            .flat_map(|id| facts.get(&return_key(id)).into_iter().flatten().copied()).collect(),
        Flow::Clean => BTreeSet::new(),
    }
}

pub(crate) type FieldFns = BTreeMap<FieldKey, BTreeSet<usize>>;

/// The function a value names: a lambda / closure written at `<fn@line:col>`, or a free function.
fn fn_value(p: &str, file_idx: usize, resolver: &Resolver, closures: &HashMap<(usize, usize, usize), usize>) -> Option<usize> {
    if let Some((l, c)) = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')).and_then(|r| r.split_once(':')) {
        return closures.get(&(file_idx, l.parse().ok()?, c.parse().ok()?)).copied();
    }
    resolver.free_function(p, file_idx)
}

/// Every function a flow mentions as a value.
fn flow_fn_values(f: &Flow, file_idx: usize, resolver: &Resolver, closures: &HashMap<(usize, usize, usize), usize>, out: &mut BTreeSet<usize>) {
    match f {
        Flow::Path(p) => out.extend(fn_value(p, file_idx, resolver, closures)),
        Flow::Call(c) => c.recv.iter().chain(&c.args).for_each(|x| flow_fn_values(x, file_idx, resolver, closures, out)),
        Flow::Join(v) => v.iter().for_each(|x| flow_fn_values(x, file_idx, resolver, closures, out)),
        Flow::Clean => {}
    }
}

/// The variable / member paths a flow reads.
fn flow_paths(f: &Flow, out: &mut Vec<String>) {
    match f {
        Flow::Path(p) => out.push(p.clone()),
        Flow::Call(c) => c.recv.iter().chain(&c.args).for_each(|x| flow_paths(x, out)),
        Flow::Join(v) => v.iter().for_each(|x| flow_paths(x, out)),
        Flow::Clean => {}
    }
}

pub(crate) fn module_key(file_idx: usize, var: &str) -> FieldKey {
    ("<module>".to_string(), format!("{file_idx}:{var}"))
}

/// Functions stored in fields of the object (`self.cb = f`, `self.handlers.append(f)`) and in
/// module-level variables (`HANDLERS = {"a": f}`), found by looking at every function once.
pub(crate) fn collect_field_fns<'f>(
    fns: impl Iterator<Item = (usize, &'f Cfg)>,
    resolver: &Resolver,
    closures: &HashMap<(usize, usize, usize), usize>,
) -> FieldFns {
    let fns: Vec<_> = fns.collect();
    let classes: HashMap<_, _> = fns.iter().filter_map(|(_, c)| class_of(&c.name).map(|c| (simple_name(c).to_string(), c.to_string()))).collect();
    let mut out = FieldFns::new();
    for &(file_idx, cfg) in &fns {
        let mut types: HashMap<String, String> = cfg.declared_vars().into_iter()
            .filter_map(|(n, t)| classes.get(t).map(|c| (n.to_string(), c.clone()))).collect();
        for _ in 0..=cfg.graph.node_count() {
            let before = types.clone();
            for a in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns) {
                let class = match &a.value {
                    Flow::Call(c) => classes.get(simple_name(&c.callee)).cloned(),
                    Flow::Path(p) => types.get(p).cloned(),
                    _ => None,
                };
                if let Some(c) = class { types.insert(a.target.clone(), c); }
            }
            if before == types { break; }
        }
        let class = class_of(&cfg.name);
        let recv = cfg.receiver.as_deref();
        let module = cfg.name == "<module>";
        // where a store to `target` is remembered
        let key_of = |target: &str| -> Option<FieldKey> {
            let (root, rest) = target.split_once('.').map_or((target, None), |(r, x)| (r, Some(x)));
            if let (Some(r), Some(class), Some(rest)) = (recv, class, rest)
                && root == r
            {
                return Some((class.to_string(), rest.split('.').next().unwrap_or(rest).to_string()));
            }
            if let (Some(class), Some(rest)) = (types.get(root), rest) {
                return Some((class.clone(), rest.split('.').next().unwrap_or(rest).to_string()));
            }
            module.then(|| module_key(file_idx, root))
        };
        for st in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
            for a in &st.assigns {
                let mut vals = BTreeSet::new();
                flow_fn_values(&a.value, file_idx, resolver, closures, &mut vals);
                if let (false, Some(key)) = (vals.is_empty(), key_of(&a.target)) {
                    out.entry(key).or_default().extend(vals);
                }
            }
            for c in &st.calls {
                if let Some(Flow::Path(p)) = &c.recv
                    && MUTATORS.contains(&last_segment(&c.callee))
                    && let Some(key) = key_of(p)
                {
                    let mut vals = BTreeSet::new();
                    c.args.iter().for_each(|a| flow_fn_values(a, file_idx, resolver, closures, &mut vals));
                    if !vals.is_empty() {
                        out.entry(key).or_default().extend(vals);
                    }
                }
            }
        }
    }
    // Callable contents travel with containers and object arguments. This finite
    // points-to fixpoint is shared with the data-flow graph; taint summaries
    // still substitute each call's actual inputs separately.
    loop {
        let before = out.clone();
        for (id, &(file, cfg)) in fns.iter().enumerate() {
            let mut locals = BTreeMap::new();
            for name in cfg.params.iter().flatten() {
                locals.insert(name.clone(), before.get(&parameter_key(id, name)).cloned().unwrap_or_default());
            }
            let mut stmts: Vec<_> = cfg.graph.node_weights().flat_map(|b| &b.stmts).collect();
            stmts.sort_by_key(|s| (s.line, s.col));
            for st in stmts {
                for c in &st.calls {
                    let mut targets = stored_values(&Flow::Path(c.callee.clone()), file, &locals, &before, resolver, closures);
                    if targets.is_empty() { targets.extend(resolver.resolve(&c.callee, file).ids); }
                    for callee in targets {
                        let params = &fns[callee].1.params;
                        for (target, refs) in callable_writes(&before, callee) {
                            let (root, suffix) = target.split_once('.').map_or((target.as_str(), String::new()), |(r, s)| (r, format!(".{s}")));
                            if let Some(j) = params.iter().position(|ns| ns.iter().any(|n| n == root))
                                && let Some(Flow::Path(actual)) = arg_for(c, j, params)
                            {
                                let path = format!("{actual}{suffix}");
                                locals.entry(path.clone()).or_default().extend(refs);
                                if cfg.params.iter().flatten().any(|p| p == actual) {
                                    out.entry((writes_key(id), path)).or_default().extend(refs);
                                }
                            }
                        }
                        for (j, names) in params.iter().enumerate() {
                            if let Some(arg) = arg_for(c, j, params) {
                                let refs = stored_values(arg, file, &locals, &before, resolver, closures);
                                if !refs.is_empty() {
                                    for name in names { out.entry(parameter_key(callee, name)).or_default().extend(&refs); }
                                }
                            }
                        }
                    }
                    if MUTATORS.contains(&last_segment(&c.callee)) && let Some(Flow::Path(p)) = &c.recv {
                        let refs: BTreeSet<_> = c.args.iter().flat_map(|a| stored_values(a, file, &locals, &before, resolver, closures)).collect();
                        locals.entry(p.clone()).or_default().extend(refs);
                    }
                }
                for a in &st.assigns {
                    let refs = stored_values(&a.value, file, &locals, &before, resolver, closures);
                    let root = a.target.split('.').next().unwrap_or(&a.target);
                    if !refs.is_empty() && (!a.strong || a.target.contains('.')) && cfg.params.iter().flatten().any(|p| p == root) {
                        out.entry((writes_key(id), a.target.clone())).or_default().extend(&refs);
                    }
                    if !refs.is_empty() && let Some((root, field)) = a.target.split_once('.')
                        && cfg.receiver.as_deref() == Some(root)
                        && let Some(class) = class_of(&cfg.name)
                    {
                        out.entry((class.to_string(), field.to_string())).or_default().extend(&refs);
                    }
                    if a.strong { locals.insert(a.target.clone(), refs); }
                    else { locals.entry(a.target.clone()).or_default().extend(refs); }
                }
                if let Some(ret) = &st.ret {
                    let refs = stored_values(ret, file, &locals, &before, resolver, closures);
                    if !refs.is_empty() { out.entry(return_key(id)).or_default().extend(refs); }
                }
            }
        }
        if out == before { break; }
    }
    out
}

impl Env<'_> {
    fn summary(&self, id: usize) -> Option<&Summary> {
        let found = self.overlay.get(&id).or_else(|| self.summaries[id].as_ref());
        let mut reads = self.reads.borrow_mut();
        if !reads.summaries.iter().any(|(f, _)| *f == id) {
            reads.summaries.push((id, self.versions[id]));
        }
        found
    }

    fn field(&self, key: &FieldKey) -> Option<&Taint> {
        let found = self.fields.get(key);
        self.reads.borrow_mut().fields.push((key.clone(), found.cloned()));
        found
    }

    fn class_fields<'f>(&'f self, class: &'f str) -> Vec<(&'f String, &'f Taint)> {
        let found: Vec<_> = class_fields(self.fields, class).collect();
        self.reads.borrow_mut().classes.push((class.to_string(), found.iter().map(|(v, t)| ((*v).clone(), (*t).clone())).collect()));
        found
    }

    fn outer_hits(&self, id: usize) -> &[(usize, Hit)] {
        let found = self.outer.get(&id);
        self.reads.borrow_mut().outer.push((id, found.cloned()));
        found.map_or(&[], Vec::as_slice)
    }
}

#[derive(Clone)]
struct FnResult {
    findings: Vec<Finding>,
    summary: Summary,
    /// Untrusted data this function stores in fields of its class.
    field_taints: Vec<(FieldKey, Taint)>,
    outer_sinks: Vec<(usize, Hit)>,
}

fn base(file: &Path) -> String {
    file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// The class a method belongs to: its name without the last segment.
pub(crate) fn class_of(name: &str) -> Option<&str> {
    let i = name.rfind(['.', ':'])?;
    let c = name[..i].trim_end_matches(':');
    (!c.is_empty()).then_some(c)
}

/// The argument of `c` that binds to parameter `j` (keyword names first).
pub(crate) fn arg_for<'c>(c: &'c CallFlow, j: usize, params: &[Vec<String>]) -> Option<&'c Flow> {
    if let Some(names) = params.get(j) {
        for (i, n) in c.arg_names.iter().enumerate() {
            if n.as_ref().is_some_and(|n| names.contains(n)) {
                return c.args.get(i);
            }
        }
    }
    c.args
        .iter()
        .enumerate()
        .filter(|(i, _)| c.arg_names.get(*i).is_none_or(|n| n.is_none()))
        .map(|(_, a)| a)
        .nth(j)
}

struct Analyzer<'a> {
    env: &'a Env<'a>,
    me: &'a FnInfo<'a>,
    id: usize,
    /// Names of functions whose call result this function returns (`return fn(x)`).
    ret_calls: HashSet<String>,
    /// The line of the statement being analyzed (variables shadowed in nested scopes keep one type each).
    line: std::cell::Cell<usize>,
}

/// Calls whose result a `return` hands back.
fn returned_calls(f: &Flow, out: &mut HashSet<String>) {
    match f {
        Flow::Call(c) => {
            out.insert(c.callee.clone());
            c.recv.iter().chain(&c.args).for_each(|x| returned_calls(x, out));
        }
        Flow::Join(v) => v.iter().for_each(|x| returned_calls(x, out)),
        _ => {}
    }
}

impl Analyzer<'_> {
    fn rules(&self) -> &'static RuleSet {
        self.me.rules
    }

    /// `(class, field)` if `p` is a field of this method's object (`self.cmd`)
    /// or of a variable known to hold an instance (`r.d` after `r = Req(..)`).
    /// The key the type of variable `name` is kept under at the statement being analyzed.
    fn type_key(&self, name: &str) -> String {
        self.me.cfg.type_key(name, self.line.get())
    }

    fn field_key(&self, p: &str, st: &State) -> Option<FieldKey> {
        let (root, rest) = p.split_once('.')?;
        let field = rest.split('.').next().unwrap_or(rest).to_string();
        if self.me.cfg.receiver.as_deref() == Some(root) {
            return Some((class_of(&self.me.cfg.name)?.to_string(), field));
        }
        st.types.get(&self.type_key(root)).map(|class| (class.clone(), field))
    }

    /// The key of one property of a field (`this.opts.algorithms` is `(Class, "opts.algorithms")`).
    fn property_key(&self, p: &str, st: &State) -> Option<FieldKey> {
        let (root, rest) = p.split_once('.')?;
        if !rest.contains(['.', '[']) {
            return None;
        }
        if self.me.cfg.receiver.as_deref() == Some(root) {
            return Some((class_of(&self.me.cfg.name)?.to_string(), rest.to_string()));
        }
        st.types.get(&self.type_key(root)).map(|class| (class.clone(), rest.to_string()))
    }

    /// The functions a flow may hold as a value: what the state recorded for the variable,
    /// field or container, what other methods of the class stored in the field, and module-level
    /// registries. With `named`, a function named directly counts as well.
    fn refs_of(&self, f: &Flow, st: &State, named: bool) -> BTreeSet<usize> {
        match f {
            Flow::Path(p) => {
                let mut out = BTreeSet::new();
                if named {
                    out.extend(fn_value(p, self.me.file_idx, self.env.resolver, self.env.closures));
                }
                let root = p.split('.').next().unwrap_or(p);
                for (path, refs) in &st.fnrefs {
                    if path == p || path == root || path.strip_prefix(p).is_some_and(|r| r.starts_with('.')) {
                        out.extend(refs);
                    }
                }
                if let Some(key) = self.field_key(p, st)
                    && !st.is_bound(p)
                    && let Some(v) = self.env.field_fns.get(&key)
                {
                    out.extend(v);
                }
                let local = st.is_bound(p) || st.is_bound(root) || st.fnrefs.contains_key(root) || self.me.cfg.params.iter().flatten().any(|n| n == root);
                if !local && let Some(v) = self.env.field_fns.get(&module_key(self.me.file_idx, root)) {
                    out.extend(v);
                }
                out
            }
            Flow::Join(v) => v.iter().flat_map(|x| self.refs_of(x, st, named)).collect(),
            Flow::Call(c) => {
                let mut out = BTreeSet::new();
                let r = self.env.resolver.resolve(&c.callee, self.me.file_idx);
                for id in r.ids.into_iter().filter(|_| r.exact) {
                    if let Some(sum) = self.env.summary(id) {
                        out.extend(&sum.ret_fns);
                        for &j in &sum.ret_params {
                            if let Some(arg) = arg_for(c, j, &self.env.fns[id].cfg.params) {
                                out.extend(self.refs_of(arg, st, named));
                            }
                        }
                    }
                }
                out
            }
            _ => BTreeSet::new(),
        }
    }

    /// The class of variable `root` at `line`: the declaration in effect there (scopes shadow
    /// each other), else what the flow state knows.
    fn class_at(&self, root: &str, line: usize, st: &State) -> Option<String> {
        self.me.cfg.declared_type_at(root, line).and_then(|t| self.env.classes.get(t)).cloned().or_else(|| st.types.get(&self.me.cfg.type_key(root, line)).cloned())
    }

    /// Resolve a call, using the class of the object it is called on when known.
    fn resolve(&self, c: &CallFlow, st: &State) -> super::callgraph::Resolved {
        // calling a variable, field or registry entry that holds functions
        let held = self.refs_of(&Flow::Path(c.callee.clone()), st, false);
        if !held.is_empty() {
            return super::callgraph::Resolved { ids: held.into_iter().collect(), exact: true };
        }
        if let Some((path, method)) = c.callee.rsplit_once('.')
            && let Some(class) = self.env.types.path_class(self.env.resolver, self.me.cfg, path, |root| self.class_at(root, c.line, st))
        {
            let r = self.env.resolver.resolve_method(&class, method, self.me.file_idx);
            if !r.ids.is_empty() {
                return r;
            }
        }
        // Go: a value declared with an interface may be any type that satisfies it
        if self.me.lang == crate::lang::Language::Go {
            let ids = self.env.types.interface_targets(self.env.resolver, self.id, &c.callee, self.me.file_idx, |obj| {
                self.env.types.path_class(self.env.resolver, self.me.cfg, obj, |root| self.class_at(root, c.line, st))
            });
            if !ids.is_empty() {
                return super::callgraph::Resolved { ids, exact: true };
            }
        }
        self.env.resolver.resolve(&c.callee, self.me.file_idx)
    }

    /// The class of a freshly constructed object: `Req(..)`, `new Svc(..)`, `S::new(..)`.
    fn constructed(&self, f: &Flow, st: &State) -> Option<(String, Option<usize>)> {
        let Flow::Call(c) = f else { return None };
        let r = self.resolve(c, st);
        if r.ids.is_empty() {
            // a class without a constructor of its own: `Runner()`, `new Runner()`
            let simple = last_segment(&c.callee);
            return self.env.classes.get(simple).map(|cls| (cls.clone(), None));
        }
        let (&id, true) = (r.ids.first()?, r.exact && r.ids.len() == 1) else { return None };
        let name = &self.env.fns[id].cfg.name;
        let simple = simple_name(name);
        if let Some(class) = class_of(name) {
            let class_simple = simple_name(class);
            if matches!(simple, "__init__" | "constructor" | "new") || simple == class_simple {
                return Some((class.to_string(), Some(id)));
            }
        }
        // a factory or any function declared to return a known class: `NewServer()`, `Foo.create()`
        let ret = self.env.fns[id].cfg.ret_type.as_ref()?;
        self.env.classes.get(ret).map(|cls| (cls.clone(), None))
    }

    /// The causes of untrusted data that `f` may carry.
    fn eval(&self, f: &Flow, st: &State, line: usize) -> Taint {
        match f {
            Flow::Clean => Taint::new(),
            Flow::Path(p) => {
                let mut t = lookup(st, p);
                // Escaped closures can mutate a shared lexical cell between invocations.
                let mut owner = Some(self.id);
                while let Some(id) = owner {
                    if id != self.id && st.is_bound(p) { break; }
                    // cells are kept per variable: a read of `box[0]` sees what was written to `box`
                    let cell = [p.as_str(), p.split('[').next().unwrap_or(p)]
                        .into_iter()
                        .find_map(|k| self.env.field(&(format!("<deferred {id}>"), k.to_string())));
                    if let Some(v) = cell {
                        let mut depth = 0;
                        let mut current = self.id;
                        while current != id {
                            let Some(&parent) = self.env.creators.get(&current) else { break };
                            depth += 1;
                            current = parent;
                        }
                        let shifted = v.iter().map(|cause| match cause {
                            Cause::Param(p) if *p != RECV_PARAM => Cause::Param(p + depth * OUTER_PARAM),
                            c => c.clone(),
                        }).collect();
                        union_into(&mut t, &shifted);
                    }
                    owner = self.env.creators.get(&id).copied();
                }
                if self.rules().is_source_path(p) {
                    let desc = match self.rules().source_path_note(p) {
                        Some(note) => format!("{p} ({note})"),
                        None => p.clone(),
                    };
                    t.insert(Cause::Source { line, desc });
                }
                if let Some(key) = self.field_key(p, st)
                    && !st.is_bound(p)
                    && let Some(ft) = self.env.field(&key)
                {
                    for k in ft {
                        if let Cause::Source { desc, .. } = k {
                            let desc = format!("{desc} → field `{}` of {}", key.1, key.0);
                            t.insert(Cause::Source { line, desc });
                        }
                    }
                }
                t
            }
            Flow::Call(c) => self.eval_call(c, st, line),
            Flow::Join(parts) => {
                let mut t = Taint::new();
                for p in parts {
                    union_into(&mut t, &self.eval(p, st, line));
                }
                t
            }
        }
    }

    /// The other names an imported alias gives this callee.
    fn alternatives(&self, callee: &str) -> Vec<String> {
        self.me.aliases.map(|b| b.alternatives(callee)).unwrap_or_default()
    }

    fn eval_call(&self, c: &CallFlow, st: &State, line: usize) -> Taint {
        let rules = self.rules();
        let alts = self.alternatives(&c.callee);
        let names = || std::iter::once(c.callee.as_str()).chain(alts.iter().map(String::as_str));
        if names().any(|n| rules.is_sanitizer(n)) {
            return Taint::new();
        }
        if let Some(call) = names().find(|n| rules.is_source_call(n)) {
            let desc = match rules.source_call_note(call) {
                Some(note) => format!("{}() ({note})", c.callee),
                None => format!("{}()", c.callee),
            };
            return Taint::from([Cause::Source { line: c.line, desc }]);
        }
        let mut out = Taint::new();
        let resolved = self.resolve(c, st);
        // A match by method name alone is a guess (it may be a library method):
        // it must not invent sources, so only exact matches contribute summaries.
        let exact_ids: &[usize] = if resolved.exact { &resolved.ids } else { &[] };
        for &t in exact_ids {
            let Some(sum) = self.env.summary(t) else { continue };
            if let Some(src) = &sum.ret_source {
                out.insert(Cause::Source { line: c.line, desc: format!("{src} → returned by {}()", c.callee) });
            }
            for &j in &sum.ret_params {
                if let Some(a) = arg_for(c, j, &self.env.fns[t].cfg.params) {
                    union_into(&mut out, &self.eval(a, st, line));
                }
            }
            if sum.ret_recv
                && let Some(r) = &c.recv
            {
                union_into(&mut out, &self.eval(r, st, line));
            }
            // `return fn(x)`: what the function passed in returns for these arguments
            let params = &self.env.fns[t].cfg.params;
            for cb in sum.callbacks.iter().filter(|cb| cb.ret) {
                let Some(arg) = arg_for(c, cb.param, params) else { continue };
                for g in self.callback_targets(arg, st) {
                    let Some(sg) = self.env.summary(g) else { continue };
                    if let Some(src) = &sg.ret_source {
                        let desc = format!("{src} → returned by {}()", self.env.fns[g].cfg.name);
                        out.insert(Cause::Source { line: c.line, desc });
                    }
                    if sg.ret_recv && let Flow::Path(p) = arg
                        && let Some((receiver, _)) = p.rsplit_once('.')
                    {
                        union_into(&mut out, &self.eval(&Flow::Path(receiver.to_string()), st, line));
                    }
                    for &k in &sg.ret_params {
                        if let Some(d) = cb.args.get(k) {
                            union_into(&mut out, &self.deps_taint(d, c, params, st, line));
                        }
                    }
                }
            }
        }
        // Unknown function, or only a guess by method name: assume the result
        // depends on the receiver and the arguments.
        if resolved.ids.is_empty() || !resolved.exact {
            for f in c.recv.iter().chain(&c.args) {
                union_into(&mut out, &self.eval(f, st, line));
            }
        }
        out
    }

    fn transfer(&self, s: &Stmt, st: &mut State) {
        self.line.set(s.line);
        // calling a closure runs its assignments to variables of this scope
        for c in &s.calls {
            let r = self.resolve(c, st);
            if !r.exact {
                continue;
            }
            for &t in &r.ids {
                if let Some(sum) = self.env.summary(t) {
                    for ((param, suffix), d) in &sum.param_writes {
                        let params = &self.env.fns[t].cfg.params;
                        if let Some(Flow::Path(root)) = arg_for(c, *param, params) {
                            let taint = self.deps_taint(d, c, params, st, s.line);
                            store_through(st, &format!("{root}{suffix}"), taint, false);
                        }
                    }
                    for ((param, suffix), (direct, inputs)) in &sum.callable_writes {
                        let params = &self.env.fns[t].cfg.params;
                        if let Some(Flow::Path(root)) = arg_for(c, *param, params) {
                            let mut refs = direct.clone();
                            for &i in inputs {
                                if let Some(arg) = arg_for(c, i, params) { refs.extend(self.refs_of(arg, st, true)); }
                            }
                            let path = format!("{root}{suffix}");
                            st.fnrefs.entry(path).or_default().extend(refs);
                        }
                    }
                }
                // only a closure this function created writes into this function's variables
                // (a same-named closure of another function is not the one being called)
                let mine = self.env.creators.get(&t) == Some(&self.id)
                    || self.env.fns[t].cfg.name.strip_prefix(self.me.cfg.name.as_str()).is_some_and(|r| r.starts_with(['.', ':']));
                if !mine {
                    continue;
                }
                let Some(sum) = self.env.summary(t).filter(|m| !m.captured_writes.is_empty()) else { continue };
                for (var, d) in &sum.captured_writes {
                    let taint = self.deps_taint(d, c, &self.env.fns[t].cfg.params, st, s.line);
                    store_through(st, var, taint, false);
                }
            }
        }
        // `parts.append(tainted)` stores the taint in `parts`
        for c in &s.calls {
            let method = last_segment(&c.callee);
            if let Some(Flow::Path(p)) = &c.recv
                && MUTATORS.contains(&method)
            {
                let mut t = Taint::new();
                for a in &c.args {
                    union_into(&mut t, &self.eval(a, st, s.line));
                }
                store_through(st, p, t, false);
                let refs: BTreeSet<usize> = c.args.iter().flat_map(|a| self.refs_of(a, st, true)).collect();
                if !refs.is_empty() {
                    st.fnrefs.entry(p.clone()).or_default().extend(refs);
                }
            }
        }
        // `xs[0] = v` is stored under the element (`xs[0]`) rather than in the whole container
        let element_bases: Vec<&str> = s.elems.iter().filter(|e| !e.strong).filter_map(|e| e.target.split('[').next()).collect();
        let covered = |a: &crate::ir::Assign| {
            !a.strong && element_bases.iter().any(|b| a.target == *b || a.target.strip_prefix(b).is_some_and(|r| r.starts_with('.')))
        };
        for a in &s.assigns {
            let t = self.eval(&a.value, st, s.line);
            let refs = self.refs_of(&a.value, st, true);
            let targets = match a.target.split_once('.') {
                Some((root, rest)) => mates(st, root).into_iter().map(|m| format!("{m}.{rest}")).collect(),
                None => vec![a.target.clone()],
            };
            for target in targets {
                if a.strong {
                    let prefix = format!("{target}.");
                    st.fnrefs.retain(|p, _| !p.starts_with(&prefix));
                    st.fnrefs.insert(target, refs.clone());
                } else if !refs.is_empty() {
                    st.fnrefs.entry(target).or_default().extend(&refs);
                }
            }
            // what the variable now holds: an instance of a class, or nothing known
            // `b = identity(a)` hands `a` back: the same object under another name
            let returned = if a.strong { self.returned_arg(&a.value, st).map(Flow::Path) } else { None };
            let value = returned.as_ref().unwrap_or(&a.value);
            let class = if a.strong { self.constructed(&a.value, st).or_else(|| self.copy_of(value, st)) } else { None };
            if !covered(a) {
                store_through(st, &a.target, t, a.strong);
            }
            // `opts = build(req)`: the properties of the literal `build` returns
            if a.strong && let Flow::Call(cc) = &a.value {
                let r = self.resolve(cc, st);
                for &id in r.ids.iter().filter(|_| r.exact) {
                    let Some(sum) = self.env.summary(id) else { continue };
                    for (name, d) in &sum.ret_props {
                        let taint = self.ret_prop_taint(d, id, cc, st, s.line);
                        store_through(st, &self.prop_path(&a.target, name), taint, true);
                    }
                }
            }
            if a.strong
                && let Flow::Path(src) = value
                && !src.contains('.')
                && *src != a.target
                && (st.types.contains_key(&self.type_key(src)) || self.me.cfg.params.iter().flatten().any(|p| p == src))
            {
                // `b = a` where `a` is an object: one object under two names
                let rep = st.alias.get(src).cloned().unwrap_or_else(|| src.clone());
                st.alias.insert(src.clone(), rep.clone());
                st.alias.insert(a.target.clone(), rep);
            }
            match class {
                Some((class, ctor)) => {
                    st.types.insert(self.type_key(&a.target), class);
                    if let Some(ctor) = ctor {
                        self.init_fields(&a.target, &a.value, ctor, st, s.line);
                    }
                }
                None => {
                    let declared = self.me.cfg.declared_vars().into_iter()
                        .find(|(name, _)| *name == a.target).and_then(|(_, ty)| self.env.classes.get(ty));
                    if let Some(class) = declared { st.types.insert(self.type_key(&a.target), class.clone()); }
                    else { st.types.remove(&self.type_key(&a.target)); }
                }
            }
        }
        // writes to elements with a literal key
        for e in &s.elems {
            let t = self.eval(&e.value, st, s.line);
            store_through(st, &e.target, t, e.strong);
            if e.strong
                && let Flow::Path(src) = &e.value
                && !src.contains('.')
                && (st.types.contains_key(&self.type_key(src)) || self.me.cfg.params.iter().flatten().any(|p| p == src))
            {
                // `xs = [a]`: `xs[0]` is `a`
                let rep = st.alias.get(src).cloned().unwrap_or_else(|| src.clone());
                st.alias.insert(src.clone(), rep.clone());
                st.alias.insert(e.target.clone(), rep);
            }
        }
    }

    /// The variable a call hands back as itself: `f(a)` where `f` does `return param`.
    fn returned_arg(&self, f: &Flow, st: &State) -> Option<String> {
        let Flow::Call(c) = f else { return None };
        let r = self.resolve(c, st);
        let (&id, true) = (r.ids.first()?, r.exact && r.ids.len() == 1) else { return None };
        let sum = self.env.summary(id)?;
        let params = &self.env.fns[id].cfg.params;
        let mut mine = sum.ret_alias.iter().filter_map(|&i| match arg_for(c, i, params) {
            Some(Flow::Path(p)) if !p.contains('.') => Some(p.clone()),
            _ => None,
        });
        let first = mine.next()?;
        mine.next().is_none().then_some(first)
    }

    /// `y = x` where `x` holds an instance: so does `y`.
    fn copy_of(&self, f: &Flow, st: &State) -> Option<(String, Option<usize>)> {
        let Flow::Path(p) = f else { return None };
        st.types.get(&self.type_key(p)).map(|c| (c.clone(), None))
    }

    /// `r = Req(arg)`: the constructor stores its parameters in fields of `r`.
    /// Record that on `r` itself, so this instance is judged by its own
    /// arguments and not by what other instances of the class hold.
    fn init_fields(&self, var: &str, ctor_call: &Flow, ctor: usize, st: &mut State, line: usize) {
        let (Flow::Call(c), Some(sum)) = (ctor_call, self.env.summary(ctor)) else { return };
        for ((_, field), params) in &sum.field_writes {
            let mut t = Taint::new();
            for &j in params {
                if let Some(arg) = arg_for(c, j, &self.env.fns[ctor].cfg.params) {
                    union_into(&mut t, &self.eval(arg, st, line));
                }
            }
            store_through(st, &format!("{var}.{field}"), t, true);
        }
    }

    /// Fields of the object written by this statement, with what they receive.
    /// Closures created by `s` start with the untrusted data in scope here.
    fn record_captures(&self, s: &Stmt, st: &State, out: &mut Output) {
        self.line.set(s.line);
        // Publishing a closure to another function or returning it lets its
        // captured writes run after this activation. Keep those facts on the
        // lexical owner, so sibling event handlers share the same cells.
        let escaped: BTreeSet<usize> = s.calls.iter().flat_map(|c| &c.args).chain(s.ret.iter())
            .chain(s.assigns.iter().filter(|a| a.target.contains('.') || !a.strong).map(|a| &a.value))
            .flat_map(|f| self.refs_of(f, st, true)).collect();
        for cid in escaped {
            if let (Some(&owner), Some(sum)) = (self.env.creators.get(&cid), self.env.summary(cid)) {
                for (var, deps) in &sum.captured_writes {
                    let mut t: Taint = deps.sources.iter().map(|(line, desc)| Cause::Source { line: *line, desc: desc.clone() }).collect();
                    // Captured parameters keep their dependency on the owner.
                    for &p in &deps.params {
                        if p >= OUTER_PARAM && p != RECV_PARAM { t.insert(Cause::Param(p - OUTER_PARAM)); }
                    }
                    if !t.is_empty() { out.field_taints.push(((format!("<deferred {owner}>"), var.clone()), t)); }
                }
            }
        }
        let mut refs = vec![];
        for a in &s.assigns {
            closure_refs(&a.value, &mut refs);
        }
        for c in &s.calls {
            c.recv.iter().chain(&c.args).for_each(|x| closure_refs(x, &mut refs));
        }
        if let Some(r) = &s.ret {
            closure_refs(r, &mut refs);
        }
        for (line, col) in refs {
            let Some(&cid) = self.env.closures.get(&(self.me.file_idx, line, col)) else { continue };
            for (var, t) in &st.taint {
                // the creator's parameters become `OUTER_PARAM + i` in the closure
                let carried: Taint = t
                    .iter()
                    .filter_map(|c| match c {
                        Cause::Param(i) if *i != RECV_PARAM => i.checked_add(OUTER_PARAM).map(Cause::Param),
                        Cause::Param(_) => None,
                        src => Some(src.clone()),
                    })
                    .collect();
                if !carried.is_empty() {
                    out.field_taints.push(((capture_class(cid), var.clone()), carried));
                }
            }
        }
    }

    fn record_fields(&self, s: &Stmt, st: &State, out: &mut Output) {
        self.line.set(s.line);
        let mut writes: Vec<(String, Taint)> = vec![];
        for a in &s.assigns {
            writes.push((a.target.clone(), self.eval(&a.value, st, s.line)));
        }
        for c in &s.calls {
            let method = last_segment(&c.callee);
            if let Some(Flow::Path(p)) = &c.recv
                && MUTATORS.contains(&method)
            {
                let mut t = Taint::new();
                for a in &c.args {
                    union_into(&mut t, &self.eval(a, st, s.line));
                }
                writes.push((p.clone(), t));
            }
        }
        // what is stored under a property of a field (`this.opts = { algorithms: x }`)
        for e in &s.elems {
            writes.push((e.target.clone(), self.eval(&e.value, st, s.line)));
        }
        for (target, taint) in writes {
            if let Some(key) = self.property_key(&target, st) {
                out.field_write(key, &taint, self.me.file, s.line);
            }
            let Some(key) = self.field_key(&target, st) else { continue };
            out.field_write(key, &taint, self.me.file, s.line);
        }
    }

    /// Report sinks reached by untrusted data and record, for the summary, the
    /// sinks reached by parameters.
    fn check(&self, s: &Stmt, st: &State, out: &mut Output) {
        self.line.set(s.line);
        for c in &s.calls {
            let alts = self.alternatives(&c.callee);
            let applicable = |r: &&CallRule| {
                std::iter::once(c.callee.as_str()).chain(alts.iter().map(String::as_str)).any(|n| matches(r.pattern, n) && !r.except.iter().any(|e| matches(e, n)))
            };
            for rule in self.rules().rules.iter().filter(applicable) {
                let (taint, always) = match rule.mode {
                    Mode::Tainted(sel) => (self.select(c, sel, st, s.line), false),
                    Mode::Always => (self.select(c, ArgSel::Any, st, s.line), true),
                };
                let skip_env = ignores_env_sources(rule.id);
                let source = taint.iter().find_map(|k| match k {
                    Cause::Source { line, desc } if !(skip_env && is_env_source(desc)) => Some((*line, desc.clone())),
                    _ => None,
                });
                let severity = if always && !taint.is_empty() { rule.severity.escalate() } else { rule.severity };
                let mut finding = Finding {
                    rule: rule.id,
                    cwe: rule.cwe,
                    severity,
                    message: format!("{}: `{}`", rule.message, c.callee),
                    file: self.me.file.to_path_buf(),
                    function: self.me.cfg.name.clone(),
                    line: c.line,
                    col: c.col,
                    origin: None,
                };
                if always && !taint.is_empty() {
                    finding.message.push_str(" receives untrusted input");
                }
                if always || source.is_some() {
                    let mut f = finding.clone();
                    f.origin = source.map(|(line, desc)| format!("{desc} (line {line})"));
                    out.findings.push(f);
                }
                for k in &taint {
                    if let Cause::Param(i) = k {
                        out.hit(*i, Hit { finding: finding.clone(), path: vec![], prop: None });
                    }
                }
                // an options object received as a parameter: the caller decides what its property holds
                if let Mode::Tainted(ArgSel::Named(name)) = rule.mode {
                    for a in &c.args {
                        if let Flow::Path(p) = a
                            && let Some(j) = self.me.cfg.params.iter().position(|ns| ns.contains(p))
                        {
                            out.hit(j, Hit { finding: finding.clone(), path: vec![], prop: Some(name.to_string()) });
                        }
                    }
                }
            }
            self.check_callees(c, st, s.line, out);
            // a parameter called as a function
            let head = c.callee.split('.').next().unwrap_or(&c.callee);
            if self.refs_of(&Flow::Path(c.callee.clone()), st, false).is_empty() {
                for cause in lookup(st, head) {
                    if let Cause::Param(i) = cause && i < OUTER_PARAM {
                        let args = c.args.iter().map(|a| split_deps(&self.eval(a, st, s.line))).collect();
                        out.callback(CallbackUse { param: i, args, ret: self.ret_calls.contains(&c.callee) });
                    }
                }
            }
        }
    }

    /// What a property of the object `callee` (function `id`) returns holds, at this call.
    fn ret_prop_taint(&self, d: &ArgDeps, id: usize, cc: &CallFlow, st: &State, line: usize) -> Taint {
        let params_only = ArgDeps { params: d.params.clone(), sources: BTreeSet::new() };
        let mut t = self.deps_taint(&params_only, cc, &self.env.fns[id].cfg.params, st, line);
        for (_, desc) in &d.sources {
            t.insert(Cause::Source { line: cc.line, desc: format!("{desc} → returned by {}()", cc.callee) });
        }
        t
    }

    /// The path a literal's key is recorded under: `.name` in JS and Go, `['name']` elsewhere.
    fn prop_path(&self, base: &str, name: &str) -> String {
        if self.me.lang.dot_keys() { format!("{base}.{name}") } else { format!("{base}['{name}']") }
    }

    /// The properties recorded for the object `base` (`opts = { a: x }`), with what they hold.
    fn entries_of(&self, st: &State, base: &str) -> Vec<(String, Taint)> {
        st.taint
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .filter_map(|(k, v)| {
                let rest = k.strip_prefix(base)?;
                let name = rest.strip_prefix('.').or_else(|| rest.strip_prefix("['").and_then(|r| r.strip_suffix("']")))?;
                (!name.is_empty() && !name.contains(['.', '[', '\''])).then(|| (name.to_string(), v.clone()))
            })
            .collect()
    }

    /// What the property `name` of the object passed as `arg` holds: a literal written in the call,
    /// a variable with recorded properties, or the result of a function that returns a literal.
    fn prop_taint(&self, c: &CallFlow, arg: &Flow, name: &str, st: &State, line: usize) -> Taint {
        let mut t = Taint::new();
        // a literal in the call (it may have collapsed into one of its values, which is no variable)
        if !c.props.is_empty() {
            for (_, v) in c.props.iter().filter(|(k, _)| k == name) {
                union_into(&mut t, &self.eval(v, st, line));
            }
            return t;
        }
        match arg {
            Flow::Call(cc) => {
                let r = self.resolve(cc, st);
                for &id in r.ids.iter().filter(|_| r.exact) {
                    if let Some(d) = self.env.summary(id).and_then(|m| m.ret_props.get(name)) {
                        union_into(&mut t, &self.ret_prop_taint(d, id, cc, st, line));
                    }
                }
            }
            Flow::Path(p) => {
                let path = self.prop_path(p, name);
                if st.taint.get(&path).is_some_and(|v| !v.is_empty()) {
                    union_into(&mut t, &self.eval(&Flow::Path(path), st, line));
                } else if !st.is_bound(&path)
                    && let Some(key) = self.property_key(&path, st)
                    && let Some(ft) = self.env.field(&key)
                {
                    // what other methods of the class stored in that property of the field
                    for k in ft {
                        if let Cause::Source { desc, .. } = k {
                            t.insert(Cause::Source { line, desc: format!("{desc} → field `{}` of {}", key.1.split(['.', '[']).next().unwrap_or(&key.1), key.0) });
                        }
                    }
                }
            }
            _ => {}
        }
        t
    }

    fn select(&self, c: &CallFlow, sel: ArgSel, st: &State, line: usize) -> Taint {
        let mut t = Taint::new();
        match sel {
            ArgSel::Any => c.args.iter().for_each(|a| union_into(&mut t, &self.eval(a, st, line))),
            ArgSel::At(i) => {
                if let Some(a) = c.args.get(i) {
                    union_into(&mut t, &self.eval(a, st, line));
                }
            }
            ArgSel::Named(name) => {
                for (a, n) in c.args.iter().zip(&c.arg_names) {
                    if n.as_deref() == Some(name) {
                        union_into(&mut t, &self.eval(a, st, line));
                    }
                }
                // a property of an object / dictionary / struct literal argument, nested ones included
                for (_, v) in c.props.iter().filter(|(k, _)| k == name) {
                    union_into(&mut t, &self.eval(v, st, line));
                }
                // ... or of one built in a variable (`opts = { algorithm: x }; f(opts)`) or returned by a
                // function (`f(build())`; not when an argument is a literal: it may have collapsed into
                // one of its values, which is no variable). Only an element the code recorded counts,
                // not what the whole variable holds: a tainted `iv` is no options object with a `key`
                for a in c.args.iter().filter(|_| c.props.is_empty()) {
                    if matches!(a, Flow::Path(_) | Flow::Call(_)) {
                        union_into(&mut t, &self.prop_taint(c, a, name, st, line));
                    }
                }
            }
        }
        t
    }

    /// `taint` reaches the sinks `hits`: findings for real sources, summary entries for parameters.
    fn apply_hits(&self, hits: &[Hit], taint: &Taint, step: &str, out: &mut Output) {
        for cause in taint {
            for h in hits {
                let mut path = vec![step.to_string()];
                path.extend(h.path.iter().cloned());
                match cause {
                    Cause::Source { desc, .. } if ignores_env_sources(h.finding.rule) && is_env_source(desc) => {}
                    Cause::Source { line, desc } => {
                        let mut f = h.finding.clone();
                        f.origin = Some(format!("{desc} (line {line}) via {}", path.join(" → ")));
                        out.findings.push(f);
                    }
                    Cause::Param(k) => out.hit(*k, Hit { finding: h.finding.clone(), path, prop: None }),
                }
            }
        }
    }

    /// The taint of an argument position of a callback, from this call's actual arguments.
    fn deps_taint(&self, d: &ArgDeps, c: &CallFlow, params: &[Vec<String>], st: &State, line: usize) -> Taint {
        let mut t = Taint::new();
        for &j in &d.params {
            if j >= OUTER_PARAM {
                t.insert(Cause::Param(j - OUTER_PARAM));
                continue;
            }
            if let Some(a) = arg_for(c, j, params) {
                union_into(&mut t, &self.eval(a, st, line));
            }
        }
        for (l, desc) in &d.sources {
            t.insert(Cause::Source { line: *l, desc: desc.clone() });
        }
        t
    }

    /// The functions a value passed as a callback may be: a lambda / closure written
    /// here, a free function, or a method named by a path.
    fn callback_targets(&self, f: &Flow, st: &State) -> Vec<usize> {
        let mut targets = self.refs_of(f, st, true);
        if let Flow::Path(p) = f
            && let Some((root, method)) = p.rsplit_once('.')
        {
                let r = match st.types.get(&self.type_key(root)) {
                    Some(class) => self.env.resolver.resolve_method(class, method, self.me.file_idx),
                    None => self.env.resolver.resolve(p, self.me.file_idx),
                };
                // A method explicitly passed as a callback can denote any visible
                // implementation when its receiver's class is unknown.
                targets.extend(r.ids);
        }
        targets.into_iter().collect()
    }

    /// What the arguments of a call do inside the callee: reach its sinks or
    /// get stored in fields of its class.
    fn check_callees(&self, c: &CallFlow, st: &State, line: usize, out: &mut Output) {
        let resolved = self.resolve(c, st);
        if !resolved.exact {
            return; // a guess by method name must not invent findings
        }
        for &t in &resolved.ids {
            let Some(sum) = self.env.summary(t) else { continue };
            let callee = &self.env.fns[t];
            let step = format!("{}() at {}:{}", callee.cfg.name, base(self.me.file), c.line);
            for (j, hits) in sum.param_sinks.iter().enumerate() {
                let Some(arg) = (!hits.is_empty()).then(|| arg_for(c, j, &callee.cfg.params)).flatten() else { continue };
                let (by_prop, whole): (Vec<Hit>, Vec<Hit>) = hits.iter().cloned().partition(|h| h.prop.is_some());
                if !whole.is_empty() {
                    self.apply_hits(&whole, &self.eval(arg, st, line), &step, out);
                }
                for h in &by_prop {
                    let name = h.prop.as_deref().unwrap_or_default();
                    self.apply_hits(std::slice::from_ref(h), &self.prop_taint(c, arg, name, st, line), &step, out);
                    // our own parameter is handed on as the options object
                    if let Flow::Path(p) = arg
                        && let Some(m) = self.me.cfg.params.iter().position(|ns| ns.contains(p))
                    {
                        let mut path = vec![step.clone()];
                        path.extend(h.path.iter().cloned());
                        out.hit(m, Hit { finding: h.finding.clone(), path, prop: h.prop.clone() });
                    }
                }
            }
            // `r.run()` where `r` holds untrusted data in its fields and `run` reads them
            if let Some(recv) = &c.recv
                && !sum.recv_sinks.is_empty()
            {
                self.apply_hits(&sum.recv_sinks, &self.eval(recv, st, line), &step, out);
            }
            // a function passed in is called by the callee with these arguments
            for cb in &sum.callbacks {
                let Some(arg) = arg_for(c, cb.param, &callee.cfg.params) else { continue };
                let forwarded = match arg {
                    Flow::Path(p) => self.me.cfg.params.iter().position(|ns| ns.iter().any(|n| n == p)),
                    _ => None,
                };
                if let Some(m) = forwarded.filter(|_| self.refs_of(arg, st, true).is_empty()) {
                    // our own parameter is handed on: we call it, too
                    let args = cb.args.iter().map(|d| split_deps(&self.deps_taint(d, c, &callee.cfg.params, st, line))).collect();
                    out.callback(CallbackUse { param: m, args, ret: cb.ret && self.ret_calls.contains(&c.callee) });
                    continue;
                }
                for g in self.callback_targets(arg, st) {
                    let Some(sg) = self.env.summary(g) else { continue };
                    let step = format!("{}() via {}() at {}:{}", self.env.fns[g].cfg.name, callee.cfg.name, base(self.me.file), c.line);
                    if let Flow::Path(p) = arg && let Some((receiver, _)) = p.rsplit_once('.') {
                        self.apply_hits(&sg.recv_sinks, &self.eval(&Flow::Path(receiver.to_string()), st, line), &step, out);
                    }
                    for (k, hits) in sg.param_sinks.iter().enumerate() {
                        let Some(d) = (!hits.is_empty()).then(|| cb.args.get(k)).flatten() else { continue };
                        self.apply_hits(hits, &self.deps_taint(d, c, &callee.cfg.params, st, line), &step, out);
                    }
                }
            }
            // `Job(input())` where the constructor stores its parameter in `self.cmd`
            for (key, params) in &sum.field_writes {
                for &j in params {
                    if let Some(arg) = arg_for(c, j, &callee.cfg.params) {
                        let taint = self.eval(arg, st, line);
                        out.field_write(key.clone(), &taint, self.me.file, c.line);
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct Output {
    findings: Vec<Finding>,
    param_sinks: Vec<Vec<Hit>>,
    field_writes: BTreeMap<FieldKey, BTreeSet<usize>>,
    field_taints: Vec<(FieldKey, Taint)>,
    /// Sinks reached from the creating function's parameters (closures only).
    outer_sinks: Vec<(usize, Hit)>,
    recv_sinks: Vec<Hit>,
    callbacks: Vec<CallbackUse>,
}

impl Output {
    fn callback(&mut self, cb: CallbackUse) {
        if self.callbacks.len() < MAX_CALLBACKS && !self.callbacks.contains(&cb) {
            self.callbacks.push(cb);
        }
    }

    fn hit(&mut self, param: usize, hit: Hit) {
        if hit.path.len() > MAX_PATH {
            return;
        }
        if param == RECV_PARAM {
            let key = |h: &Hit| (h.finding.file.clone(), h.finding.line, h.finding.col, h.finding.rule);
            if self.recv_sinks.len() < MAX_HITS_PER_PARAM && !self.recv_sinks.iter().any(|h| key(h) == key(&hit)) {
                self.recv_sinks.push(hit);
            }
            return;
        }
        if param >= OUTER_PARAM {
            if self.outer_sinks.len() < MAX_HITS_PER_PARAM {
                self.outer_sinks.push((param - OUTER_PARAM, hit));
            }
            return;
        }
        if self.param_sinks.len() <= param {
            self.param_sinks.resize_with(param + 1, Vec::new);
        }
        let list = &mut self.param_sinks[param];
        let key = |h: &Hit| (h.finding.file.clone(), h.finding.line, h.finding.col, h.finding.rule);
        if list.len() < MAX_HITS_PER_PARAM && !list.iter().any(|h| key(h) == key(&hit)) {
            list.push(hit);
        }
    }

    /// A field receives `taint`: parameters go into the summary, real sources
    /// into the project-wide field facts.
    fn field_write(&mut self, key: FieldKey, taint: &Taint, file: &Path, line: usize) {
        let mut sources = Taint::new();
        for k in taint {
            match k {
                Cause::Param(j) if *j < OUTER_PARAM => {
                    self.field_writes.entry(key.clone()).or_default().insert(*j);
                }
                Cause::Param(_) => {}
                Cause::Source { desc, line: l } => {
                    sources.insert(Cause::Source { line, desc: format!("{desc} at {}:{l}", base(file)) });
                }
            }
        }
        if !sources.is_empty() {
            self.field_taints.push((key, sources));
        }
    }
}

/// Merge `from` into the entry state `into`; true if `into` changed.
fn merge(into: &mut Option<State>, from: &State) -> bool {
    let Some(cur) = into else {
        *into = Some(from.clone());
        return true;
    };
    let mut changed = false;
    for (k, v) in &from.taint {
        let slot = cur.taint.entry(k.clone()).or_default();
        let before = slot.clone();
        union_into(slot, v);
        changed |= *slot != before;
    }
    // assigned on *every* path: intersect
    let before = cur.bound.len();
    cur.bound.retain(|x| from.bound.contains(x));
    changed |= cur.bound.len() != before;
    // a variable has a known class only if every path agrees
    let before = cur.types.len();
    cur.types.retain(|k, v| from.types.get(k) == Some(v));
    changed |= cur.types.len() != before;
    // function references: any path may have stored one
    for (k, v) in &from.fnrefs {
        let slot = cur.fnrefs.entry(k.clone()).or_default();
        let before = slot.len();
        slot.extend(v);
        changed |= slot.len() != before;
    }
    // aliases hold only if the same variables are grouped on every path
    if !cur.alias.is_empty() {
        let before = cur.alias.len();
        let keep: BTreeSet<String> = cur.alias.keys().filter(|k| mates(cur, k) == mates(from, k)).cloned().collect();
        cur.alias.retain(|k, _| keep.contains(k));
        changed |= cur.alias.len() != before;
    }
    changed
}

/// The pseudo-class under which the variables a closure captures are recorded
/// as tainted fields (the enclosing function writes them, the closure reads them).
fn capture_class(closure: usize) -> String {
    format!("<capture {closure}>")
}

fn closure_refs(f: &Flow, out: &mut Vec<(usize, usize)>) {
    match f {
        Flow::Path(p) => {
            if let Some((l, c)) = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')).and_then(|r| r.split_once(':')) {
                out.extend(l.parse().ok().zip(c.parse().ok()));
            }
        }
        Flow::Call(c) => {
            c.recv.iter().chain(&c.args).for_each(|x| closure_refs(x, out));
        }
        Flow::Join(v) => v.iter().for_each(|x| closure_refs(x, out)),
        Flow::Clean => {}
    }
}

fn analyze_fn(env: &Env, id: usize) -> FnResult {
    let me = &env.fns[id];
    let cfg = me.cfg;
    let mut ret_calls = HashSet::new();
    for s in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
        if let Some(r) = &s.ret {
            returned_calls(r, &mut ret_calls);
        }
    }
    let an = Analyzer { env, me, id, ret_calls, line: std::cell::Cell::new(0) };
    let bound = cfg.graph.node_bound();

    // Parameters are symbolic (for the summary); those of configured entry
    // points are also real sources of untrusted data.
    let simple = simple_name(&cfg.name);
    let entry_rule = me.rules.entries.iter().find(|e| wild(e.pattern, &cfg.name) || wild(e.pattern, simple));
    // what the enclosing function had in scope where this closure was created
    let class = capture_class(id);
    let mut entry = State::default();
    for (var, t) in env.class_fields(&class) {
        entry.taint.insert(var.clone(), t.clone());
    }
    for (i, names) in cfg.params.iter().enumerate() {
        for n in names {
            let mut t = Taint::from([Cause::Param(i)]);
            if entry_rule.is_some_and(|e| e.params.is_empty() || e.params.contains(&n.as_str())) {
                t.insert(Cause::Source { line: cfg.line, desc: format!("parameter `{n}` of {}()", cfg.name) });
            }
            entry.taint.insert(n.clone(), t);
            entry.bound.insert(n.clone());
        }
    }
    // the receiver's state is symbolic, too (what its caller knows about the object's fields)
    if let Some(r) = &cfg.receiver {
        entry.taint.insert(r.clone(), Taint::from([Cause::Param(RECV_PARAM)]));
    }
    // parameters declared with a class we know are instances of it
    for (n, t) in cfg.declared_vars() {
        if let Some(class) = env.classes.get(t) {
            entry.types.insert(n.to_string(), class.clone());
        }
    }
    // Implicit flows: what a branch on tainted data controls is tainted, too (off by default).
    // `controllers[(block, idx)]` lists the branch statements that decide whether it runs.
    let mut controllers: HashMap<(NodeIndex, usize), Vec<(NodeIndex, usize)>> = HashMap::new();
    if super::config::implicit_flows() {
        let sg = crate::cpg::cfg::stmt_graph(cfg);
        for (a, d, _) in crate::cpg::cdg::control_dependence(&sg) {
            if let (SNode::Stmt { block: ab, idx: ai }, SNode::Stmt { block: db, idx: di }) = (sg.graph[a], sg.graph[d]) {
                controllers.entry((db, di)).or_default().push((ab, ai));
            }
        }
    }
    type Implicit = HashMap<(NodeIndex, usize), Taint>;
    // a statement's effect, with the taint of the branches that control it added to what it assigns
    let step = |s: &Stmt, st: &mut State, implicit: Option<&Taint>| {
        an.transfer(s, st);
        if let Some(t) = implicit {
            for a in &s.assigns {
                store(st, &a.target, t.clone(), false);
            }
        }
    };
    let solve = |implicit: &Implicit| -> Vec<Option<State>> {
        let mut inn: Vec<Option<State>> = vec![None; bound];
        let mut queued = vec![false; bound];
        inn[cfg.entry.index()] = Some(entry.clone());
        let mut work: VecDeque<NodeIndex> = VecDeque::from([cfg.entry]);
        queued[cfg.entry.index()] = true;

        // Taint only ever grows, so this terminates; the cap guards pathological graphs.
        let mut budget = bound * 50 + 1000;
        while let Some(b) = work.pop_front() {
            queued[b.index()] = false;
            if budget == 0 {
                break;
            }
            budget -= 1;
            let mut st = inn[b.index()].clone().expect("queued blocks have a state");
            for (i, s) in cfg.graph[b].stmts.iter().enumerate() {
                step(s, &mut st, implicit.get(&(b, i)));
            }
            for succ in cfg.graph.neighbors(b) {
                if merge(&mut inn[succ.index()], &st) && !queued[succ.index()] {
                    queued[succ.index()] = true;
                    work.push_back(succ);
                }
            }
        }
        inn
    };
    // what each controlled statement inherits from the conditions that are tainted at the final states
    let implicit_from = |inn: &[Option<State>], implicit: &Implicit| -> Implicit {
        let mut cond: HashMap<(NodeIndex, usize), Taint> = HashMap::new();
        for b in cfg.graph.node_indices() {
            let Some(start) = &inn[b.index()] else { continue };
            let mut st = start.clone();
            for (i, s) in cfg.graph[b].stmts.iter().enumerate() {
                if let Some(c) = &s.cond {
                    let t = an.eval(c, &st, s.line);
                    if !t.is_empty() {
                        cond.insert((b, i), t);
                    }
                }
                step(s, &mut st, implicit.get(&(b, i)));
            }
        }
        // a branch under a tainted branch is tainted as well
        let mut out: Implicit = HashMap::new();
        loop {
            let mut changed = false;
            for (d, cs) in &controllers {
                let mut t = out.get(d).cloned().unwrap_or_default();
                let before = t.len();
                for c in cs.iter().filter(|c| *c != d) {
                    union_into(&mut t, cond.get(c).unwrap_or(&Taint::new()));
                    union_into(&mut t, out.get(c).unwrap_or(&Taint::new()));
                }
                if t.len() != before {
                    changed = true;
                }
                if !t.is_empty() {
                    out.insert(*d, t);
                }
            }
            if !changed {
                break;
            }
        }
        out
    };
    let mut implicit = Implicit::new();
    let mut inn = solve(&implicit);
    // the conditions depend on the states, which depend on the conditions: a few rounds settle it
    for _ in 0..4 {
        if controllers.is_empty() {
            break;
        }
        let next = implicit_from(&inn, &implicit);
        if next == implicit {
            break;
        }
        implicit = next;
        inn = solve(&implicit);
    }

    // Replay with the final states: report sinks, collect what flows out.
    let reassigned: HashSet<&str> = cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns).map(|a| a.target.as_str()).collect();
    let mut out = Output::default();
    let mut summary = Summary::default();
    let mut ret_src: Option<(usize, String)> = None;
    for b in cfg.graph.node_indices() {
        let Some(start) = &inn[b.index()] else { continue };
        let mut st = start.clone();
        for (idx, s) in cfg.graph[b].stmts.iter().enumerate() {
            an.check(s, &st, &mut out);
            an.record_fields(s, &st, &mut out);
            an.record_captures(s, &st, &mut out);
            for c in &s.calls {
                let resolved = an.resolve(c, &st);
                for id in resolved.ids.into_iter().filter(|_| resolved.exact) {
                    let Some(sum) = env.summary(id) else { continue };
                    let params = &env.fns[id].cfg.params;
                    for ((j, suffix), d) in &sum.param_writes {
                        let Some(Flow::Path(actual)) = arg_for(c, *j, params) else { continue };
                        let (root, rest) = actual.split_once('.').map_or((actual.as_str(), String::new()), |(r, x)| (r, format!(".{x}")));
                        let Some(outer) = cfg.params.iter().position(|ns| ns.iter().any(|n| n == root)) else { continue };
                        let mut deps = split_deps(&an.deps_taint(d, c, params, &st, s.line));
                        deps.params.retain(|p| *p < OUTER_PARAM);
                        let slot = summary.param_writes.entry((outer, format!("{rest}{suffix}"))).or_default();
                        slot.params.extend(deps.params);
                        slot.sources.extend(deps.sources);
                    }
                    for ((j, suffix), (direct, inputs)) in &sum.callable_writes {
                        let Some(Flow::Path(actual)) = arg_for(c, *j, params) else { continue };
                        let Some(outer) = cfg.params.iter().position(|ns| ns.contains(actual)) else { continue };
                        let slot = summary.callable_writes.entry((outer, suffix.clone())).or_default();
                        slot.0.extend(direct);
                        for &i in inputs {
                            if let Some(arg) = arg_for(c, i, params) {
                                slot.0.extend(an.refs_of(arg, &st, true));
                                slot.1.extend(split_deps(&an.eval(arg, &st, s.line)).params.into_iter().filter(|p| *p < OUTER_PARAM));
                            }
                        }
                    }
                }
            }
            for a in &s.assigns {
                let (root, suffix) = a.target.split_once('.').map_or((a.target.as_str(), String::new()), |(r, s)| (r, format!(".{s}")));
                if (!a.strong || !suffix.is_empty())
                    && let Some(param) = cfg.params.iter().position(|ns| ns.iter().any(|n| n == root))
                {
                    let refs = an.refs_of(&a.value, &st, true);
                    let deps = split_deps(&an.eval(&a.value, &st, s.line));
                    if !suffix.is_empty() {
                        let slot = summary.param_writes.entry((param, suffix.clone())).or_default();
                        slot.params.extend(deps.params.iter().copied().filter(|p| *p < OUTER_PARAM));
                        slot.sources.extend(deps.sources.iter().cloned());
                    }
                    let inputs = deps.params;
                    let slot = summary.callable_writes.entry((param, suffix)).or_default();
                    slot.0.extend(refs);
                    slot.1.extend(inputs.into_iter().filter(|p| *p < OUTER_PARAM));
                }
            }
            if let Some(r) = &s.ret {
                // the properties of a returned literal, or of a variable that holds one
                let mut props: Vec<(String, Taint)> = s.ret_props.iter().map(|(k, f)| (k.clone(), an.eval(f, &st, s.line))).collect();
                if let Flow::Path(p) = r {
                    props.extend(an.entries_of(&st, p));
                }
                for (name, taint) in props {
                    let mut deps = split_deps(&taint);
                    deps.params.retain(|p| *p < OUTER_PARAM);
                    if !deps.params.is_empty() || !deps.sources.is_empty() {
                        let slot = summary.ret_props.entry(name).or_default();
                        slot.params.extend(deps.params);
                        // described with where it comes from, like a returned source
                        slot.sources.extend(deps.sources.into_iter().map(|(l, desc)| (0, format!("{desc} at {}:{l}", base(me.file)))));
                    }
                }
                summary.ret_fns.extend(an.refs_of(r, &st, true));
                if let Flow::Path(name) = r
                    && !reassigned.contains(name.as_str())
                    && let Some(i) = cfg.params.iter().position(|ns| ns.contains(name))
                {
                    summary.ret_alias.insert(i);
                }
                let carried = implicit.get(&(b, idx)).cloned().unwrap_or_default();
                for k in an.eval(r, &st, s.line).into_iter().chain(carried) {
                    match k {
                        Cause::Param(RECV_PARAM) => summary.ret_recv = true,
                        Cause::Param(i) if i >= OUTER_PARAM => {}
                        Cause::Param(i) => {
                            summary.ret_params.insert(i);
                        }
                        Cause::Source { line, desc } => {
                            if ret_src.as_ref().is_none_or(|(l, d)| (line, &desc) < (*l, d)) {
                                ret_src = Some((line, desc));
                            }
                        }
                    }
                }
            }
            step(s, &mut st, implicit.get(&(b, idx)));
        }
    }
    summary.ret_source = ret_src.map(|(line, desc)| format!("{desc} at {}:{line}", base(me.file)));
    // sinks inside closures this function created, reached from its parameters
    for (param, hit) in env.outer_hits(id) {
        out.hit(*param, hit.clone());
    }
    out.param_sinks.resize_with(cfg.params.len(), Vec::new);
    summary.param_sinks = out.param_sinks;
    summary.field_writes = out.field_writes;
    summary.recv_sinks = out.recv_sinks;
    // what the closure leaves in the variables it assigns of its creator's scope
    if let Some(end) = &inn[cfg.exit.index()] {
        for name in &cfg.free_writes {
            let d = split_deps(&lookup(end, name));
            if !d.params.is_empty() || !d.sources.is_empty() {
                summary.captured_writes.insert(name.clone(), d);
            }
        }
    }
    summary.callbacks = out.callbacks;
    FnResult { findings: out.findings, summary, field_taints: out.field_taints, outer_sinks: out.outer_sinks }
}

/// Analyze every function: callees before callers, independent groups in
/// parallel. `progress` is called once per function in the first pass.
pub fn analyze_project(
    fns: &[FnInfo],
    visible: Option<Vec<std::collections::HashSet<usize>>>,
    progress: &(dyn Fn() + Sync),
) -> Vec<Finding> {
    use petgraph::algo::tarjan_scc;
    use petgraph::graph::DiGraph;

    let resolver = Resolver::new(fns.iter().map(|f| (f.file_idx, f.lang.family(), f.cfg.name.as_str())))
        .with_hierarchy(fns.iter().map(|f| (f.cfg.name.as_str(), f.cfg.class_bases.as_slice())))
        .with_visibility(visible)
        .with_hierarchy(fns.iter().map(|f| (f.cfg.name.as_str(), f.cfg.class_bases.as_slice())));
    let types = Types::infer(&fns.iter().map(|f| (f.file_idx, f.lang, f.cfg)).collect::<Vec<_>>(), &resolver);
    let mut graph: DiGraph<(), ()> = DiGraph::with_capacity(fns.len(), fns.len());
    for _ in fns {
        graph.add_node(());
    }
    let closures: HashMap<(usize, usize, usize), usize> =
        fns.iter().enumerate().map(|(id, f)| ((f.file_idx, f.cfg.line, f.cfg.col), id)).collect();
    let field_fns = collect_field_fns(fns.iter().map(|f| (f.file_idx, f.cfg)), &resolver, &closures);
    for (id, f) in fns.iter().enumerate() {
        let mut edge = |t: usize| {
            graph.update_edge(NodeIndex::new(id), NodeIndex::new(t), ());
        };
        // the registry a path reads from: a field of the object, or a module-level variable
        let registry = |p: &str| -> FieldKey {
            match (p.split_once('.'), f.cfg.receiver.as_deref(), class_of(&f.cfg.name)) {
                (Some((r, rest)), Some(recv), Some(class)) if r == recv => {
                    (class.to_string(), rest.split('.').next().unwrap_or(rest).to_string())
                }
                _ => module_key(f.file_idx, p.split('.').next().unwrap_or(p)),
            }
        };
        for st in f.cfg.graph.node_weights().flat_map(|b| &b.stmts) {
            let mut read = vec![];
            for c in &st.calls {
                resolver.resolve(&c.callee, f.file_idx).ids.into_iter().for_each(&mut edge);
                if let Some((path, method)) = c.callee.rsplit_once('.')
                    && let Some(class) = types.path_class(&resolver, f.cfg, path, |root| types.locals[id].get(root).cloned())
                {
                    resolver.resolve_method(&class, method, f.file_idx).ids.into_iter().for_each(&mut edge);
                }
                read.push(c.callee.clone());
                c.recv.iter().chain(&c.args).for_each(|x| flow_paths(x, &mut read));
            }
            st.assigns.iter().for_each(|a| flow_paths(&a.value, &mut read));
            st.ret.iter().for_each(|r| flow_paths(r, &mut read));
            // a function stored in a field or a module-level registry that this function reads
            for p in read {
                field_fns.get(&registry(&p)).into_iter().flatten().copied().for_each(&mut edge);
                if p.contains('.') { resolver.resolve(&p, f.file_idx).ids.into_iter().for_each(&mut edge); }
            }
            // functions handed over or stored must be analyzed before the function that uses them
            let mut vals = BTreeSet::new();
            st.assigns.iter().for_each(|a| flow_fn_values(&a.value, f.file_idx, &resolver, &closures, &mut vals));
            st.calls.iter().for_each(|c| c.args.iter().for_each(|x| flow_fn_values(x, f.file_idx, &resolver, &closures, &mut vals)));
            vals.into_iter().for_each(&mut edge);
        }
    }

    // tarjan lists a component after everything it calls
    let comps = tarjan_scc(&graph);
    let mut comp_of = vec![0usize; fns.len()];
    for (ci, comp) in comps.iter().enumerate() {
        for n in comp {
            comp_of[n.index()] = ci;
        }
    }
    let mut level = vec![0usize; comps.len()];
    for (ci, comp) in comps.iter().enumerate() {
        for n in comp {
            for callee in graph.neighbors(*n) {
                let cc = comp_of[callee.index()];
                if cc != ci {
                    level[ci] = level[ci].max(level[cc] + 1);
                }
            }
        }
    }
    let mut by_level: Vec<Vec<usize>> = vec![];
    for (ci, &l) in level.iter().enumerate() {
        if by_level.len() <= l {
            by_level.resize_with(l + 1, Vec::new);
        }
        by_level[l].push(ci);
    }

    // classes by simple name (ambiguous names are dropped)
    let mut classes: HashMap<String, String> = HashMap::new();
    let mut ambiguous: std::collections::HashSet<String> = Default::default();
    for f in fns {
        if let Some(c) = class_of(&f.cfg.name) {
            let simple = simple_name(c).to_string();
            if classes.get(&simple).is_some_and(|prev| prev != c) {
                ambiguous.insert(simple.clone());
            }
            classes.insert(simple, c.to_string());
        }
    }
    classes.retain(|k, _| !ambiguous.contains(k));

    // who creates which closure (the first function that mentions it)
    let mut creators: HashMap<usize, usize> = HashMap::new();
    for (id, f) in fns.iter().enumerate() {
        let mut refs = vec![];
        for st in f.cfg.graph.node_weights().flat_map(|b| &b.stmts) {
            st.assigns.iter().for_each(|a| closure_refs(&a.value, &mut refs));
            st.calls.iter().for_each(|c| c.recv.iter().chain(&c.args).for_each(|x| closure_refs(x, &mut refs)));
            st.ret.iter().for_each(|r| closure_refs(r, &mut refs));
        }
        for (l, c) in refs {
            if let Some(&cid) = closures.get(&(f.file_idx, l, c)) {
                creators.entry(cid).or_insert(id);
            }
        }
    }
    let plan = Plan { resolver: &resolver, types: &types, graph: &graph, comps: &comps, by_level: &by_level, classes: &classes, closures: &closures, creators: &creators, field_fns: &field_fns };

    // Pass 0 knows no tainted fields. If it finds some, analyze again with
    // them, until no new ones appear; the last pass's findings are the result.
    let mut fields = FieldTaint::new();
    let mut outer = OuterHits::new();
    let mut carry = Carry { cache: vec![None; comps.len()], summaries: vec![None; fns.len()], versions: vec![0; fns.len()] };
    // versions start at 1: 0 means a summary that does not exist yet
    let version_counter = std::sync::atomic::AtomicU64::new(1);
    let mut result = vec![];
    let capture_depth = creators.keys().map(|&id| {
        let mut current = id;
        let mut depth = 0;
        while let Some(&parent) = creators.get(&current) {
            depth += 1;
            current = parent;
            if depth >= fns.len() { break; }
        }
        depth
    }).max().unwrap_or(0);
    for pass in 0..=MAX_FIELD_ROUNDS + capture_depth * 2 {
        let silent: &(dyn Fn() + Sync) = &|| {};
        let ((findings, found, found_outer), next) = run_pass(fns, &plan, &fields, &outer, &carry, &version_counter, if pass == 0 { progress } else { silent });
        carry = next;
        result = findings;
        let mut next = fields.clone();
        for (k, t) in found {
            union_into(next.entry(k).or_default(), &t);
        }
        let mut next_outer = found_outer;
        next_outer.values_mut().for_each(|v| v.sort_by_key(|(p, h)| (*p, h.finding.line, h.finding.col)));
        if next == fields && next_outer == outer {
            break;
        }
        fields = next;
        outer = next_outer;
    }
    result
}

type Pass = (Vec<Finding>, Vec<(FieldKey, Taint)>, OuterHits);

/// The call-graph structure shared by all passes.
#[derive(Clone, Copy)]
struct Plan<'a> {
    resolver: &'a Resolver,
    types: &'a Types,
    graph: &'a petgraph::graph::DiGraph<(), ()>,
    comps: &'a [Vec<NodeIndex>],
    by_level: &'a [Vec<usize>],
    classes: &'a HashMap<String, String>,
    closures: &'a HashMap<(usize, usize, usize), usize>,
    creators: &'a HashMap<usize, usize>,
    field_fns: &'a FieldFns,
}

/// What a pass leaves for the next one.
struct Carry {
    cache: Vec<Option<Cached>>,
    summaries: Vec<Option<Summary>>,
    versions: Vec<u64>,
}

fn run_pass(fns: &[FnInfo], plan: &Plan, fields: &FieldTaint, outer: &OuterHits, prev: &Carry, version_counter: &std::sync::atomic::AtomicU64, progress: &(dyn Fn() + Sync)) -> (Pass, Carry) {
    let (prev_cache, prev_summaries, prev_versions) = (&prev.cache, &prev.summaries, &prev.versions);
    let Plan { resolver, types, graph, comps, by_level, classes, closures, creators, field_fns } = *plan;
    use rayon::prelude::*;
    let mut summaries: Vec<Option<Summary>> = vec![None; fns.len()];
    let mut cache: Vec<Option<Cached>> = vec![None; comps.len()];
    let mut versions: Vec<u64> = vec![0; fns.len()];
    let (mut findings, mut field_taints) = (vec![], vec![]);
    let mut next_outer = OuterHits::new();
    for comps_here in by_level {
        let solved: Vec<(usize, Cached)> = comps_here
            .par_iter()
            .map(|&ci| {
                if let Some(c) = prev_cache[ci].as_ref().filter(|c| c.reads.still_hold(&versions, fields, outer)) {
                    return (ci, c.clone());
                }
                let members: Vec<usize> = comps[ci].iter().map(|n| n.index()).collect();
                let recursive = members.len() > 1 || graph.contains_edge(NodeIndex::new(members[0]), NodeIndex::new(members[0]));
                let mut overlay: HashMap<usize, Summary> = HashMap::new();
                if recursive {
                    for &m in &members {
                        overlay.insert(m, Summary { param_sinks: vec![vec![]; fns[m].cfg.params.len()], ..Summary::default() });
                    }
                }
                let mut results: Vec<(usize, FnResult)> = vec![];
                // everything any round read: a result is reusable only if none of it changed
                let mut reads = Reads::default();
                for _ in 0..if recursive { MAX_SCC_ROUNDS } else { 1 } {
                    let env = Env { reads: Default::default(), fns, resolver, types, summaries: &summaries, versions: &versions, overlay: &overlay, fields, classes, closures, outer, field_fns, creators };
                    results = members.iter().map(|&m| (m, analyze_fn(&env, m))).collect();
                    let seen = env.reads.take();
                    reads.summaries.extend(seen.summaries.into_iter().filter(|(f, _)| !members.contains(f)));
                    reads.fields.extend(seen.fields);
                    reads.classes.extend(seen.classes);
                    reads.outer.extend(seen.outer);
                    let next: HashMap<usize, Summary> = results.iter().map(|(m, r)| (*m, r.summary.clone())).collect();
                    let stable = next == overlay;
                    overlay = next;
                    if !recursive || stable {
                        break;
                    }
                }
                reads.summaries.sort_by_key(|(f, _)| *f);
                reads.summaries.dedup_by_key(|(f, _)| *f);
                results.iter().for_each(|_| progress());
                (ci, Cached { reads, results })
            })
            .collect();
        for (ci, group) in solved {
            for (id, r) in &group.results {
                let id = *id;
                // an unchanged summary keeps its version; a changed one gets a fresh, never reused, number
                versions[id] = match prev_summaries[id].as_ref() {
                    Some(old) if *old == r.summary => prev_versions[id],
                    _ => version_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                };
                summaries[id] = Some(r.summary.clone());
                findings.extend(r.findings.iter().cloned());
                field_taints.extend(r.field_taints.iter().cloned());
                if let Some(&creator) = creators.get(&id) {
                    next_outer.entry(creator).or_default().extend(r.outer_sinks.iter().cloned());
                }
            }
            cache[ci] = Some(group);
        }
    }
    ((findings, field_taints, next_outer), Carry { cache, summaries, versions })
}
