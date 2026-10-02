//! Data flow graph: which definition of a value reaches which use.
//!
//! Nodes are parameters, assignments, calls, returns and free variables
//! (globals, `request.args`, ...). An edge `a -> b` means the value of `a` may
//! flow into `b`. Inside a function the edges come from a reaching-definitions
//! fixpoint over the CFG; across functions, call arguments are linked to the
//! callee's parameters and the callee's returns to the call. Variables are
//! tracked by access path (`self.a` and `self.b` are separate; `a[i]` counts as `a`). Objects that are
//! the same under two names are followed: `b = a`, `h.r = a`, `b = identity(a)`, and fields a callee
//! assigns on its parameters (`fill(a)` defines `a.d`). Aliases hold for the whole function (a variable
//! that is assigned once).

use super::ProjectFile;
use super::callgraph::{Resolver, Types, last_segment, simple_name};
use super::deps;
use super::rules::MUTATORS;
use super::taint::{FieldFns, arg_for, class_of, collect_field_fns, module_key, parameter_key, return_key, callable_writes};
use crate::cpg::{cdg::control_dependence, cfg::{SNode, stmt_graph}};
use crate::ir::{CallFlow, Flow, Stmt, StmtKind};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A function parameter.
    Param,
    /// A variable or field that is assigned.
    Def,
    /// A call: it joins its arguments and produces a result.
    Call,
    /// A `return` (or implicit return).
    Return,
    /// A value defined outside the function: a global, `request.args`, ...
    Free,
    /// A branch: the test of an `if` / loop; with `control`, it points to what it decides.
    Branch,
    /// A field of a class (`Job.cmd`), shared by all its methods: what methods
    /// store in `self.cmd` flows into what other methods read from it.
    Field,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Inside one function.
    Flow,
    /// Call argument -> callee parameter.
    Arg,
    /// Callee return -> call.
    Ret,
    /// Branch -> a statement that only runs depending on it.
    Control,
}

#[derive(Debug, Clone)]
pub struct Node {
    /// Index into [`DataFlow::functions`].
    pub func: usize,
    pub kind: NodeKind,
    /// The variable, parameter, callee or path this node stands for.
    pub var: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub kind: EdgeKind,
    /// For `Arg` edges: the callee parameter that receives the value.
    pub label: Option<String>,
}

pub struct FnMeta {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
}

pub struct DataFlow {
    pub functions: Vec<FnMeta>,
    pub graph: DiGraph<Node, Edge>,
}

/// Reaching definitions per path, and the functions each path may hold
/// (`h = sink`, `self.cb = f`, `handlers[k] = f`, `queue.append(f)`).
#[derive(Clone, Default)]
struct State {
    defs: BTreeMap<String, BTreeSet<NodeIndex>>,
    fns: BTreeMap<String, BTreeSet<usize>>,
    /// Element paths (`xs[0]`) that were written with a literal on every way here: they shadow
    /// the definitions of the container for reads of that element.
    sealed: BTreeSet<String>,
}

impl State {
    fn new() -> Self {
        Self::default()
    }

    /// A strong write to `target` replaces what its fields and elements held.
    fn kill_below(&mut self, target: &str) {
        let under = |k: &str| k.strip_prefix(target).is_some_and(below);
        self.defs.retain(|k, _| !under(k));
        self.sealed.retain(|k| !under(k));
        self.fns.retain(|k, _| !under(k));
    }
}

impl std::ops::Deref for State {
    type Target = BTreeMap<String, BTreeSet<NodeIndex>>;
    fn deref(&self) -> &Self::Target {
        &self.defs
    }
}

impl std::ops::DerefMut for State {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.defs
    }
}

/// Per-function lookup tables for nodes, so each source position gets one node.
#[derive(Default)]
struct Local {
    defs: HashMap<(usize, usize, usize), NodeIndex>,
    calls: HashMap<(usize, usize, String), NodeIndex>,
    rets: HashMap<(usize, usize), NodeIndex>,
    free: HashMap<String, NodeIndex>,
    emitted: HashSet<NodeIndex>,
    /// `b = a` (assigned once): `b.f` is `a.f`.
    aliases: HashMap<String, String>,
    /// Class of a variable assigned from a constructor: `j = Job()`.
    types: HashMap<String, String>,
    /// Variables holding a function (`f = lambda ..`, `cb = handler`), assigned once.
    fn_vars: HashMap<String, usize>,
    /// Nodes made by each statement `(block, index)`.
    stmt_nodes: HashMap<(usize, usize), Vec<NodeIndex>>,
    /// The branch node of each branching statement.
    branches: HashMap<(usize, usize), NodeIndex>,
}

struct Builder<'a> {
    files: &'a [ProjectFile<'a>],
    /// `(file index, cfg index)` of every function, in function-id order.
    ids: Vec<(usize, usize)>,
    resolver: Resolver,
    types: Types,
    graph: DiGraph<Node, Edge>,
    seen: HashSet<(NodeIndex, NodeIndex, EdgeKind)>,
    params: Vec<Vec<Vec<NodeIndex>>>,
    /// The node of each method's receiver (`self`, `this`).
    receivers: Vec<Option<NodeIndex>>,
    rets: Vec<Vec<NodeIndex>>,
    /// Calls to link with the returns of their callees once every function is done.
    pending_rets: Vec<(NodeIndex, usize)>,
    /// Per function: the fields of its parameters it assigns (`o.d = x`), as `(parameter, ".d")`.
    write_targets: Vec<Vec<(usize, String)>>,
    /// Per function: the definition nodes of those assignments.
    writes: Vec<Vec<(usize, String, NodeIndex)>>,
    /// Calls to link with the field writes of their callees: `(call, callee, parameter, ".d")`.
    pending_writes: Vec<(NodeIndex, usize, usize, String)>,
    fields: HashMap<String, NodeIndex>,
    /// Also build branch nodes and control-dependence edges.
    control: bool,
    /// Lambdas and closures by `(file index, line, column)`.
    closures: HashMap<(usize, usize, usize), usize>,
    /// Where closures are created: the closure and the definitions in scope there.
    captures: Vec<(usize, State)>,
    /// The free variables of each function.
    frees: Vec<HashMap<String, NodeIndex>>,
    /// Functions stored in fields of a class or in module-level variables.
    field_fns: FieldFns,
    fid: usize,
}

/// The tracked part of a path: `a.b[i].c` and `a.b->c` are tracked as `a.b`. A literal key
/// (`[0]`, `['k']`) names one element, so `xs[0].d` is tracked as it is.
fn tracked(path: &str) -> &str {
    let b = path.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'-' => return &path[..i],
            b'[' => {
                let Some(close) = path[i..].find(']').map(|c| i + c) else { return &path[..i] };
                if !literal_key(&path[i + 1..close]) {
                    return &path[..i];
                }
                i = close;
            }
            _ => {}
        }
        i += 1;
    }
    path
}

/// The inside of `[..]` names one element: a small integer or a quoted word.
fn literal_key(k: &str) -> bool {
    let word = |w: &str| !w.is_empty() && w.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'));
    (!k.is_empty() && k.len() <= 6 && k.bytes().all(|c| c.is_ascii_digit()))
        || k.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')).is_some_and(word)
}

/// Is `rest` (what follows a path prefix) a field or an element of it?
fn below(rest: &str) -> bool {
    rest.starts_with(['.', '['])
}

/// The variable at the start of a path.
fn root(path: &str) -> &str {
    path.split(['.', '[', '-']).next().unwrap_or(path)
}

/// Definitions a read of `path` may see: those of the path itself, of its
/// parents (`self` for `self.a`) and of its fields (`self.a` for `self`).
fn reaching(st: &State, path: &str) -> BTreeSet<NodeIndex> {
    let k = tracked(path);
    let mut out = BTreeSet::new();
    // the path itself and the paths containing it, the longest first, until one is sealed
    let mut above: Vec<(&String, &BTreeSet<NodeIndex>)> =
        st.defs.iter().filter(|(e, _)| *e == k || k.strip_prefix(e.as_str()).is_some_and(below)).collect();
    above.sort_by_key(|(e, _)| std::cmp::Reverse(e.len()));
    for (e, defs) in above {
        out.extend(defs);
        if st.sealed.contains(e.as_str()) {
            break;
        }
    }
    // the fields and elements of the path: reading the whole object reads what was written into it
    for (e, defs) in &st.defs {
        if e.strip_prefix(k).is_some_and(below) {
            out.extend(defs);
        }
    }
    out
}

fn merge(into: &mut State, from: &State, first: bool) -> bool {
    let mut changed = false;
    // sealed on every way here
    if first {
        changed |= !from.sealed.is_empty();
        into.sealed = from.sealed.clone();
    } else {
        let before = into.sealed.len();
        into.sealed.retain(|p| from.sealed.contains(p));
        changed |= into.sealed.len() != before;
    }
    for (k, v) in &from.defs {
        let e = into.defs.entry(k.clone()).or_default();
        for n in v {
            changed |= e.insert(*n);
        }
    }
    for (k, v) in &from.fns {
        let e = into.fns.entry(k.clone()).or_default();
        for f in v {
            changed |= e.insert(*f);
        }
    }
    changed
}

pub fn build(files: &[ProjectFile], control: bool) -> DataFlow {
    let mut ids = vec![];
    for (fi, f) in files.iter().enumerate() {
        for ci in 0..f.cfgs.len() {
            ids.push((fi, ci));
        }
    }
    let dep_files: Vec<deps::DepFile> = files
        .iter()
        .map(|f| deps::DepFile { path: f.file, lang: f.lang, imports: f.imports.to_vec(), cfgs: f.cfgs })
        .collect();
    let visible = (!files.iter().all(|f| f.imports.is_empty())).then(|| deps::visibility(&dep_files));
    let resolver = Resolver::new(ids.iter().map(|&(fi, ci)| (fi, files[fi].lang.family(), files[fi].cfgs[ci].name.as_str())))
        .with_visibility(visible)
        .with_hierarchy(ids.iter().map(|&(fi, ci)| { let c = &files[fi].cfgs[ci]; (c.name.as_str(), c.class_bases.as_slice()) }));

    let functions: Vec<FnMeta> = ids
        .iter()
        .map(|&(fi, ci)| FnMeta { name: files[fi].cfgs[ci].name.clone(), file: files[fi].file.to_path_buf(), line: files[fi].cfgs[ci].line })
        .collect();
    let types = Types::infer(&ids.iter().map(|&(fi, ci)| (fi, files[fi].lang, &files[fi].cfgs[ci])).collect::<Vec<_>>(), &resolver);
    let mut b = Builder {
        types,
        files,
        ids,
        resolver,
        graph: DiGraph::new(),
        seen: HashSet::new(),
        params: vec![],
        receivers: vec![],
        rets: vec![],
        pending_rets: vec![],
        write_targets: vec![],
        writes: vec![],
        pending_writes: vec![],
        fields: HashMap::new(),
        control,
        closures: HashMap::new(),
        captures: vec![],
        frees: vec![],
        field_fns: FieldFns::new(),
        fid: 0,
    };

    // Parameter nodes first: calls in any function link to them.
    for fid in 0..b.ids.len() {
        let cfg = b.cfg(fid);
        b.closures.insert((b.ids[fid].0, cfg.line, cfg.col), fid);
    }
    b.field_fns = collect_field_fns(b.ids.iter().map(|&(fi, ci)| (fi, &files[fi].cfgs[ci])), &b.resolver, &b.closures);
    for fid in 0..b.ids.len() {
        let cfg = b.cfg(fid);
        let ps: Vec<Vec<NodeIndex>> = cfg
            .params
            .iter()
            .map(|names| names.iter().map(|n| b.node(fid, NodeKind::Param, n, cfg.line)).collect())
            .collect();
        b.params.push(ps);
        let recv = cfg.receiver.as_deref().map(|r| b.node(fid, NodeKind::Param, r, cfg.line));
        b.receivers.push(recv);
        b.rets.push(vec![]);
        b.frees.push(HashMap::new());
        b.writes.push(vec![]);
        let targets = b.param_writes(fid);
        b.write_targets.push(targets);
    }
    for fid in 0..b.ids.len() {
        b.fid = fid;
        b.function(fid);
    }
    let pending = std::mem::take(&mut b.pending_rets);
    for (call, callee) in pending {
        for r in b.rets[callee].clone() {
            b.edge(r, call, EdgeKind::Ret, None);
        }
    }
    // what a callee stores in the fields of its parameters flows into the call
    for (call, callee, param, suffix) in std::mem::take(&mut b.pending_writes) {
        for (_, _, node) in b.writes[callee].clone().into_iter().filter(|(j, sfx, _)| *j == param && *sfx == suffix) {
            b.edge(node, call, EdgeKind::Flow, None);
        }
    }
    // variables a closure uses but does not define come from where it was created
    for (cid, st) in std::mem::take(&mut b.captures) {
        for (path, node) in b.frees[cid].clone() {
            for def in reaching(&st, tracked(&path)) {
                b.edge(def, node, EdgeKind::Arg, Some("captured".into()));
            }
        }
    }
    DataFlow { functions, graph: b.graph }
}

impl<'a> Builder<'a> {
    /// The class of `root` at `line`: the declaration in effect there, else what the function's
    /// flow knows (a name declared in two scopes has no single class for the whole function).
    fn class_at(&self, loc: &Local, root: &str, line: usize) -> Option<String> {
        self.cfg(self.fid)
            .declared_type_at(root, line)
            .and_then(|t| self.resolver.class_named(t))
            .map(str::to_string)
            .or_else(|| loc.types.get(&self.cfg(self.fid).type_key(root, line)).cloned())
    }

    fn cfg(&self, fid: usize) -> &'a crate::ir::Cfg {
        let (fi, ci) = self.ids[fid];
        &self.files[fi].cfgs[ci]
    }

    /// The shared node of the field `self.<f>` of this method's class, for a
    /// path that starts at the receiver.
    fn field_node(&mut self, path: &str) -> Option<NodeIndex> {
        let cfg = self.cfg(self.fid);
        let recv = cfg.receiver.as_deref()?;
        let field = path.strip_prefix(recv)?.strip_prefix('.')?.split(['.', '[', '-']).next()?;
        let name = &cfg.name;
        let class = &name[..name.rfind(['.', ':'])?].trim_end_matches(':');
        let id = format!("{class}.{field}");
        let fid = self.fid;
        Some(*self.fields.entry(id.clone()).or_insert_with(|| self.graph.add_node(Node { func: fid, kind: NodeKind::Field, var: id, line: 0 })))
    }

    fn node(&mut self, func: usize, kind: NodeKind, var: &str, line: usize) -> NodeIndex {
        self.graph.add_node(Node { func, kind, var: var.to_string(), line })
    }

    fn edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind, label: Option<String>) {
        if from != to && self.seen.insert((from, to, kind)) {
            self.graph.add_edge(from, to, Edge { kind, label });
        }
    }

    fn function(&mut self, fid: usize) {
        let cfg = self.cfg(fid);
        let mut loc = Local::default();
        self.prepass(&mut loc, fid);
        loc.types.extend(self.types.locals[fid].clone());
        let mut entry = State::new();
        for names in cfg.params.iter().zip(&self.params[fid]) {
            for (name, &n) in names.0.iter().zip(names.1) {
                entry.entry(tracked(name).to_string()).or_default().insert(n);
                if let Some(refs) = self.field_fns.get(&parameter_key(fid, name)) {
                    entry.fns.insert(name.clone(), refs.clone());
                }
            }
        }
        if let (Some(name), Some(n)) = (&cfg.receiver, self.receivers[fid]) {
            entry.entry(name.clone()).or_default().insert(n);
        }

        // Reaching definitions: forward fixpoint over the blocks.
        let mut ins: HashMap<NodeIndex, State> = HashMap::new();
        ins.insert(cfg.entry, entry);
        let mut work: VecDeque<NodeIndex> = VecDeque::from([cfg.entry]);
        while let Some(blk) = work.pop_front() {
            let mut st = ins[&blk].clone();
            for (si, s) in cfg.graph[blk].stmts.iter().enumerate() {
                self.apply(&mut loc, (blk.index(), si), s, &mut st, false);
            }
            for succ in cfg.graph.neighbors(blk) {
                let is_new = !ins.contains_key(&succ);
                let changed = merge(ins.entry(succ).or_default(), &st, is_new);
                if (changed || is_new) && !work.contains(&succ) {
                    work.push_back(succ);
                }
            }
        }

        // With the fixpoint known, walk every statement once and add the edges.
        let mut blocks: Vec<NodeIndex> = cfg.graph.node_indices().collect();
        blocks.sort();
        for blk in blocks {
            let mut st = ins.get(&blk).cloned().unwrap_or_default();
            for (si, s) in cfg.graph[blk].stmts.iter().enumerate() {
                self.apply(&mut loc, (blk.index(), si), s, &mut st, true);
            }
        }
        if self.control {
            self.control_edges(cfg, &loc);
        }
        self.frees[fid] = loc.free;
    }

    /// Branch -> everything that only runs depending on it.
    fn control_edges(&mut self, cfg: &crate::ir::Cfg, loc: &Local) {
        let sg = stmt_graph(cfg);
        let key = |n: NodeIndex| match sg.graph[n] {
            SNode::Stmt { block, idx } => Some((block.index(), idx)),
            _ => None,
        };
        for (a, b, kind) in control_dependence(&sg) {
            let (Some(ka), Some(kb)) = (key(a), key(b)) else { continue };
            let Some(&branch) = loc.branches.get(&ka) else { continue };
            for &n in loc.stmt_nodes.get(&kb).into_iter().flatten() {
                self.edge(branch, n, EdgeKind::Control, Some(kind.as_str().to_string()));
            }
        }
    }

    /// Find aliases and variable types, which do not depend on control flow.
    fn prepass(&mut self, loc: &mut Local, fid: usize) {
        let cfg = self.cfg(fid);
        let (fi, _) = self.ids[fid];
        let mut count: HashMap<&str, usize> = HashMap::new();
        let assigns: Vec<&crate::ir::Assign> =
            cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns).collect();
        // the line of each assignment: a variable declared in several scopes is one per scope
        let lines: Vec<usize> = cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| s.assigns.iter().map(move |_| s.line)).collect();
        // `xs[0] = v` / `xs.append(v)` write into `xs`; only an assignment rebinds it
        for a in assigns.iter().filter(|a| a.strong || a.target.contains(['.', '['])) {
            *count.entry(&a.target).or_default() += 1;
        }
        for a in &assigns {
            if let (Flow::Path(p), 1, false) = (&a.value, count[a.target.as_str()], a.target.contains(['.', '[', '-']))
                && let Some(cb) = self.function_ref(cfg, p, fi, &count)
            {
                loc.fn_vars.insert(a.target.clone(), cb);
            }
        }
        let mut ambiguous: HashSet<String> = HashSet::new();
        for (a, line) in assigns.into_iter().zip(lines) {
            let key = cfg.type_key(&a.target, line);
            if !a.strong && !a.target.contains(['.', '[', '-']) {
                continue; // a write into the object, not a new binding
            }
            // `h.r = a`: the path `h.r` is `a` (not for the receiver's fields, which methods share)
            if a.target.contains('.')
                && !a.target.contains(['[', '-'])
                && cfg.receiver.as_deref() != Some(root(&a.target))
            {
                if let Flow::Path(p) = &a.value
                    && a.strong
                    && count.get(a.target.as_str()) == Some(&1)
                    && root(p) != root(&a.target)
                {
                    loc.aliases.insert(a.target.clone(), tracked(p).to_string());
                }
                continue;
            }
            if a.target.contains(['.', '[', '-']) {
                continue;
            }
            match &a.value {
                Flow::Path(p) if count[a.target.as_str()] == 1 && root(p) != a.target => {
                    loc.aliases.insert(a.target.clone(), tracked(p).to_string());
                }
                // `b = identity(a)`: the callee hands its argument back
                Flow::Call(c) if count[a.target.as_str()] == 1 && let Some(p) = self.returned_arg(c, fi) && root(&p) != a.target => {
                    loc.aliases.insert(a.target.clone(), tracked(&p).to_string());
                    ambiguous.insert(key);
                }
                Flow::Call(c) => match self.ctor_class(c, fi) {
                    Some(class) => {
                        if loc.types.insert(key.clone(), class.clone()).is_some_and(|old| old != class) {
                            ambiguous.insert(key);
                        }
                    }
                    None => {
                        ambiguous.insert(key);
                    }
                },
                _ => {
                    ambiguous.insert(key);
                }
            }
        }
        for v in &ambiguous {
            loc.types.remove(v);
        }
        if let (Some(r), Some(i)) = (&cfg.receiver, cfg.name.rfind(['.', ':'])) {
            loc.types.insert(r.clone(), cfg.name[..i].trim_end_matches(':').to_string());
        }
    }

    /// The function a path stands for: a lambda written in place or a scanned
    /// function mentioned by name (not a local variable or parameter).
    fn function_ref(&self, cfg: &crate::ir::Cfg, p: &str, fi: usize, assigned: &HashMap<&str, usize>) -> Option<usize> {
        if let Some(pos) = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')) {
            let (line, col) = pos.split_once(':')?;
            return self.closures.get(&(fi, line.parse().ok()?, col.parse().ok()?)).copied();
        }
        if p.contains('.') || assigned.contains_key(p) || cfg.params.iter().flatten().any(|n| n == p) {
            return None;
        }
        let r = self.resolver.resolve(p, fi);
        (r.exact && r.ids.len() == 1).then(|| r.ids[0])
    }

    /// `Job(..)`, `new Job(..)`, `Job::new(..)`: the class a call constructs.
    fn ctor_class(&self, c: &CallFlow, fi: usize) -> Option<String> {
        let r = self.resolver.resolve(&c.callee, fi);
        let [id] = r.ids[..] else { return self.resolver.class_named(simple_name(&c.callee)).map(str::to_string) };
        if !r.exact {
            return None;
        }
        let name = &self.cfg(id).name;
        let i = name.rfind(['.', ':'])?;
        let (class, method) = (name[..i].trim_end_matches(':'), &name[i + 1..]);
        let last = simple_name(class);
        matches!(method, "__init__" | "constructor" | "new") .then_some(class.to_string()).or((method == last).then_some(class.to_string()))
    }

    /// `b.f` -> `a.f` when `b` is an alias of `a` (`h.r.f` -> `a.f` when `h.r` is).
    fn canon(loc: &Local, path: &str) -> String {
        let mut p = tracked(path).to_string();
        for _ in 0..8 {
            // the longest proper prefix that is an alias
            let hit = p
                .match_indices(['.', '['])
                .map(|(i, _)| i)
                .rev()
                .find_map(|i| loc.aliases.get(&p[..i]).filter(|a| **a != p[..i]).map(|a| (i, a.clone())));
            match hit {
                Some((i, a)) => p = format!("{a}{}", &p[i..]),
                None => break,
            }
        }
        p
    }

    /// The fields of its parameters a function assigns: `(parameter, ".field")` for `o.d = x`.
    fn param_writes(&self, fid: usize) -> Vec<(usize, String)> {
        let cfg = self.cfg(fid);
        let mut out: Vec<(usize, String)> = vec![];
        for a in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns) {
            let Some((head, rest)) = a.target.split_once('.') else { continue };
            if a.target.contains(['[', '-']) || cfg.receiver.as_deref() == Some(head) {
                continue;
            }
            if let Some(j) = cfg.params.iter().position(|ns| ns.iter().any(|n| n == head)) {
                let w = (j, format!(".{rest}"));
                if !out.contains(&w) {
                    out.push(w);
                }
            }
        }
        out
    }

    /// The argument a call hands back as the result: `f(a)` where `f` is `return param`.
    fn returned_arg(&self, c: &CallFlow, fi: usize) -> Option<String> {
        let r = self.resolver.resolve(&c.callee, fi);
        let [id] = r.ids[..] else { return None };
        if !r.exact {
            return None;
        }
        let callee = self.cfg(id);
        let stmts = || callee.graph.node_weights().flat_map(|b| &b.stmts);
        let mut returned = stmts().filter_map(|s| s.ret.as_ref());
        let Some(Flow::Path(name)) = returned.next() else { return None };
        if returned.any(|r| !matches!(r, Flow::Path(n) if n == name)) || stmts().flat_map(|s| &s.assigns).any(|a| a.strong && a.target == *name) {
            return None;
        }
        let i = callee.params.iter().position(|ns| ns.contains(name))?;
        match arg_for(c, i, &callee.params)? {
            Flow::Path(p) => Some(p.clone()),
            _ => None,
        }
    }

    /// The functions the value at `p` may be: what the state recorded for the variable, field or
    /// container, what other methods stored in the field of the class, and module-level
    /// registries. With `named`, a function written in place or named directly counts too.
    fn held(&self, loc: &Local, st: &State, p: &str, named: bool) -> BTreeSet<usize> {
        let (fi, _) = self.ids[self.fid];
        let mut out = BTreeSet::new();
        if let Some(pos) = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')) {
            if named
                && let Some((l, c)) = pos.split_once(':')
                && let Some(&cb) = self.closures.get(&(fi, l.parse().unwrap_or(0), c.parse().unwrap_or(0)))
            {
                out.insert(cb);
            }
            return out;
        }
        let canon = Self::canon(loc, p);
        let head = root(&canon);
        if named && !canon.contains('.') && reaching(st, &canon).is_empty() {
            out.extend(self.resolver.free_function(&canon, fi));
        }
        for (path, refs) in &st.fns {
            if path == &canon || path == head || path.strip_prefix(&canon).is_some_and(below) { out.extend(refs); }
        }
        // a field of the object: stored by another method of the class
        let cfg = self.cfg(self.fid);
        if let Some((r, rest)) = canon.split_once('.') {
            let class = if cfg.receiver.as_deref() == Some(r) {
                class_of(&cfg.name).map(str::to_string)
            } else {
                loc.types.get(r).cloned()
            };
            if let Some(class) = class
                && let Some(v) = self.field_fns.get(&(class, rest.split('.').next().unwrap_or(rest).to_string()))
            {
                out.extend(v);
            }
        }
        if reaching(st, head).is_empty()
            && let Some(v) = self.field_fns.get(&module_key(fi, head))
        {
            out.extend(v);
        }
        if named && out.is_empty() && !st.fns.contains_key(&canon)
            && let Some((root, method)) = canon.rsplit_once('.')
        {
            let resolved = match loc.types.get(root) {
                Some(class) => self.resolver.resolve_method(class, method, fi),
                None => self.resolver.resolve(&canon, fi),
            };
            out.extend(resolved.ids);
        }
        out
    }

    fn held_by(&self, loc: &Local, st: &State, f: &Flow) -> BTreeSet<usize> {
        match f {
            Flow::Path(p) => self.held(loc, st, p, true),
            Flow::Join(v) => v.iter().flat_map(|x| self.held_by(loc, st, x)).collect(),
            Flow::Call(c) => self.resolver.resolve(&c.callee, self.ids[self.fid].0).ids.into_iter()
                .flat_map(|id| self.field_fns.get(&return_key(id)).into_iter().flatten().copied()).collect(),
            _ => BTreeSet::new(),
        }
    }

    /// Evaluate one statement against `st`; with `emit`, also add its edges.
    fn apply(&mut self, loc: &mut Local, key: (usize, usize), s: &Stmt, st: &mut State, emit: bool) {
        if emit {
            for c in &s.calls {
                let n = self.call(loc, c, st);
                self.note(loc, key, n);
            }
            if self.control && s.kind == StmtKind::Branch {
                let var: String = s.text.chars().take(40).collect();
                let n = self.node(self.fid, NodeKind::Branch, &var, s.line);
                if let Some(cond) = &s.cond {
                    for src in self.eval(loc, cond, st) {
                        self.edge(src, n, EdgeKind::Flow, None);
                    }
                }
                loc.branches.insert(key, n);
                self.note(loc, key, n);
            }
        }
        for c in &s.calls {
            let resolved = self.resolver.resolve(&c.callee, self.ids[self.fid].0);
            for id in resolved.ids.into_iter().filter(|_| resolved.exact) {
                let params = &self.cfg(id).params;
                for (target, refs) in callable_writes(&self.field_fns, id) {
                    let (root, suffix) = target.split_once('.').map_or((target.as_str(), String::new()), |(r, s)| (r, format!(".{s}")));
                    if let Some(j) = params.iter().position(|ns| ns.iter().any(|n| n == root))
                        && let Some(Flow::Path(actual)) = arg_for(c, j, params)
                    {
                        st.fns.entry(Self::canon(loc, &format!("{actual}{suffix}"))).or_default().extend(refs);
                    }
                }
            }
            // `fill(a)` where `fill` assigns `o.d`: the call defines `a.d`
            let resolved = self.resolver.resolve(&c.callee, self.ids[self.fid].0);
            for id in resolved.ids.into_iter().filter(|_| resolved.exact) {
                let params = &self.cfg(id).params;
                for (j, suffix) in self.write_targets[id].clone() {
                    let Some(Flow::Path(actual)) = arg_for(c, j, params) else { continue };
                    let n = self.call_node(loc, c);
                    st.entry(Self::canon(loc, &format!("{actual}{suffix}"))).or_default().insert(n);
                    if emit {
                        self.pending_writes.push((n, id, j, suffix));
                    }
                }
            }
            let simple = last_segment(&c.callee);
            if let (true, Some(Flow::Path(p))) = (MUTATORS.contains(&simple), &c.recv) {
                let n = self.call_node(loc, c);
                st.entry(Self::canon(loc, p)).or_default().insert(n);
                let refs: BTreeSet<usize> = c.args.iter().flat_map(|a| self.held_by(loc, st, a)).collect();
                if !refs.is_empty() {
                    st.fns.entry(Self::canon(loc, p)).or_default().extend(refs);
                }
            }
        }
        // `xs[0] = v` defines the element `xs[0]`, not the whole container
        let element_bases: Vec<&str> = s.elems.iter().filter(|e| !e.strong).filter_map(|e| e.target.split('[').next()).collect();
        // (the field path `xs.d` of `xs[0].d = v` stays: it carries aliases of what the container holds)
        let covered = |a: &crate::ir::Assign| !a.strong && element_bases.iter().any(|b| a.target == *b);
        for (ai, a) in s.assigns.iter().enumerate().filter(|(_, a)| !covered(a)) {
            let target = Self::canon(loc, &a.target);
            let node = *loc.defs.entry((key.0, key.1, ai)).or_insert_with(|| {
                self.graph.add_node(Node { func: self.fid, kind: NodeKind::Def, var: a.target.clone(), line: s.line })
            });
            if emit {
                self.note(loc, key, node);
                if let Some((_, rest)) = a.target.split_once('.')
                    && let Some((j, suffix)) = self.write_targets[self.fid].iter().find(|(_, s)| *s == format!(".{rest}")).cloned()
                    && !self.writes[self.fid].iter().any(|(_, _, n)| *n == node)
                {
                    self.writes[self.fid].push((j, suffix, node));
                }
                for src in self.eval(loc, &a.value, st) {
                    self.edge(src, node, EdgeKind::Flow, None);
                }
                if let Some(f) = self.field_node(&a.target) {
                    self.edge(node, f, EdgeKind::Flow, None);
                }
            }
            let refs = self.held_by(loc, st, &a.value);
            // a variable or field path replaces its definitions (and those of its
            // fields); an element (`a[i] = x`) only adds one
            if a.strong || target == tracked(&a.target) {
                st.kill_below(&target);
                if refs.is_empty() {
                    st.fns.remove(&target);
                } else {
                    st.fns.insert(target.clone(), refs);
                }
                st.insert(target, BTreeSet::from([node]));
            } else {
                if !refs.is_empty() {
                    st.fns.entry(target.clone()).or_default().extend(refs);
                }
                // a write at an unknown index may hit any element
                st.sealed.retain(|k| !k.strip_prefix(target.as_str()).is_some_and(below));
                st.entry(target).or_default().insert(node);
            }
        }
        // elements with a literal key: `xs = [a, b]`, `d["k"] = v`
        for (ei, e) in s.elems.iter().enumerate() {
            let target = Self::canon(loc, &e.target);
            let node = *loc.defs.entry((key.0, key.1, 1 << 20 | ei)).or_insert_with(|| {
                self.graph.add_node(Node { func: self.fid, kind: NodeKind::Def, var: e.target.clone(), line: s.line })
            });
            if emit {
                self.note(loc, key, node);
                for src in self.eval(loc, &e.value, st) {
                    self.edge(src, node, EdgeKind::Flow, None);
                }
                if let Some(f) = self.field_node(&e.target) {
                    self.edge(node, f, EdgeKind::Flow, None);
                }
            }
            let refs = self.held_by(loc, st, &e.value);
            if e.strong {
                st.kill_below(&target);
                if refs.is_empty() {
                    st.fns.remove(&target);
                } else {
                    st.fns.insert(target.clone(), refs);
                }
                if target.ends_with(']') {
                    st.sealed.insert(target.clone());
                }
                st.insert(target, BTreeSet::from([node]));
            } else {
                if !refs.is_empty() {
                    st.fns.entry(target.clone()).or_default().extend(refs);
                }
                st.entry(target).or_default().insert(node);
            }
        }
        if emit && let Some(flow) = &s.ret {
            let node = *loc.rets.entry(key).or_insert_with(|| {
                let n = self.graph.add_node(Node { func: self.fid, kind: NodeKind::Return, var: "return".into(), line: s.line });
                self.rets[self.fid].push(n);
                n
            });
            self.note(loc, key, node);
            for src in self.eval(loc, flow, st) {
                self.edge(src, node, EdgeKind::Flow, None);
            }
        }
    }

    /// Remember that statement `key` made `n` (for control dependence).
    fn note(&self, loc: &mut Local, key: (usize, usize), n: NodeIndex) {
        if self.control {
            loc.stmt_nodes.entry(key).or_default().push(n);
        }
    }

    fn call_node(&mut self, loc: &mut Local, c: &CallFlow) -> NodeIndex {
        let key = (c.line, c.col, c.callee.clone());
        if let Some(&n) = loc.calls.get(&key) {
            return n;
        }
        let n = self.node(self.fid, NodeKind::Call, &c.callee, c.line);
        loc.calls.insert(key, n);
        n
    }

    /// Add the edges into a call node once: receiver, arguments and callee.
    fn call(&mut self, loc: &mut Local, c: &CallFlow, st: &State) -> NodeIndex {
        let n = self.call_node(loc, c);
        if !loc.emitted.insert(n) {
            return n;
        }
        if let Some(r) = &c.recv {
            for src in self.eval(loc, r, st) {
                self.edge(src, n, EdgeKind::Flow, None);
            }
        }
        for a in &c.args {
            for src in self.eval(loc, a, st) {
                self.edge(src, n, EdgeKind::Flow, None);
            }
        }
        // link to the functions it may call
        let (fi, _) = self.ids[self.fid];
        let mut r = self.resolver.resolve(&c.callee, fi);
        // Declared locals and chains of declared fields select the receiver class.
        if let Some((path, method)) = c.callee.rsplit_once('.')
            && let Some(class) = self.types.path_class(&self.resolver, self.cfg(self.fid), path, |root| self.class_at(loc, root, c.line))
        {
            let typed = self.resolver.resolve_method(&class, method, fi);
            if typed.exact && !typed.ids.is_empty() { r = typed; }
        }
        // Go: a value declared with an interface may be any type that satisfies it
        if self.files[fi].lang == crate::lang::Language::Go {
            let ids = self.types.interface_targets(&self.resolver, self.fid, &c.callee, fi, |obj| {
                self.types.path_class(&self.resolver, self.cfg(self.fid), obj, |root| self.class_at(loc, root, c.line))
            });
            if !ids.is_empty() { r = super::callgraph::Resolved { ids, exact: true }; }
        }
        // `f(x)` where `f` holds a function
        if c.recv.is_none()
            && let Some(&cb) = loc.fn_vars.get(c.callee.as_str())
        {
            r = super::callgraph::Resolved { ids: vec![cb], exact: true };
        }
        // a variable, field, container or registry entry that holds functions (flow-sensitive)
        let held = self.held(loc, st, &c.callee, false);
        if !held.is_empty() {
            r = super::callgraph::Resolved { ids: held.into_iter().collect(), exact: true };
        }
        // a function passed as an argument is called by the callee with the other arguments
        let mut callbacks = vec![];
        // `queue.append(f)` stores `f`, it does not call it
        let stores = MUTATORS.contains(&last_segment(&c.callee));
        for (i, a) in c.args.iter().enumerate().filter(|_| !stores) {
            let Flow::Path(p) = a else { continue };
            let stored = self.held(loc, st, p, true);
            if !stored.is_empty() {
                callbacks.extend(stored.into_iter().map(|cb| (i, cb)));
            } else if let Some(&cb) = loc.fn_vars.get(p.as_str()) {
                callbacks.push((i, cb));
            } else if let Some(pos) = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')) {
                // a lambda / closure written in place
                let (line, col) = pos.split_once(':').unwrap_or_default();
                if let Some(&cb) = self.closures.get(&(fi, line.parse().unwrap_or(0), col.parse().unwrap_or(0))) {
                    callbacks.push((i, cb));
                }
            } else if reaching(st, tracked(p)).is_empty() && !p.contains('.') {
                let cb = self.resolver.resolve(p, fi);
                if cb.exact && cb.ids.len() == 1 {
                    callbacks.push((i, cb.ids[0]));
                }
            }
        }
        for (i, cb) in callbacks {
            let params = self.cfg(cb).params.clone();
            // what the callee has besides the callback: other arguments and the
            // object it is called on (`items.forEach(cb)`)
            let mut inputs: Vec<&Flow> = c.args.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, a)| a).collect();
            inputs.extend(c.recv.as_ref());
            for a in inputs {
                for src in self.eval(loc, a, st) {
                    for (names, targets) in params.iter().zip(self.params[cb].clone()) {
                        for (&t, name) in targets.iter().zip(names) {
                            self.edge(src, t, EdgeKind::Arg, Some(name.clone()));
                        }
                    }
                }
            }
            self.pending_rets.push((n, cb));
        }
        if r.exact {
            for callee in r.ids {
                if let (Some(recv), Some(target)) = (&c.recv, self.receivers[callee]) {
                    let name = self.cfg(callee).receiver.clone();
                    for src in self.eval(loc, recv, st) {
                        self.edge(src, target, EdgeKind::Arg, name.clone());
                    }
                }
                let params = self.cfg(callee).params.clone();
                for (j, names) in params.iter().enumerate() {
                    let Some(arg) = arg_for(c, j, &params) else { continue };
                    let targets = self.params[callee][j].clone();
                    for src in self.eval(loc, arg, st) {
                        for (&t, name) in targets.iter().zip(names) {
                            self.edge(src, t, EdgeKind::Arg, Some(name.clone()));
                        }
                    }
                }
                self.pending_rets.push((n, callee));
            }
        }
        n
    }

    /// The nodes whose value `f` depends on.
    fn eval(&mut self, loc: &mut Local, f: &Flow, st: &State) -> Vec<NodeIndex> {
        match f {
            Flow::Clean => vec![],
            Flow::Path(p) if p.starts_with("<fn@") => {
                // a closure is created here: it sees the definitions in scope
                let (fi, _) = self.ids[self.fid];
                let pos = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')).and_then(|r| r.split_once(':'));
                if let Some((l, c)) = pos
                    && let Some(&cid) = self.closures.get(&(fi, l.parse().unwrap_or(0), c.parse().unwrap_or(0)))
                {
                    self.captures.push((cid, st.clone()));
                }
                vec![]
            }
            Flow::Path(p) => match Some(reaching(st, &Self::canon(loc, p))).filter(|d| !d.is_empty()) {
                // only the receiver itself reaches: the field was set by another method
                Some(defs) if defs.iter().all(|d| Some(*d) == self.receivers[self.fid]) => {
                    self.field_node(p).map_or_else(|| defs.into_iter().collect(), |f| vec![f])
                }
                Some(defs) => defs.into_iter().collect(),
                None => {
                    let fid = self.fid;
                    let n = *loc.free.entry(p.clone()).or_insert_with(|| self.graph.add_node(Node { func: fid, kind: NodeKind::Free, var: p.clone(), line: 0 }));
                    vec![n]
                }
            },
            Flow::Call(c) => vec![self.call(loc, c, st)],
            Flow::Join(v) => v.iter().flat_map(|x| self.eval(loc, x, st)).collect(),
        }
    }
}

impl DataFlow {
    /// Keep what the nodes matching `name` (variable, callee or parameter) may
    /// flow into, following edges across functions.
    pub fn slice_from(&self, name: &str) -> HashSet<NodeIndex> {
        let g = &self.graph;
        let mut seen: HashSet<NodeIndex> = g
            .node_indices()
            .filter(|&n| {
                let v = &g[n].var;
                v == name || root(v) == name || last_segment(v) == name
            })
            .collect();
        let mut stack: Vec<NodeIndex> = seen.iter().copied().collect();
        while let Some(n) = stack.pop() {
            for m in g.neighbors(n) {
                if seen.insert(m) {
                    stack.push(m);
                }
            }
        }
        seen
    }
}
