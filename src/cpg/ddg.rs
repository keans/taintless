//! Data dependence inside one function: reaching definitions over the
//! statement CFG. A definition is an assignment (or a parameter, defined at
//! `Entry`, or a container mutated through a method such as `xs.append(v)`);
//! a use is any variable path a statement reads (assigned values, call
//! receivers and arguments, return values, branch conditions).
//!
//! Paths are tracked like `analysis::dataflow` does: `a.b[i].c` is `a.b`. A
//! definition of `a` reaches a read of `a.b` and the other way round, so
//! assigning a whole object and one of its fields both count. Plain variables
//! (and exact paths) are replaced by a new assignment; element writes add to
//! what is there. A method's reads of fields of its receiver (`self.cmd`) start
//! from a definition at `Entry`: what the class's other methods store there. A write to `r.d` shadows the definitions of `r` for reads of `r.d`.

use super::cfg::{SNode, StmtGraph};
use crate::analysis::rules::MUTATORS;
use crate::ir::{Cfg, Flow, Stmt};
use petgraph::graph::NodeIndex;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// What the graph knows beyond one function's own statements: aliases, effects of
/// calls, and names a function receives from the scope around it.
#[derive(Default, Clone)]
pub struct Extras {
    /// `b` -> `a` for `b = a`, `h.r` -> `a` for `h.r = a`, `b = identity(a)`: the same object under
    /// another name. Defining or reading `b.f` is defining or reading `a.f`.
    pub aliases: HashMap<String, String>,
    /// Extra definitions at a statement (by statement-graph node): what a callee stores in
    /// the fields of its arguments, in the receiver, or in captured variables. `true` replaces.
    pub defs: HashMap<NodeIndex, Vec<(String, bool)>>,
    /// Extra reads at a statement: the variables a called closure reads from this scope.
    pub uses: HashMap<NodeIndex, Vec<String>>,
    /// Names defined at `Entry` beyond the parameters: the captured variables a closure reads.
    pub entry: Vec<String>,
}

/// `path` with its aliases resolved: `h.r.d` is `a.d` when `h.r` is `a`.
pub fn canon(aliases: &HashMap<String, String>, path: &str) -> String {
    let mut p = tracked(path).to_string();
    for _ in 0..8 {
        if aliases.is_empty() {
            break;
        }
        let hit = p
            .match_indices(['.', '['])
            .map(|(i, _)| i)
            .rev()
            .find_map(|i| aliases.get(&p[..i]).filter(|a| a.as_str() != &p[..i]).map(|a| (i, a.clone())));
        match hit {
            Some((i, a)) => p = format!("{a}{}", &p[i..]),
            None => break,
        }
    }
    p
}

/// The definitions of one tracked path. `sealed`: a strong write to exactly
/// this path happened (on every way here), so it shadows the definitions of
/// the paths that contain it: after `r = f(); r.d = "x"`, a read of `r.d` sees
/// only the second one.
#[derive(Clone, Default, PartialEq, Eq)]
struct Slot {
    defs: BTreeSet<NodeIndex>,
    sealed: bool,
}

type State = BTreeMap<String, Slot>;

/// The part of a path that is tracked as one variable: `a.b.c` and `xs[0].d` (a literal key
/// names one element) but not what follows a `->`.
fn tracked(path: &str) -> &str {
    path.split('-').next().unwrap_or(path)
}

/// Is `rest` (what follows a path prefix) a field or an element of it?
fn below(rest: &str) -> bool {
    rest.starts_with(['.', '['])
}

fn last_segment(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

fn paths(f: &Flow, ex: &Extras, out: &mut Vec<String>) {
    match f {
        Flow::Clean => {}
        Flow::Path(p) => {
            if !p.starts_with('<') {
                out.push(canon(&ex.aliases, p));
            }
        }
        Flow::Call(c) => {
            paths_opt(c.recv.as_ref(), ex, out);
            c.args.iter().for_each(|a| paths(a, ex, out));
        }
        Flow::Join(parts) => parts.iter().for_each(|p| paths(p, ex, out)),
    }
}

fn paths_opt(f: Option<&Flow>, ex: &Extras, out: &mut Vec<String>) {
    if let Some(f) = f {
        paths(f, ex, out);
    }
}

fn uses(s: &Stmt, ex: &Extras, extra: Option<&Vec<String>>) -> Vec<String> {
    let mut out = vec![];
    for a in &s.assigns {
        paths(&a.value, ex, &mut out);
    }
    for e in &s.elems {
        paths(&e.value, ex, &mut out);
    }
    for c in &s.calls {
        paths_opt(c.recv.as_ref(), ex, &mut out);
        c.args.iter().for_each(|a| paths(a, ex, &mut out));
        // `f(x)` reads `f`: the definitions of a variable that holds the function
        if !c.callee.is_empty() && !c.callee.contains(['.', '<']) {
            out.push(canon(&ex.aliases, &c.callee));
        }
    }
    paths_opt(s.ret.as_ref(), ex, &mut out);
    paths_opt(s.cond.as_ref(), ex, &mut out);
    out.extend(extra.into_iter().flatten().cloned());
    out.sort();
    out.dedup();
    out
}

/// The variables (tracked paths) a statement defines or mutates.
pub fn defined_vars(s: &Stmt) -> Vec<String> {
    defined_vars_with(s, &Extras::default(), None)
}

/// [`defined_vars`] with aliases resolved and the effects of the statement's calls.
pub fn defined_vars_with(s: &Stmt, ex: &Extras, extra: Option<&Vec<(String, bool)>>) -> Vec<String> {
    let mut v: Vec<String> = defs(s, ex, extra).into_iter().map(|d| d.0).collect();
    v.sort();
    v.dedup();
    v
}

/// What a statement defines, in order: `(variable, replaces what it held)`.
fn defs(s: &Stmt, ex: &Extras, extra: Option<&Vec<(String, bool)>>) -> Vec<(String, bool)> {
    // `xs[0] = v` defines the element `xs[0]`, not the whole container
    let elems: Vec<&str> = s.elems.iter().filter(|e| !e.strong).filter_map(|e| e.target.split('[').next()).collect();
    let covered = |a: &crate::ir::Assign| !a.strong && elems.iter().any(|b| a.target == *b || a.target.strip_prefix(b).is_some_and(|r| r.starts_with('.')));
    let mut out: Vec<(String, bool)> = s
        .assigns
        .iter()
        .filter(|a| !covered(a))
        .map(|a| (canon(&ex.aliases, &a.target), a.strong || tracked(&a.target) == a.target))
        .collect();
    out.extend(s.elems.iter().map(|e| (canon(&ex.aliases, &e.target), e.strong)));
    for c in &s.calls {
        if let (true, Some(Flow::Path(p))) = (MUTATORS.contains(&last_segment(&c.callee)), &c.recv) {
            out.push((canon(&ex.aliases, p), false));
        }
    }
    out.extend(extra.into_iter().flatten().cloned());
    out
}

fn transfer(n: NodeIndex, defs: &[(String, bool)], mut st: State) -> State {
    for (var, strong) in defs {
        if *strong {
            st.retain(|k, _| !k.strip_prefix(var.as_str()).is_some_and(below));
            st.insert(var.clone(), Slot { defs: BTreeSet::from([n]), sealed: true });
        } else {
            st.entry(var.clone()).or_default().defs.insert(n);
        }
    }
    st
}

fn join(into: &mut State, from: &State, first: bool) -> bool {
    if first {
        *into = from.clone();
        return true;
    }
    let before = into.clone();
    for (k, v) in from {
        match into.get_mut(k) {
            Some(e) => {
                e.defs.extend(&v.defs);
                e.sealed &= v.sealed;
            }
            None => {
                // not written on the other way here: the paths containing it still show through
                into.insert(k.clone(), Slot { defs: v.defs.clone(), sealed: false });
            }
        }
    }
    // a key only `into` has was not written on the `from` way either
    for (k, e) in into.iter_mut() {
        if !from.contains_key(k) {
            e.sealed = false;
        }
    }
    *into != before
}

/// The definitions a read of `read` can see in `st`.
fn visible<'a>(st: &'a State, read: &str) -> Vec<(&'a str, &'a BTreeSet<NodeIndex>)> {
    let mut out = vec![];
    // paths containing `read` (or equal to it), the longest first, until one is sealed
    let mut ancestors: Vec<(&String, &Slot)> = st.iter().filter(|(k, _)| k.as_str() == read || read.strip_prefix(k.as_str()).is_some_and(below)).collect();
    ancestors.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    for (k, slot) in ancestors {
        out.push((k.as_str(), &slot.defs));
        if slot.sealed {
            break;
        }
    }
    // fields of `read`: reading the whole object reads what was written into it
    out.extend(st.iter().filter(|(k, _)| k.strip_prefix(read).is_some_and(below)).map(|(k, v)| (k.as_str(), &v.defs)));
    out
}

/// `(definition, use, variable)`: the value `variable` that `definition` stores
/// may be read by `use`. Parameters are defined at `Entry`.
pub fn reaching_definitions(cfg: &Cfg, g: &StmtGraph) -> Vec<(NodeIndex, NodeIndex, String)> {
    reaching_definitions_with(cfg, g, &Extras::default())
}

/// [`reaching_definitions`] with aliases resolved and the effects of calls added.
pub fn reaching_definitions_with(cfg: &Cfg, g: &StmtGraph, ex: &Extras) -> Vec<(NodeIndex, NodeIndex, String)> {
    let stmt_of = |n: NodeIndex| match g.graph[n] {
        SNode::Stmt { block, idx } => Some(&cfg.graph[block].stmts[idx]),
        _ => None,
    };
    // fields of the receiver this method reads (`self.cmd`): what the object's other
    // methods stored there reaches the method through a definition of its own at entry
    let mut fields: Vec<String> = vec![];
    if let Some(r) = &cfg.receiver {
        for s in g.graph.node_indices().filter_map(stmt_of) {
            for u in uses(s, ex, None) {
                let mut seg = u.split('.');
                if seg.next() == Some(r.as_str())
                    && let Some(f) = seg.next()
                {
                    fields.push(format!("{r}.{f}"));
                }
            }
        }
        fields.sort();
        fields.dedup();
    }
    let node_defs: Vec<Vec<(String, bool)>> = g
        .graph
        .node_indices()
        .map(|n| {
            if n == g.entry {
                let params = cfg.params.iter().flatten().chain(&cfg.receiver);
                params
                    .map(|p| (tracked(p).to_string(), true))
                    .chain(fields.iter().map(|f| (f.clone(), true)))
                    .chain(ex.entry.iter().map(|v| (v.clone(), true)))
                    .collect()
            } else {
                stmt_of(n).map(|s| defs(s, ex, ex.defs.get(&n))).unwrap_or_default()
            }
        })
        .collect();

    let mut ins: Vec<State> = vec![State::new(); g.graph.node_count()];
    let mut queue: VecDeque<NodeIndex> = VecDeque::from([g.entry]);
    let mut queued = vec![false; g.graph.node_count()];
    let mut visited = vec![false; g.graph.node_count()];
    // `ins[n]` has received a contribution from some predecessor
    let mut fed = vec![false; g.graph.node_count()];
    queued[g.entry.index()] = true;
    while let Some(n) = queue.pop_front() {
        queued[n.index()] = false;
        visited[n.index()] = true;
        let out = transfer(n, &node_defs[n.index()], ins[n.index()].clone());
        for s in g.graph.neighbors(n) {
            // every successor is visited once, even when nothing flows into it
            let changed = join(&mut ins[s.index()], &out, !std::mem::replace(&mut fed[s.index()], true));
            if (changed || !visited[s.index()]) && !queued[s.index()] {
                queued[s.index()] = true;
                queue.push_back(s);
            }
        }
    }

    let mut edges = vec![];
    for n in g.graph.node_indices() {
        let Some(s) = stmt_of(n) else { continue };
        for read in uses(s, ex, ex.uses.get(&n)) {
            for (var, ds) in visible(&ins[n.index()], &read) {
                edges.extend(ds.iter().map(|&d| (d, n, var.to_string())));
            }
        }
    }
    edges.sort_by_key(|(d, u, v)| (d.index(), u.index(), v.clone()));
    edges.dedup();
    edges
}
