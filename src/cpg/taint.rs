//! Taint tracking as a query over the CPG: untrusted data flows from sources
//! to dangerous calls along `Reaching`, `ParamIn` and `ReturnOut` edges, using
//! the same rule tables as `analysis::taint`.
//!
//! A statement that reads a tainted variable taints the variables it defines
//! (excluding values inside sanitizer calls). A tainted argument taints the callee's
//! parameter, and a tainted `return` taints the result of the calls it
//! answers. A sink is hit when one of its arguments reads a tainted variable,
//! calls something that returns tainted data, or contains a source. Reaching
//! definitions already provide the kills and the branch merges.
//!
//! Parameters of entry points (`main(args)`, configured request handlers) are sources.
//!
//! With implicit flows on, a branch whose condition reads untrusted data also taints what the
//! statements it controls (`Cdg` edges) define and return.
//!
//! Taint follows what the graph records beyond one function: aliases and element keys are part
//! of the `Reaching` paths; a callee's stores for its caller (`ParamOut`, `Capture`) and the
//! receiver of a method call carry taint across calls. Each fact remembers the calls it went
//! through (see [`Ctx`]), so what one call hands to a function does not come back out of
//! another: `Req(input())` and `Req("ls")` build different objects. Arguments bind to
//! parameters by keyword where the call names them.

use super::graph::{Cpg, EdgeKind};
use super::node::NodeKind;
use crate::analysis::rules::{ArgSel, Mode, RuleSet, ignores_env_sources, is_env_source, matches, rules_for, wild};
use crate::lang::common::normalize_callee;
use petgraph::Direction;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaintFlow {
    pub rule: &'static str,
    pub file: usize,
    pub line: usize,
    pub col: usize,
    /// The call expression that is the sink.
    pub sink: NodeIndex,
    /// What carries the data into the sink: a tainted variable, or a call
    /// (`helper()`) returning tainted data; `None` when the argument holds a source itself.
    pub via: Option<String>,
}

/// A path-like text (`a.b.c`, `xs[0].d`, `d['k']`).
fn is_path(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '$' | '[' | ']' | '\'' | '"'))
}

/// The class a method belongs to: its qualified name without the last segment.
fn class_of(name: &str) -> Option<String> {
    let c = name[..name.rfind(['.', ':'])?].trim_end_matches(':');
    (!c.is_empty()).then(|| c.to_string())
}

/// `code` up to its first subscript that is not a literal key: `xs[i].d` reads the whole of
/// `xs`, while `xs[0].d` names one element.
fn read_path(code: &str) -> &str {
    let mut from = 0;
    while let Some(i) = code[from..].find('[').map(|i| i + from) {
        let Some(end) = code[i..].find(']').map(|e| e + i) else { return &code[..i] };
        let key = &code[i + 1..end];
        let literal = (!key.is_empty() && key.bytes().all(|b| b.is_ascii_digit()))
            || key.strip_prefix(['\'', '"']).and_then(|k| k.strip_suffix(['\'', '"'])).is_some_and(|k| !k.is_empty());
        if !literal {
            return &code[..i];
        }
        from = end + 1;
    }
    code
}

/// Does the identifier or member path `n` read the variable `v`? Aliases are resolved, and a
/// bare name reads `this.name` in Java / C++ methods.
fn mentions(cpg: &Cpg, fn_of: &HashMap<NodeIndex, usize>, n: NodeIndex, v: &str) -> bool {
    let x = &cpg.graph[n];
    if !(matches!(x.kind, NodeKind::Identifier | NodeKind::FieldAccess) && is_path(&x.code)) {
        return false;
    }
    let f = fn_of.get(&cpg.enclosing_method(n)).copied();
    let code = f.map_or_else(|| read_path(&x.code).to_string(), |f| cpg.canon(f, read_path(&x.code)));
    if related(v, &code) {
        return true;
    }
    let recv = f.and_then(|i| cpg.receivers[i].as_deref());
    x.kind == NodeKind::Identifier && recv.is_some_and(|r| v.strip_prefix(r).and_then(|f| f.strip_prefix('.')).is_some_and(|f| related(f, &code)))
}

/// Is `rest` (what follows a path prefix) a field or an element of it?
fn below(rest: &str) -> bool {
    rest.starts_with(['.', '['])
}

fn related(a: &str, b: &str) -> bool {
    a == b || a.strip_prefix(b).is_some_and(below) || b.strip_prefix(a).is_some_and(below)
}

/// The calls a fact travelled through to get where it is, the innermost last: taint that a
/// call hands to a function leaves it again only through that call (or any caller, when it
/// began inside). Only the last few calls are kept; once they are used up, any caller will do.
type Ctx = Vec<NodeIndex>;
const MAX_CTX: usize = 3;

fn enter(ctx: &Ctx, call: NodeIndex) -> Ctx {
    let mut c = ctx.clone();
    c.push(call);
    if c.len() > MAX_CTX {
        c.remove(0);
    }
    c
}

/// A definition that holds untrusted data, with how it got there.
type Fact = (NodeIndex, String, Ctx);

struct Solver<'a> {
    cpg: &'a Cpg,
    /// Statements whose values contain a source.
    sources: HashSet<NodeIndex>,
    calls_in: HashMap<NodeIndex, Vec<NodeIndex>>,
    /// Definitions `(statement or method, variable, context)` that hold untrusted data.
    tainted: HashSet<Fact>,
    /// Tainted variables each statement reads (any context).
    reads: HashMap<NodeIndex, HashSet<String>>,
    /// `(statement, variable, context)` reads already followed.
    followed: HashSet<Fact>,
    /// Calls whose result is untrusted.
    tainted_calls: HashSet<NodeIndex>,
    returned: HashSet<(NodeIndex, Ctx)>,
    queue: Vec<Fact>,
    /// Fields `(class, name)` some method stores untrusted data in.
    tainted_fields: HashSet<(String, String)>,
    /// Function index of each method node, and the functions of each class.
    fn_of: HashMap<NodeIndex, usize>,
    class_fns: HashMap<String, Vec<usize>>,
    /// Leave out environment variables and system properties as sources.
    skip_env: bool,
    /// Follow implicit flows: what a branch on tainted data controls is tainted, too.
    implicit: bool,
    /// Branches whose controlled statements are already tainted.
    controlling: HashSet<(NodeIndex, Ctx)>,
}

impl<'a> Solver<'a> {
    fn rules(&self, n: NodeIndex) -> &'static RuleSet {
        rules_for(self.cpg.files[self.cpg.graph[n].file].lang)
    }

    fn is_source(&self, n: NodeIndex) -> bool {
        let x = &self.cpg.graph[n];
        let desc = match x.kind {
            NodeKind::Call => x.name.as_deref().map(normalize_callee).filter(|c| self.rules(n).is_source_call(c)),
            NodeKind::FieldAccess | NodeKind::Identifier => Some(x.code.clone()).filter(|c| is_path(c) && self.rules(n).is_source_path(c)),
            _ => None,
        };
        desc.is_some_and(|d| !(self.skip_env && is_env_source(&d)))
    }

    fn is_sanitizer(&self, n: NodeIndex) -> bool {
        let x = &self.cpg.graph[n];
        x.kind == NodeKind::Call && x.name.as_deref().is_some_and(|c| self.rules(n).is_sanitizer(&normalize_callee(c)))
    }

    /// Sanitizers clean only their own result; sibling expressions still flow.
    fn flow_nodes(&self, root: NodeIndex) -> Vec<NodeIndex> {
        self.cpg.flow_nodes_until(root, |n| self.is_sanitizer(n))
    }

    /// Variables a statement defines.
    fn defined(&self, s: NodeIndex) -> HashSet<String> {
        self.cpg.graph[s].defines.iter().cloned().collect()
    }

    /// The context after leaving a callee through the call statement `stmt`: the call it was
    /// entered from must be one of that statement's, or the taint began inside the callee.
    fn leave_stmt(&self, ctx: &Ctx, stmt: NodeIndex) -> Option<Ctx> {
        match ctx.last() {
            None => Some(vec![]),
            Some(&top) if top == stmt || self.cpg.statement_of(top) == stmt => Some(ctx[..ctx.len() - 1].to_vec()),
            Some(_) => None,
        }
    }

    /// The context after returning to the call expression `call`.
    fn leave_call(&self, ctx: &Ctx, call: NodeIndex) -> Option<Ctx> {
        match ctx.last() {
            None => Some(vec![]),
            Some(&top) if top == call => Some(ctx[..ctx.len() - 1].to_vec()),
            Some(_) => None,
        }
    }

    fn taint(&mut self, def: NodeIndex, var: String, ctx: Ctx) {
        if !self.tainted.insert((def, var.clone(), ctx.clone())) {
            return;
        }
        self.taint_field(def, &var);
        // what the callee stores for its caller: the call statement defines it, too
        let outs: Vec<(NodeIndex, String)> = self
            .cpg
            .graph
            .edges_directed(def, Direction::Outgoing)
            .filter(|e| e.weight().kind == EdgeKind::ParamOut)
            .filter_map(|e| {
                let (callee, caller) = e.weight().var.as_deref()?.split_once('>')?;
                (callee == var).then(|| (e.target(), caller.to_string()))
            })
            .collect();
        for (stmt, v) in outs {
            if let Some(c) = self.leave_stmt(&ctx, stmt) {
                self.taint(stmt, v, c);
            }
        }
        self.queue.push((def, var, ctx));
    }

    /// A definition of `self.f` that is tainted taints the field for every method of the class.
    fn taint_field(&mut self, def: NodeIndex, var: &str) {
        let cpg = self.cpg;
        let Some(&i) = self.fn_of.get(&cpg.enclosing_method(def)) else { return };
        let Some(recv) = cpg.receivers[i].as_deref() else { return };
        let mut seg = var.split('.');
        if seg.next() != Some(recv) {
            return;
        }
        let Some(field) = seg.next() else { return };
        let Some(class) = class_of(cpg.graph[cpg.methods[i]].name.as_deref().unwrap_or("")) else { return };
        if !self.tainted_fields.insert((class.clone(), field.to_string())) {
            return;
        }
        for j in self.class_fns.get(&class).cloned().unwrap_or_default() {
            if let Some(r) = cpg.receivers[j].clone() {
                self.taint(cpg.methods[j], format!("{r}.{field}"), vec![]);
            }
        }
    }

    fn taint_defs(&mut self, s: NodeIndex, ctx: &Ctx) {
        for w in self.defined(s) {
            self.taint(s, w, ctx.clone());
        }
    }

    /// Like [`Self::taint_defs`], but an element of a list literal (`xs[1]` in `xs = [a, b]`)
    /// is only tainted when `hit` finds untrusted data in its own expression.
    fn taint_defs_if(&mut self, s: NodeIndex, ctx: &Ctx, hit: impl Fn(&Self, &[NodeIndex]) -> bool) {
        let vars: Vec<String> = self.defined(s).into_iter().filter(|w| self.cpg.elem_value(s, w).is_none_or(|e| hit(self, &self.flow_nodes(e)))).collect();
        for w in vars {
            self.taint(s, w, ctx.clone());
        }
    }

    /// The condition of branch `b` holds untrusted data: the statements it controls (through
    /// `Cdg` edges, nested branches included) taint what they define and return.
    fn control_taint(&mut self, b: NodeIndex, ctx: &Ctx) {
        if !self.implicit || !self.controlling.insert((b, ctx.clone())) {
            return;
        }
        let controlled: Vec<NodeIndex> = self.cpg.out(b, EdgeKind::Cdg).filter(|&d| d != b).collect();
        for d in controlled {
            self.taint_defs(d, ctx);
            self.taint_returns(d, ctx);
            self.control_taint(d, ctx);
        }
    }

    /// Parameters of the callees of `call` that receive argument `i`.
    fn taint_params(&mut self, call: NodeIndex, i: usize, ctx: &Ctx) {
        let edges: Vec<_> = self
            .cpg
            .graph
            .edges_directed(call, Direction::Outgoing)
            .filter(|e| e.weight().kind == EdgeKind::ParamIn && e.weight().order as usize == i)
            .filter_map(|e| Some((e.target(), e.weight().var.clone()?)))
            .collect();
        for (m, p) in edges {
            let def = self.fn_of.get(&m).map_or(m, |&i| self.cpg.param_def(i, &p));
            self.taint(def, p, enter(ctx, call));
        }
    }

    /// The statement `s` returns untrusted data to the calls it answers.
    fn taint_returns(&mut self, s: NodeIndex, ctx: &Ctx) {
        let calls: Vec<_> = self.cpg.out(s, EdgeKind::ReturnOut).collect();
        for c in calls {
            let Some(ctx) = self.leave_call(ctx, c) else { continue };
            if !self.returned.insert((c, ctx.clone())) {
                continue;
            }
            self.tainted_calls.insert(c);
            // `f(g())` with a tainted `g()`: `g()` is an argument of `f`
            let mut up = self.cpg.graph[c].ast.and_then(|i| self.cpg.files[self.cpg.graph[c].file].ast.nodes[i].parent);
            let info = &self.cpg.files[self.cpg.graph[c].file];
            let mut outer = vec![];
            while let Some(p) = up {
                if info.ast.nodes[p].kind == NodeKind::Call {
                    outer.push(info.nodes[p]);
                }
                if self.cpg.into(info.nodes[p], EdgeKind::Cfg).next().is_some() || self.cpg.out(info.nodes[p], EdgeKind::Cfg).next().is_some() {
                    break;
                }
                up = info.ast.nodes[p].parent;
            }
            for o in outer {
                for (i, a) in self.cpg.arguments(o).into_iter().enumerate() {
                    if self.flow_nodes(a).contains(&c) {
                        self.taint_params(o, i, &ctx);
                    }
                }
            }
            let st = self.cpg.statement_of(c);
            if self.flow_nodes(st).contains(&c) {
                self.taint_defs_if(st, &ctx, |_, nodes| nodes.contains(&c));
                self.control_taint(st, &ctx);
                // `return g(x)`
                if self.cpg.out(st, EdgeKind::ReturnOut).next().is_some() {
                    self.taint_returns(st, &ctx);
                }
            }
        }
    }

    /// Statement `u` reads the tainted variable `v`.
    fn on_read(&mut self, u: NodeIndex, v: &str, ctx: &Ctx) {
        let cpg = self.cpg;
        for c in self.calls_in.get(&u).cloned().unwrap_or_default() {
            for (i, a) in cpg.arguments(c).into_iter().enumerate() {
                let sub = self.flow_nodes(a);
                if sub.iter().any(|&n| self.mentions(n, v)) {
                    self.taint_params(c, i, ctx);
                }
            }
            // the object a method is called on: what it holds is what the method's receiver holds
            let Some(r) = cpg.out(c, EdgeKind::Receiver).next() else { continue };
            let x = &cpg.graph[r];
            if !(matches!(x.kind, NodeKind::Identifier | NodeKind::FieldAccess) && is_path(&x.code)) {
                continue;
            }
            let f = self.fn_of.get(&cpg.enclosing_method(r)).copied();
            let obj = f.map_or_else(|| read_path(&x.code).to_string(), |f| cpg.canon(f, read_path(&x.code)));
            let rest = if let Some(rest) = v.strip_prefix(obj.as_str()).filter(|r| r.is_empty() || below(r)) {
                rest.to_string()
            } else if obj.strip_prefix(v).is_some_and(below) {
                String::new() // the whole object holds it
            } else {
                continue;
            };
            let callees: Vec<NodeIndex> = cpg.out(c, EdgeKind::Call).collect();
            for m in callees {
                if let Some(rn) = self.fn_of.get(&m).and_then(|&j| cpg.receivers[j].clone()) {
                    self.taint(m, format!("{rn}{rest}"), enter(ctx, c));
                }
            }
        }
        // a closure called or created here reads this variable from the scope around it
        let captured: Vec<NodeIndex> = cpg
            .graph
            .edges_directed(u, Direction::Outgoing)
            .filter(|e| e.weight().kind == EdgeKind::Capture && e.weight().var.as_deref() == Some(v))
            .map(|e| e.target())
            .collect();
        for m in captured {
            self.taint(m, v.to_string(), enter(ctx, u));
        }
        // the statement's own value depends on the variable only outside calls to scanned functions
        if self.flow_nodes(u).iter().any(|&n| self.mentions(n, v)) {
            self.taint_defs_if(u, ctx, |s, nodes| nodes.iter().any(|&n| s.mentions(n, v)));
            self.taint_returns(u, ctx);
            self.control_taint(u, ctx);
        }
    }

    fn mentions(&self, n: NodeIndex, v: &str) -> bool {
        mentions(self.cpg, &self.fn_of, n, v)
    }

    fn run(&mut self) {
        let cpg = self.cpg;
        let top: Ctx = vec![];
        for (i, &m) in cpg.methods.iter().enumerate() {
            if let Some(c) = cpg.graph[m].name.as_deref().and_then(class_of) {
                self.class_fns.entry(c).or_default().push(i);
            }
        }
        for n in cpg.graph.node_indices() {
            if cpg.graph[n].ast.is_none() {
                continue;
            }
            let s = cpg.statement_of(n);
            // a source inside the arguments of a scanned function is the callee's business
            if self.is_source(n) && self.flow_nodes(s).contains(&n) {
                self.sources.insert(s);
            }
            if cpg.graph[n].kind == NodeKind::Call {
                self.calls_in.entry(s).or_default().push(n);
            }
        }
        let seeds: Vec<NodeIndex> = self.sources.iter().copied().collect();
        for s in seeds {
            self.taint_defs_if(s, &top, |s, nodes| nodes.iter().any(|&n| s.is_source(n)));
            self.taint_returns(s, &top);
            self.control_taint(s, &top);
        }
        // parameters of entry points (`main(args)`, configured request handlers) are sources
        for (i, &m) in cpg.methods.iter().enumerate() {
            let Some(name) = cpg.graph[m].name.as_deref() else { continue };
            let simple = crate::lang::common::simple_name(name);
            let Some(entry) = self.rules(m).entries.iter().find(|e| wild(e.pattern, name) || wild(e.pattern, simple)) else { continue };
            for p in cpg.params[i].iter().flatten().filter(|p| entry.params.is_empty() || entry.params.contains(&p.as_str())) {
                self.taint(cpg.param_def(i, p), p.clone(), top.clone());
            }
        }
        // a source handed straight to a callee: `run(input())`
        for calls in self.calls_in.clone().into_values() {
            for c in calls {
                for (i, a) in cpg.arguments(c).into_iter().enumerate() {
                    let sub = self.flow_nodes(a);
                    if sub.iter().any(|&n| self.is_source(n)) {
                        self.taint_params(c, i, &top);
                    }
                }
            }
        }
        while let Some((d, v, ctx)) = self.queue.pop() {
            let targets: Vec<NodeIndex> = cpg
                .graph
                .edges_directed(d, Direction::Outgoing)
                .filter(|e| e.weight().kind == EdgeKind::Reaching && e.weight().label.is_none() && e.weight().var.as_deref() == Some(&v))
                .map(|e| e.target())
                .collect();
            for u in targets {
                if self.followed.insert((u, v.clone(), ctx.clone())) {
                    self.reads.entry(u).or_default().insert(v.clone());
                    self.on_read(u, &v, &ctx);
                }
            }
        }
    }
}

fn solve(cpg: &Cpg, skip_env: bool, implicit: bool) -> Solver<'_> {
    let mut s = Solver {
        cpg,
        sources: HashSet::new(),
        calls_in: HashMap::new(),
        tainted: HashSet::new(),
        reads: HashMap::new(),
        followed: HashSet::new(),
        tainted_calls: HashSet::new(),
        returned: HashSet::new(),
        queue: vec![],
        tainted_fields: HashSet::new(),
        fn_of: cpg.methods.iter().enumerate().map(|(i, &m)| (m, i)).collect(),
        class_fns: HashMap::new(),
        skip_env,
        implicit,
        controlling: HashSet::new(),
    };
    s.run();
    s
}

/// The flows the configuration asks for (`implicit_flows` in `.taintless.toml`).
pub fn taint_flows(cpg: &Cpg) -> Vec<TaintFlow> {
    taint_flows_with(cpg, crate::analysis::config::implicit_flows())
}

/// With `implicit`, also the flows through branches on untrusted data (`if secret: x = 1`).
pub fn taint_flows_with(cpg: &Cpg, implicit: bool) -> Vec<TaintFlow> {
    let mut out = vec![];
    // rules about paths, URLs and pages do not count environment variables as untrusted
    for skip_env in [false, true] {
        let s = solve(cpg, skip_env, implicit);
        sinks(&s, &mut out);
    }
    out.sort();
    out.dedup_by(|a, b| (a.file, a.line, a.col, a.rule) == (b.file, b.line, b.col, b.rule));
    out
}

fn sinks(s: &Solver, out: &mut Vec<TaintFlow>) {
    let cpg = s.cpg;
    for c in cpg.nodes_of(NodeKind::Call) {
        let Some(callee) = cpg.graph[c].name.as_deref().map(normalize_callee) else { continue };
        let args = cpg.arguments(c);
        let stmt = cpg.statement_of(c);
        let rules = s.rules(c);
        for rule in rules.rules.iter().filter(|r| matches(r.pattern, &callee) && !r.except.iter().any(|x| matches(x, &callee)) && ignores_env_sources(r.id) == s.skip_env) {
            // `Always` rules are reported anyway; tainted data escalates them
            let sel = match rule.mode {
                Mode::Tainted(sel) => sel,
                Mode::Always => ArgSel::Any,
            };
            let chosen: Vec<NodeIndex> = match sel {
                ArgSel::Any => args.clone(),
                ArgSel::At(i) => args.get(i).copied().into_iter().collect(),
            };
            for a in chosen {
                let sub = s.flow_nodes(a);
                let via = if sub.iter().any(|&n| s.is_source(n)) {
                    Some(None)
                } else if let Some(&t) = sub.iter().find(|&&n| s.tainted_calls.contains(&n)) {
                    Some(cpg.graph[t].name.as_ref().map(|n| format!("{n}()")))
                } else {
                    let read = s.reads.get(&stmt);
                    sub.iter()
                        .find_map(|&n| read.and_then(|r| r.iter().find(|v| mentions(cpg, &s.fn_of, n, v))))
                        .map(|v| Some(v.clone()))
                };
                if let Some(via) = via {
                    out.push(TaintFlow { rule: rule.id, file: cpg.graph[c].file, line: cpg.graph[c].line, col: cpg.graph[c].col, sink: c, via });
                }
            }
        }
    }
}
