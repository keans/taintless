//! The data-flow graph (`taintless flow`) as a view of the code property graph.
//!
//! Nodes are parameters, assignments, calls, returns, free variables (globals, `request.args`),
//! the fields of a class and, with `control`, branches. An edge `a -> b` means the value of `a`
//! may flow into `b`. Nothing is resolved here: which definition reaches a read comes from the
//! graph's `Reaching` edges (aliases and element keys resolved), which function a call reaches from
//! its `Call` links, what a callee stores for its caller from `ParamOut`, what a closure reads from
//! `Capture`, and what decides a statement from `Cdg`.

use super::cdg::control_dependence;
use super::cfg::{SNode, StmtGraph, stmt_graph};
use super::graph::{CallLink, Cpg, EdgeKind as CpgEdge, SourceFile};
use super::node::NodeKind as CpgNode;
use crate::analysis::callgraph::simple_name;
use crate::analysis::dataflow::{DataFlow, Edge, EdgeKind, FnMeta, Node, NodeKind};
use crate::analysis::taint::arg_for;
use crate::ir::{CallFlow, Cfg, Flow, StmtKind, closure_marker};
use crate::lang::common::normalize_callee;
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use std::collections::{HashMap, HashSet, VecDeque};

/// A call expression: file, position and normalized callee.
type CallKey = (usize, usize, usize, String);

fn related(var: &str, path: &str) -> bool {
    let below = |r: &str| r.starts_with(['.', '[']);
    var == path || var.strip_prefix(path).is_some_and(below) || path.strip_prefix(var).is_some_and(below)
}

/// `xs[0] = v` defines the element `xs[0]`, not the whole container: the assignment to `xs` (and
/// to its fields) that comes with an element write is covered by it.
fn covered(s: &crate::ir::Stmt, a: &crate::ir::Assign) -> bool {
    !a.strong
        && s.elems
            .iter()
            .filter(|e| !e.strong)
            .filter_map(|e| e.target.split('[').next())
            .any(|b| a.target == b || a.target.strip_prefix(b).is_some_and(|r| r.starts_with('.')))
}

fn root(path: &str) -> &str {
    path.split(['.', '[', '-']).next().unwrap_or(path)
}

struct View<'a> {
    cpg: &'a Cpg,
    cfgs: Vec<&'a Cfg>,
    fn_file: Vec<usize>,
    graph: DiGraph<Node, Edge>,
    seen: HashSet<(NodeIndex, NodeIndex, EdgeKind)>,
    /// Parameter nodes by name, and the node of each method's receiver.
    params: Vec<HashMap<String, NodeIndex>>,
    receivers: Vec<Option<NodeIndex>>,
    rets: Vec<Vec<NodeIndex>>,
    frees: Vec<HashMap<String, NodeIndex>>,
    fields: HashMap<String, NodeIndex>,
    /// Definition nodes of a CPG statement: `(statement, variable)` -> nodes.
    defs: HashMap<(NodeIndex, String), Vec<NodeIndex>>,
    /// Everything a CPG statement made (definitions, calls, returns), for the control edges.
    made: HashMap<NodeIndex, Vec<NodeIndex>>,
    assigned: HashMap<(usize, usize, usize, usize), NodeIndex>,
    calls: HashMap<CallKey, NodeIndex>,
    call_at: HashMap<CallKey, NodeIndex>,
    links: HashMap<NodeIndex, Vec<CallLink>>,
    emitted: HashSet<NodeIndex>,
    pending_rets: Vec<(NodeIndex, usize)>,
    /// The function and position of the statement a CPG statement node stands for.
    stmt_at: HashMap<NodeIndex, (usize, NodeIndex<u32>, usize)>,
    /// The function written at a position: `(file, line, col)` of lambdas and closures.
    closure_at: HashMap<(usize, usize, usize), usize>,
}

pub fn flow_graph(cpg: &Cpg, files: &[SourceFile], control: bool) -> DataFlow {
    let cfgs: Vec<&Cfg> = files.iter().flat_map(|f| f.cfgs.iter()).collect();
    let fn_file: Vec<usize> = files.iter().enumerate().flat_map(|(fi, f)| f.cfgs.iter().map(move |_| fi)).collect();
    let functions: Vec<FnMeta> = cfgs
        .iter()
        .zip(&fn_file)
        .map(|(c, &fi)| FnMeta { name: c.name.clone(), file: files[fi].path.to_path_buf(), line: c.line })
        .collect();
    let mut call_at: HashMap<CallKey, NodeIndex> = HashMap::new();
    for n in cpg.nodes_of(CpgNode::Call) {
        let x = &cpg.graph[n];
        if let Some(name) = x.name.as_deref() {
            call_at.insert((x.file, x.line, x.col, normalize_callee(name)), n);
        }
    }
    let mut links: HashMap<NodeIndex, Vec<CallLink>> = HashMap::new();
    for l in &cpg.links {
        links.entry(l.call).or_default().push(*l);
    }
    let mut v = View {
        cpg,
        cfgs,
        fn_file,
        graph: DiGraph::new(),
        seen: HashSet::new(),
        params: vec![],
        receivers: vec![],
        rets: vec![],
        frees: vec![],
        fields: HashMap::new(),
        defs: HashMap::new(),
        made: HashMap::new(),
        assigned: HashMap::new(),
        calls: HashMap::new(),
        call_at,
        links,
        emitted: HashSet::new(),
        pending_rets: vec![],
        stmt_at: HashMap::new(),
        closure_at: HashMap::new(),
    };
    for (f, cfg) in v.cfgs.iter().enumerate() {
        v.closure_at.insert((v.fn_file[f], cfg.line, cfg.col), f);
    }
    // parameter nodes first: calls in any function link to them
    for f in 0..v.cfgs.len() {
        let cfg = v.cfgs[f];
        let mut ps = HashMap::new();
        for name in cfg.params.iter().flatten() {
            ps.insert(name.clone(), v.node(f, NodeKind::Param, name, cfg.line));
        }
        v.params.push(ps);
        let recv = cfg.receiver.as_deref().map(|r| v.node(f, NodeKind::Param, r, cfg.line));
        v.receivers.push(recv);
        v.rets.push(vec![]);
        v.frees.push(HashMap::new());
    }
    for f in 0..v.cfgs.len() {
        v.function(f, control);
    }
    for (call, callee) in std::mem::take(&mut v.pending_rets) {
        for r in v.rets[callee].clone() {
            v.edge(r, call, EdgeKind::Ret, None);
        }
    }
    v.after_calls();
    DataFlow { functions, graph: v.graph }
}

impl<'a> View<'a> {
    fn node(&mut self, func: usize, kind: NodeKind, var: &str, line: usize) -> NodeIndex {
        self.graph.add_node(Node { func, kind, var: var.to_string(), line })
    }

    fn edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind, label: Option<String>) {
        if from != to && self.seen.insert((from, to, kind)) {
            self.graph.add_edge(from, to, Edge { kind, label });
        }
    }

    fn free_node(&mut self, f: usize, path: &str) -> NodeIndex {
        if let Some(&n) = self.frees[f].get(path) {
            return n;
        }
        let n = self.node(f, NodeKind::Free, path, 0);
        self.frees[f].insert(path.to_string(), n);
        n
    }

    /// The node of a field of the class of method `f`, for the path `self.field...`.
    fn field_node(&mut self, f: usize, path: &str) -> Option<NodeIndex> {
        let cfg = self.cfgs[f];
        let recv = cfg.receiver.as_deref()?;
        let field = path.strip_prefix(recv)?.strip_prefix('.')?.split(['.', '[', '-']).next()?;
        let name = &cfg.name;
        let class = name[..name.rfind(['.', ':'])?].trim_end_matches(':');
        let id = format!("{class}.{field}");
        if let Some(&n) = self.fields.get(&id) {
            return Some(n);
        }
        let n = self.node(f, NodeKind::Field, &id, 0);
        self.fields.insert(id, n);
        Some(n)
    }

    /// The statement node of statement `(block, idx)` of function `f`.
    fn stmt_node(&self, sg: &StmtGraph, f: usize, block: NodeIndex<u32>, idx: usize) -> Option<NodeIndex> {
        sg.graph.node_indices().find(|&n| sg.graph[n] == SNode::Stmt { block, idx }).map(|n| self.cpg.stmt_nodes[f][n.index()])
    }

    fn def_node(&mut self, f: usize, key: (usize, usize, usize), sn: NodeIndex, var: &str, line: usize, canon: &str) -> NodeIndex {
        let k = (f, key.0, key.1, key.2);
        if let Some(&n) = self.assigned.get(&k) {
            return n;
        }
        let n = self.node(f, NodeKind::Def, var, line);
        self.assigned.insert(k, n);
        self.defs.entry((sn, canon.to_string())).or_default().push(n);
        self.made.entry(sn).or_default().push(n);
        n
    }

    fn call_node(&mut self, f: usize, sn: NodeIndex, c: &CallFlow) -> NodeIndex {
        let key = (f, c.line, c.col, c.callee.clone());
        if let Some(&n) = self.calls.get(&key) {
            return n;
        }
        let n = self.node(f, NodeKind::Call, &c.callee, c.line);
        self.calls.insert(key, n);
        self.made.entry(sn).or_default().push(n);
        n
    }

    /// The nodes whose value a read of `p` at statement `sn` of function `f` depends on.
    fn path_sources(&mut self, f: usize, sn: NodeIndex, p: &str) -> Vec<NodeIndex> {
        let path = self.cpg.canon(f, p);
        let reaching: Vec<(NodeIndex, String)> = self
            .cpg
            .graph
            .edges_directed(sn, Direction::Incoming)
            .filter(|e| e.weight().kind == CpgEdge::Reaching && matches!(e.weight().label, None | Some("object")))
            .filter_map(|e| Some((e.source(), e.weight().var.clone()?)))
            .filter(|(_, v)| related(v, &path))
            .collect();
        let mut out: Vec<NodeIndex> = vec![];
        for (d, var) in reaching {
            for n in self.def_nodes(f, d, &var, p) {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        if out.is_empty() {
            out.push(self.free_node(f, p));
        }
        out
    }

    /// The flow nodes a definition of `var` at CPG node `d` stands for.
    fn def_nodes(&mut self, f: usize, d: NodeIndex, var: &str, read: &str) -> Vec<NodeIndex> {
        // a parameter
        let cpg = self.cpg;
        if let Some((name, _)) = cpg.param_nodes[f].iter().find(|(_, n)| **n == d) {
            return self.params[f].get(name).copied().into_iter().collect();
        }
        // entry of the method: the receiver, what other methods stored in its fields, or a captured variable
        if d == cpg.methods[f] {
            let recv = self.cfgs[f].receiver.clone();
            if recv.as_deref() == Some(var) {
                return self.receivers[f].into_iter().collect();
            }
            if recv.as_deref().is_some_and(|r| root(var) == r) {
                return self.field_node(f, var).or(self.receivers[f]).into_iter().collect();
            }
            return vec![self.free_node(f, read)];
        }
        if let Some(v) = self.defs.get(&(d, var.to_string())) {
            return v.clone();
        }
        // a definition of a path related to the one read, or anything the statement made
        let related_defs: Vec<NodeIndex> =
            self.defs.iter().filter(|((n, v), _)| *n == d && related(v, var)).flat_map(|(_, ns)| ns.iter().copied()).collect();
        if !related_defs.is_empty() {
            return related_defs;
        }
        self.made.get(&d).cloned().unwrap_or_default()
    }

    fn eval(&mut self, f: usize, sn: NodeIndex, flow: &Flow) -> Vec<NodeIndex> {
        match flow {
            Flow::Clean => vec![],
            Flow::Path(p) if p.starts_with("<fn@") => vec![],
            Flow::Path(p) => self.path_sources(f, sn, p),
            Flow::Call(c) => vec![self.call(f, sn, c)],
            Flow::Join(v) => v.iter().flat_map(|x| self.eval(f, sn, x)).collect(),
        }
    }

    /// The call node of `c`, with the edges into it and to the functions it may call.
    /// What the definitions reaching a read of `path` at statement `sn` assign to it.
    fn assigned_to(&self, sn: NodeIndex, path: &str) -> Vec<&Flow> {
        let mut values: Vec<&Flow> = vec![];
        for e in self.cpg.graph.edges_directed(sn, Direction::Incoming) {
            if e.weight().kind != CpgEdge::Reaching || e.weight().label.is_some() || e.weight().var.as_deref() != Some(path) {
                continue;
            }
            let Some(&(df, b, si)) = self.stmt_at.get(&e.source()) else { continue };
            let st = &self.cfgs[df].graph[b].stmts[si];
            values.extend(st.assigns.iter().chain(&st.elems).filter(|a| a.target == path).map(|a| &a.value));
        }
        values
    }

    /// Is `v` a reference to function `g` (a lambda written there, or its name)?
    fn refers_to(&self, v: &Flow, g: usize) -> bool {
        let cb = self.cfgs[g];
        matches!(v, Flow::Path(p) if *p == closure_marker(cb.line, cb.col) || simple_name(p) == simple_name(&cb.name))
    }

    /// Is `v` a reference to some function?
    fn is_function_ref(&self, v: &Flow) -> bool {
        matches!(v, Flow::Path(p) if p.starts_with("<fn@") || self.cfgs.iter().any(|cfg| simple_name(&cfg.name) == simple_name(p)))
    }

    /// A call through a variable (`f(x)` after `f = run`) reaches the functions that the definitions
    /// reaching the variable hold, not every function it was ever assigned.
    fn holds(&self, sn: NodeIndex, c: &CallFlow, g: usize) -> bool {
        if c.callee.contains('.') {
            return true;
        }
        let values = self.assigned_to(sn, &c.callee);
        values.is_empty() || values.iter().any(|v| self.refers_to(v, g) || !self.is_function_ref(v))
    }

    /// Is the argument `a` a function: written there, named there, or held by a variable or element
    /// the definitions reaching here assigned one to?
    fn is_function_value(&self, sn: NodeIndex, a: &Flow) -> bool {
        if self.is_function_ref(a) {
            return true;
        }
        let Flow::Path(p) = a else { return false };
        self.assigned_to(sn, p).iter().any(|v| self.is_function_ref(v))
    }

    fn call(&mut self, f: usize, sn: NodeIndex, c: &CallFlow) -> NodeIndex {
        let n = self.call_node(f, sn, c);
        if !self.emitted.insert(n) {
            return n;
        }
        if let Some(r) = &c.recv {
            for src in self.eval(f, sn, r) {
                self.edge(src, n, EdgeKind::Flow, None);
            }
        }
        for a in &c.args {
            for src in self.eval(f, sn, a) {
                self.edge(src, n, EdgeKind::Flow, None);
            }
        }
        let key = (self.fn_file[f], c.line, c.col, c.callee.clone());
        let mut links: Vec<CallLink> = self.call_at.get(&key).and_then(|cn| self.links.get(cn)).cloned().unwrap_or_default();
        links.retain(|l| self.holds(sn, c, l.callee));
        // a lambda written in an argument is called by the callee, even where nothing scanned is
        for a in &c.args {
            let Flow::Path(p) = a else { continue };
            let at = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')).and_then(|r| r.split_once(':'));
            let Some((line, col)) = at else { continue };
            if let Some(&g) = line.parse().ok().zip(col.parse().ok()).and_then(|(l, c)| self.closure_at.get(&(self.fn_file[f], l, c)))
                && !links.iter().any(|l| l.callee == g)
            {
                links.push(CallLink { call: self.call_at.get(&key).copied().unwrap_or(sn), caller: f, callee: g, flows: false, exact: true });
            }
        }
        for l in links {
            let g = l.callee;
            let cb = self.cfgs[g];
            if l.flows {
                // only a call that does not rest on the method name alone binds arguments
                if !l.exact {
                    continue;
                }
                if let (Some(recv), Some(target)) = (&c.recv, self.receivers[g]) {
                    let name = cb.receiver.clone();
                    for src in self.eval(f, sn, recv) {
                        self.edge(src, target, EdgeKind::Arg, name.clone());
                    }
                }
                for (j, names) in cb.params.iter().enumerate() {
                    let Some(arg) = arg_for(c, j, &cb.params) else { continue };
                    for src in self.eval(f, sn, arg) {
                        for name in names {
                            if let Some(&t) = self.params[g].get(name) {
                                self.edge(src, t, EdgeKind::Arg, Some(name.clone()));
                            }
                        }
                    }
                }
                self.pending_rets.push((n, g));
            } else {
                // a function handed over: its callee calls it with the other arguments and the object
                // (`queue.append(f)` only stores it)
                if crate::analysis::rules::MUTATORS.contains(&c.callee.rsplit('.').next().unwrap_or(&c.callee)) {
                    continue;
                }
                let mut inputs: Vec<&Flow> = c.args.iter().filter(|a| !self.is_function_value(sn, a)).collect();
                inputs.extend(c.recv.as_ref());
                for a in inputs {
                    for src in self.eval(f, sn, a) {
                        for name in cb.params.iter().flatten() {
                            if let Some(&t) = self.params[g].get(name) {
                                self.edge(src, t, EdgeKind::Arg, Some(name.clone()));
                            }
                        }
                    }
                }
                self.pending_rets.push((n, g));
            }
        }
        n
    }

    fn function(&mut self, f: usize, control: bool) {
        let cfg = self.cfgs[f];
        let sg = stmt_graph(cfg);
        // definitions first, in the order a walk from the entry reaches them
        let mut order: Vec<NodeIndex<u32>> = vec![];
        let mut queue: VecDeque<NodeIndex<u32>> = VecDeque::from([cfg.entry]);
        let mut queued: HashSet<NodeIndex<u32>> = HashSet::from([cfg.entry]);
        while let Some(b) = queue.pop_front() {
            order.push(b);
            for s in cfg.graph.neighbors(b) {
                if queued.insert(s) {
                    queue.push_back(s);
                }
            }
        }
        let visit = |v: &mut Self, blocks: &[NodeIndex<u32>]| {
            for &b in blocks {
                for (si, s) in cfg.graph[b].stmts.iter().enumerate() {
                    let Some(sn) = v.stmt_node(&sg, f, b, si) else { continue };
                    v.stmt_at.insert(sn, (f, b, si));
                    for (ai, a) in s.assigns.iter().enumerate().filter(|(_, a)| !covered(s, a)) {
                        let canon = v.cpg.canon(f, &a.target);
                        v.def_node(f, (b.index(), si, ai), sn, &a.target, s.line, &canon);
                    }
                    for (ei, e) in s.elems.iter().enumerate() {
                        let canon = v.cpg.canon(f, &e.target);
                        v.def_node(f, (b.index(), si, 1 << 20 | ei), sn, &e.target, s.line, &canon);
                    }
                }
            }
        };
        visit(self, &order);
        let mut blocks: Vec<NodeIndex<u32>> = cfg.graph.node_indices().collect();
        blocks.sort();
        visit(self, &blocks);

        let mut branches: HashMap<(usize, usize), NodeIndex> = HashMap::new();
        let mut made_by: HashMap<(usize, usize), Vec<NodeIndex>> = HashMap::new();
        for &b in &blocks {
            for (si, s) in cfg.graph[b].stmts.iter().enumerate() {
                let Some(sn) = self.stmt_node(&sg, f, b, si) else { continue };
                let mut mine: Vec<NodeIndex> = vec![];
                for c in &s.calls {
                    mine.push(self.call(f, sn, c));
                }
                if control && s.kind == StmtKind::Branch {
                    let var: String = s.text.chars().take(40).collect();
                    let n = self.node(f, NodeKind::Branch, &var, s.line);
                    if let Some(cond) = &s.cond {
                        for src in self.eval(f, sn, cond) {
                            self.edge(src, n, EdgeKind::Flow, None);
                        }
                    }
                    branches.insert((b.index(), si), n);
                    mine.push(n);
                }
                let written = s.assigns.iter().enumerate().chain(s.elems.iter().enumerate().map(|(ei, e)| (1 << 20 | ei, e)));
                for (ai, a) in written {
                    let Some(&node) = self.assigned.get(&(f, b.index(), si, ai)) else { continue };
                    mine.push(node);
                    for src in self.eval(f, sn, &a.value) {
                        self.edge(src, node, EdgeKind::Flow, None);
                    }
                    if let Some(field) = self.field_node(f, &a.target) {
                        self.edge(node, field, EdgeKind::Flow, None);
                    }
                }
                if let Some(flow) = &s.ret {
                    let node = self.node(f, NodeKind::Return, "return", s.line);
                    self.rets[f].push(node);
                    self.made.entry(sn).or_default().push(node);
                    mine.push(node);
                    for src in self.eval(f, sn, flow) {
                        self.edge(src, node, EdgeKind::Flow, None);
                    }
                }
                made_by.insert((b.index(), si), mine);
            }
        }
        if control {
            let key = |n: NodeIndex| match sg.graph[n] {
                SNode::Stmt { block, idx } => Some((block.index(), idx)),
                _ => None,
            };
            for (a, b, kind) in control_dependence(&sg) {
                let (Some(ka), Some(kb)) = (key(a), key(b)) else { continue };
                let Some(&branch) = branches.get(&ka) else { continue };
                for n in made_by.get(&kb).cloned().unwrap_or_default() {
                    self.edge(branch, n, EdgeKind::Control, Some(kind.as_str().to_string()));
                }
            }
        }
    }

    /// What a callee stores in the fields of its parameters flows into the call, and a closure
    /// reads the variables of the scope it was created in.
    fn after_calls(&mut self) {
        let cpg = self.cpg;
        for e in cpg.graph.edge_references().filter(|e| e.weight().kind == CpgEdge::ParamOut) {
            let Some((callee_var, _)) = e.weight().var.as_deref().and_then(|v| v.split_once('>')) else { continue };
            let Some(g) = cpg.methods.iter().position(|&m| m == cpg.enclosing_method(e.source())) else { continue };
            // only fields of a parameter and variables a closure assigns: the fields of the
            // receiver are the class's shared nodes
            let head = root(callee_var);
            if !self.cfgs[g].params.iter().flatten().any(|p| p == head) && !self.cfgs[g].free_writes.iter().any(|w| w == head) {
                continue;
            }
            let writers = self.defs.get(&(e.source(), callee_var.to_string())).cloned().unwrap_or_default();
            let calls: Vec<NodeIndex> = self
                .calls
                .iter()
                .filter(|((f, line, col, callee), _)| {
                    let key = (self.fn_file[*f], *line, *col, callee.clone());
                    cpg.statement_of(self.call_at.get(&key).copied().unwrap_or(e.target())) == e.target()
                        && self.call_at.get(&key).and_then(|cn| self.links.get(cn)).is_some_and(|ls| ls.iter().any(|l| l.callee == g))
                })
                .map(|(_, &n)| n)
                .collect();
            for w in &writers {
                for &c in &calls {
                    self.edge(*w, c, EdgeKind::Flow, None);
                }
            }
        }
        for e in cpg.graph.edge_references().filter(|e| e.weight().kind == CpgEdge::Capture) {
            let (Some(v), Some(g)) = (e.weight().var.clone(), cpg.methods.iter().position(|&m| m == e.target())) else { continue };
            let Some(f) = cpg.methods.iter().position(|&m| m == cpg.enclosing_method(e.source())) else { continue };
            // every path the closure reads below the captured variable
            let reads: Vec<NodeIndex> = self.frees[g].iter().filter(|(p, _)| root(p) == root(&v)).map(|(_, &n)| n).collect();
            let sources = self.path_sources(f, e.source(), &v);
            for target in reads {
                for &src in &sources {
                    self.edge(src, target, EdgeKind::Arg, Some("captured".into()));
                }
            }
        }
    }
}
