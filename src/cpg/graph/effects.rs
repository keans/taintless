//! Reaching definitions with aliases and the effects of calls.
//!
//! Inside one function a definition reaches a read when no definition replaces it on the way.
//! Three things go beyond a function's own statements, and all of them are `Reaching` or
//! cross-function edges:
//!
//! * **Aliases.** `b = a`, `h.r = a` and `b = identity(a)` make two names one object, so a
//!   definition of `b.f` reaches the reads of `a.f` (the edge's `var` is the path both share).
//! * **What a callee stores for its caller** (`ParamOut`): `fill(a)` where `fill` assigns
//!   `o.d` defines `a.d` at the call; `r.set(c)` and constructors define `r.f` for the fields
//!   the method assigns through its receiver; a closure that assigns a captured variable
//!   defines it at the call. The callee's statement points at the call statement.
//! * **Captured variables** (`Capture`): a call or creation of a closure reads the variables
//!   the closure reads from its creator; the closure defines them at its entry.
//!
//! Aliases hold for the whole function (a variable assigned once), like in `analysis::dataflow`.

use super::*;
use crate::analysis::taint::arg_for;
use crate::cpg::cfg::StmtGraph;
use crate::cpg::ddg::{Extras, canon, defined_vars_with, object_reaching_with, reaching_definitions_with};
use crate::ir::{CallFlow, Flow};
use petgraph::visit::IntoEdgeReferences;

/// The first name of a path: `a` for `a.b[0].c`.
fn root(path: &str) -> &str {
    path.split(['.', '[', '-']).next().unwrap_or(path)
}

fn assigns(cfg: &Cfg) -> impl Iterator<Item = &crate::ir::Assign> {
    cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| s.assigns.iter().chain(&s.elems))
}

/// The fields of its parameters a function assigns: `(parameter, ".field")` for `o.d = x`.
fn param_writes(cfg: &Cfg) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = vec![];
    for a in assigns(cfg) {
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

/// The fields of the receiver a method assigns, as paths below it: `.d` for `self.d = x`.
fn receiver_writes(cfg: &Cfg) -> Vec<String> {
    let Some(r) = &cfg.receiver else { return vec![] };
    let mut out: Vec<String> = vec![];
    for a in assigns(cfg) {
        if let Some(rest) = a.target.strip_prefix(r.as_str()).filter(|x| x.starts_with('.')) {
            let w = format!(".{}", rest[1..].split(['.', '[']).next().unwrap_or(""));
            if w.len() > 1 && !out.contains(&w) {
                out.push(w);
            }
        }
    }
    out
}

/// The variables a function reads that it neither receives, assigns nor declares.
fn free_reads(cfg: &Cfg) -> Vec<String> {
    let mut local: HashSet<&str> = cfg.params.iter().flatten().map(String::as_str).collect();
    local.extend(cfg.receiver.as_deref());
    local.extend(assigns(cfg).filter(|a| a.strong || !a.target.contains(['.', '['])).map(|a| root(&a.target)));
    local.extend(cfg.local_types.iter().map(|(n, _)| n.as_str()));
    let mut out: Vec<String> = vec![];
    fn paths<'f>(f: &'f Flow, out: &mut Vec<&'f str>) {
        match f {
            Flow::Clean => {}
            Flow::Path(p) => out.push(p),
            Flow::Call(c) => {
                c.recv.iter().chain(&c.args).for_each(|a| paths(a, out));
            }
            Flow::Join(v) => v.iter().for_each(|a| paths(a, out)),
        }
    }
    let mut read: Vec<&str> = vec![];
    for s in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
        for a in s.assigns.iter().chain(&s.elems) {
            paths(&a.value, &mut read);
        }
        for c in &s.calls {
            c.recv.iter().chain(&c.args).for_each(|a| paths(a, &mut read));
        }
        s.ret.iter().chain(&s.cond).for_each(|a| paths(a, &mut read));
    }
    for p in read {
        let r = root(p);
        if !r.is_empty() && !r.starts_with('<') && !local.contains(r) && !out.iter().any(|x| x == r) {
            out.push(r.to_string());
        }
    }
    out
}

impl Cpg {
    /// Record that call expression `from` (in function `caller`) may call function `callee`:
    /// a `Call` edge and, where arguments and result flow, `ParamIn` / `ReturnOut` edges.
    /// Argument `i` binds the parameter its keyword names, else the one at its position.
    pub(super) fn link_call(&mut self, cfgs: &[&Cfg], link: CallLink, label: Option<&'static str>, seen: &mut EdgeSet) {
        let CallLink { call: from, caller, callee, flows, .. } = link;
        let to = self.methods[callee];
        self.edge(from, to, EdgeKind::Call, label, seen);
        self.links.push(link);
        if !flows {
            return;
        }
        let args = self.arguments(from).len();
        let names = self.call_flow(cfgs[caller], from).map(|c| c.arg_names.clone()).unwrap_or_default();
        for i in 0..args {
            let pos = names.get(i).and_then(|n| n.as_ref()).and_then(|n| self.params[callee].iter().position(|ps| ps.contains(n))).unwrap_or(i);
            for name in self.params[callee].get(pos).cloned().unwrap_or_default() {
                let known = self.graph.edges_directed(from, Direction::Outgoing).any(|e| {
                    e.target() == to && e.weight().kind == EdgeKind::ParamIn && e.weight().order as usize == i && e.weight().var.as_deref() == Some(name.as_str())
                });
                if !known {
                    self.graph.add_edge(from, to, Edge { kind: EdgeKind::ParamIn, label: None, var: Some(name), order: i as u32 });
                }
            }
        }
        for r in self.returns[callee].clone() {
            self.edge(r, from, EdgeKind::ReturnOut, None, seen);
        }
    }

    /// A call through a parameter (`fn(x)` in `apply(fn, x)`) calls what its callers pass for it.
    pub(super) fn add_callback_calls(&mut self, files: &[SourceFile], seen: &mut EdgeSet) {
        let cfgs: Vec<&Cfg> = files.iter().flat_map(|f| f.cfgs.iter()).collect();
        let links = self.links.clone();
        let mut new: Vec<(NodeIndex, usize, usize)> = vec![];
        for (k, x) in self.graph.node_indices().map(|k| (k, &self.graph[k])).filter(|(_, x)| x.kind == NodeKind::Call) {
            let Some(name) = x.name.as_deref().map(normalize_callee).filter(|n| !n.contains('.')) else { continue };
            let Some(f) = self.methods.iter().position(|&m| m == self.enclosing_method(k)) else { continue };
            if !cfgs[f].params.iter().flatten().any(|p| *p == name) {
                continue;
            }
            // every call of `f` binds the parameter to an argument: a lambda written there, or a function named there
            for l in links.iter().filter(|l| l.callee == f && l.flows) {
                let bound: Vec<usize> = self
                    .graph
                    .edges_directed(l.call, Direction::Outgoing)
                    .filter(|e| e.weight().kind == EdgeKind::ParamIn && e.target() == self.methods[f] && e.weight().var.as_deref() == Some(name.as_str()))
                    .map(|e| e.weight().order as usize)
                    .collect();
                let args = self.arguments(l.call);
                for i in bound {
                    let Some(&a) = args.get(i) else { continue };
                    let ax = &self.graph[a];
                    let targets: Vec<usize> = match ax.kind {
                        NodeKind::Method => self.function_of(a).into_iter().collect(),
                        NodeKind::Identifier => links
                            .iter()
                            .filter(|c| c.call == l.call && c.callee != f)
                            .filter(|c| {
                                let n = self.graph[self.methods[c.callee]].name.as_deref().unwrap_or("");
                                crate::lang::common::simple_name(n) == ax.name.as_deref().unwrap_or("\0")
                            })
                            .map(|c| c.callee)
                            .collect(),
                        _ => vec![],
                    };
                    new.extend(targets.into_iter().map(|t| (k, f, t)));
                }
            }
        }
        for (k, f, t) in new {
            self.link_call(&cfgs, CallLink { call: k, caller: f, callee: t, flows: true, exact: true }, Some("param"), seen);
        }
    }

    /// The function id of the method or file node `n` (the file node: its top-level code).
    fn function_of(&self, n: NodeIndex) -> Option<usize> {
        self.methods.iter().position(|&m| m == n)
    }

    /// The function a closure (function id `j`) is written in.
    fn creator_of(&self, j: usize) -> Option<usize> {
        let node = &self.graph[self.methods[j]];
        let (info, mut up) = (&self.files[node.file], node.ast?);
        if self.methods[j] == info.nodes[0] {
            return None;
        }
        while let Some(p) = info.ast.nodes[up].parent {
            if info.ast.nodes[p].kind == NodeKind::Method {
                return self.function_of(info.nodes[p]);
            }
            up = p;
        }
        self.function_of(info.nodes[0]).filter(|&f| f != j)
    }

    /// The statement a closure is created in, when the creator has one around it.
    fn creation_stmt(&self, j: usize) -> Option<NodeIndex> {
        let node = &self.graph[self.methods[j]];
        let info = &self.files[node.file];
        let parent = info.ast.nodes[node.ast?].parent?;
        let s = self.statement_of(info.nodes[parent]);
        (self.graph[s].kind != NodeKind::Method && s != info.nodes[0]).then_some(s)
    }

    /// The `CallFlow` of the call expression `call` in function `f`.
    fn call_flow<'c>(&self, cfg: &'c Cfg, call: NodeIndex) -> Option<&'c CallFlow> {
        let x = &self.graph[call];
        let callee = normalize_callee(x.name.as_deref()?);
        cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.calls).find(|c| (c.line, c.col) == (x.line, x.col) && c.callee == callee)
    }

    /// The parameter a function returns as itself (`return a`, never reassigned).
    fn returned_param(cfg: &Cfg) -> Option<usize> {
        let stmts = || cfg.graph.node_weights().flat_map(|b| &b.stmts);
        let mut returned = stmts().filter_map(|s| s.ret.as_ref());
        let Some(Flow::Path(name)) = returned.next() else { return None };
        if returned.any(|r| !matches!(r, Flow::Path(n) if n == name)) || assigns(cfg).any(|a| a.strong && a.target == *name) {
            return None;
        }
        cfg.params.iter().position(|ns| ns.contains(name))
    }

    pub(super) fn add_reaching(&mut self, files: &[SourceFile], seen: &mut EdgeSet) {
        let cfgs: Vec<&Cfg> = files.iter().flat_map(|f| f.cfgs.iter()).collect();
        let sgs: Vec<StmtGraph> = cfgs.iter().map(|c| stmt_graph(c)).collect();
        let mut ex: Vec<Extras> = vec![Extras::default(); cfgs.len()];
        let links = self.links.clone();
        // the statement-graph nodes that stand for a graph node
        let sg_nodes = |cpg: &Cpg, f: usize, n: NodeIndex| -> Vec<NodeIndex> {
            sgs[f].graph.node_indices().filter(|&i| cpg.stmt_nodes[f][i.index()] == n && i != sgs[f].entry && i != sgs[f].exit).collect()
        };
        // statements of function `f` that assign a path whose first name is `name` below `prefix`
        let writers = |cpg: &Cpg, f: usize, matches: &dyn Fn(&str) -> bool| -> Vec<NodeIndex> {
            let mut out = vec![];
            for i in sgs[f].graph.node_indices() {
                let crate::cpg::cfg::SNode::Stmt { block, idx } = sgs[f].graph[i] else { continue };
                let s = &cfgs[f].graph[block].stmts[idx];
                if s.assigns.iter().chain(&s.elems).any(|a| matches(&a.target)) {
                    let n = cpg.stmt_nodes[f][i.index()];
                    if !out.contains(&n) {
                        out.push(n);
                    }
                }
            }
            out
        };

        // aliases: names that stand for one object
        for (f, cfg) in cfgs.iter().enumerate() {
            let mut count: HashMap<&str, usize> = HashMap::new();
            for a in assigns(cfg).filter(|a| a.strong || a.target.contains(['.', '['])) {
                *count.entry(&a.target).or_default() += 1;
            }
            let mut table: HashMap<String, String> = HashMap::new();
            for a in assigns(cfg) {
                if !a.strong || count.get(a.target.as_str()) != Some(&1) || cfg.params.iter().flatten().any(|p| *p == a.target) {
                    continue;
                }
                if a.target.contains('.') && (a.target.contains('-') || cfg.receiver.as_deref() == Some(root(&a.target))) {
                    continue; // the receiver's fields are shared between methods
                }
                let source = match &a.value {
                    Flow::Path(p) if root(p) != root(&a.target) && !p.starts_with('<') => Some(p.clone()),
                    Flow::Call(c) => {
                        // `b = identity(a)`: the one function it can call hands its argument back
                        let mine: Vec<&CallLink> = links
                            .iter()
                            .filter(|l| l.caller == f && l.flows && self.graph[l.call].line == c.line && self.graph[l.call].col == c.col)
                            .collect();
                        match mine[..] {
                            [l] => Self::returned_param(cfgs[l.callee]).and_then(|i| match arg_for(c, i, &cfgs[l.callee].params)? {
                                Flow::Path(p) if root(p) != root(&a.target) => Some(p.clone()),
                                _ => None,
                            }),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                if let Some(p) = source {
                    table.insert(a.target.clone(), p);
                }
            }
            ex[f].aliases = table;
        }

        // captured variables: a closure reads some of its creator's variables at entry
        let mut param_out: Vec<(NodeIndex, NodeIndex, String)> = vec![];
        let mut capture: Vec<(NodeIndex, usize, String)> = vec![];
        for j in 0..cfgs.len() {
            let Some(creator) = self.creator_of(j) else { continue };
            let defined_outside = |name: &str| {
                let mut c = Some(creator);
                while let Some(f) = c {
                    let cfg = cfgs[f];
                    if cfg.params.iter().flatten().any(|p| p == name) || cfg.receiver.as_deref() == Some(name) || assigns(cfg).any(|a| root(&a.target) == name) {
                        return true;
                    }
                    c = self.creator_of(f);
                }
                false
            };
            let reads: Vec<String> = free_reads(cfgs[j]).into_iter().filter(|n| defined_outside(n)).collect();
            ex[j].entry = reads.clone();
            if reads.is_empty() {
                continue;
            }
            if let Some(s) = self.creation_stmt(j) {
                for sg in sg_nodes(self, creator, s) {
                    ex[creator].uses.entry(sg).or_default().extend(reads.iter().cloned());
                }
                capture.extend(reads.iter().map(|v| (s, j, v.clone())));
            }
        }

        // effects of calls
        for l in links.iter().filter(|l| l.flows) {
            let (caller_cfg, callee_cfg) = (cfgs[l.caller], cfgs[l.callee]);
            let Some(flow) = self.call_flow(caller_cfg, l.call) else { continue };
            let stmt = self.statement_of(l.call);
            let at = sg_nodes(self, l.caller, stmt);
            if at.is_empty() {
                continue;
            }
            let define = |ex: &mut Vec<Extras>, var: String| {
                for &sg in &at {
                    ex[l.caller].defs.entry(sg).or_default().push((var.clone(), false));
                }
            };
            // fields of the arguments the callee assigns
            for (j, suffix) in param_writes(callee_cfg) {
                let Some(Flow::Path(a)) = arg_for(flow, j, &callee_cfg.params) else { continue };
                let var = format!("{}{suffix}", canon(&ex[l.caller].aliases, a));
                // a parameter can bind several names (a destructuring pattern): the one the callee assigns
                for name in &callee_cfg.params[j] {
                    for w in writers(self, l.callee, &|t| t == format!("{name}{suffix}")) {
                        param_out.push((w, stmt, format!("{name}{suffix}>{var}")));
                    }
                }
                define(&mut ex, var);
            }
            // fields of the receiver, or of the object a constructor builds
            let writes = receiver_writes(callee_cfg);
            if !writes.is_empty() {
                let object = match &flow.recv {
                    Some(Flow::Path(p)) => Some(p.clone()),
                    // `r = Req(..)`: the statement assigns the new object to `r`
                    _ => caller_cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns).find_map(|a| match &a.value {
                        Flow::Call(c) if (c.line, c.col) == (flow.line, flow.col) && c.callee == flow.callee && !a.target.contains(['[', '-']) => Some(a.target.clone()),
                        _ => None,
                    }),
                };
                if let (Some(object), Some(recv)) = (object, &callee_cfg.receiver) {
                    let object = canon(&ex[l.caller].aliases, &object);
                    for w in &writes {
                        let var = format!("{object}{w}");
                        for n in writers(self, l.callee, &|t| t.strip_prefix(recv.as_str()).is_some_and(|r| r.starts_with(w.as_str()) && r[w.len()..].chars().next().is_none_or(|c| matches!(c, '.' | '[')))) {
                            param_out.push((n, stmt, format!("{recv}{w}>{var}")));
                        }
                        define(&mut ex, var);
                    }
                }
            }
            // a closure assigns the variables of the function it was written in, and reads others
            if self.creator_of(l.callee) == Some(l.caller) {
                for name in &callee_cfg.free_writes {
                    for w in writers(self, l.callee, &|t| root(t) == name) {
                        param_out.push((w, stmt, format!("{name}>{name}")));
                    }
                    define(&mut ex, name.clone());
                }
                let reads = ex[l.callee].entry.clone();
                for v in reads {
                    for &sg in &at {
                        ex[l.caller].uses.entry(sg).or_default().push(v.clone());
                    }
                    capture.push((stmt, l.callee, v));
                }
            }
        }

        // definitions per statement (aliases and effects resolved), then the reaching edges
        let mut reaching: HashSet<(NodeIndex, NodeIndex, String)> = HashSet::new();
        for (f, cfg) in cfgs.iter().enumerate() {
            let (sg, map) = (&sgs[f], self.stmt_nodes[f].clone());
            for n in sg.graph.node_indices() {
                if let crate::cpg::cfg::SNode::Stmt { block, idx } = sg.graph[n] {
                    self.graph[map[n.index()]].defines.clear();
                    let _ = (block, idx);
                }
            }
            for n in sg.graph.node_indices() {
                if let crate::cpg::cfg::SNode::Stmt { block, idx } = sg.graph[n] {
                    let st = &cfg.graph[block].stmts[idx];
                    for v in defined_vars_with(st, &ex[f], ex[f].defs.get(&n)) {
                        if !self.graph[map[n.index()]].defines.contains(&v) {
                            self.graph[map[n.index()]].defines.push(v);
                        }
                    }
                }
            }
            let ordinary = reaching_definitions_with(cfg, sg, &ex[f]);
            let ordinary_set: HashSet<_> = ordinary.iter().cloned().collect();
            for (d, u, var) in &ordinary {
                let (from, to) = (map[d.index()], map[u.index()]);
                // a parameter is defined where it is declared; what the receiver holds is defined by the method
                let from = match self.param_nodes.get(f).zip(var.split('.').next()) {
                    Some((nodes, root)) if *d == sg.entry && cfg.receiver.as_deref() != Some(root) => nodes.get(root).copied().unwrap_or(from),
                    _ => from,
                };
                if reaching.insert((from, to, var.clone())) {
                    self.graph.add_edge(from, to, Edge { kind: EdgeKind::Reaching, label: None, var: Some(var.clone()), order: 0 });
                }
            }
            for (d, u, var) in object_reaching_with(cfg, sg, &ex[f]) {
                if ordinary_set.contains(&(d, u, var.clone())) {
                    continue;
                }
                let from = match self.param_nodes.get(f).zip(var.split('.').next()) {
                    Some((nodes, root)) if d == sg.entry && cfg.receiver.as_deref() != Some(root) => nodes.get(root).copied().unwrap_or(map[d.index()]),
                    _ => map[d.index()],
                };
                self.graph.add_edge(from, map[u.index()], Edge { kind: EdgeKind::Reaching, label: Some("object"), var: Some(var), order: 0 });
            }
        }
        for (from, to, var) in param_out {
            if reaching.insert((from, to, format!(">{var}"))) {
                self.graph.add_edge(from, to, Edge { kind: EdgeKind::ParamOut, label: None, var: Some(var), order: 0 });
            }
        }
        for (from, j, var) in capture {
            if reaching.insert((from, self.methods[j], format!("^{var}"))) {
                self.graph.add_edge(from, self.methods[j], Edge { kind: EdgeKind::Capture, label: None, var: Some(var), order: 0 });
            }
        }
        self.aliases = ex.into_iter().map(|e| e.aliases).collect();
        self.add_element_values(&cfgs, &sgs);
        self.add_interprocedural(&cfgs);
        let _ = seen;
    }

    /// `Reaching` edges between functions, labelled by what crosses (`param_in`, `return`,
    /// `param_out`, `field`): the definitions that reach an argument reach the parameter it binds,
    /// a returned value reaches the call (and the variable it is assigned to), what a callee stores
    /// in the fields of its arguments, its receiver or a captured variable reaches the call, and what
    /// one method stores in a field of its receiver reaches the methods of the class that read it.
    /// Calls through variables and parameters are calls like any other, so callbacks are covered.
    ///
    /// The taint query follows calls with its own call-site stacks, so it skips these edges.
    fn add_interprocedural(&mut self, cfgs: &[&Cfg]) {
        fn related(var: &str, path: &str) -> bool {
            let below = |r: &str| r.starts_with(['.', '[']);
            var == path || var.strip_prefix(path).is_some_and(below) || path.strip_prefix(var).is_some_and(below)
        }
        fn paths<'f>(f: &'f Flow, out: &mut Vec<&'f str>) {
            match f {
                Flow::Clean => {}
                Flow::Path(p) => out.push(p),
                Flow::Call(c) => c.recv.iter().chain(&c.args).for_each(|a| paths(a, out)),
                Flow::Join(v) => v.iter().for_each(|a| paths(a, out)),
            }
        }
        let mut found: Vec<(NodeIndex, NodeIndex, String, &'static str)> = vec![];
        let links = self.links.clone();
        // the definitions that reach statement `s` for one of `vars`
        let reach = |cpg: &Cpg, s: NodeIndex, vars: &[String]| -> Vec<NodeIndex> {
            cpg.graph
                .edges_directed(s, Direction::Incoming)
                .filter(|e| e.weight().kind == EdgeKind::Reaching && e.weight().label.is_none())
                .filter(|e| e.weight().var.as_deref().is_some_and(|v| vars.iter().any(|p| related(v, p))))
                .map(|e| e.source())
                .collect()
        };
        for l in links.iter().filter(|l| l.flows) {
            let Some(flow) = self.call_flow(cfgs[l.caller], l.call) else { continue };
            let stmt = self.statement_of(l.call);
            let callee = self.methods[l.callee];
            let canon_all = |cpg: &Cpg, f: &Flow| -> Vec<String> {
                let mut p = vec![];
                paths(f, &mut p);
                p.into_iter().filter(|p| !p.starts_with('<')).map(|p| cpg.canon(l.caller, p)).collect()
            };
            // arguments reach the parameters they bind (a value made right here: the call statement)
            let bound: Vec<(usize, String)> = self
                .graph
                .edges_directed(l.call, Direction::Outgoing)
                .filter(|e| e.weight().kind == EdgeKind::ParamIn && e.target() == callee)
                .filter_map(|e| Some((e.weight().order as usize, e.weight().var.clone()?)))
                .collect();
            for (i, param) in bound {
                let Some(arg) = flow.args.get(i) else { continue };
                let vars = canon_all(self, arg);
                let from = if vars.is_empty() { vec![stmt] } else { reach(self, stmt, &vars) };
                let to = self.function_of(callee).map_or(callee, |j| self.param_def(j, &param));
                found.extend(from.into_iter().map(|f| (f, to, param.clone(), "param_in")));
            }
            // the object a method is called on reaches the method's receiver
            if let (Some(recv @ Flow::Path(_)), Some(rn)) = (&flow.recv, self.receivers[l.callee].clone()) {
                let vars = canon_all(self, recv);
                found.extend(reach(self, stmt, &vars).into_iter().map(|f| (f, callee, rn.clone(), "param_in")));
            }
            // what the callee returns reaches the call, and the variable it is assigned to
            let targets: Vec<String> = cfgs[l.caller]
                .graph
                .node_weights()
                .flat_map(|b| &b.stmts)
                .flat_map(|s| &s.assigns)
                .filter(|a| matches!(&a.value, Flow::Call(c) if (c.line, c.col) == (flow.line, flow.col) && c.callee == flow.callee) && !a.target.contains('-'))
                .map(|a| a.target.clone())
                .collect();
            for r in self.returns[l.callee].clone() {
                if targets.is_empty() {
                    found.push((r, stmt, "<return>".to_string(), "return"));
                }
                found.extend(targets.iter().map(|t| (r, stmt, t.clone(), "return")));
            }
        }
        // what callees store for their callers
        for e in self.graph.edge_references().filter(|e| e.weight().kind == EdgeKind::ParamOut) {
            if let Some((_, caller)) = e.weight().var.as_deref().and_then(|v| v.split_once('>')) {
                found.push((e.source(), e.target(), caller.to_string(), "param_out"));
            }
        }
        // fields shared between the methods of a class
        let mut classes: HashMap<(u8, String), Vec<usize>> = HashMap::new();
        for (f, cfg) in cfgs.iter().enumerate() {
            if let (Some(_), Some(class)) = (&cfg.receiver, crate::analysis::callgraph::class_of(&cfg.name)) {
                let fam = self.files[self.graph[self.methods[f]].file].lang.family();
                classes.entry((fam, crate::analysis::callgraph::simple_name(&class).to_string())).or_default().push(f);
            }
        }
        for fns in classes.values().filter(|f| f.len() > 1) {
            // the fields each method reads from its receiver: its entry defines them
            let reads: Vec<HashSet<String>> = fns
                .iter()
                .map(|&g| {
                    let rn = cfgs[g].receiver.clone().unwrap_or_default();
                    self.graph
                        .edges_directed(self.methods[g], Direction::Outgoing)
                        .filter(|e| e.weight().kind == EdgeKind::Reaching && e.weight().label.is_none())
                        .filter_map(|e| e.weight().var.as_deref()?.strip_prefix(rn.as_str())?.strip_prefix('.').map(|f| f.to_string()))
                        .collect()
                })
                .collect();
            for (a, &f) in fns.iter().enumerate() {
                let rf = cfgs[f].receiver.clone().unwrap_or_default();
                for &w in &self.stmt_nodes[f] {
                    for var in self.graph[w].defines.clone() {
                        let Some(field) = var.strip_prefix(rf.as_str()).and_then(|r| r.strip_prefix('.')) else { continue };
                        let field = field.split(['.', '[']).next().unwrap_or(field);
                        for (b, &g) in fns.iter().enumerate().filter(|(b, _)| *b != a) {
                            if reads[b].contains(field) {
                                let rg = cfgs[g].receiver.clone().unwrap_or_default();
                                found.push((w, self.methods[g], format!("{rg}.{field}"), "field"));
                            }
                        }
                    }
                }
            }
        }
        let mut seen: HashSet<(NodeIndex, NodeIndex, String, &'static str)> = HashSet::new();
        for (from, to, var, label) in found {
            if from != to && seen.insert((from, to, var.clone(), label)) {
                self.graph.add_edge(from, to, Edge { kind: EdgeKind::Reaching, label: Some(label), var: Some(var), order: 0 });
            }
        }
    }

    /// For `xs = [a, b]`: which expression each element variable (`xs[0]`, `xs[1]`) is defined from.
    fn add_element_values(&mut self, cfgs: &[&Cfg], sgs: &[StmtGraph]) {
        const LITERALS: [&str; 10] =
            ["list", "tuple", "array", "array_expression", "tuple_expression", "initializer_list", "array_initializer", "dictionary", "object", "literal_value"];
        let mut found: Vec<((NodeIndex, String), NodeIndex)> = vec![];
        for (f, cfg) in cfgs.iter().enumerate() {
            for n in sgs[f].graph.node_indices() {
                let crate::cpg::cfg::SNode::Stmt { block, idx } = sgs[f].graph[n] else { continue };
                let st = &cfg.graph[block].stmts[idx];
                let elems: Vec<&str> = st.elems.iter().filter(|e| e.strong).map(|e| e.target.as_str()).collect();
                let node = self.stmt_nodes[f][n.index()];
                let (Some(a), false) = (self.graph[node].ast, elems.is_empty()) else { continue };
                let info = &self.files[self.graph[node].file];
                // the list literal on the right: the first literal below the statement with that many elements
                let lit = info.ast.subtree(a).into_iter().find(|&i| {
                    LITERALS.contains(&info.ast.raw_kind(i)) && info.ast.nodes[i].children.iter().filter(|&&c| info.ast.raw_kind(c) != "comment").count() == elems.len()
                });
                let Some(lit) = lit else { continue };
                let kids = info.ast.nodes[lit].children.iter().filter(|&&c| info.ast.raw_kind(c) != "comment");
                for (target, &kid) in elems.iter().zip(kids) {
                    // `"k": v` / `k: v` (Go `keyed_element`): the value is the last part of the entry
                    let entry = matches!(info.ast.raw_kind(kid), "pair" | "keyed_element");
                    let k = info.ast.nodes[kid].children.last().copied().filter(|_| entry).unwrap_or(kid);
                    found.push(((node, target.to_string()), info.nodes[k]));
                }
            }
        }
        self.elem_values.extend(found);
    }

    /// The expression a statement defines the element variable `var` from, if it is an element
    /// of a list literal.
    pub fn elem_value(&self, stmt: NodeIndex, var: &str) -> Option<NodeIndex> {
        self.elem_values.get(&(stmt, var.to_string())).copied()
    }

    /// `path` with the aliases of function `f` (an index into `methods`) resolved.
    pub fn canon(&self, f: usize, path: &str) -> String {
        match self.aliases.get(f) {
            Some(a) => canon(a, path),
            None => path.to_string(),
        }
    }
}
