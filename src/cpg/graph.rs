//! The code property graph: all files of a project in one graph.
//!
//! Nodes are the AST nodes of every file (plus a synthetic `MethodReturn` per
//! function). Edges of different kinds sit on the same nodes:
//! * `Ast`: parent -> child, `order` is the position among the children;
//! * `Contains`: a file or method -> the methods it declares (and its `MethodReturn`); a method ->
//!   its `Local` nodes; a file -> the `Type` nodes its declarations name;
//! * `Cfg`: statement -> statement executed next (label: the CFG edge kind);
//!   the method node is the entry, its `MethodReturn` the exit;
//! * `Cdg`: branch -> statement it controls (label: the edge taken);
//! * `Call`: call expression -> the method it may call (label `callback` when
//!   the function is handed over or called through a variable, `param` for a call through a
//!   parameter (`fn(x)` in `apply(fn, x)`) to what the callers of `apply` pass for it);
//! * `Reaching`: statement defining a variable (a parameter: its `Param` node, else the method) ->
//!   statement that may read that definition, inside one function (`var` = the variable);
//! * `ParamIn` / `ReturnOut`: a call -> the callee's method node (argument position
//!   `order` flows into parameter `var`) / the callee's `return` statements -> the call;
//! * `Argument` / `Receiver`: call expression -> its argument expressions (in
//!   `order`) / the object of a method call;
//! * `Imports`: file -> file it imports;
//! * `TypeOf`: a `Param`, `Local` or `Field` -> the `Type` it is declared with;
//! * `Scope`: a method or class -> the method, class or file it is nested in (the lexical
//!   scope tree: file, class, method, closure; a method's `Param` and `Local` nodes live in its scope);
//! * `Ref`: an identifier or member access -> the `Param`, `Local` or `Field` it names
//!   (a variable of an enclosing function is a captured variable);
//! * `Inherits`: a class declaration -> the declarations of its base classes and interfaces (Go: the
//!   embedded types and the interfaces satisfied by shape);
//! * `ParamOut`: a callee statement that stores into something its caller sees (a field of a
//!   parameter, of the receiver or of the new object, a captured variable) -> the call
//!   statement, which defines that variable for the caller: `var` is `callee_path>caller_path`;
//! * `Capture`: a statement that calls a closure or creates it -> the closure's method node,
//!   which defines the captured variable (`var`) at its entry.
//!
//! `Reaching` edges also run between functions, labelled by what crosses: `param_in` (what reaches
//! an argument or the object of a method call reaches the parameter or receiver it binds),
//! `return` (a returned value reaches the call and the variable it is assigned to), `param_out`
//! (what a callee stores for its caller reaches the call), `field` (what a method stores in a field
//! of its receiver reaches the methods of the class that read it). Calls through variables and
//! parameters are calls like any other, so callbacks are covered. Unlabelled `Reaching` edges stay
//! inside one function. They resolve aliases (`b = a`, `h.r = a`, `b = identity(a)`): a definition of
//! `b.f` reaches the reads of `a.f`, and `var` names the path of the object they share. Element
//! keys (`xs[0]`) are part of a path.

use super::ast::{Ast, AstIdx};
use super::cdg::control_dependence;
use super::cfg::{SNode, stmt_graph};
use super::ddg::defined_vars;
use super::node::{NodeId, NodeKind};
use crate::analysis::{callgraph, deps};
use crate::ir::Cfg;
use crate::lang::common::{Import, normalize_callee};
use crate::lang::{Language, build_ast};
use anyhow::Result;
use petgraph::Direction;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One parsed source file with the CFGs lowered from it.
pub struct SourceFile<'a> {
    pub path: &'a Path,
    pub lang: Language,
    pub src: &'a str,
    pub cfgs: &'a [Cfg],
    pub imports: &'a [Import],
}

/// What a call says about its arguments beyond their order.
#[derive(Debug, Clone, Default)]
pub struct CallMeta {
    /// The keyword name of each argument (`None`: positional).
    pub arg_names: Vec<Option<String>>,
    /// The properties of object / dictionary / struct literals among the arguments: name and value node.
    pub props: Vec<(String, NodeIndex)>,
    /// The position of the argument each of `props` belongs to.
    pub prop_args: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct Node {
    /// Index into [`Cpg::files`].
    pub file: usize,
    /// Stable id; `None` for synthetic nodes (`MethodReturn`, statements without a source node).
    pub id: Option<NodeId>,
    /// Index into the file's [`Ast`]; `None` for synthetic nodes.
    pub ast: Option<AstIdx>,
    pub kind: NodeKind,
    pub name: Option<String>,
    pub code: String,
    pub line: usize,
    pub col: usize,
    /// For statements: the variables they define or mutate, whether or not the
    /// function reads them afterwards (`self.cmd = x` is read in another method).
    pub defines: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    Ast,
    Contains,
    Cfg,
    Cdg,
    Call,
    /// Definition -> statement that may read it (`var` names the variable).
    Reaching,
    /// Call -> callee method: argument `order` flows into the parameter named `var`.
    ParamIn,
    /// A `return` statement of the callee -> the call it answers.
    ReturnOut,
    /// Call -> argument expression (`order` = position).
    Argument,
    /// Call -> the object a method is called on.
    Receiver,
    Imports,
    /// Parameter, local or field -> the type it is declared with.
    TypeOf,
    /// Method or class -> the scope around it.
    Scope,
    /// Use of a name -> the declaration it refers to.
    Ref,
    /// Class declaration -> a base class or interface.
    Inherits,
    /// Callee statement -> the call that sees what it stores (`var`: `callee_path>caller_path`).
    ParamOut,
    /// Call or creation of a closure -> the closure, which defines its captured variable at entry.
    Capture,
}

impl EdgeKind {
    pub const ALL: [Self; 17] = [
        Self::Ast,
        Self::Contains,
        Self::Cfg,
        Self::Cdg,
        Self::Call,
        Self::Reaching,
        Self::ParamIn,
        Self::ReturnOut,
        Self::Argument,
        Self::Receiver,
        Self::Imports,
        Self::TypeOf,
        Self::Scope,
        Self::Ref,
        Self::Inherits,
        Self::ParamOut,
        Self::Capture,
    ];

    /// The kind with this name (`as_str`), for command-line options.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ast => "ast",
            Self::Contains => "contains",
            Self::Cfg => "cfg",
            Self::Cdg => "cdg",
            Self::Call => "call",
            Self::Reaching => "reaching",
            Self::ParamIn => "param_in",
            Self::ReturnOut => "return_out",
            Self::Argument => "argument",
            Self::Receiver => "receiver",
            Self::Imports => "imports",
            Self::TypeOf => "type_of",
            Self::Scope => "scope",
            Self::Ref => "ref",
            Self::Inherits => "inherits",
            Self::ParamOut => "param_out",
            Self::Capture => "capture",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub kind: EdgeKind,
    pub label: Option<&'static str>,
    /// For `Reaching` edges: the variable.
    pub var: Option<String>,
    /// Position among siblings for `Ast` edges, else 0.
    pub order: u32,
}

pub struct FileInfo {
    pub path: PathBuf,
    pub lang: Language,
    pub ast: Ast,
    /// Graph node of each AST node, by [`AstIdx`].
    pub nodes: Vec<NodeIndex>,
}

pub struct Cpg {
    pub graph: StableDiGraph<Node, Edge>,
    pub files: Vec<FileInfo>,
    /// The method node of each function, in the order of `files x cfgs` (the
    /// ids of the call graph). A file's `<module>` code is the file node.
    pub methods: Vec<NodeIndex>,
    /// Names bound by each parameter of each function (same order as `methods`;
    /// a destructuring pattern binds several), without the receiver.
    pub params: Vec<Vec<Vec<String>>>,
    /// The name each method calls its object by (`self`, `this`), same order as `methods`.
    pub receivers: Vec<Option<String>>,
    /// The `return` statements of each function (same order as `methods`).
    pub returns: Vec<Vec<NodeIndex>>,
    /// The `Param` node of each parameter name of each function (same order as `methods`);
    /// parameters are defined there, not at the method.
    pub param_nodes: Vec<HashMap<String, NodeIndex>>,
    /// The `Type` node of a type name in a file.
    types: HashMap<(usize, String), NodeIndex>,
    /// The graph node of each statement-graph node of each function (same order as `methods`).
    pub(crate) stmt_nodes: Vec<Vec<NodeIndex>>,
    /// The calls that may reach a scanned function.
    pub(crate) links: Vec<CallLink>,
    /// Aliases each function establishes (`b` -> `a`), same order as `methods`.
    aliases: Vec<HashMap<String, String>>,
    /// Keyword names and literal properties of calls, for the calls that have any.
    pub(crate) call_meta: HashMap<NodeIndex, CallMeta>,
    /// What each file's imports call things (`import os as o`), by file index.
    pub(crate) bindings: Vec<Option<crate::analysis::crypto::Bindings>>,
    /// The expression of each element of a list literal a statement assigns: `xs = [a, b]`
    /// defines `xs[0]` from `a` and `xs[1]` from `b`, keyed by `(statement, "xs[0]")`.
    elem_values: HashMap<(NodeIndex, String), NodeIndex>,
    /// What the `Call` edges were drawn from; see [`Cpg::call_graph`].
    calls: callgraph::CallGraph,
    /// What the `Imports` edges were drawn from; see [`Cpg::dep_graph`].
    deps: deps::DepGraph,
}

/// A call expression and a function it may call.
#[derive(Debug, Clone, Copy)]
pub struct CallLink {
    pub call: NodeIndex,
    /// Function ids (indices into `methods`).
    pub caller: usize,
    pub callee: usize,
    /// The arguments and the result flow (false where a function is only handed over).
    pub flows: bool,
    /// The callee does not rest on a method name alone.
    pub exact: bool,
}

mod effects;

type EdgeSet = HashSet<(NodeIndex, NodeIndex, EdgeKind, Option<&'static str>)>;

mod symbols;

impl Cpg {
    pub fn build(files: &[SourceFile]) -> Result<Self> {
        let mut cpg = Cpg {
            graph: StableDiGraph::new(),
            files: vec![],
            methods: vec![],
            params: vec![],
            receivers: vec![],
            returns: vec![],
            param_nodes: vec![],
            types: HashMap::new(),
            stmt_nodes: vec![],
            links: vec![],
            aliases: vec![],
            call_meta: HashMap::new(),
            bindings: vec![],
            elem_values: HashMap::new(),
            calls: callgraph::CallGraph { graph: Default::default(), external: HashMap::new() },
            deps: deps::DepGraph { graph: Default::default(), external: Default::default() },
        };
        let mut seen = EdgeSet::new();
        cpg.bindings = files.iter().map(|f| crate::analysis::crypto::file_bindings(f.lang, f.path, f.imports, f.cfgs)).collect();
        for (fi, f) in files.iter().enumerate() {
            cpg.add_ast(fi, f.path, f.lang, build_ast(f.lang, fi as u32, f.src)?);
        }
        let mut fn_file = vec![];
        for (fi, f) in files.iter().enumerate() {
            cpg.add_methods(fi, f.cfgs, &mut seen);
            fn_file.extend(f.cfgs.iter().map(|_| fi));
        }
        // imports and calls are resolved once: the `Imports` and `Call` edges, `call_graph()` and
        // `dep_graph()` all come from this one pass
        let dep_files: Vec<deps::DepFile> =
            files.iter().map(|f| deps::DepFile { path: f.path, lang: f.lang, imports: f.imports.to_vec(), cfgs: f.cfgs }).collect();
        let deps::Resolved { deps: dg, calls: with_imports, .. } = deps::resolve(&dep_files);
        // without any import there is nothing to choose between same-named functions with
        let cg = if files.iter().all(|f| f.imports.is_empty()) {
            let refs: Vec<(&Path, Language, &[Cfg])> = files.iter().map(|f| (f.path, f.lang, f.cfgs)).collect();
            callgraph::build_refs(&refs, None)
        } else {
            with_imports
        };
        cpg.add_calls(files, &cg, &fn_file, &mut seen);
        cpg.add_callback_calls(files, &mut seen);
        cpg.add_reaching(files, &mut seen);
        cpg.add_imports(&dg, &mut seen);
        cpg.calls = cg;
        cpg.deps = dg;
        cpg.add_symbols(files, &mut seen);
        Ok(cpg)
    }

    fn edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind, label: Option<&'static str>, seen: &mut EdgeSet) {
        if seen.insert((from, to, kind, label)) {
            self.graph.add_edge(from, to, Edge { kind, label, var: None, order: 0 });
        }
    }

    fn add_ast(&mut self, fi: usize, path: &Path, lang: Language, ast: Ast) {
        let nodes: Vec<NodeIndex> = ast
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                self.graph.add_node(Node {
                    file: fi,
                    id: Some(n.id),
                    ast: Some(i),
                    kind: n.kind,
                    name: n.name.clone(),
                    code: n.code.clone(),
                    line: n.line,
                    col: n.col,
                    defines: vec![],
                })
            })
            .collect();
        for (i, n) in ast.nodes.iter().enumerate() {
            if let Some(p) = n.parent {
                self.graph.add_edge(nodes[p], nodes[i], Edge { kind: EdgeKind::Ast, label: None, var: None, order: n.order });
            }
            for (pos, &a) in n.args.iter().enumerate() {
                self.graph.add_edge(nodes[i], nodes[a], Edge { kind: EdgeKind::Argument, label: None, var: None, order: pos as u32 });
            }
            if let Some(r) = n.receiver {
                self.graph.add_edge(nodes[i], nodes[r], Edge { kind: EdgeKind::Receiver, label: None, var: None, order: 0 });
            }
            if n.arg_names.iter().any(Option::is_some) || !n.props.is_empty() {
                let props = n.props.iter().map(|(k, v)| (k.clone(), nodes[*v])).collect();
                self.call_meta.insert(nodes[i], CallMeta { arg_names: n.arg_names.clone(), props, prop_args: n.prop_args.clone() });
            }
            if n.kind == NodeKind::Method {
                let mut up = n.parent;
                while let Some(p) = up.filter(|&p| ast.nodes[p].kind != NodeKind::Method && p != 0) {
                    up = ast.nodes[p].parent;
                }
                let owner = nodes[up.unwrap_or(0)];
                self.graph.add_edge(owner, nodes[i], Edge { kind: EdgeKind::Contains, label: None, var: None, order: 0 });
            }
        }
        self.files.push(FileInfo { path: path.to_path_buf(), lang, ast, nodes });
    }

    fn synthetic(&mut self, file: usize, kind: NodeKind, owner: NodeIndex, code: String, seen: &mut EdgeSet) -> NodeIndex {
        let (line, col) = (self.graph[owner].line, self.graph[owner].col);
        let n = self.graph.add_node(Node { file, id: None, ast: None, kind, name: None, code, line, col, defines: vec![] });
        self.edge(owner, n, EdgeKind::Contains, None, seen);
        n
    }

    /// The `Param` nodes of a method, by the name they bind (not those of nested functions).
    fn param_nodes_of(&mut self, fi: usize, method: NodeIndex) -> HashMap<String, NodeIndex> {
        let info = &self.files[fi];
        let Some(m) = self.graph[method].ast.filter(|&i| info.ast.nodes[i].kind == NodeKind::Method) else { return HashMap::new() };
        let mut out = HashMap::new();
        let mut stack: Vec<AstIdx> = info.ast.nodes[m].children.iter().rev().copied().collect();
        while let Some(i) = stack.pop() {
            let n = &info.ast.nodes[i];
            match n.kind {
                NodeKind::Method => continue,
                NodeKind::Param => {
                    if let Some(name) = &n.name {
                        out.entry(name.clone()).or_insert(info.nodes[i]);
                    }
                }
                _ => {}
            }
            stack.extend(n.children.iter().rev());
        }
        for (name, &node) in &out {
            self.graph[node].defines = vec![name.clone()];
        }
        out
    }

    /// `Local` nodes for the variables a function declares or assigns, and `Type` nodes for the
    /// declared types of its parameters and locals.
    fn declare_types(&mut self, fi: usize, cfg: &Cfg, method: NodeIndex, params: &HashMap<String, NodeIndex>, seen: &mut EdgeSet) {
        // first definition of each plain variable
        let mut first: HashMap<&str, (usize, usize)> = HashMap::new();
        for st in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
            for a in &st.assigns {
                let t = a.target.as_str();
                if t.contains(['.', '[', '<']) || params.contains_key(t) || cfg.receiver.as_deref() == Some(t) || cfg.free_writes.iter().any(|w| w == t) {
                    continue;
                }
                let at = first.entry(t).or_insert((st.line, st.col));
                *at = (*at).min((st.line, st.col));
            }
        }
        for (name, _) in &cfg.local_types {
            first.entry(name.as_str()).or_insert((self.graph[method].line, self.graph[method].col));
        }
        let mut locals: Vec<(&str, (usize, usize))> = first.into_iter().collect();
        locals.sort_by_key(|&(name, at)| (at, name));
        let mut local_nodes: HashMap<&str, NodeIndex> = HashMap::new();
        for (name, (line, col)) in locals {
            let n = self.synthetic(fi, NodeKind::Local, method, name.to_string(), seen);
            let x = &mut self.graph[n];
            (x.name, x.line, x.col) = (Some(name.to_string()), line, col);
            local_nodes.insert(name, n);
        }
        for (name, t) in cfg.param_types.iter().chain(&cfg.local_types) {
            let var = params.get(name).or_else(|| local_nodes.get(name.as_str())).copied();
            let (Some(var), Some(ty)) = (var, self.type_node(fi, t, method, seen)) else { continue };
            self.edge(var, ty, EdgeKind::TypeOf, None, seen);
        }
    }

    /// The `Type` node of a declared type, created at the first mention.
    fn type_node(&mut self, fi: usize, name: &str, at: NodeIndex, seen: &mut EdgeSet) -> Option<NodeIndex> {
        if name.is_empty() {
            return None;
        }
        if let Some(&n) = self.types.get(&(fi, name.to_string())) {
            return Some(n);
        }
        let (line, col) = (self.graph[at].line, self.graph[at].col);
        let n = self.graph.add_node(Node { file: fi, id: None, ast: None, kind: NodeKind::Type, name: Some(name.to_string()), code: name.to_string(), line, col, defines: vec![] });
        let file = self.files[fi].nodes[0];
        self.edge(file, n, EdgeKind::Contains, None, seen);
        self.types.insert((fi, name.to_string()), n);
        Some(n)
    }

    /// The node where parameter `var` of method `m` (index into `methods`) is defined.
    pub fn param_def(&self, m: usize, var: &str) -> NodeIndex {
        let root = var.split('.').next().unwrap_or(var);
        self.param_nodes[m].get(root).copied().filter(|_| self.receivers[m].as_deref() != Some(root)).unwrap_or(self.methods[m])
    }

    fn add_methods(&mut self, fi: usize, cfgs: &[Cfg], seen: &mut EdgeSet) {
        for cfg in cfgs {
            let info = &self.files[fi];
            let method = info.ast.find(cfg.span, cfg.node_kind).map_or(info.nodes[0], |i| info.nodes[i]);
            self.methods.push(method);
            self.params.push(cfg.params.clone());
            self.receivers.push(cfg.receiver.clone());
            let param_nodes = self.param_nodes_of(fi, method);
            self.declare_types(fi, cfg, method, &param_nodes, seen);
            self.param_nodes.push(param_nodes);
            let mut returns = vec![];
            let sg = stmt_graph(cfg);
            let ret = self.synthetic(fi, NodeKind::MethodReturn, method, String::new(), seen);
            let map: Vec<NodeIndex> = sg
                .graph
                .node_indices()
                .map(|n| match sg.graph[n] {
                    SNode::Entry => method,
                    SNode::Exit => ret,
                    SNode::Stmt { block, idx } => {
                        let st = &cfg.graph[block].stmts[idx];
                        let info = &self.files[fi];
                        let node = match info.ast.find(st.span, st.node_kind).filter(|_| st.span != (0, 0)) {
                            Some(i) => info.nodes[i],
                            None => self.synthetic(fi, NodeKind::Other, method, st.text.clone(), seen),
                        };
                        for v in defined_vars(st) {
                            if !self.graph[node].defines.contains(&v) {
                                self.graph[node].defines.push(v);
                            }
                        }
                        if st.ret.is_some() && !returns.contains(&node) {
                            returns.push(node);
                        }
                        node
                    }
                })
                .collect();
            for e in sg.graph.edge_references() {
                self.edge(map[e.source().index()], map[e.target().index()], EdgeKind::Cfg, Some(e.weight().as_str()), seen);
            }
            self.returns.push(returns);
            // reaching definitions need the calls (aliases, what callees write): see `add_reaching`
            self.stmt_nodes.push(map.clone());
            for (a, d, k) in control_dependence(&sg) {
                self.edge(map[a.index()], map[d.index()], EdgeKind::Cdg, Some(k.as_str()), seen);
            }
        }
    }

    fn add_calls(&mut self, files: &[SourceFile], cg: &callgraph::CallGraph, fn_file: &[usize], seen: &mut EdgeSet) {
        // call expressions by position, per file
        let by_pos: Vec<HashMap<(usize, usize), Vec<AstIdx>>> = self
            .files
            .iter()
            .map(|f| {
                let mut m: HashMap<(usize, usize), Vec<AstIdx>> = HashMap::new();
                for (i, n) in f.ast.nodes.iter().enumerate().filter(|(_, n)| n.kind == NodeKind::Call) {
                    m.entry((n.line, n.col)).or_default().push(i);
                }
                m
            })
            .collect();
        let cfgs: Vec<&Cfg> = files.iter().flat_map(|f| f.cfgs.iter()).collect();
        for e in cg.graph.edge_references() {
            let (caller, callee) = (e.source().index(), e.target().index());
            let fi = fn_file[caller];
            for site in &e.weight().call_sites {
                let Some(cands) = by_pos[fi].get(&(site.line, site.col)) else { continue };
                // chained calls start at the same position: pick the one named like the callee
                let ast = &self.files[fi].ast;
                let pick = cands.iter().copied().find(|&i| ast.nodes[i].name.as_deref().is_some_and(|n| normalize_callee(n) == site.callee)).unwrap_or(cands[0]);
                let from = self.files[fi].nodes[pick];
                let flows = !(site.callback && !site.invoked);
                self.link_call(&cfgs, CallLink { call: from, caller, callee, flows, exact: site.exact }, site.callback.then_some("callback"), seen);
            }
        }
    }

    fn add_imports(&mut self, dg: &deps::DepGraph, seen: &mut EdgeSet) {
        for e in dg.graph.edge_references().filter(|e| !e.weight().imports.is_empty()) {
            let (a, b) = (self.files[e.source().index()].nodes[0], self.files[e.target().index()].nodes[0]);
            self.edge(a, b, EdgeKind::Imports, None, seen);
        }
    }

    // ---- views -------------------------------------------------------------

    /// The call graph the `Call` edges were drawn from (function ids are indices into `methods`).
    pub fn call_graph(&self) -> &callgraph::CallGraph {
        &self.calls
    }

    /// The file dependencies the `Imports` edges were drawn from (node `i` is `files[i]`).
    pub fn dep_graph(&self) -> &deps::DepGraph {
        &self.deps
    }

    // ---- queries -----------------------------------------------------------

    /// Targets of the edges of `kind` leaving `n`.
    pub fn out(&self, n: NodeIndex, kind: EdgeKind) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.edges_directed(n, Direction::Outgoing).filter(move |e| e.weight().kind == kind).map(|e| e.target())
    }

    /// Sources of the edges of `kind` entering `n`.
    pub fn into(&self, n: NodeIndex, kind: EdgeKind) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.edges_directed(n, Direction::Incoming).filter(move |e| e.weight().kind == kind).map(|e| e.source())
    }

    /// The innermost method (or the file node, for top-level code) around `n`.
    pub fn enclosing_method(&self, n: NodeIndex) -> NodeIndex {
        let node = &self.graph[n];
        let info = &self.files[node.file];
        let mut cur = node.ast;
        // synthetic nodes hang off their method through `Contains`
        let Some(mut i) = cur.take() else { return self.into(n, EdgeKind::Contains).next().unwrap_or(info.nodes[0]) };
        loop {
            if info.ast.nodes[i].kind == NodeKind::Method {
                return info.nodes[i];
            }
            match info.ast.nodes[i].parent {
                Some(p) => i = p,
                None => return info.nodes[0],
            }
        }
    }
}
