//! Language-independent control-flow graph IR on top of petgraph.
pub mod builder;

use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Normal,
    True,
    False,
    Back,
    Break,
    Continue,
    Return,
    Exception,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StmtKind {
    Call,
    Assign,
    Branch,
    Other,
}

/// Symbolic value of an expression, for taint analysis: what it depends on.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Flow {
    /// Literals and anything that depends on no variable.
    Clean,
    /// A variable or member path such as `x` or `request.args` (dots, no calls).
    Path(String),
    /// The result of a call.
    Call(Box<CallFlow>),
    /// Depends on all of its parts (concatenation, arithmetic, f-strings, ...).
    Join(Vec<Flow>),
}

/// A call expression with the values flowing into it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CallFlow {
    /// Normalized callee: `os.system`, `Runtime.getRuntime.exec`, `Command.new`.
    pub callee: String,
    /// The callee as written with its literal subscript keys kept (`handlers['a']`,
    /// `self.hooks[0]`), when it has any; `callee` has them removed.
    pub callee_key: Option<String>,
    pub recv: Option<Flow>,
    pub args: Vec<Flow>,
    /// Keyword names parallel to `args` (`None` = positional; may be shorter).
    pub arg_names: Vec<Option<String>>,
    pub line: usize,
    pub col: usize,
}

/// `target = value`. `strong` when `target` is a plain variable, so the
/// assignment replaces what it held; otherwise it only adds to it.
/// What a lambda / closure / nested function evaluates to in a [`Flow::Path`]:
/// a name no variable can have, so it can be matched with the function's [`Cfg`].
pub fn closure_marker(line: usize, col: usize) -> String {
    format!("<fn@{line}:{col}>")
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Assign {
    pub target: String,
    pub strong: bool,
    pub value: Flow,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Stmt {
    pub kind: StmtKind,
    /// 1-based source line and column.
    pub line: usize,
    pub col: usize,
    pub text: String,
    /// Byte range of the source node this statement came from (`(0, 0)` when synthetic).
    pub span: (usize, usize),
    /// Grammar node kind of that source node (with `span`, picks its AST node: a block can span exactly one statement).
    pub node_kind: u16,
    pub assigns: Vec<Assign>,
    /// Writes to elements with a literal key (`xs[0] = v`, `d["k"].f = v`, the elements of
    /// `xs = [a, b]`), with the element in the target (`xs[0]`, `d['k'].f`). They refine
    /// `assigns`, which holds the same writes against the whole container; only the taint
    /// analysis reads them. A strong one is an element of a literal (it replaces the element).
    pub elems: Vec<Assign>,
    pub calls: Vec<CallFlow>,
    /// For `return v` (and implicit returns): what the returned value depends on.
    pub ret: Option<Flow>,
    /// For a branch on a condition: what the condition depends on.
    pub cond: Option<Flow>,
}

impl Stmt {
    pub fn new(kind: StmtKind, line: usize, col: usize, text: String) -> Self {
        Self { kind, line, col, text, span: (0, 0), node_kind: 0, assigns: vec![], elems: vec![], calls: vec![], ret: None, cond: None }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Block {
    /// Not stored: only the entry and exit blocks are labeled, see [`Cfg::restore_labels`].
    #[serde(skip)]
    pub label: Option<&'static str>,
    pub stmts: Vec<Stmt>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Cfg {
    /// Source retained for graph views built from an in-memory CFG project.
    #[serde(skip)]
    pub source: std::sync::Arc<str>,
    pub name: String,
    /// 1-based line where the function starts.
    pub line: usize,
    /// 1-based column where the function starts (with `line`, identifies a lambda
    /// that another function mentions as [`closure_marker`]).
    pub col: usize,
    /// Byte range of the whole function in its file (the AST node of the same span is its declaration).
    pub span: (usize, usize),
    /// Grammar node kind of the function node.
    pub node_kind: u16,
    /// Names bound by each parameter, in order (a destructuring pattern binds several).
    pub params: Vec<Vec<String>>,
    /// The name the method calls its object by (`self`, `this`, a Go receiver).
    pub receiver: Option<String>,
    /// Declared class of parameters, as `(name, class)` (Java, Go, Rust, TypeScript, Python, C/C++).
    pub param_types: Vec<(String, String)>,
    /// Superclasses / interfaces / implemented traits of the class this method belongs to, as written.
    pub class_bases: Vec<String>,
    /// Structs declared in the project, including those with no methods of their own,
    /// and the types they embed. Filled by declaration linking.
    pub class_decls: Vec<(String, Vec<String>)>,
    /// Variables of the enclosing function that this closure assigns (`nonlocal x`, `x = ..`
    /// without a declaration in the closure).
    pub free_writes: Vec<String>,
    /// Declared class of the return value.
    pub ret_type: Option<String>,
    /// Declared class of local variables, as `(name, class)` (`Runner r;`, `x: Foo = ..`, `const x: Foo`).
    pub local_types: Vec<(String, String)>,
    /// For each of `local_types`, the lines `(first, last)` its declaration is in effect in.
    pub local_scopes: Vec<(usize, usize)>,
    /// Every block-scoped local the function declares, typed or not, with the lines
    /// `(first, last)` its declaration is in effect in (Rust / Go / JS / C-like languages).
    pub local_decls: Vec<(String, (usize, usize))>,
    /// Declared class of the fields of the class this method belongs to, as `(field, class)`.
    pub field_types: Vec<(String, String)>,
    /// Go: the methods of each interface that a declared parameter, local or field type names
    /// (`(interface, methods)`, embedded interfaces included), filled in from the declarations.
    pub iface_methods: Vec<(String, Vec<String>)>,
    pub graph: StableDiGraph<Block, EdgeKind>,
    pub entry: NodeIndex,
    pub exit: NodeIndex,
}

impl Cfg {
    /// Put back the block labels a stored CFG does not carry: the entry and exit blocks.
    pub fn restore_labels(&mut self) {
        self.graph[self.entry].label = Some("entry");
        self.graph[self.exit].label = Some("exit");
    }

    /// Declared types of parameters and locals as `(name, class)`, except names this function
    /// declares more than once with different types (shadowing in nested scopes): those are
    /// not typed at all rather than given whichever declaration came last.
    pub fn declared_vars(&self) -> Vec<(&str, &str)> {
        let all = || self.param_types.iter().chain(&self.local_types).map(|(n, t)| (n.as_str(), t.as_str()));
        let mut out: Vec<(&str, &str)> = vec![];
        for (n, t) in all() {
            if !out.contains(&(n, t)) {
                out.push((n, t));
            }
        }
        let ambiguous: Vec<&str> = out.iter().filter(|(n, _)| out.iter().filter(|(m, _)| m == n).count() > 1).map(|(n, _)| *n).collect();
        out.retain(|(n, _)| !ambiguous.contains(n));
        out
    }
}

impl Cfg {
    /// Declared types of parameters and locals in effect at `line`: of several declarations of
    /// one name, the innermost one whose scope contains the line (a local over a parameter).
    pub fn declared_vars_at(&self, line: usize) -> Vec<(&str, &str)> {
        let mut out: Vec<(&str, &str, usize)> = self.param_types.iter().map(|(n, t)| (n.as_str(), t.as_str(), 0)).collect();
        for (i, (n, t)) in self.local_types.iter().enumerate() {
            let (first, last) = self.local_scopes.get(i).copied().unwrap_or((0, usize::MAX));
            if line < first || line > last {
                continue;
            }
            match out.iter_mut().find(|(m, _, _)| m == n) {
                Some(e) if first >= e.2 => *e = (n.as_str(), t.as_str(), first),
                Some(_) => {}
                None => out.push((n.as_str(), t.as_str(), first)),
            }
        }
        out.into_iter().map(|(n, t, _)| (n, t)).collect()
    }

    /// The key a name's inferred type is kept under at `line`: the name itself, or, when the
    /// function declares it in several scopes (shadowing), the name with the first line of the
    /// innermost declaration around `line`, so that each variable keeps its own type.
    pub fn type_key(&self, name: &str, line: usize) -> String {
        let mut decls = self.local_decls.iter().filter(|(n, _)| n == name).map(|(_, s)| *s);
        let first = decls.next();
        if first.is_none() || decls.all(|s| Some(s) == first) {
            return name.to_string();
        }
        let inner = self.local_decls.iter().filter(|(n, (f, l))| n == name && *f <= line && line <= *l).map(|(_, (f, _))| *f).max();
        inner.map_or_else(|| name.to_string(), |f| format!("{name}@{f}"))
    }

    /// The declared type of `name` at `line`.
    pub fn declared_type_at(&self, name: &str, line: usize) -> Option<&str> {
        // the innermost local in scope (the latest start), else a parameter
        let local = self
            .local_types
            .iter()
            .enumerate()
            .filter(|(_, (n, _))| n == name)
            .filter_map(|(i, (_, t))| {
                let (first, last) = self.local_scopes.get(i).copied().unwrap_or((0, usize::MAX));
                (first <= line && line <= last).then_some((first, t.as_str()))
            })
            .max_by_key(|(first, _)| *first);
        local.map(|(_, t)| t).or_else(|| self.param_types.iter().find(|(n, _)| n == name).map(|(_, t)| t.as_str()))
    }
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::True => "true",
            Self::False => "false",
            Self::Back => "back",
            Self::Break => "break",
            Self::Continue => "continue",
            Self::Return => "return",
            Self::Exception => "exception",
        }
    }
}

impl StmtKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Assign => "assign",
            Self::Branch => "branch",
            Self::Other => "other",
        }
    }
}
