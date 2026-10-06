//! Shared lowering engine for brace-style languages.
//!
//! A language implements [`Spec`]: it recognises functions and maps each
//! syntax node to a [`Ctl`] describing its control-flow shape. The [`Engine`]
//! turns those shapes into CFG blocks and edges, including `finally`
//! inlining, labeled break/continue, goto, and switch fallthrough.

use crate::ir::builder::CfgBuilder;
use crate::ir::{Assign, CallFlow, Cfg, EdgeKind, Flow, Stmt, StmtKind};
use anyhow::{Result, anyhow};
use petgraph::stable_graph::NodeIndex;
use std::collections::HashMap;
use tree_sitter::{Node, Parser};

pub enum LoopKind {
    /// Tested before each iteration.
    Cond,
    /// `for x in xs` / range loops: header shows the loop line.
    Each,
    /// `loop {}`, `for (;;)`: no exit edge from the header.
    Infinite,
}

pub struct Case<'a> {
    /// Empty for `default`.
    pub labels: Vec<Node<'a>>,
    /// `pat if cond` (Rust) / `case p if cond` (Python): on failure the next case is tried.
    pub guard: Option<Node<'a>>,
    pub body: Vec<Node<'a>>,
}

/// One clause of a comprehension, in source order.
pub enum Clause<'a> {
    For(Node<'a>),
    If(Node<'a>),
}

/// Control flow hidden inside an expression.
pub enum ExprCtl<'a> {
    Ternary { cond: Node<'a>, then: Node<'a>, els: Node<'a> },
    /// `rhs` runs only if `lhs` is truthy (`and`) or falsy / nullish (`!and`).
    Short { lhs: Node<'a>, rhs: Node<'a>, and: bool },
    /// `a?.b`: the rest of the node runs only if `obj` is not nullish.
    Optional { obj: Node<'a> },
    /// Lower the node as a statement (switch/match/if used as an expression).
    Stmt,
    Comprehension { clauses: Vec<Clause<'a>>, elements: Vec<Node<'a>> },
}

pub struct Handler<'a> {
    pub head: Node<'a>,
    pub body: Option<Node<'a>>,
}

/// Control-flow shape of one syntax node.
pub enum Ctl<'a> {
    /// Statements executed in order.
    Block(Vec<Node<'a>>),
    /// A straight-line statement.
    Simple(StmtKind),
    /// Not part of the function's flow (nested declarations, comments).
    Skip,
    If {
        pre: Vec<Node<'a>>,
        cond: Option<Node<'a>>,
        then: Option<Node<'a>>,
        els: Option<Node<'a>>,
    },
    Loop {
        label: Option<String>,
        pre: Vec<Node<'a>>,
        kind: LoopKind,
        cond: Option<Node<'a>>,
        body: Option<Node<'a>>,
        update: Vec<Node<'a>>,
    },
    DoWhile { body: Option<Node<'a>>, cond: Option<Node<'a>> },
    Switch {
        cases: Vec<Case<'a>>,
        /// Whether a bare `break` leaves the switch (false for Rust `match`).
        breakable: bool,
        /// Whether a case body continues into the next one.
        fallthrough: bool,
        /// The cases cover every value (Rust `match`): no "nothing matched" edge.
        exhaustive: bool,
    },
    Try {
        /// Resources / setup evaluated before the body (Java try-with-resources).
        pre: Vec<Node<'a>>,
        /// Resources closed (in reverse order) on every path out of the body.
        closes: Vec<Node<'a>>,
        body: Option<Node<'a>>,
        handlers: Vec<Handler<'a>>,
        finally: Option<Node<'a>>,
    },
    /// A header statement (`with ...`, `let k = ...`) followed by nested statements.
    Header(StmtKind, Vec<Node<'a>>),
    /// Go `defer`: recorded now, run on every exit path in reverse order.
    Defer,
    /// Go `fallthrough`: continue into the next case body.
    Fallthrough,
    Return,
    Throw,
    Break(Option<String>),
    Continue(Option<String>),
    Goto(String),
    Labeled { label: String, stmt: Option<Node<'a>> },
}

impl<'a> Ctl<'a> {
    /// A loop with no label, init or update clause.
    pub fn simple_loop(kind: LoopKind, cond: Option<Node<'a>>, body: Option<Node<'a>>) -> Self {
        Ctl::Loop { label: None, pre: vec![], kind, cond, body, update: vec![] }
    }
}

/// Short-circuit structure of a condition.
pub enum BoolOp<'a> {
    And(Node<'a>, Node<'a>),
    Or(Node<'a>, Node<'a>),
    Not(Node<'a>),
}

/// `&&`/`||`/`!` (and Python `and`/`or`/`not`) over the common node shapes.
pub fn std_bool_op<'a>(src: &[u8], n: Node<'a>) -> Option<BoolOp<'a>> {
    match n.kind() {
        "binary_expression" | "boolean_operator" => {
            let op = text(src, n.child_by_field_name("operator")?);
            let (l, r) = (n.child_by_field_name("left")?, n.child_by_field_name("right")?);
            match op.as_str() {
                "&&" | "and" => Some(BoolOp::And(l, r)),
                "||" | "or" => Some(BoolOp::Or(l, r)),
                _ => None,
            }
        }
        "unary_expression" if n.child(0)?.kind() == "!" => Some(BoolOp::Not(n.named_child(0)?)),
        "not_operator" => Some(BoolOp::Not(n.child_by_field_name("argument")?)),
        _ => None,
    }
}

/// A call expression, as seen by the data-flow facts.
pub struct CallParts<'a> {
    /// Callee text (normalized later): `os.system`, `cursor.execute`.
    pub callee: String,
    /// The object a method is called on, if any.
    pub receiver: Option<Node<'a>>,
    /// Argument expressions (keyword arguments reduced to their values).
    pub args: Vec<Node<'a>>,
    /// Keyword names parallel to `args`; empty when the language has none.
    pub names: Vec<Option<String>>,
}

/// An assignment-like node: `targets = values`.
pub struct AssignParts<'a> {
    pub targets: Vec<Node<'a>>,
    pub values: Vec<Node<'a>>,
    /// `x += v`: the target also depends on its old value.
    pub augmented: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ImportKind {
    /// `import x`, `use x`, `require("x")`.
    Module,
    /// Rust `mod x;` -- a child module in its own file.
    ModDecl,
    /// C `#include "x.h"`.
    LocalInclude,
    /// C `#include <x.h>`.
    SystemInclude,
}

/// A dependency on another module / file, as written in the source.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Import {
    /// The module path exactly as written (`a.b`, `./lib`, `crate::x`, `x/y.h`).
    pub module: String,
    /// Names imported from it (`from m import a, b`, `use m::{a, b}`).
    pub names: Vec<String>,
    pub line: usize,
    pub kind: ImportKind,
}

impl Import {
    pub fn module(module: impl Into<String>, line: usize) -> Self {
        Self { module: module.into(), names: vec![], line, kind: ImportKind::Module }
    }
}

/// Strip the quotes of a string literal.
pub fn unquote(s: &str) -> String {
    s.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string()
}

pub trait Spec {
    /// Imports declared by the node `n` (called for every node of the file).
    fn imports_of(&self, _src: &[u8], _n: Node) -> Vec<Import> {
        vec![]
    }
    fn call_parts<'a>(&self, _src: &[u8], _n: Node<'a>) -> Option<CallParts<'a>> {
        None
    }
    /// `object.name` access: the object and the member name.
    fn member_parts<'a>(&self, _src: &[u8], _n: Node<'a>) -> Option<(Node<'a>, String)> {
        None
    }
    /// The path suffix for a literal element key. JS object keys also have dot syntax.
    fn key_path(&self, key: &str) -> String {
        key.to_string()
    }
    fn assignment<'a>(&self, _src: &[u8], _n: Node<'a>) -> Option<AssignParts<'a>> {
        None
    }
    /// Names bound by each parameter of function `f`, excluding the receiver.
    fn params(&self, _src: &[u8], _f: Node) -> Vec<Vec<String>> {
        vec![]
    }
    /// The name an instance method uses for its object (`self`, `this`, a Go receiver).
    fn receiver(&self, _src: &[u8], _f: Node) -> Option<String> {
        None
    }
    /// Fields of the class around `f` that a bare name refers to (`cmd` for `this.cmd`):
    /// declared fields minus anything the function declares itself.
    fn implicit_fields(&self, _src: &[u8], _f: Node) -> Vec<String> {
        vec![]
    }
    /// Declared types: `(parameter name, type)` pairs and the return type, as written.
    fn declared_types(&self, _src: &[u8], _f: Node) -> (Vec<(String, String)>, Option<String>) {
        (vec![], None)
    }
    /// Declared types of the local variables of `f` and of the fields of its class, as
    /// written: `(locals, fields)`, each `(name, type)`.
    fn declared_vars(&self, _src: &[u8], _f: Node) -> (Scoped, Typed) {
        (vec![], vec![])
    }
    /// Struct / class definitions and type aliases declared by node `n` itself.
    fn declarations_of(&self, _src: &[u8], _n: Node, _out: &mut Declarations) {}
    /// Bases of the class around method `f`: superclasses, interfaces, implemented traits.
    fn class_bases(&self, _src: &[u8], _f: Node) -> Vec<String> {
        vec![]
    }
    /// The operator of a binary expression (`+`, `&&`, `==`); its operands are the node's children.
    fn binary_op(&self, src: &[u8], n: Node) -> Option<String> {
        const KINDS: &[&str] = &["binary_expression", "binary_operator", "boolean_operator"];
        if !KINDS.contains(&n.kind()) {
            return None;
        }
        n.child_by_field_name("operator").map(|o| text(src, o))
    }
    /// The name a class / struct / interface / enum / trait declaration introduces.
    fn type_decl_name(&self, src: &[u8], n: Node) -> Option<String> {
        const KINDS: &[&str] = &[
            "class_definition", "class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
            "struct_item", "enum_item", "trait_item", "type_spec",
        ];
        // C / C++ `struct foo` also names a type without declaring it: only with a body
        const WITH_BODY: &[&str] = &["class_specifier", "struct_specifier", "enum_specifier", "union_specifier"];
        let k = n.kind();
        if KINDS.contains(&k) || (WITH_BODY.contains(&k) && n.child_by_field_name("body").is_some()) {
            n.child_by_field_name("name").map(|x| text(src, x))
        } else {
            None
        }
    }
    /// A comment node (never a statement or an operand).
    fn is_comment(&self, n: Node) -> bool {
        n.kind().contains("comment")
    }
    /// `a[i]` / `a.at(i)`-style element access, whose first child is the container.
    fn is_subscript(&self, n: Node) -> bool {
        n.kind().contains("subscript") || n.kind().contains("index")
    }
    /// The elements of a list / array / tuple literal, in order (none for other nodes, or when
    /// a spread / splat makes the positions unknown).
    fn sequence_elements<'a>(&self, n: Node<'a>) -> Option<Vec<Node<'a>>> {
        if !matches!(n.kind(), "list" | "tuple" | "array" | "array_expression" | "tuple_expression" | "initializer_list" | "array_initializer" | "literal_value") {
            return None;
        }
        let elems: Vec<Node<'a>> = named_children(n).into_iter().filter(|k| !self.is_comment(*k)).collect();
        let unknown = |k: &Node| ["splat", "spread", "rest", "elision"].iter().any(|w| k.kind().contains(w));
        (elems.len() <= MAX_ELEMENTS && !elems.iter().any(|e| unknown(e) || e.kind() == "keyed_element")).then_some(elems)
    }
    /// The entries of a dict / object / map literal as `(key, value)`, the key in the form of
    /// [`element_key`] (`['a']`, `[0]`); none for other nodes, or when a key is not a literal
    /// or a spread / splat makes the entries unknown.
    fn mapping_entries<'a>(&self, src: &[u8], n: Node<'a>) -> Option<Vec<(String, Node<'a>)>> {
        if !matches!(n.kind(), "dictionary" | "object" | "literal_value") {
            return None;
        }
        let mut out = vec![];
        for e in named_children(n).into_iter().filter(|k| !self.is_comment(*k)) {
            let (k, v) = match e.kind() {
                "pair" => (e.child_by_field_name("key")?, e.child_by_field_name("value")?),
                "shorthand_property_identifier" => (e, e),
                "keyed_element" => {
                    let kv = named_children(e);
                    // Go: the key is a `literal_element` around the expression
                    let inner = |x: Node<'a>| if x.kind() == "literal_element" { x.named_child(0).unwrap_or(x) } else { x };
                    (inner(*kv.first()?), inner(*kv.get(1)?))
                }
                _ => return None,
            };
            let bare = matches!(k.kind(), "property_identifier" | "shorthand_property_identifier");
            out.push((self.key_path(&element_key(&text(src, k), bare)?), v));
        }
        (out.len() <= MAX_ELEMENTS).then_some(out)
    }
    /// What an expression nested in a branch (ternary arm, `?:` operand) does as a statement.
    fn expr_kind(&self, n: Node) -> StmtKind {
        let k = n.kind();
        if k.contains("call") || k.contains("invocation") || k.contains("new_expression") {
            StmtKind::Call
        } else if k.contains("assignment") {
            StmtKind::Assign
        } else {
            StmtKind::Other
        }
    }
    /// C++ init-captures bind a new closure-local name when it is created.
    fn capture_initializers<'a>(&self, _f: Node<'a>) -> Vec<(Node<'a>, Node<'a>)> {
        vec![]
    }
    /// Variables of the enclosing scope that closure `f` assigns.
    fn free_writes(&self, _src: &[u8], _f: Node) -> Vec<String> {
        vec![]
    }
    /// The expression a `return` hands back.
    fn return_value<'a>(&self, n: Node<'a>) -> Option<Node<'a>> {
        named_children(n).into_iter().find(|c| !self.is_comment(*c))
    }
    /// Value a function returns without a `return` (expression-bodied lambdas,
    /// Rust's tail expression).
    fn implicit_return<'a>(&self, _f: Node<'a>) -> Option<Node<'a>> {
        None
    }
    /// A plain variable reference.
    fn is_ident(&self, n: Node) -> bool {
        n.kind() == "identifier"
    }
    fn is_function(&self, n: Node) -> bool;
    fn function_name(&self, src: &[u8], f: Node) -> String;
    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>>;
    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a>;
    fn bool_op<'a>(&self, src: &[u8], n: Node<'a>) -> Option<BoolOp<'a>> {
        std_bool_op(src, n)
    }
    /// `else` block of a loop that runs when it ends without `break` (Python).
    fn loop_else<'a>(&self, _n: Node<'a>) -> Option<Node<'a>> {
        None
    }
    /// `else` block of a `try` that runs after the body succeeds (Python).
    fn try_else<'a>(&self, _n: Node<'a>) -> Option<Node<'a>> {
        None
    }
    /// Control flow hidden inside an expression (ternary, `?.`, comprehension, ...).
    fn expr_flow<'a>(&self, _src: &[u8], _n: Node<'a>) -> Option<ExprCtl<'a>> {
        None
    }
    /// A `defer` whose call may `recover()` from a panic (Go).
    fn recovers(&self, _src: &[u8], _defer: Node) -> bool {
        false
    }
    /// Lower the file's top-level statements as a `<module>` CFG (scripts).
    fn top_level(&self) -> bool {
        false
    }
    /// Statement may leave the function early (e.g. Rust `?`).
    fn early_exit(&self, _n: Node) -> bool {
        false
    }
}

// ---- helpers for Spec implementations -------------------------------------

pub fn text(src: &[u8], n: Node) -> String {
    n.utf8_text(src).unwrap_or("").to_string()
}

/// The token between the operands of a binary expression or assignment (`&&`, `?:`, `+=`); with
/// `words` false an alphabetic token (`as`, `is`, `in`) is not an operator.
pub fn operator_token(src: &[u8], n: Node, words: bool) -> Option<String> {
    let mut c = n.walk();
    n.children(&mut c)
        .find(|k| !k.is_named() && !matches!(k.kind(), "(" | ")") && (words || !k.kind().starts_with(char::is_alphabetic)))
        .map(|k| text(src, k))
}

/// Call arguments with the labels they were written with; none at all when no argument has one.
pub fn unlabelled_if_none<'a>(args: Vec<Node<'a>>, mut names: Vec<Option<String>>) -> (Vec<Node<'a>>, Vec<Option<String>>) {
    if names.iter().all(Option::is_none) {
        names.clear();
    }
    (args, names)
}

/// Does `f` carry one of the `words` in its `modifiers` (`static`, `class`)?
pub fn has_modifier(src: &[u8], f: Node, words: &[&str]) -> bool {
    named_children(f)
        .into_iter()
        .filter(|c| c.kind() == "modifiers")
        .any(|m| text(src, m).split_whitespace().any(|w| words.contains(&w)))
}

/// The named children of `n` without comments.
pub fn kids_without_comments<'a>(n: Node<'a>) -> Vec<Node<'a>> {
    named_children(n).into_iter().filter(|c| !c.kind().contains("comment")).collect()
}

pub fn named_children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// Named children whose field name is not in `exclude`.
pub fn children_excluding<'a>(n: Node<'a>, exclude: &[&str]) -> Vec<Node<'a>> {
    let mut out = vec![];
    let mut c = n.walk();
    if !c.goto_first_child() {
        return out;
    }
    loop {
        let node = c.node();
        if node.is_named() && !c.field_name().is_some_and(|f| exclude.contains(&f)) {
            out.push(node);
        }
        if !c.goto_next_sibling() {
            break;
        }
    }
    out
}

pub fn children_by_field<'a>(n: Node<'a>, field: &str) -> Vec<Node<'a>> {
    let mut c = n.walk();
    n.children_by_field_name(field, &mut c).collect()
}

pub fn first_child_of_kind<'a>(n: Node<'a>, kind: &str) -> Option<Node<'a>> {
    named_children(n).into_iter().find(|k| k.kind() == kind)
}

/// Does `n` contain a node of `kind`, without entering nested functions?
pub fn contains_kind(n: Node, kind: &str, stop: &[&str]) -> bool {
    let mut c = n.walk();
    for ch in n.children(&mut c) {
        if ch.kind() == kind || (!stop.contains(&ch.kind()) && contains_kind(ch, kind, stop)) {
            return true;
        }
    }
    false
}

/// Name of a C-style declarator chain (`*f(int)` -> `f`).
pub fn declarator_name(src: &[u8], f: Node) -> String {
    let Some(mut d) = f.child_by_field_name("declarator") else {
        return "<anon>".into();
    };
    while let Some(inner) = d.child_by_field_name("declarator") {
        d = inner;
    }
    text(src, d)
}

/// Prefix `base` with the names of enclosing scopes, e.g. `Class.method`.
/// `parents` maps an ancestor node kind to the field holding its name.
pub fn qualify(src: &[u8], f: Node, sep: &str, base: String, parents: &[(&str, &str)]) -> String {
    let mut parts = vec![];
    let mut p = f.parent();
    while let Some(n) = p {
        if let Some((_, field)) = parents.iter().find(|(k, _)| *k == n.kind())
            && let Some(name) = n.child_by_field_name(field)
        {
            let mut t = text(src, name);
            if let Some(i) = t.find('<') {
                t.truncate(i);
            }
            parts.push(t);
        }
        p = n.parent();
    }
    parts.reverse();
    parts.push(base);
    parts.join(sep)
}

/// Texts of all variable-like nodes inside `n` (the names a pattern binds).
pub fn bound_names<S: Spec + ?Sized>(spec: &S, src: &[u8], n: Node) -> Vec<String> {
    fn go<S: Spec + ?Sized>(spec: &S, src: &[u8], n: Node, depth: usize, out: &mut Vec<String>) {
        if depth > 20 {
            return;
        }
        if spec.is_ident(n) {
            out.push(text(src, n));
            return;
        }
        let mut c = n.walk();
        for k in n.named_children(&mut c) {
            go(spec, src, k, depth + 1, out);
        }
    }
    let mut out = vec![];
    go(spec, src, n, 0, &mut out);
    out
}

/// Generic wrappers that are looked through: calling a method on an `Optional<Foo>` /
/// `Box<Foo>` / `shared_ptr<Foo>` means calling it on the `Foo` inside.
const WRAPPERS: &[&str] = &[
    "Optional", "Option", "Box", "Rc", "Arc", "Cell", "RefCell", "Mutex", "RwLock", "Pin", "Cow", "unique_ptr", "shared_ptr",
    "weak_ptr", "optional", "reference_wrapper", "Maybe", "Ref", "RefMut",
];

/// The part after the last `.` or `::` (the simple name of a qualified function or class).
pub fn simple_name(name: &str) -> &str {
    name.rsplit(['.', ':']).next().unwrap_or(name)
}

/// The class a written type names: `&mut Foo<T>` -> `Foo`, `*pkg.Server` -> `Server`, `: Foo` -> `Foo`,
/// `Optional<Foo>` -> `Foo`.
pub fn type_name(t: &str) -> String {
    const SKIP: [&str; 9] = ["mut", "const", "dyn", "impl", "struct", "class", "static", "final", "unsigned"];
    let mut chars = t.char_indices().peekable();
    let mut cur = String::new();
    while let Some((i, c)) = chars.next() {
        if c == '\'' {
            while chars.next_if(|(_, c)| c.is_alphanumeric() || *c == '_').is_some() {}
        } else if c.is_alphanumeric() || matches!(c, '_' | '.' | ':') {
            cur.push(c);
        } else if !cur.is_empty() {
            if SKIP.contains(&cur.as_str()) {
                cur.clear();
            } else if WRAPPERS.contains(&simple_name(&cur)) && (c.is_whitespace() || matches!(c, '<' | '[')) {
                // `Optional<Runner>`, `Option<Box<Runner>>`: the payload is what is called on
                let mut open = (i, c);
                if c.is_whitespace() {
                    while chars.next_if(|(_, c)| c.is_whitespace()).is_some() {}
                    open = chars.next_if(|(_, c)| matches!(c, '<' | '[')).unwrap_or((i, c));
                }
                if matches!(open.1, '<' | '[') {
                    let payload = type_name(&t[open.0 + 1..]);
                    if !payload.is_empty() {
                        return payload;
                    }
                }
                break;
            } else {
                break;
            }
        }
    }
    if SKIP.contains(&cur.as_str()) {
        return String::new();
    }
    simple_name(&cur).to_string()
}

/// Visit every node of function `f`, without descending into nested functions
/// (those are visited themselves, so their names can be read).
pub fn walk_scope<'a, S: Spec + ?Sized>(spec: &S, f: Node<'a>, visit: &mut dyn FnMut(Node<'a>)) {
    let mut stack = vec![f];
    while let Some(n) = stack.pop() {
        if n != f {
            visit(n);
            if spec.is_function(n) {
                continue;
            }
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
}

/// Written names that no declaration or parameter of the function accounts for.
pub fn undeclared(written: Vec<String>, declared: &std::collections::HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = written.into_iter().filter(|w| !declared.contains(w)).collect();
    out.sort();
    out.dedup();
    out
}

/// The nearest ancestor of `f` of one of `kinds`.
pub fn enclosing<'a>(f: Node<'a>, kinds: &[&str]) -> Option<Node<'a>> {
    let mut p = f.parent();
    while let Some(n) = p {
        if kinds.contains(&n.kind()) {
            return Some(n);
        }
        p = n.parent();
    }
    None
}

/// List / array literals longer than this get no per-element facts.
const MAX_ELEMENTS: usize = 32;

/// `(name, type)` pairs as written in the source.
pub type Typed = Vec<(String, String)>;

/// `(name, type, lines)` for declared locals: the lines (first, last) in which the declaration is in effect.
pub type Scoped = Vec<(String, String, (usize, usize))>;

/// The lines a declaration made by node `n` is visible in: from `n` to the end of the block
/// (or `for` statement) it is declared in. Without a block (Python) the whole function.
pub fn scope_lines(n: Node) -> (usize, usize) {
    let start = n.start_position().row + 1;
    let mut p = n.parent();
    while let Some(x) = p {
        let k = x.kind();
        if k.contains("block") || k == "compound_statement" || k.starts_with("for_") || k.starts_with("function") || k.ends_with("_function") || k == "method_declaration" || k == "lambda" || k == "lambda_expression" || k == "arrow_function" {
            return (start, x.end_position().row + 1);
        }
        p = x.parent();
    }
    (start, usize::MAX)
}

/// Attach the scope of declaration node `n` to what it declares.
pub fn scoped(v: Typed, n: Node) -> Scoped {
    let s = scope_lines(n);
    v.into_iter().map(|(a, b)| (a, b, s)).collect()
}

/// Types a file declares, which methods in other files may belong to.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Declarations {
    /// Struct / class definitions: `(name, fields)`, field types as written.
    pub types: Vec<(String, Typed)>,
    /// Type aliases: `(alias, target)`, the target as written (`type R = Runner`, `using R = Runner`).
    pub aliases: Vec<(String, String)>,
    /// Defined types over another type: `(name, underlying)`. They have the underlying type's
    /// fields (or interface methods) but not its methods (Go `type R T`).
    pub defined: Vec<(String, String)>,
    /// Go interfaces: `(name, methods, embedded interfaces)`.
    pub interfaces: Vec<(String, Vec<String>, Vec<String>)>,
    /// Go structs with embedded types, which promote their methods: `(struct, embedded types as written)`.
    pub embeds: Vec<(String, Vec<String>)>,
}

/// Every node below `n` that `pick` accepts, in source order, without entering nested functions.
pub fn collect_nodes<'a>(n: Node<'a>, stop: &dyn Fn(Node) -> bool, pick: &mut dyn FnMut(Node<'a>)) {
    let mut c = n.walk();
    for k in n.children(&mut c) {
        if stop(k) {
            continue;
        }
        pick(k);
        collect_nodes(k, stop, pick);
    }
}

/// The type / class names listed in a base clause (`(A, B)`, `extends A implements B, C`),
/// without generic arguments or keyword arguments.
pub fn base_names(src: &[u8], n: Node, out: &mut Vec<String>) {
    match n.kind() {
        "type_identifier" | "identifier" | "scoped_type_identifier" | "nested_type_identifier" | "nested_identifier"
        | "qualified_identifier" | "member_expression" | "attribute" | "scoped_identifier" => out.push(text(src, n)),
        "keyword_argument" => {}
        "generic_type" => {
            if let Some(c) = n.named_child(0) {
                base_names(src, c, out);
            }
        }
        _ => {
            let mut c = n.walk();
            for k in n.named_children(&mut c) {
                base_names(src, k, out);
            }
        }
    }
}

/// `os . system`, `std::process::Command::new`, `Runtime.getRuntime().exec`,
/// `a?.b` -> dotted path without calls, generics, subscripts, `?`, `!`.
pub fn normalize_callee(t: &str) -> String {
    // `new Foo(..)` calls `Foo`; a method named `newFoo` is not a constructor call
    let t = match t.trim_start().strip_prefix("new") {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest,
        _ => t,
    };
    let mut out = String::with_capacity(t.len());
    let mut depth = 0usize;
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // C / C++ `p->f`
            '-' if depth == 0 && chars.peek() == Some(&'>') => {
                chars.next();
                out.push('.');
            }
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth = depth.saturating_sub(1),
            _ if depth > 0 => {}
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                out.push('.');
            }
            c if c.is_whitespace() || matches!(c, '?' | '!' | '&' | '*') => {}
            c => out.push(c),
        }
    }
    out.split('.').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(".")
}

/// The literal behind an argument: `&Config{..}` and `Config{..}` (Go) are their `{..}` body.
fn literal_of(n: Node) -> Node {
    match n.kind() {
        "unary_expression" | "parenthesized_expression" => n.named_child(0).map_or(n, literal_of),
        "composite_literal" => named_children(n).into_iter().find(|c| c.kind() == "literal_value").unwrap_or(n),
        _ => n,
    }
}

/// The properties of the object / dictionary / struct literals among `args` (and of the literals
/// nested in them, two levels deep) as `(name, value expression)`: `{ algorithm: x }`,
/// `{"key": k}`, `&Config{MinVersion: v}`.
pub fn literal_props<'a, S: Spec + ?Sized>(spec: &S, src: &[u8], args: &[Node<'a>]) -> Vec<(String, Node<'a>)> {
    indexed_props(spec, src, args, false).into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// [`literal_props`], and the properties of the literals that variable arguments were assigned
/// (`opts = { algorithm: x }; f(opts)`), each with the position of the argument it belongs to. The
/// summary analysis follows those through the values of the variables instead, which keeps the
/// line of the source.
pub fn indexed_props<'a, S: Spec + ?Sized>(spec: &S, src: &[u8], args: &[Node<'a>], variables: bool) -> Vec<(usize, String, Node<'a>)> {
    let mut out = vec![];
    for (i, a) in args.iter().enumerate() {
        let mut found = vec![];
        nested_props(spec, src, *a, 0, &mut found);
        if variables {
            variable_props(spec, src, *a, &mut found);
        }
        out.extend(found.into_iter().map(|(k, v)| (i, k, v)));
    }
    out
}

/// The properties of the literal a variable argument was last assigned before the call
/// (`opts = { algorithm: x }; f(opts)`), looked for in the same function.
fn variable_props<'a, S: Spec + ?Sized>(spec: &S, src: &[u8], arg: Node<'a>, out: &mut Vec<(String, Node<'a>)>) {
    if !spec.is_ident(arg) {
        return;
    }
    let name = text(src, arg);
    let mut scope = arg;
    while let Some(p) = scope.parent() {
        scope = p;
        if spec.is_function(p) {
            break;
        }
    }
    let mut best: Option<Node<'a>> = None;
    let mut visited = 0;
    walk_scope(spec, scope, &mut |n| {
        visited += 1;
        if visited > 4000 || n.end_byte() > arg.start_byte() {
            return;
        }
        let Some(parts) = spec.assignment(src, n) else { return };
        if parts.augmented || parts.targets.len() != parts.values.len() {
            return;
        }
        for (t, v) in parts.targets.iter().zip(&parts.values) {
            if text(src, *t) == name && spec.mapping_entries(src, literal_of(*v)).is_some() && best.is_none_or(|b| b.start_byte() < v.start_byte()) {
                best = Some(*v);
            }
        }
    });
    if let Some(v) = best {
        nested_props(spec, src, v, 0, out);
    }
}

fn nested_props<'a, S: Spec + ?Sized>(spec: &S, src: &[u8], n: Node<'a>, level: usize, out: &mut Vec<(String, Node<'a>)>) {
    if level >= 3 {
        return;
    }
    let lit = literal_of(n);
    let entries: Vec<(String, Node<'a>)> = match spec.mapping_entries(src, lit) {
        // the key as `['a']`, or `.a` where the language has dot syntax (JS)
        Some(entries) => entries
            .into_iter()
            .filter_map(|(k, v)| Some((k.strip_prefix("['").and_then(|k| k.strip_suffix("']")).or_else(|| k.strip_prefix('.'))?.to_string(), v)))
            .collect(),
        // Go struct literals: `Config{MinVersion: v}` has bare field names as keys
        None if lit.kind() == "literal_value" => named_children(lit)
            .into_iter()
            .filter(|e| e.kind() == "keyed_element")
            .filter_map(|e| {
                let kv = named_children(e);
                let inner = |x: Node<'a>| if x.kind() == "literal_element" { x.named_child(0).unwrap_or(x) } else { x };
                let key = text(src, inner(*kv.first()?));
                let value = inner(*kv.get(1)?);
                key.chars().all(|c| c.is_alphanumeric() || c == '_').then_some((key, value))
            })
            .collect(),
        None => vec![],
    };
    for (name, value) in entries {
        out.push((name, value));
        nested_props(spec, src, value, level + 1, out);
    }
}

/// The key of an element written as `t`: `[0]` for a small integer, `['k']` for a short quoted
/// word (or, with `bare`, an unquoted one as in a JS object literal); none for anything else.
pub fn element_key(t: &str, bare: bool) -> Option<String> {
    let t = t.trim();
    if !t.is_empty() && t.len() <= 6 && t.bytes().all(|b| b.is_ascii_digit()) {
        return Some(format!("[{t}]"));
    }
    let inner = match t.strip_prefix(['\'', '"']).and_then(|r| r.strip_suffix(['\'', '"'])) {
        Some(i) => i,
        None if bare => t,
        None => return None,
    };
    (!inner.is_empty() && inner.len() <= 32 && inner.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
        .then(|| format!("['{inner}']"))
}

/// `handlers["a"]` / `self.hooks[0].run` as written, with literal subscript keys kept and
/// everything else normalized like [`normalize_callee`]; none when no key is kept.
fn keyed_callee(raw: &str) -> Option<String> {
    if !raw.contains('[') {
        return None;
    }
    let (mut out, mut depth, mut key) = (String::new(), 0usize, String::new());
    let mut chars = raw.chars().peekable();
    let mut in_key = false;
    while let Some(c) = chars.next() {
        match c {
            '[' if depth == 0 && !in_key => in_key = true,
            ']' if in_key => {
                in_key = false;
                if let Some(literal) = element_key(&key, false) {
                    out.push_str(&literal);
                } else if key.trim().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && key.trim().bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                {
                    out.push('[');
                    out.push_str(key.trim());
                    out.push(']');
                } else {
                    return None;
                }
                key.clear();
            }
            _ if in_key => key.push(c),
            '-' if depth == 0 && chars.peek() == Some(&'>') => {
                chars.next();
                out.push('.');
            }
            '(' | '<' => depth += 1,
            ')' | '>' => depth = depth.saturating_sub(1),
            _ if depth > 0 => {}
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                out.push('.');
            }
            c if c.is_whitespace() || matches!(c, '?' | '!' | '&' | '*') => {}
            c => out.push(c),
        }
    }
    (out.contains('[') && !in_key).then_some(out)
}

fn join(mut parts: Vec<Flow>) -> Flow {
    parts.retain(|f| !matches!(f, Flow::Clean));
    match parts.len() {
        0 => Flow::Clean,
        1 => parts.pop().expect("one part"),
        _ => Flow::Join(parts),
    }
}

/// Fields and node kinds that hold a statement's body rather than its header.
const BODY_FIELDS: &[&str] = &["body", "consequence", "alternative", "handler", "finalizer"];
const BLOCKY: &[&str] = &[
    "block", "statement_block", "compound_statement", "match_block", "class_body", "switch_block",
    "switch_body", "declaration_list", "expression_case", "default_case", "type_case",
    "communication_case", "case_statement", "elif_clause", "else_clause", "except_clause",
    "finally_clause", "catch_clause",
];
/// Expression nesting beyond this is ignored (generated / minified code).
const MAX_DEPTH: usize = 200;

// ---- engine ---------------------------------------------------------------

struct Target {
    label: Option<String>,
    brk: NodeIndex,
    cont: Option<NodeIndex>,
    fin_depth: usize,
}

/// Work to run on every path that leaves a `try`.
#[derive(Clone)]
enum Cleanup<'a> {
    Finally(Node<'a>),
    Close(Vec<Node<'a>>),
}

struct Engine<'a, S: Spec> {
    spec: &'a S,
    src: &'a [u8],
    finallys: Vec<Cleanup<'a>>,
    handlers: Vec<(Vec<NodeIndex>, usize)>,
    targets: Vec<Target>,
    labels: HashMap<String, NodeIndex>,
    pending_label: Option<String>,
    /// Go `defer`red calls registered on the current path.
    defers: Vec<Node<'a>>,
    /// Block of the next `case` body, for Go `fallthrough`.
    fall_to: Option<NodeIndex>,
    /// Bare names of the current method that mean `<receiver>.name`.
    implicit: HashMap<String, String>,
}

/// Reject recovered syntax trees so incomplete analysis cannot look successful.
pub(crate) fn validate_tree(tree: &tree_sitter::Tree) -> Result<()> {
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        // tree-sitter-c recovers GNU case ranges as `value (ERROR ... upper)`.
        // The lowering already handles this extension as part of the case label.
        let case_range = node.is_error()
            && node.parent().is_some_and(|p| p.kind() == "case_statement")
            && node.child_count() == 2
            && node.child(0).is_some_and(|n| n.kind() == "...")
            && node.child(1).is_some_and(|n| n.is_named() && !n.has_error() && !n.is_missing())
            && node.prev_named_sibling().is_some_and(|n| {
                node.parent().and_then(|p| p.child_by_field_name("value")) == Some(n)
            })
            && node.next_sibling().is_some_and(|n| n.kind() == ":");
        if case_range {
            continue;
        }
        if node.is_error() || node.is_missing() {
            let p = node.start_position();
            return Err(anyhow!("syntax error at {}:{} ({})", p.row + 1, p.column + 1, node.kind()));
        }
        if node.has_error() {
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor).collect::<Vec<_>>().into_iter().rev());
        }
    }
    Ok(())
}

/// Every import in the file, wherever it appears.
pub fn parse_imports<S: Spec>(spec: &S, lang: tree_sitter::Language, src: &str) -> Result<Vec<Import>> {
    let mut parser = Parser::new();
    parser.set_language(&lang)?;
    let tree = parser.parse(src, None).ok_or_else(|| anyhow!("parse failed"))?;
    validate_tree(&tree)?;
    let mut out = vec![];
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        out.extend(spec.imports_of(src.as_bytes(), n));
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        stack.extend(kids.into_iter().rev());
    }
    Ok(out)
}

/// Every struct / class definition and type alias in the file, wherever it appears.
pub fn parse_declarations<S: Spec>(spec: &S, lang: tree_sitter::Language, src: &str) -> Result<Declarations> {
    let mut parser = Parser::new();
    parser.set_language(&lang)?;
    let tree = parser.parse(src, None).ok_or_else(|| anyhow!("parse failed"))?;
    validate_tree(&tree)?;
    let mut out = Declarations::default();
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        spec.declarations_of(src.as_bytes(), n, &mut out);
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        stack.extend(kids.into_iter().rev());
    }
    Ok(out)
}

pub fn lower<S: Spec>(spec: &S, lang: tree_sitter::Language, src: &str) -> Result<Vec<Cfg>> {
    let mut parser = Parser::new();
    parser.set_language(&lang)?;
    let tree = parser.parse(src, None).ok_or_else(|| anyhow!("parse failed"))?;
    validate_tree(&tree)?;
    let mut out = vec![];
    if spec.top_level()
        && let Some(cfg) = Engine::new(spec, src.as_bytes()).module(tree.root_node())
    {
        out.push(cfg);
    }
    collect(spec, src.as_bytes(), tree.root_node(), &mut out);
    Ok(out)
}

/// Every function anywhere in the tree gets its own CFG.
fn collect<'a, S: Spec>(spec: &S, src: &'a [u8], node: Node<'a>, out: &mut Vec<Cfg>) {
    if spec.is_function(node)
        && let Some(cfg) = Engine::new(spec, src).function(node)
    {
        out.push(cfg);
    }
    let mut c = node.walk();
    for child in node.children(&mut c) {
        collect(spec, src, child, out);
    }
}

impl<'a, S: Spec> Engine<'a, S> {
    fn new(spec: &'a S, src: &'a [u8]) -> Self {
        Self {
            spec,
            src,
            finallys: vec![],
            handlers: vec![],
            targets: vec![],
            labels: HashMap::new(),
            pending_label: None,
            defers: vec![],
            fall_to: None,
            implicit: HashMap::new(),
        }
    }

    fn function(&mut self, f: Node<'a>) -> Option<Cfg> {
        let body = self.spec.function_body(f)?;
        let name = self.spec.function_name(self.src, f);
        self.implicit = match self.spec.receiver(self.src, f) {
            Some(r) => self.spec.implicit_fields(self.src, f).into_iter().map(|n| (n, r.clone())).collect(),
            None => HashMap::new(),
        };
        let mut b = CfgBuilder::new();
        for (target, value) in self.spec.capture_initializers(f) {
            let pos = target.start_position();
            let mut st = Stmt::new(StmtKind::Assign, pos.row + 1, pos.column + 1, format!("<capture {}>", text(self.src, target)));
            st.span = (value.start_byte(), value.end_byte());
            st.node_kind = value.kind_id();
            st.assigns.push(Assign { target: text(self.src, target), strong: true, value: self.flow(value, 0) });
            b.push_stmt(st);
        }
        if body.id() == f.id() {
            // the statements are the function's own children (a Kotlin lambda has no body node)
            if let Ctl::Block(children) = self.spec.classify(self.src, body) {
                self.all(&children, &mut b);
            }
        } else {
            self.stmt(body, &mut b);
        }
        if let Some(v) = self.spec.implicit_return(f)
            && b.current().is_some()
        {
            let mut st = Stmt::new(StmtKind::Other, v.start_position().row + 1, v.start_position().column + 1, "<return>".into());
            st.span = (v.start_byte(), v.end_byte());
            st.node_kind = v.kind_id();
            st.ret = Some(self.flow(v, 0));
            st.ret_props = self.ret_props(v);
            b.push_stmt(st);
        }
        self.run_defers(&mut b);
        let params = self.spec.params(self.src, f);
        let mut cfg = b.finish(name, f.start_position().row + 1, params);
        cfg.col = f.start_position().column + 1;
        cfg.span = (f.start_byte(), f.end_byte());
        cfg.node_kind = f.kind_id();
        cfg.receiver = self.spec.receiver(self.src, f);
        cfg.free_writes = self.spec.free_writes(self.src, f);
        cfg.class_bases = self.spec.class_bases(self.src, f).iter().map(|b| type_name(b)).filter(|b| !b.is_empty()).collect();
        let (pt, rt) = self.spec.declared_types(self.src, f);
        cfg.param_types = pt.into_iter().map(|(n, t)| (n, type_name(&t))).filter(|(_, t)| !t.is_empty()).collect();
        cfg.ret_type = rt.map(|t| type_name(&t)).filter(|t| !t.is_empty());
        let (locals, fields) = self.spec.declared_vars(self.src, f);
        let locals: Vec<_> = locals.into_iter().map(|(n, t, s)| (n, type_name(&t), s)).collect();
        cfg.local_decls = locals.iter().map(|(n, _, s)| (n.clone(), *s)).collect();
        let locals: Vec<_> = locals.into_iter().filter(|(_, t, _)| !t.is_empty()).collect();
        cfg.local_types = locals.iter().map(|(n, t, _)| (n.clone(), t.clone())).collect();
        cfg.local_scopes = locals.into_iter().map(|(_, _, s)| s).collect();
        cfg.field_types = fields.into_iter().map(|(n, t)| (n, type_name(&t))).filter(|(_, t)| !t.is_empty()).collect();
        Some(cfg)
    }

    /// Top-level script code; skipped when it holds only imports/declarations.
    fn module(&mut self, root: Node<'a>) -> Option<Cfg> {
        let mut b = CfgBuilder::new();
        self.stmt(root, &mut b);
        let mut cfg = b.finish("<module>".into(), 1, vec![]);
        cfg.span = (root.start_byte(), root.end_byte());
        cfg.node_kind = root.kind_id();
        let interesting = cfg
            .graph
            .node_weights()
            .flat_map(|blk| &blk.stmts)
            .any(|st| st.kind != StmtKind::Other);
        interesting.then_some(cfg)
    }

    fn run_defers(&mut self, b: &mut CfgBuilder) {
        if b.current().is_none() {
            return;
        }
        for i in (0..self.defers.len()).rev() {
            let d = self.defers[i];
            let t = self.head(d);
            let call = t.strip_prefix("defer").unwrap_or(&t).trim();
            self.push_f(d, StmtKind::Call, format!("deferred {call}"), b, false);
        }
    }

    fn head(&self, n: Node) -> String {
        text(self.src, n).lines().next().unwrap_or("").trim().to_string()
    }

    /// Condition text without the surrounding parentheses.
    fn cond_text(&self, n: Node) -> String {
        let t = text(self.src, n);
        let t = t.trim();
        let t = if matches!(n.kind(), "parenthesized_expression" | "condition_clause") {
            t.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(t)
        } else {
            t
        };
        t.lines().next().unwrap_or("").trim().to_string()
    }

    /// The properties of a returned object / dictionary literal.
    fn ret_props(&self, v: Node<'a>) -> Vec<(String, Flow)> {
        literal_props(self.spec, self.src, &[v]).into_iter().map(|(k, n)| (k, self.flow(n, 1))).collect()
    }

    /// A statement without data-flow facts (synthetic or purely structural).
    fn push(&self, n: Node, kind: StmtKind, text: String, b: &mut CfgBuilder) {
        let p = n.start_position();
        let mut st = Stmt::new(kind, p.row + 1, p.column + 1, text);
        st.span = (n.start_byte(), n.end_byte());
        st.node_kind = n.kind_id();
        b.push_stmt(st);
    }

    /// A statement with the assignments and calls found in `n`. With `header`,
    /// only the part before the body is analyzed (loop/switch/with headers).
    fn push_f(&self, n: Node<'a>, kind: StmtKind, text: String, b: &mut CfgBuilder, header: bool) {
        let p = n.start_position();
        let mut st = Stmt::new(kind, p.row + 1, p.column + 1, text);
        st.span = (n.start_byte(), n.end_byte());
        st.node_kind = n.kind_id();
        (st.assigns, st.elems, st.calls) = self.facts(n, header);
        if kind == StmtKind::Branch && !header {
            st.cond = Some(self.flow(n, 0));
        }
        b.push_stmt(st);
    }

    /// If `n` may leave the function early (Rust `?`), split the block: one
    /// edge to the exit, one to the code that follows.
    fn early_exit(&self, n: Node, b: &mut CfgBuilder) {
        if self.spec.early_exit(n) {
            let cur = b.ensure_current();
            let next = b.new_block();
            b.edge(cur, next, EdgeKind::Normal);
            b.edge(cur, b.exit_node(), EdgeKind::Return);
            b.set_current(Some(next));
        }
    }

    /// A branch with no condition expression (loop/switch header, `let ... else`).
    fn head_branch(&self, owner: Node, b: &mut CfgBuilder) -> NodeIndex {
        self.push_f(owner, StmtKind::Branch, self.head(owner), b, true);
        self.early_exit(owner, b);
        b.ensure_current()
    }

    /// Emit the test of `cond` (or of `owner` itself) into the current block,
    /// splitting `&&`/`||`/`!` into one branch block per operand so short
    /// circuiting shows up as control flow. After this the current block is
    /// `None`; `tk`/`fk` label the final true/false edges.
    #[allow(clippy::too_many_arguments)]
    fn branch_to(
        &mut self,
        owner: Node<'a>,
        cond: Option<Node<'a>>,
        t: NodeIndex,
        tk: EdgeKind,
        f: NodeIndex,
        fk: EdgeKind,
        b: &mut CfgBuilder,
    ) {
        match cond {
            Some(c) => self.cond_flow(c, t, tk, f, fk, b),
            None => {
                let cur = self.head_branch(owner, b);
                b.edge(cur, t, tk);
                b.edge(cur, f, fk);
                b.set_current(None);
            }
        }
    }

    fn cond_flow(
        &mut self,
        c: Node<'a>,
        t: NodeIndex,
        tk: EdgeKind,
        f: NodeIndex,
        fk: EdgeKind,
        b: &mut CfgBuilder,
    ) {
        let mut c = c;
        while matches!(c.kind(), "parenthesized_expression" | "condition_clause")
            && c.named_child_count() == 1
        {
            c = c.named_child(0).expect("one named child");
        }
        match self.spec.bool_op(self.src, c) {
            Some(BoolOp::And(l, r)) => {
                let mid = b.new_block();
                self.cond_flow(l, mid, EdgeKind::True, f, EdgeKind::False, b);
                b.set_current(Some(mid));
                self.cond_flow(r, t, tk, f, fk, b);
            }
            Some(BoolOp::Or(l, r)) => {
                let mid = b.new_block();
                self.cond_flow(l, t, tk, mid, EdgeKind::False, b);
                b.set_current(Some(mid));
                self.cond_flow(r, t, tk, f, fk, b);
            }
            Some(BoolOp::Not(x)) => self.cond_flow(x, f, EdgeKind::True, t, EdgeKind::False, b),
            None => {
                self.push_f(c, StmtKind::Branch, self.cond_text(c), b, false);
                self.early_exit(c, b);
                let cur = b.ensure_current();
                b.edge(cur, t, tk);
                b.edge(cur, f, fk);
                b.set_current(None);
            }
        }
    }

    fn opt(&mut self, n: Option<Node<'a>>, b: &mut CfgBuilder) {
        if let Some(n) = n {
            self.stmt(n, b);
        }
    }

    fn all(&mut self, ns: &[Node<'a>], b: &mut CfgBuilder) {
        for &n in ns {
            self.stmt(n, b);
        }
    }

    // ---- data-flow facts ------------------------------------------------

    /// Assignments and calls performed by the statement `n`. Nested functions
    /// and nested blocks are separate statements and are not included.
    fn facts(&self, n: Node<'a>, header: bool) -> (Vec<Assign>, Vec<Assign>, Vec<CallFlow>) {
        let (mut assigns, mut elems, mut calls) = (vec![], vec![], vec![]);
        self.visit(n, header, 0, &mut assigns, &mut elems, &mut calls);
        (assigns, elems, calls)
    }

    fn visit(&self, n: Node<'a>, header: bool, depth: usize, assigns: &mut Vec<Assign>, elems: &mut Vec<Assign>, calls: &mut Vec<CallFlow>) {
        if depth > MAX_DEPTH || (depth > 0 && (self.spec.is_function(n) || BLOCKY.contains(&n.kind()))) {
            return;
        }
        if let Some(a) = self.spec.assignment(self.src, n) {
            self.record_assign(a, assigns, elems);
        }
        if let Some(cp) = self.spec.call_parts(self.src, n) {
            calls.push(self.call_flow(n, cp, depth));
        }
        let mut c = n.walk();
        if !c.goto_first_child() {
            return;
        }
        loop {
            let k = c.node();
            let skip = header
                && depth == 0
                && (c.field_name().is_some_and(|f| BODY_FIELDS.contains(&f)) || BLOCKY.contains(&k.kind()));
            if k.is_named() && !skip {
                self.visit(k, header, depth + 1, assigns, elems, calls);
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }

    fn call_flow(&self, n: Node<'a>, cp: CallParts<'a>, depth: usize) -> CallFlow {
        let p = n.start_position();
        let mut callee = normalize_callee(&cp.callee);
        // `r.run()` where `r` is a field of the class: `this.r.run()`
        if let Some((head, _)) = callee.split_once('.')
            && let Some(q) = self.qualify_implicit(head)
        {
            callee.replace_range(..head.len(), &q);
        }
        let callee_key = keyed_callee(&cp.callee).map(|mut k| {
            if let Some((head, _)) = k.split_once('.')
                && let Some(q) = self.qualify_implicit(head)
            {
                k.replace_range(..head.len(), &q);
            } else if let Some(q) = self.qualify_implicit(k.split('[').next().unwrap_or(&k)) {
                k = format!("{q}{}", &k[k.split('[').next().unwrap_or(&k).len()..]);
            }
            k
        });
        // properties of literal arguments by name: `f({ algorithm: x })`, `g(&Config{Min: v})`
        let props = literal_props(self.spec, self.src, &cp.args).into_iter().map(|(name, value)| (name, self.flow(value, depth + 1))).collect();
        CallFlow {
            callee,
            callee_key,
            recv: cp.receiver.map(|r| self.flow(r, depth + 1)),
            args: cp.args.iter().map(|a| self.flow(*a, depth + 1)).collect(),
            arg_names: cp.names,
            props,
            line: p.row + 1,
            col: p.column + 1,
        }
    }

    /// What the value of expression `n` depends on.
    fn flow(&self, n: Node<'a>, depth: usize) -> Flow {
        if self.spec.is_function(n) {
            let p = n.start_position();
            return Flow::Path(crate::ir::closure_marker(p.row + 1, p.column + 1));
        }
        if depth > MAX_DEPTH {
            return Flow::Clean;
        }
        if let Some(cp) = self.spec.call_parts(self.src, n) {
            return Flow::Call(Box::new(self.call_flow(n, cp, depth)));
        }
        if let Some(p) = self.path(n) {
            return Flow::Path(p);
        }
        if let Some((obj, _)) = self.spec.member_parts(self.src, n) {
            return self.flow(obj, depth + 1); // `f(x).field` depends on `f(x)`
        }
        let mut c = n.walk();
        join(n.named_children(&mut c).map(|k| self.flow(k, depth + 1)).collect())
    }

    /// A variable name; a bare field of the current class becomes `this.name`.
    fn ident(&self, n: Node<'a>) -> String {
        let t = text(self.src, n);
        self.qualify_implicit(&t).unwrap_or(t)
    }

    /// `this.name` if `name` is a bare field of the current class.
    fn qualify_implicit(&self, name: &str) -> Option<String> {
        self.implicit.get(name).map(|r| format!("{r}.{name}"))
    }

    /// `a.b.c` like [`Self::path`], but looking through subscripts: `xs[i].f` is `xs.f`.
    fn element_path(&self, n: Node<'a>) -> Option<String> {
        if self.spec.is_ident(n) {
            return Some(self.ident(n));
        }
        if let Some((obj, name)) = self.spec.member_parts(self.src, n) {
            return Some(format!("{}.{}", self.element_path(obj)?, name));
        }
        if self.spec.is_subscript(n) {
            return self.element_path(n.named_child(0)?);
        }
        None
    }

    /// The key of `a[0]` / `d["k"]`: `[0]` / `['k']` when the index is a literal.
    fn const_key(&self, n: Node<'a>) -> Option<String> {
        let count = n.named_child_count();
        element_key(&text(self.src, n.named_child(u32::try_from(count.checked_sub(1).filter(|c| *c >= 1)?).ok()?)?), false)
    }

    /// `a.b.c` made only of variables and member accesses (and subscripts with literal keys).
    fn path(&self, n: Node<'a>) -> Option<String> {
        self.path_keyed(n, true)
    }

    /// Like [`Self::path`], but a subscript is not part of a path.
    fn plain_path(&self, n: Node<'a>) -> Option<String> {
        self.path_keyed(n, false)
    }

    fn path_keyed(&self, n: Node<'a>, keys: bool) -> Option<String> {
        if self.spec.is_ident(n) {
            return Some(self.ident(n));
        }
        if keys
            && self.spec.is_subscript(n)
            && let Some(key) = self.const_key(n)
        {
            return Some(format!("{}{}", self.path_keyed(n.named_child(0)?, keys)?, self.spec.key_path(&key)));
        }
        let (obj, name) = self.spec.member_parts(self.src, n)?;
        Some(format!("{}.{}", self.path_keyed(obj, keys)?, name))
    }

    fn record_assign(&self, a: AssignParts<'a>, out: &mut Vec<Assign>, elems: &mut Vec<Assign>) {
        let values: Vec<Flow> = a.values.iter().map(|v| self.flow(*v, 1)).collect();
        // `a, b = x, y` pairs up; `a, b = f()` gives every target the whole value
        let paired = a.targets.len() > 1 && a.targets.len() == values.len();
        // `xs = [a, b]` also assigns the elements, so `xs[0]` is `a` and `xs[1]` is `b`
        let container = a.values.first().copied().map(|v| {
            if v.kind() == "composite_literal" { named_children(v).into_iter().find(|c| c.kind() == "literal_value").unwrap_or(v) } else { v }
        });
        let literal = (a.targets.len() == 1 && a.values.len() == 1 && !a.augmented)
            .then(|| container.and_then(|v| self.spec.sequence_elements(v)))
            .flatten();
        let mapping = (a.targets.len() == 1 && a.values.len() == 1 && !a.augmented).then(|| container.and_then(|v| self.spec.mapping_entries(self.src, v))).flatten();
        for (i, t) in a.targets.iter().enumerate() {
            let mut value = if paired { values[i].clone() } else { join(values.clone()) };
            // `all = { k: x }` holds `x`, it is not another name for it
            if mapping.is_some() && matches!(value, Flow::Path(_)) {
                value = Flow::Join(vec![value, Flow::Clean]);
            }
            let mut names = vec![];
            self.target_names(*t, true, 0, &mut names);
            if a.augmented {
                let old: Vec<Flow> = names.iter().map(|(n, _)| Flow::Path(n.clone())).collect();
                value = join(old.into_iter().chain([value]).collect());
            }
            // `xs[0].d = v` / `xs[0] = v`: also that element on its own
            if let Some(p) = self.path(*t).filter(|p| p.contains('[')) {
                elems.push(Assign { target: p, strong: false, value: value.clone() });
            }
            for (target, plain) in names {
                if plain && !target.contains('[') && let Some(literal_elems) = &literal {
                    // only literal elements are strong assignments of an element key
                    for (k, e) in literal_elems.iter().enumerate() {
                        elems.push(Assign { target: format!("{target}[{k}]"), strong: true, value: self.flow(*e, 1) });
                    }
                }
                if plain && !target.contains('[') && let Some(entries) = &mapping {
                    self.mapping_elems(&target, entries, 0, elems);
                }
                out.push(Assign { target, strong: plain && !a.augmented, value: value.clone() });
            }
        }
    }

    /// The elements of a dictionary / object literal assigned to `target`, and those of the literals
    /// nested in it (`all = { jwt: { algorithms: x } }` gives `all.jwt` and `all.jwt.algorithms`).
    fn mapping_elems(&self, target: &str, entries: &[(String, Node<'a>)], depth: usize, elems: &mut Vec<Assign>) {
        for (key, v) in entries {
            let path = format!("{target}{key}");
            let inner = (depth < 2).then(|| self.spec.mapping_entries(self.src, literal_of(*v))).flatten();
            let mut value = self.flow(*v, 1);
            // a literal holds what is in it, it is not another name for it
            if inner.is_some() && matches!(value, Flow::Path(_)) {
                value = Flow::Join(vec![value, Flow::Clean]);
            }
            elems.push(Assign { target: path.clone(), strong: true, value });
            if let Some(inner) = inner {
                self.mapping_elems(&path, &inner, depth + 1, elems);
            }
        }
    }

    /// Variables written by assigning to `t`. `plain` is false for member and
    /// subscript targets (`o.f = v`, `a[i] = v`), which only update `o` / `a`.
    fn target_names(&self, t: Node<'a>, plain: bool, depth: usize, out: &mut Vec<(String, bool)>) {
        if depth > 50 {
            return;
        }
        if self.spec.is_ident(t) {
            let name = self.ident(t);
            let plain = plain && !name.contains('.');
            out.push((name, plain));
        } else if let Some((obj, _)) = self.spec.member_parts(self.src, t) {
            // `a.b.c = v` writes that field; if the path is not plain, the object as a whole
            match self.plain_path(t) {
                Some(p) => out.push((p, plain)),
                None => {
                    // `xs[i].f = v` also writes field `f` of what the container holds (weakly)
                    if let Some(p) = self.element_path(t) {
                        out.push((p, false));
                    }
                    self.target_names(obj, false, depth + 1, out)
                }
            }
        } else if self.spec.is_subscript(t) {
            if let Some(o) = t.named_child(0) {
                self.target_names(o, false, depth + 1, out);
            }
        } else {
            let mut c = t.walk();
            for k in t.named_children(&mut c) {
                self.target_names(k, plain, depth + 1, out);
            }
        }
    }

    // ---- expression-level control flow --------------------------------

    /// Lower flow hidden in the expression `n` itself or below it.
    fn flows(&mut self, n: Node<'a>, b: &mut CfgBuilder) {
        match self.spec.expr_flow(self.src, n) {
            Some(f) if !matches!(f, ExprCtl::Stmt) => self.lower_flow(n, f, b),
            _ => self.flows_in(n, b),
        }
    }

    /// Lower flow hidden in the children of `n`, left to right.
    fn flows_in(&mut self, n: Node<'a>, b: &mut CfgBuilder) {
        let mut c = n.walk();
        let kids: Vec<Node<'a>> = n.named_children(&mut c).collect();
        for k in kids {
            if self.spec.is_function(k) || self.spec.is_comment(k) {
                continue;
            }
            match self.spec.expr_flow(self.src, k) {
                Some(f) => self.lower_flow(k, f, b),
                None => self.flows_in(k, b),
            }
        }
    }

    /// Evaluate an operand that is about to be branched on.
    fn operand(&mut self, x: Node<'a>, b: &mut CfgBuilder) {
        if self.spec.bool_op(self.src, x).is_some() {
            return; // split into branches by `cond_flow`
        }
        self.flows(x, b);
    }

    /// One arm of an expression-level branch: its own flow, then its value.
    fn arm(&mut self, x: Node<'a>, b: &mut CfgBuilder) {
        match self.spec.expr_flow(self.src, x) {
            Some(f) if !matches!(f, ExprCtl::Stmt) => self.lower_flow(x, f, b),
            _ => {
                self.flows_in(x, b);
                let kind = self.spec.expr_kind(x);
                self.push_f(x, kind, self.head(x), b, false);
            }
        }
    }

    fn lower_flow(&mut self, k: Node<'a>, f: ExprCtl<'a>, b: &mut CfgBuilder) {
        match f {
            ExprCtl::Stmt => self.stmt(k, b),
            ExprCtl::Ternary { cond, then, els } => {
                self.operand(cond, b);
                let (t, e, join) = (b.new_block(), b.new_block(), b.new_block());
                self.branch_to(k, Some(cond), t, EdgeKind::True, e, EdgeKind::False, b);
                b.set_current(Some(t));
                self.arm(then, b);
                b.goto(join, EdgeKind::Normal);
                b.set_current(Some(e));
                self.arm(els, b);
                b.goto(join, EdgeKind::Normal);
                b.set_current(Some(join));
            }
            ExprCtl::Short { lhs, rhs, and } => {
                self.operand(lhs, b);
                let (r, join) = (b.new_block(), b.new_block());
                if and {
                    self.branch_to(k, Some(lhs), r, EdgeKind::True, join, EdgeKind::False, b);
                } else {
                    self.branch_to(k, Some(lhs), join, EdgeKind::True, r, EdgeKind::False, b);
                }
                b.set_current(Some(r));
                self.arm(rhs, b);
                b.goto(join, EdgeKind::Normal);
                b.set_current(Some(join));
            }
            ExprCtl::Optional { obj } => {
                self.operand(obj, b);
                let (r, join) = (b.new_block(), b.new_block());
                self.branch_to(k, Some(obj), r, EdgeKind::True, join, EdgeKind::False, b);
                b.set_current(Some(r));
                self.push_f(k, StmtKind::Other, self.head(k), b, false);
                b.goto(join, EdgeKind::Normal);
                b.set_current(Some(join));
            }
            ExprCtl::Comprehension { clauses, elements } => {
                // Control continues in the exit block of the outermost `for`.
                let unused = b.new_block();
                self.comprehension(&clauses, &elements, unused, b);
            }
        }
    }

    /// Nested `for`/`if` clauses become nested loops and filters.
    fn comprehension(&mut self, clauses: &[Clause<'a>], elements: &[Node<'a>], cont: NodeIndex, b: &mut CfgBuilder) {
        match clauses.split_first() {
            None => {
                for &e in elements {
                    self.arm(e, b);
                }
            }
            Some((Clause::If(c), rest)) => {
                let ok = b.new_block();
                self.branch_to(*c, Some(*c), ok, EdgeKind::True, cont, EdgeKind::False, b);
                b.set_current(Some(ok));
                self.comprehension(rest, elements, cont, b);
            }
            Some((Clause::For(c), rest)) => {
                let (header, body, after) = (b.new_block(), b.new_block(), b.new_block());
                b.goto(header, EdgeKind::Normal);
                self.branch_to(*c, None, body, EdgeKind::True, after, EdgeKind::False, b);
                b.set_current(Some(body));
                self.comprehension(rest, elements, header, b);
                if let Some(cur) = b.current() {
                    b.edge(cur, header, EdgeKind::Back);
                }
                b.set_current(Some(after));
            }
        }
    }

    fn label_block(&mut self, name: &str, b: &mut CfgBuilder) -> NodeIndex {
        if let Some(&n) = self.labels.get(name) {
            return n;
        }
        let n = b.new_block();
        self.labels.insert(name.to_string(), n);
        n
    }

    fn stmt(&mut self, n: Node<'a>, b: &mut CfgBuilder) {
        let pending = self.pending_label.take();
        if self.spec.is_comment(n) { return; }
        if self.spec.is_function(n) {
            let mut parent = n.parent();
            let mut nested = false;
            while let Some(p) = parent {
                if self.spec.is_function(p) { nested = true; break; }
                parent = p.parent();
            }
            if nested && let Some(name) = n.child_by_field_name("name") {
                let pos = n.start_position();
                let mut st = Stmt::new(StmtKind::Assign, pos.row + 1, pos.column + 1, self.head(n));
                st.span = (n.start_byte(), n.end_byte());
                st.node_kind = n.kind_id();
                st.assigns.push(Assign { target: text(self.src, name), strong: true,
                    value: Flow::Path(crate::ir::closure_marker(pos.row + 1, pos.column + 1)) });
                b.push_stmt(st);
            }
            return;
        }
        match self.spec.classify(self.src, n) {
            Ctl::Skip => {}
            Ctl::Block(children) => self.all(&children, b),
            Ctl::Simple(kind) => {
                self.flows(n, b);
                self.push_f(n, kind, self.head(n), b, false);
                self.early_exit(n, b);
            }
            Ctl::If { pre, cond, then, els } => {
                let defers = self.defers.len();
                self.if_stmt(n, &pre, cond, then, els, b);
                self.defers.truncate(defers);
            }
            Ctl::Loop { label, pre, kind, cond, body, update } => {
                let defers = self.defers.len();
                self.loop_stmt(n, label.or(pending), &pre, kind, cond, body, &update, b);
                self.defers.truncate(defers);
            }
            Ctl::DoWhile { body, cond } => {
                let defers = self.defers.len();
                self.do_while(n, pending, body, cond, b);
                self.defers.truncate(defers);
            }
            Ctl::Switch { cases, breakable, fallthrough, exhaustive } => {
                let defers = self.defers.len();
                self.switch(n, pending, &cases, (breakable, fallthrough, exhaustive), b);
                self.defers.truncate(defers);
            }
            Ctl::Try { pre, closes, body, handlers, finally } => {
                let defers = self.defers.len();
                self.try_stmt(n, &pre, &closes, body, &handlers, finally, b);
                self.defers.truncate(defers);
            }
            Ctl::Header(kind, children) => {
                self.push_f(n, kind, self.head(n), b, true);
                self.all(&children, b);
            }
            Ctl::Defer => {
                self.push(n, StmtKind::Call, self.head(n), b);
                self.defers.push(n);
            }
            Ctl::Fallthrough => {
                if let Some(t) = self.fall_to {
                    b.jump(t, EdgeKind::Normal);
                }
            }
            Ctl::Return => {
                self.flows_in(n, b);
                let value = self.spec.return_value(n);
                let ret = value.map(|v| self.flow(v, 0));
                let props = value.map(|v| self.ret_props(v)).unwrap_or_default();
                self.push_f(n, StmtKind::Other, self.head(n), b, false);
                if let (Some(flow), Some(blk)) = (ret, b.current())
                    && let Some(last) = b.last_stmt_mut(blk)
                {
                    last.ret = Some(flow);
                    last.ret_props = props;
                }
                self.early_exit(n, b);
                self.run_finallys(0, b);
                self.run_defers(b);
                b.do_return();
            }
            Ctl::Throw => {
                self.flows_in(n, b);
                self.push_f(n, StmtKind::Other, self.head(n), b, false);
                self.run_defers(b);
                // A deferred `recover()` turns the panic into a normal return.
                if self.defers.iter().any(|d| self.spec.recovers(self.src, *d)) {
                    b.do_return();
                } else {
                    self.raise(b);
                }
            }
            Ctl::Break(label) => self.jump_target(label, false, b),
            Ctl::Continue(label) => self.jump_target(label, true, b),
            Ctl::Goto(label) => {
                self.push(n, StmtKind::Other, self.head(n), b);
                let target = self.label_block(&label, b);
                b.jump(target, EdgeKind::Normal);
            }
            Ctl::Labeled { label, stmt } => {
                let blk = self.label_block(&label, b);
                b.goto(blk, EdgeKind::Normal);
                self.pending_label = Some(label);
                self.opt(stmt, b);
                self.pending_label = None;
            }
        }
    }

    fn if_stmt(
        &mut self,
        n: Node<'a>,
        pre: &[Node<'a>],
        cond: Option<Node<'a>>,
        then: Option<Node<'a>>,
        els: Option<Node<'a>>,
        b: &mut CfgBuilder,
    ) {
        self.all(pre, b);
        let join = b.new_block();
        let then_blk = b.new_block();
        let else_blk = els.map(|_| b.new_block());
        self.branch_to(n, cond, then_blk, EdgeKind::True, else_blk.unwrap_or(join), EdgeKind::False, b);
        let defers = self.defers.len();
        b.set_current(Some(then_blk));
        self.opt(then, b);
        b.goto(join, EdgeKind::Normal);
        self.defers.truncate(defers);
        if let (Some(e), Some(blk)) = (els, else_blk) {
            b.set_current(Some(blk));
            self.stmt(e, b);
            b.goto(join, EdgeKind::Normal);
        }
        b.set_current(Some(join));
    }

    #[allow(clippy::too_many_arguments)]
    fn loop_stmt(
        &mut self,
        n: Node<'a>,
        label: Option<String>,
        pre: &[Node<'a>],
        kind: LoopKind,
        cond: Option<Node<'a>>,
        body: Option<Node<'a>>,
        update: &[Node<'a>],
        b: &mut CfgBuilder,
    ) {
        self.all(pre, b);
        let header = b.new_block();
        let after = b.new_block();
        b.goto(header, EdgeKind::Normal);
        let body_blk = b.new_block();
        // `else` runs when the loop ends without `break`.
        let else_node = self.spec.loop_else(n);
        let else_blk = else_node.map(|_| b.new_block());
        let exit_to = else_blk.unwrap_or(after);
        match kind {
            LoopKind::Cond => {
                self.branch_to(n, cond, body_blk, EdgeKind::True, exit_to, EdgeKind::False, b)
            }
            LoopKind::Each => {
                self.branch_to(n, None, body_blk, EdgeKind::True, exit_to, EdgeKind::False, b)
            }
            LoopKind::Infinite => {
                self.push(n, StmtKind::Other, "loop".into(), b);
                b.edge(header, body_blk, EdgeKind::Normal);
            }
        }
        let upd_blk = (!update.is_empty()).then(|| b.new_block());
        b.set_current(Some(body_blk));
        self.targets.push(Target {
            label,
            brk: after,
            cont: Some(upd_blk.unwrap_or(header)),
            fin_depth: self.finallys.len(),
        });
        self.opt(body, b);
        self.targets.pop();
        if let Some(u) = upd_blk {
            b.goto(u, EdgeKind::Normal);
            self.all(update, b);
        }
        if let Some(c) = b.current() {
            b.edge(c, header, EdgeKind::Back);
        }
        if let (Some(e), Some(blk)) = (else_node, else_blk) {
            b.set_current(Some(blk));
            self.stmt(e, b);
            b.goto(after, EdgeKind::Normal);
        }
        b.set_current(Some(after));
    }

    fn do_while(
        &mut self,
        n: Node<'a>,
        label: Option<String>,
        body: Option<Node<'a>>,
        cond: Option<Node<'a>>,
        b: &mut CfgBuilder,
    ) {
        let body_blk = b.new_block();
        let cond_blk = b.new_block();
        let after = b.new_block();
        b.goto(body_blk, EdgeKind::Normal);
        self.targets.push(Target {
            label,
            brk: after,
            cont: Some(cond_blk),
            fin_depth: self.finallys.len(),
        });
        self.opt(body, b);
        self.targets.pop();
        b.goto(cond_blk, EdgeKind::Normal);
        self.branch_to(n, cond, body_blk, EdgeKind::Back, after, EdgeKind::False, b);
        b.set_current(Some(after));
    }

    fn switch(
        &mut self,
        n: Node<'a>,
        label: Option<String>,
        cases: &[Case<'a>],
        (breakable, fallthrough, exhaustive): (bool, bool, bool),
        b: &mut CfgBuilder,
    ) {
        let head = self.head_branch(n, b);
        let join = b.new_block();
        let blocks: Vec<NodeIndex> = cases.iter().map(|_| b.new_block()).collect();
        for &blk in &blocks {
            b.edge(head, blk, EdgeKind::True);
        }
        if !exhaustive && cases.iter().all(|c| !c.labels.is_empty()) {
            b.edge(head, join, EdgeKind::False);
        }
        if breakable {
            self.targets.push(Target { label, brk: join, cont: None, fin_depth: self.finallys.len() });
        }
        let defers = self.defers.len();
        let outer_fall = self.fall_to;
        for (i, (case, &blk)) in cases.iter().zip(&blocks).enumerate() {
            self.defers.truncate(defers);
            self.fall_to = blocks.get(i + 1).copied();
            b.set_current(Some(blk));
            let title = if case.labels.is_empty() {
                "default".to_string()
            } else {
                let ls: Vec<String> = case.labels.iter().map(|l| self.cond_text(*l)).collect();
                format!("case {}", ls.join(", "))
            };
            self.push(case.labels.first().copied().unwrap_or(n), StmtKind::Branch, title, b);
            if let Some(g) = case.guard {
                // A failing guard moves on to the next case.
                let ok = b.new_block();
                let fail = blocks.get(i + 1).copied().unwrap_or(join);
                self.branch_to(g, Some(g), ok, EdgeKind::True, fail, EdgeKind::False, b);
                b.set_current(Some(ok));
            }
            self.all(&case.body, b);
            match blocks.get(i + 1) {
                Some(&next) if fallthrough => b.goto(next, EdgeKind::Normal),
                _ => b.goto(join, EdgeKind::Normal),
            }
        }
        self.fall_to = outer_fall;
        if breakable {
            self.targets.pop();
        }
        b.set_current(Some(join));
    }

    #[allow(clippy::too_many_arguments)]
    fn try_stmt(
        &mut self,
        n: Node<'a>,
        pre_stmts: &[Node<'a>],
        closes: &[Node<'a>],
        body: Option<Node<'a>>,
        handlers: &[Handler<'a>],
        finally: Option<Node<'a>>,
        b: &mut CfgBuilder,
    ) {
        self.all(pre_stmts, b);
        let pre = b.ensure_current();
        let join = b.new_block();
        let h_blocks: Vec<NodeIndex> = handlers.iter().map(|_| b.new_block()).collect();
        // No handler: an exception still has to run the `finally` on its way out.
        let ex_fin = (handlers.is_empty() && finally.is_some()).then(|| b.new_block());

        // Implicit "something in the body may throw" edges. Resources are
        // closed first, so route through a block that does that.
        let targets: Vec<NodeIndex> = h_blocks.iter().copied().chain(ex_fin).collect();
        let entry = if closes.is_empty() || targets.is_empty() {
            pre
        } else {
            let cb = b.new_block();
            b.edge(pre, cb, EdgeKind::Exception);
            let saved = b.current();
            b.set_current(Some(cb));
            self.emit_closes(closes, b);
            b.set_current(saved);
            cb
        };
        for &t in &targets {
            b.edge(entry, t, EdgeKind::Exception);
        }

        if let Some(f) = finally {
            self.finallys.push(Cleanup::Finally(f));
        }
        if !h_blocks.is_empty() {
            self.handlers.push((h_blocks.clone(), self.finallys.len()));
        }
        if !closes.is_empty() {
            self.finallys.push(Cleanup::Close(closes.to_vec()));
        }
        self.opt(body, b);
        if !closes.is_empty() {
            self.emit_closes(closes, b);
            self.finallys.pop();
        }
        if !h_blocks.is_empty() {
            self.handlers.pop();
        }
        self.opt(self.spec.try_else(n), b);
        b.goto(join, EdgeKind::Normal);
        for (h, &blk) in handlers.iter().zip(&h_blocks) {
            b.set_current(Some(blk));
            self.push(h.head, StmtKind::Branch, self.head(h.head), b);
            self.opt(h.body, b);
            b.goto(join, EdgeKind::Normal);
        }
        if finally.is_some() {
            self.finallys.pop();
        }
        b.set_current(Some(join));
        self.opt(finally, b);
        if let Some(ex) = ex_fin {
            let after = b.current();
            b.set_current(Some(ex));
            self.opt(finally, b);
            self.raise(b);
            b.set_current(after);
        }
    }

    /// `r.close()` for each resource, last opened first.
    fn emit_closes(&mut self, resources: &[Node<'a>], b: &mut CfgBuilder) {
        if b.current().is_none() {
            return;
        }
        for &r in resources.iter().rev() {
            let name = r.child_by_field_name("name").map(|x| text(self.src, x)).unwrap_or_else(|| self.head(r));
            self.push(r, StmtKind::Call, format!("{name}.close()"), b);
        }
    }

    /// Inline the `finally` bodies from index `from` (innermost first) on the
    /// current path; see the Python lowering for the rationale.
    fn run_finallys(&mut self, from: usize, b: &mut CfgBuilder) {
        if b.current().is_none() || from >= self.finallys.len() {
            return;
        }
        let saved = self.finallys.clone();
        for i in (from..saved.len()).rev() {
            self.finallys.truncate(i);
            match &saved[i] {
                Cleanup::Finally(f) => self.stmt(*f, b),
                Cleanup::Close(rs) => self.emit_closes(rs, b),
            }
        }
        self.finallys = saved;
    }

    fn raise(&mut self, b: &mut CfgBuilder) {
        let (hs, from) = self.handlers.last().cloned().unwrap_or_default();
        self.run_finallys(from, b);
        b.do_raise(&hs);
    }

    fn jump_target(&mut self, label: Option<String>, is_continue: bool, b: &mut CfgBuilder) {
        if b.current().is_none() {
            return;
        }
        let found = self.targets.iter().rev().find(|t| {
            (!is_continue || t.cont.is_some())
                && label.as_ref().is_none_or(|l| t.label.as_ref() == Some(l))
        });
        let Some(t) = found else { return };
        let (to, fin, kind) = if is_continue {
            (t.cont.expect("checked above"), t.fin_depth, EdgeKind::Continue)
        } else {
            (t.brk, t.fin_depth, EdgeKind::Break)
        };
        self.run_finallys(fin, b);
        b.jump(to, kind);
    }
}
