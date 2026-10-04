//! Language-neutral AST: every named tree-sitter node, in source order, with
//! a normalized [`NodeKind`] and a stable [`NodeId`].
//!
//! The normalization reuses the lowering's [`Spec`] (what is a function, a
//! call, an assignment, a member access), so the AST and the CFG agree on
//! what those are. Statements of a [`Cfg`](crate::ir::Cfg) point at their AST
//! node through [`Ast::find`].

use super::node::{NodeId, NodeKind};
use crate::lang::common::Spec;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use tree_sitter::{Node, Parser};

/// Index into [`Ast::nodes`].
pub type AstIdx = usize;

#[derive(Debug, Clone)]
pub struct AstNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub parent: Option<AstIdx>,
    /// Position among the parent's named children, from 0.
    pub order: u32,
    pub children: Vec<AstIdx>,
    /// 1-based source line and column.
    pub line: usize,
    pub col: usize,
    /// First line of the source text. Leaves (identifiers, literals) have their full text.
    pub code: String,
    /// For identifiers, methods and field accesses: the name.
    pub name: Option<String>,
    /// For calls: the argument expressions in order (keyword arguments reduced to their values).
    pub args: Vec<AstIdx>,
    /// For calls: the keyword name of each of `args` (`None` for a positional one).
    pub arg_names: Vec<Option<String>>,
    /// For calls: the properties of object / dictionary / struct literals among the arguments, by
    /// name, with the node of the value.
    pub props: Vec<(String, AstIdx)>,
    /// The position of the argument each of `props` belongs to.
    pub prop_args: Vec<usize>,
    /// For method calls: the object the method is called on.
    pub receiver: Option<AstIdx>,
    /// For type declarations: the superclasses, interfaces and traits it names, as written
    /// (without generics).
    pub bases: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Ast {
    /// Parents come before their children; siblings are in source order. `nodes[0]` is the file.
    pub nodes: Vec<AstNode>,
    by_span: HashMap<(u32, u32), Vec<AstIdx>>,
    /// Grammar node kind names by `NodeId::kind`.
    raw_kinds: HashMap<u16, String>,
}

impl Ast {
    pub fn root(&self) -> &AstNode {
        &self.nodes[0]
    }

    /// The node with exactly this byte range and grammar kind (a
    /// [`Stmt`](crate::ir::Stmt)'s or [`Cfg`](crate::ir::Cfg)'s `span` and `node_kind`).
    /// The range alone is not enough: a block can span exactly one statement.
    pub fn find(&self, span: (usize, usize), node_kind: u16) -> Option<AstIdx> {
        self.by_span.get(&(span.0 as u32, span.1 as u32))?.iter().copied().find(|&i| self.nodes[i].id.kind == node_kind)
    }

    /// The grammar's own node kind (`call_expression`, `if_statement`, ...).
    pub fn raw_kind(&self, i: AstIdx) -> &str {
        self.raw_kinds.get(&self.nodes[i].id.kind).map_or("?", String::as_str)
    }

    /// All nodes of `kind`, in source order.
    pub fn of_kind(&self, kind: NodeKind) -> impl Iterator<Item = &AstNode> {
        self.nodes.iter().filter(move |n| n.kind == kind)
    }

    /// `i` and everything below it, parents first.
    pub fn subtree(&self, i: AstIdx) -> Vec<AstIdx> {
        let mut out = vec![];
        let mut stack = vec![i];
        while let Some(n) = stack.pop() {
            out.push(n);
            stack.extend(self.nodes[n].children.iter().rev());
        }
        out
    }
}

/// Parse `src` and build its AST. `file` is the id the nodes carry (the
/// project assigns one per file).
pub fn build<S: Spec>(spec: &S, lang: tree_sitter::Language, file: u32, src: &str) -> Result<Ast> {
    let mut parser = Parser::new();
    parser.set_language(&lang)?;
    let tree = parser.parse(src, None).ok_or_else(|| anyhow!("parse failed"))?;
    crate::lang::common::validate_tree(&tree)?;
    let mut b = Builder { spec, src: src.as_bytes(), file, ast: Ast::default(), seen: HashMap::new() };
    b.add(tree.root_node(), None, 0);
    Ok(b.ast)
}

struct Builder<'a, S: Spec> {
    spec: &'a S,
    src: &'a [u8],
    file: u32,
    ast: Ast,
    /// How many nodes with this (range, kind) were added so far.
    seen: HashMap<(u32, u32, u16), u16>,
}

impl<S: Spec> Builder<'_, S> {
    fn add(&mut self, n: Node, parent: Option<AstIdx>, order: u32) -> AstIdx {
        let (start, end) = (n.start_byte() as u32, n.end_byte() as u32);
        let depth = self.seen.entry((start, end, n.kind_id())).or_insert(0);
        let id = NodeId { file: self.file, start, end, kind: n.kind_id(), depth: *depth };
        *depth += 1;
        self.ast.raw_kinds.entry(n.kind_id()).or_insert_with(|| n.kind().to_string());
        let (kind, name) = match parent {
            None => (NodeKind::File, None),
            Some(p) => match self.classify(n) {
                // `string_start` / `string_content` inside a string are parts of it, not literals.
                (NodeKind::Literal, _) if self.ast.nodes[p].kind == NodeKind::Literal => (NodeKind::Other, None),
                k => k,
            },
        };
        let p = n.start_position();
        let text = String::from_utf8_lossy(&self.src[n.start_byte()..n.end_byte()]);
        let code = text.lines().next().unwrap_or("").trim().to_string();
        let idx = self.ast.nodes.len();
        self.ast.nodes.push(AstNode {
            id,
            kind,
            parent,
            order,
            children: vec![],
            line: p.row + 1,
            col: p.column + 1,
            code,
            name,
            args: vec![],
            arg_names: vec![],
            props: vec![],
            prop_args: vec![],
            receiver: None,
            bases: vec![],
        });
        self.ast.by_span.entry((start, end)).or_default().push(idx);
        let mut c = n.walk();
        let kids: Vec<Node> = n.named_children(&mut c).collect();
        for (i, k) in kids.into_iter().enumerate() {
            let child = self.add(k, Some(idx), i as u32);
            self.ast.nodes[idx].children.push(child);
        }
        if kind == NodeKind::TypeDecl
            && let Some(first) = n.named_child(0)
        {
            // the lowering finds the bases from any node inside the class
            self.ast.nodes[idx].bases =
                self.spec.class_bases(self.src, first).iter().map(|b| crate::lang::common::type_name(b)).filter(|b| !b.is_empty()).collect();
        }
        // `return { algorithms: [x] }`: what the properties of the returned literal hold
        if kind == NodeKind::Return
            && let Some(v) = self.spec.return_value(n)
        {
            let found: Vec<(String, AstIdx)> = crate::lang::common::literal_props(self.spec, self.src, &[v]).into_iter().filter_map(|(k, x)| Some((k, self.ast.find((x.start_byte(), x.end_byte()), x.kind_id())?))).collect();
            self.ast.nodes[idx].prop_args = vec![0; found.len()];
            self.ast.nodes[idx].props = found;
        }
        if kind == NodeKind::Call
            && let Some(cp) = self.spec.call_parts(self.src, n)
        {
            let find = |x: Node| self.ast.find((x.start_byte(), x.end_byte()), x.kind_id());
            let found: Vec<(AstIdx, Option<String>)> = cp.args.iter().enumerate().filter_map(|(i, &a)| Some((find(a)?, cp.names.get(i).cloned().flatten()))).collect();
            let receiver = cp.receiver.and_then(find);
            let indexed: Vec<(usize, String, AstIdx)> = crate::lang::common::indexed_props(self.spec, self.src, &cp.args, true).into_iter().filter_map(|(i, k, v)| Some((i, k, find(v)?))).collect();
            self.ast.nodes[idx].prop_args = indexed.iter().map(|(i, ..)| *i).collect();
            let props = indexed.into_iter().map(|(_, k, v)| (k, v)).collect();
            self.ast.nodes[idx].args = found.iter().map(|(a, _)| *a).collect();
            self.ast.nodes[idx].arg_names = found.into_iter().map(|(_, n)| n).collect();
            self.ast.nodes[idx].props = props;
            self.ast.nodes[idx].receiver = receiver;
        }
        idx
    }

    /// The name bound by `n` if it is a formal parameter: a named child of the
    /// `parameters` of a function, a bare lambda parameter, or one name of a Go
    /// declaration that binds several (`a, b int`).
    fn param_name(&self, n: Node) -> Option<String> {
        let text = |x: Node| String::from_utf8_lossy(&self.src[x.start_byte()..x.end_byte()]).into_owned();
        if self.spec.is_comment(n) {
            return None;
        }
        let parent = n.parent()?;
        // a single bare parameter: JS `x => ..`, Java `x -> ..`
        if self.spec.is_function(parent)
            && self.spec.is_ident(n)
            && (parent.child_by_field_name("parameter") == Some(n) || parent.child_by_field_name("parameters") == Some(n))
        {
            return Some(text(n));
        }
        // Go `a, b int` binds two names: each name is a parameter, the declaration around them is not
        fn names<'t>(d: Node<'t>) -> Vec<Node<'t>> {
            let mut c = d.walk();
            d.children_by_field_name("name", &mut c).collect()
        }
        let go_decl = |d: Node| matches!(d.kind(), "parameter_declaration" | "variadic_parameter_declaration");
        if go_decl(n) && !names(n).is_empty() {
            return None;
        }
        let (list, by_name) = match parent {
            d if go_decl(d) && names(d).contains(&n) => (d.parent()?, true),
            _ => (parent, false),
        };
        let mut owner = list.parent()?;
        if owner.child_by_field_name("parameters") != Some(list) {
            return None;
        }
        // C / C++: the list belongs to the `function_declarator` inside the definition
        while owner.kind().ends_with("_declarator") {
            owner = owner.parent()?;
        }
        if !self.spec.is_function(owner) {
            return None;
        }
        if by_name {
            return Some(text(n));
        }
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            if self.spec.is_ident(x) {
                return Some(text(x));
            }
            let mut c = x.walk();
            stack.extend(x.named_children(&mut c).collect::<Vec<_>>().into_iter().rev());
        }
        // `self` / `this` parameters have no identifier child
        Some(text(n).trim().to_string())
    }

    fn classify(&self, n: Node) -> (NodeKind, Option<String>) {
        let src = self.src;
        if self.spec.is_function(n) {
            return (NodeKind::Method, Some(self.spec.function_name(src, n)));
        }
        if let Some(cp) = self.spec.call_parts(src, n) {
            return (NodeKind::Call, Some(cp.callee));
        }
        if self.spec.assignment(src, n).is_some() {
            return (NodeKind::Assign, None);
        }
        if let Some((_, member)) = self.spec.member_parts(src, n) {
            return (NodeKind::FieldAccess, Some(member));
        }
        if let Some(op) = self.spec.binary_op(src, n) {
            return (NodeKind::BinaryOp, Some(op));
        }
        if let Some(name) = self.spec.type_decl_name(src, n) {
            return (NodeKind::TypeDecl, Some(name));
        }
        if let Some(name) = self.param_name(n) {
            return (NodeKind::Param, Some(name));
        }
        if self.spec.is_ident(n) {
            let t = String::from_utf8_lossy(&src[n.start_byte()..n.end_byte()]).into_owned();
            return (NodeKind::Identifier, Some(t));
        }
        let k = n.kind();
        if k.contains("return") {
            return (NodeKind::Return, None);
        }
        if is_literal(k) {
            return (NodeKind::Literal, None);
        }
        if is_control(k) {
            return (NodeKind::Control, None);
        }
        (NodeKind::Other, None)
    }
}

fn is_literal(k: &str) -> bool {
    const EXACT: &[&str] = &["true", "false", "none", "null", "nil", "undefined", "nullptr", "boolean", "number"];
    EXACT.contains(&k)
        || (!k.contains("expression") && ["string", "integer", "float", "number", "char", "boolean", "literal"].iter().any(|w| k.contains(w)))
}

fn is_control(k: &str) -> bool {
    const WORDS: &[&str] = &[
        "if_", "for_", "while_", "do_", "loop_", "switch", "match_", "try_", "catch", "except", "with_", "select_", "break_", "continue_",
        "throw", "raise", "goto", "defer",
    ];
    k.ends_with("_statement") && WORDS.iter().any(|w| k.contains(w)) || k.ends_with("_expression") && WORDS.iter().any(|w| k.starts_with(w))
}
