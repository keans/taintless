use super::common::{
    AssignParts, CallParts, Case, Clause, Ctl, ExprCtl, Handler, Import, ImportKind, LoopKind, Spec,
    children_by_field, first_child_of_kind, named_children, qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct Python;

fn block_child(n: Node) -> Option<Node> {
    first_child_of_kind(n, "block")
}

impl Spec for Python {
    fn is_function(&self, n: Node) -> bool {
        matches!(n.kind(), "function_definition" | "lambda")
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = match f.kind() {
            // `f = lambda x: ..` is named after the variable
            "lambda" => f
                .parent()
                .filter(|p| p.kind() == "assignment")
                .and_then(|p| p.child_by_field_name("left"))
                .filter(|l| l.kind() == "identifier")
                .map(|n| text(src, n))
                .unwrap_or_else(|| "<lambda>".into()),
            _ => f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into()),
        };
        qualify(src, f, ".", base, &[("class_definition", "name"), ("function_definition", "name")])
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        (f.kind() == "lambda").then(|| f.child_by_field_name("body")).flatten()
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        if n.kind() != "call" {
            return None;
        }
        let func = n.child_by_field_name("function")?;
        let receiver = (func.kind() == "attribute").then(|| func.child_by_field_name("object")).flatten();
        let (mut args, mut names) = (vec![], vec![]);
        for a in n.child_by_field_name("arguments").map(named_children).unwrap_or_default() {
            match a.kind() {
                "keyword_argument" => {
                    if let Some(v) = a.child_by_field_name("value") {
                        args.push(v);
                        names.push(a.child_by_field_name("name").map(|x| text(src, x)));
                    }
                }
                "list_splat" | "dictionary_splat" => {
                    if let Some(x) = a.named_child(0) {
                        args.push(x);
                        names.push(None);
                    }
                }
                "comment" => {}
                _ => {
                    args.push(a);
                    names.push(None);
                }
            }
        }
        Some(CallParts { callee: text(src, func), receiver, args, names })
    }

    fn declarations_of(&self, src: &[u8], n: Node, out: &mut super::common::Declarations) {
        let upper = |s: &str| s.chars().next().is_some_and(char::is_uppercase);
        let at_module = |n: Node| n.parent().and_then(|p| p.parent()).is_some_and(|g| g.kind() == "module");
        match n.kind() {
            // `R = Runner` / `R: TypeAlias = Runner` at module level, capitalised like classes
            "assignment" if at_module(n) => {
                let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) else { return };
                let (l, r) = (text(src, l), text(src, r));
                let r = r.rsplit('.').next().unwrap_or(&r).to_string();
                if upper(&l) && upper(&r) && l != r && l.chars().all(|c| c.is_alphanumeric() || c == '_') && r.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    out.aliases.push((l, r));
                }
            }
            // `type R = Runner`
            "type_alias_statement" => {
                let ts = named_children(n);
                if let [l, r, ..] = ts.as_slice() {
                    out.aliases.push((text(src, *l), text(src, *r)));
                }
            }
            _ => {}
        }
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        let line = n.start_position().row + 1;
        let name_of = |c: Node| match c.kind() {
            "dotted_name" => Some(text(src, c)),
            "aliased_import" => c.child_by_field_name("name").map(|x| text(src, x)),
            _ => None,
        };
        match n.kind() {
            // `import a.b, c as d`
            "import_statement" => named_children(n).into_iter().filter_map(name_of).map(|m| Import::module(m, line)).collect(),
            // `from .pkg import a, b as c` / `from m import *`
            "import_from_statement" => {
                let Some(m) = n.child_by_field_name("module_name") else { return vec![] };
                let mut names: Vec<String> = children_by_field(n, "name").into_iter().filter_map(name_of).collect();
                if named_children(n).iter().any(|c| c.kind() == "wildcard_import") {
                    names.push("*".into());
                }
                vec![Import { module: text(src, m), names, line, kind: ImportKind::Module }]
            }
            // `importlib.import_module("a.b")`, `__import__("a.b")`
            "call" => {
                let callee = n.child_by_field_name("function").map(|f| text(src, f)).unwrap_or_default();
                if !matches!(callee.as_str(), "importlib.import_module" | "import_module" | "__import__") {
                    return vec![];
                }
                let arg = n.child_by_field_name("arguments").and_then(|a| a.named_child(0)).filter(|a| a.kind() == "string");
                match arg.map(|a| text(src, a)) {
                    Some(t) if t.starts_with(['"', '\'']) && !t.contains('{') => vec![Import::module(super::common::unquote(&t), line)],
                    _ => vec![],
                }
            }
            _ => vec![],
        }
    }

    fn receiver(&self, src: &[u8], f: Node) -> Option<String> {
        let first = f.child_by_field_name("parameters")?.named_child(0)?;
        (first.kind() == "identifier" && text(src, first) == "self").then(|| "self".to_string())
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        let Some(ps) = f.child_by_field_name("parameters") else { return vec![] };
        let mut out: Vec<Vec<String>> = vec![];
        for p in named_children(ps) {
            let name = match p.kind() {
                "identifier" => Some(p),
                "default_parameter" | "typed_default_parameter" => p.child_by_field_name("name"),
                "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
                    p.named_child(0).and_then(|c| if c.kind() == "identifier" { Some(c) } else { c.named_child(0) })
                }
                _ => None,
            };
            if let Some(n) = name {
                out.push(vec![text(src, n)]);
            }
        }
        // the receiver is not an argument at call sites
        if out.first().is_some_and(|p| p[0] == "self" || p[0] == "cls") {
            out.remove(0);
        }
        out
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = f.child_by_field_name("parameters") {
            for p in named_children(ps) {
                let name = match p.kind() {
                    "typed_parameter" => p.named_child(0).filter(|c| c.kind() == "identifier"),
                    "typed_default_parameter" => p.child_by_field_name("name"),
                    _ => None,
                };
                if let (Some(n), Some(t)) = (name, p.child_by_field_name("type")) {
                    out.push((text(src, n), text(src, t)));
                }
            }
        }
        (out, f.child_by_field_name("return_type").map(|t| text(src, t)))
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let (mut locals, mut fields) = (vec![], vec![]);
        let annotated = |n: Node, locals: &mut super::common::Scoped, fields: &mut Vec<(String, String)>| {
            if n.kind() != "assignment" {
                return;
            }
            let (Some(l), Some(t)) = (n.child_by_field_name("left"), n.child_by_field_name("type")) else { return };
            match l.kind() {
                "identifier" => locals.push((text(src, l), text(src, t), (n.start_position().row + 1, usize::MAX))),
                // `self.r: Runner = ..`
                "attribute" if l.child_by_field_name("object").is_some_and(|o| text(src, o) == "self") => {
                    if let Some(a) = l.child_by_field_name("attribute") {
                        fields.push((text(src, a), text(src, t)));
                    }
                }
                _ => {}
            }
        };
        if let Some(body) = f.child_by_field_name("body") {
            let stop = |k: Node| k.kind() == "function_definition" || k.kind() == "lambda";
            super::common::collect_nodes(body, &stop, &mut |n| annotated(n, &mut locals, &mut fields));
        }
        // class-level annotations: `r: Runner`
        if let Some(class_body) = super::common::enclosing(f, &["class_definition"]).and_then(|c| c.child_by_field_name("body")) {
            for st in named_children(class_body) {
                let assignment = named_children(st).into_iter().find(|n| n.kind() == "assignment");
                if let Some(a) = assignment
                    && let (Some(l), Some(t)) = (a.child_by_field_name("left"), a.child_by_field_name("type"))
                    && l.kind() == "identifier"
                {
                    fields.push((text(src, l), text(src, t)));
                }
            }
        }
        (locals, fields)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut out = vec![];
        if let Some(sc) = super::common::enclosing(f, &["class_definition"]).and_then(|c| c.child_by_field_name("superclasses")) {
            super::common::base_names(src, sc, &mut out);
        }
        out
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        // assignment makes a name local unless `nonlocal` / `global` says otherwise
        let mut out = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if matches!(n.kind(), "nonlocal_statement" | "global_statement") {
                out.extend(named_children(n).into_iter().filter(|c| c.kind() == "identifier").map(|c| text(src, c)));
            }
        });
        out
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "attribute" {
            return None;
        }
        Some((n.child_by_field_name("object")?, text(src, n.child_by_field_name("attribute")?)))
    }

    fn assignment<'a>(&self, _src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        let (target, value, augmented) = match n.kind() {
            "assignment" => (f("left")?, f("right"), false),
            "augmented_assignment" => (f("left")?, f("right"), true),
            "named_expression" => (f("name")?, f("value"), false),
            "for_statement" | "for_in_clause" => (f("left")?, f("right"), false),
            "as_pattern" => (f("alias")?, n.named_child(0), false),
            _ => return None,
        };
        Some(AssignParts { targets: vec![target], values: value.into_iter().collect(), augmented })
    }

    fn top_level(&self) -> bool {
        true
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        match n.kind() {
            // `then if cond else els`
            "conditional_expression" => Some(ExprCtl::Ternary {
                then: n.named_child(0)?,
                cond: n.named_child(1)?,
                els: n.named_child(2)?,
            }),
            "boolean_operator" => Some(ExprCtl::Short {
                lhs: n.child_by_field_name("left")?,
                rhs: n.child_by_field_name("right")?,
                and: text(src, n.child_by_field_name("operator")?) == "and",
            }),
            "list_comprehension" | "set_comprehension" | "dictionary_comprehension" | "generator_expression" => {
                let body = n.child_by_field_name("body")?;
                let clauses = named_children(n)
                    .into_iter()
                    .filter_map(|c| match c.kind() {
                        "for_in_clause" => Some(Clause::For(c)),
                        "if_clause" => c.named_child(0).map(Clause::If),
                        _ => None,
                    })
                    .collect();
                Some(ExprCtl::Comprehension { clauses, elements: vec![body] })
            }
            _ => None,
        }
    }

    fn loop_else<'a>(&self, n: Node<'a>) -> Option<Node<'a>> {
        n.child_by_field_name("alternative").and_then(block_child)
    }

    fn try_else<'a>(&self, n: Node<'a>) -> Option<Node<'a>> {
        first_child_of_kind(n, "else_clause").and_then(block_child)
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "module" | "block" => Ctl::Block(named_children(n)),
            "if_statement" => Ctl::If {
                pre: vec![],
                cond: f("condition"),
                then: f("consequence"),
                els: f("alternative"),
            },
            // The remaining `elif`/`else` clauses chain through next siblings.
            "elif_clause" => Ctl::If {
                pre: vec![],
                cond: f("condition"),
                then: f("consequence"),
                els: n.next_named_sibling().filter(|s| matches!(s.kind(), "elif_clause" | "else_clause")),
            },
            "else_clause" => Ctl::Block(f("body").into_iter().collect()),
            "while_statement" => Ctl::simple_loop(LoopKind::Cond, f("condition"), f("body")),
            "for_statement" => Ctl::simple_loop(LoopKind::Each, None, f("body")),
            "try_statement" => Ctl::Try {
                pre: vec![],
                closes: vec![],
                body: f("body"),
                handlers: named_children(n)
                    .into_iter()
                    .filter(|c| matches!(c.kind(), "except_clause" | "except_group_clause"))
                    .map(|c| Handler { head: c, body: block_child(c) })
                    .collect(),
                finally: first_child_of_kind(n, "finally_clause").and_then(block_child),
            },
            "match_statement" => {
                let cases = f("body")
                    .map(named_children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|c| c.kind() == "case_clause")
                    .map(|c| {
                        let guard = c.child_by_field_name("guard").and_then(|g| g.named_child(0));
                        let patterns: Vec<_> =
                            named_children(c).into_iter().filter(|p| p.kind() == "case_pattern").collect();
                        let wildcard = guard.is_none()
                            && patterns.len() == 1
                            && text(src, patterns[0]).trim() == "_";
                        Case {
                            labels: if wildcard { vec![] } else { patterns },
                            guard,
                            body: block_child(c).into_iter().collect(),
                        }
                    })
                    .collect();
                Ctl::Switch { cases, breakable: false, fallthrough: false, exhaustive: false }
            }
            "with_statement" => Ctl::Header(StmtKind::Other, f("body").into_iter().collect()),
            "return_statement" => Ctl::Return,
            "raise_statement" => Ctl::Throw,
            "break_statement" => Ctl::Break(None),
            "continue_statement" => Ctl::Continue(None),
            "expression_statement" => Ctl::Simple(match n.named_child(0).map(|c| c.kind()) {
                Some("assignment" | "augmented_assignment") => StmtKind::Assign,
                Some("call" | "await") => StmtKind::Call,
                _ => StmtKind::Other,
            }),
            "class_definition" | "decorated_definition" => Ctl::Skip,
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
