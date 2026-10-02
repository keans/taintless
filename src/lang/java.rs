use super::common::{
    AssignParts, CallParts, Case, Ctl, ExprCtl, Handler, Import, LoopKind, Spec, bound_names,
    children_by_field, children_excluding, first_child_of_kind, named_children, qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct Java;

impl Spec for Java {
    fn is_subscript(&self, n: Node) -> bool {
        n.kind() == "array_access"
    }

    fn expr_kind(&self, n: Node) -> StmtKind {
        match n.kind() {
            "method_invocation" | "object_creation_expression" => StmtKind::Call,
            "assignment_expression" => StmtKind::Assign,
            _ => StmtKind::Other,
        }
    }

    fn is_function(&self, n: Node) -> bool {
        matches!(
            n.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "compact_constructor_declaration"
                | "lambda_expression"
        )
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = match f.kind() {
            // `Runnable r = () -> ...` is named after the variable.
            "lambda_expression" => f
                .parent()
                .filter(|p| p.kind() == "variable_declarator")
                .and_then(|p| p.child_by_field_name("name"))
                .map(|n| text(src, n))
                .unwrap_or_else(|| "<lambda>".into()),
            _ => f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into()),
        };
        let parents = [
            ("class_declaration", "name"),
            ("interface_declaration", "name"),
            ("enum_declaration", "name"),
            ("record_declaration", "name"),
            ("method_declaration", "name"),
            ("constructor_declaration", "name"),
        ];
        qualify(src, f, ".", base, &parents)
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        if n.kind() != "import_declaration" {
            return vec![];
        }
        let line = n.start_position().row + 1;
        let kids = named_children(n);
        let Some(path) = kids.iter().find(|c| matches!(c.kind(), "scoped_identifier" | "identifier")) else {
            return vec![];
        };
        let wildcard = kids.iter().any(|c| c.kind() == "asterisk");
        let m = text(src, *path);
        vec![Import::module(if wildcard { format!("{m}.*") } else { m }, line)]
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "identifier" | "this")
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        let args = |n: Node<'a>| -> Vec<Node<'a>> {
            n.child_by_field_name("arguments")
                .map(named_children)
                .unwrap_or_default()
                .into_iter()
                .filter(|a| !a.kind().contains("comment"))
                .collect()
        };
        match n.kind() {
            "method_invocation" => {
                let name = text(src, n.child_by_field_name("name")?);
                let receiver = n.child_by_field_name("object");
                let callee = match receiver {
                    Some(o) => format!("{}.{name}", text(src, o)),
                    None => name,
                };
                Some(CallParts { callee, receiver, args: args(n), names: vec![] })
            }
            "object_creation_expression" => Some(CallParts {
                callee: text(src, n.child_by_field_name("type")?),
                receiver: None,
                args: args(n),
                names: vec![],
            }),
            _ => None,
        }
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        let Some(ps) = f.child_by_field_name("parameters") else { return vec![] };
        // lambdas: `x -> ..` (identifier), `(a, b) -> ..` (inferred_parameters / formal_parameters)
        if ps.kind() == "identifier" {
            return vec![vec![text(src, ps)]];
        }
        named_children(ps)
            .into_iter()
            .filter(|p| matches!(p.kind(), "formal_parameter" | "spread_parameter" | "identifier"))
            .map(|p| match p.kind() {
                "identifier" => vec![text(src, p)],
                "formal_parameter" => p.child_by_field_name("name").map(|n| vec![text(src, n)]).unwrap_or_default(),
                _ => bound_names(self, src, p),
            })
            .collect()
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        if f.kind() != "lambda_expression" { return vec![]; }
        let mut declared: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let mut written = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if n.kind() == "variable_declarator" {
                if let Some(name) = n.child_by_field_name("name") { declared.insert(text(src, name)); }
            } else if n.kind() == "assignment_expression"
                && let Some(l) = n.child_by_field_name("left").filter(|l| matches!(l.kind(), "array_access" | "field_access")) {
                    let path = text(src, l).split('[').next().unwrap_or("").to_string();
                    written.push(path);
            }
        });
        written.into_iter().filter(|p| !declared.contains(p.split('.').next().unwrap_or(p))).collect()
    }

    fn receiver(&self, src: &[u8], f: Node) -> Option<String> {
        if f.kind() == "lambda_expression" {
            return None;
        }
        // static methods have no object
        let is_static = named_children(f)
            .into_iter()
            .find(|c| c.kind() == "modifiers")
            .is_some_and(|m| text(src, m).split_whitespace().any(|w| w == "static"));
        (!is_static).then(|| "this".to_string())
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = f.child_by_field_name("parameters").filter(|p| p.kind() == "formal_parameters") {
            for p in named_children(ps).into_iter().filter(|p| p.kind() == "formal_parameter") {
                if let (Some(n), Some(t)) = (p.child_by_field_name("name"), p.child_by_field_name("type")) {
                    out.push((text(src, n), text(src, t)));
                }
            }
        }
        let ret = (f.kind() == "method_declaration").then(|| f.child_by_field_name("type")).flatten().map(|t| text(src, t));
        (out, ret)
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let decl = |n: Node, out: &mut Vec<(String, String)>| {
            let Some(t) = n.child_by_field_name("type").map(|t| text(src, t)).filter(|t| t != "var") else { return };
            for d in named_children(n).into_iter().filter(|d| d.kind() == "variable_declarator") {
                if let Some(name) = d.child_by_field_name("name") {
                    out.push((text(src, name), t.clone()));
                }
            }
        };
        let (mut locals, mut fields) = (vec![], vec![]);
        if let Some(body) = f.child_by_field_name("body") {
            let stop = |k: Node| matches!(k.kind(), "lambda_expression" | "method_declaration" | "class_declaration");
            super::common::collect_nodes(body, &stop, &mut |n| {
                if n.kind() == "local_variable_declaration" {
                    let mut one = vec![];
                    decl(n, &mut one);
                    locals.extend(super::common::scoped(one, n));
                }
            });
        }
        let class = super::common::enclosing(f, &["class_declaration", "interface_declaration", "enum_declaration", "record_declaration"]);
        if let Some(cb) = class.and_then(|c| c.child_by_field_name("body")) {
            for m in named_children(cb).into_iter().filter(|m| m.kind() == "field_declaration") {
                decl(m, &mut fields);
            }
        }
        (locals, fields)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut out = vec![];
        let Some(c) = super::common::enclosing(f, &["class_declaration", "interface_declaration", "enum_declaration", "record_declaration"])
        else {
            return out;
        };
        for k in named_children(c) {
            if matches!(k.kind(), "superclass" | "super_interfaces" | "extends_interfaces") {
                super::common::base_names(src, k, &mut out);
            }
        }
        out
    }

    fn implicit_fields(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut fields = vec![];
        let mut p = f.parent();
        while let Some(n) = p {
            if matches!(n.kind(), "class_declaration" | "enum_declaration" | "record_declaration") {
                if let Some(body) = n.child_by_field_name("body") {
                    for m in named_children(body).into_iter().filter(|m| m.kind() == "field_declaration") {
                        let mut c = m.walk();
                        for d in m.children_by_field_name("declarator", &mut c) {
                            if let Some(name) = d.child_by_field_name("name") {
                                fields.push(text(src, name));
                            }
                        }
                    }
                }
                break;
            }
            p = n.parent();
        }
        // locals, parameters, catch / for variables shadow fields
        let mut locals = std::collections::HashSet::new();
        for p in self.params(src, f).into_iter().flatten() {
            locals.insert(p);
        }
        let mut stack = vec![f];
        while let Some(n) = stack.pop() {
            if matches!(n.kind(), "variable_declarator" | "catch_formal_parameter" | "enhanced_for_statement" | "formal_parameter" | "resource")
                && let Some(name) = n.child_by_field_name("name")
            {
                locals.insert(text(src, name));
            }
            stack.extend(named_children(n));
        }
        fields.retain(|n| !locals.contains(n));
        fields
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        (f.kind() == "lambda_expression")
            .then(|| f.child_by_field_name("body"))
            .flatten()
            .filter(|b| b.kind() != "block")
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "field_access" {
            return None;
        }
        Some((n.child_by_field_name("object")?, text(src, n.child_by_field_name("field")?)))
    }

    fn assignment<'a>(&self, src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        let (target, value, augmented) = match n.kind() {
            "variable_declarator" => (f("name")?, f("value"), false),
            "assignment_expression" => {
                let op = f("operator").map(|o| text(src, o)).unwrap_or_default();
                (f("left")?, f("right"), op != "=")
            }
            "enhanced_for_statement" => (f("name")?, f("value"), false),
            _ => return None,
        };
        Some(AssignParts { targets: vec![target], values: value.into_iter().collect(), augmented })
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            // `return switch (k) { ... };`
            "switch_expression" => Some(ExprCtl::Stmt),
            "ternary_expression" => Some(ExprCtl::Ternary {
                cond: f("condition")?,
                then: f("consequence")?,
                els: f("alternative")?,
            }),
            "binary_expression" => {
                let and = match text(src, f("operator")?).as_str() {
                    "&&" => true,
                    "||" => false,
                    _ => return None,
                };
                Some(ExprCtl::Short { lhs: f("left")?, rhs: f("right")?, and })
            }
            _ => None,
        }
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "block" | "constructor_body" => Ctl::Block(named_children(n)),
            "synchronized_statement" => {
                Ctl::Header(StmtKind::Other, first_child_of_kind(n, "block").into_iter().collect())
            }
            "resource" => Ctl::Simple(StmtKind::Assign),
            "if_statement" => Ctl::If {
                pre: vec![],
                cond: f("condition"),
                then: f("consequence"),
                els: f("alternative"),
            },
            "for_statement" => {
                let cond = f("condition");
                Ctl::Loop {
                    label: None,
                    pre: children_by_field(n, "init"),
                    kind: if cond.is_some() { LoopKind::Cond } else { LoopKind::Infinite },
                    cond,
                    body: f("body"),
                    update: children_by_field(n, "update"),
                }
            }
            "enhanced_for_statement" => Ctl::Loop {
                label: None, pre: vec![], kind: LoopKind::Each,
                cond: None, body: f("body"), update: vec![],
            },
            "while_statement" => Ctl::Loop {
                label: None, pre: vec![], kind: LoopKind::Cond,
                cond: f("condition"), body: f("body"), update: vec![],
            },
            "do_statement" => Ctl::DoWhile { body: f("body"), cond: f("condition") },
            "switch_expression" | "switch_statement" => {
                let groups = f("body").map(named_children).unwrap_or_default();
                let arrow = groups.iter().any(|g| g.kind() == "switch_rule");
                let cases = groups
                    .into_iter()
                    .filter(|g| matches!(g.kind(), "switch_block_statement_group" | "switch_rule"))
                    .map(|g| {
                        let label = first_child_of_kind(g, "switch_label");
                        let is_default = label.is_some_and(|l| text(src, l).trim_start().starts_with("default"));
                        Case {
                            labels: label
                                .filter(|_| !is_default)
                                .map(named_children)
                                .unwrap_or_default(),
                            guard: None,
                            body: children_excluding(g, &[]).into_iter()
                                .filter(|c| c.kind() != "switch_label")
                                .collect(),
                        }
                    })
                    .collect();
                Ctl::Switch { cases, breakable: true, fallthrough: !arrow, exhaustive: false }
            }
            "try_statement" | "try_with_resources_statement" => Ctl::Try {
                pre: f("resources").map(named_children).unwrap_or_default(),
                closes: f("resources").map(named_children).unwrap_or_default(),
                body: f("body"),
                handlers: named_children(n)
                    .into_iter()
                    .filter(|c| c.kind() == "catch_clause")
                    .map(|c| Handler { head: c, body: c.child_by_field_name("body") })
                    .collect(),
                finally: first_child_of_kind(n, "finally_clause").and_then(|c| first_child_of_kind(c, "block")),
            },
            "return_statement" => Ctl::Return,
            "throw_statement" => Ctl::Throw,
            "break_statement" => Ctl::Break(first_child_of_kind(n, "identifier").map(|l| text(src, l))),
            "continue_statement" => Ctl::Continue(first_child_of_kind(n, "identifier").map(|l| text(src, l))),
            "labeled_statement" => match n.named_child(0) {
                Some(l) => Ctl::Labeled { label: text(src, l), stmt: n.named_child(1) },
                None => Ctl::Skip,
            },
            "expression_statement" => Ctl::Simple(match n.named_child(0).map(|c| c.kind()) {
                Some("method_invocation" | "object_creation_expression") => StmtKind::Call,
                Some("assignment_expression") => StmtKind::Assign,
                _ => StmtKind::Other,
            }),
            "local_variable_declaration" => Ctl::Simple(StmtKind::Assign),
            "class_declaration" | "interface_declaration" | "enum_declaration"
            | "record_declaration" => Ctl::Skip,
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
