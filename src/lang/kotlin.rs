use super::common::{operator_token, kids_without_comments as kids, 
    AssignParts, CallParts, Case, Ctl, ExprCtl, Handler, Import, LoopKind, Spec, enclosing, first_child_of_kind,
    named_children, qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct Kotlin;

const TYPES: &[&str] = &["class_declaration", "object_declaration"];

fn is_type(k: &str) -> bool {
    k.ends_with("_type") || k == "type_reference"
}

/// The statements of a lambda: everything after its parameters.
fn lambda_statements<'a>(f: Node<'a>) -> Vec<Node<'a>> {
    kids(f).into_iter().filter(|c| c.kind() != "lambda_parameters").collect()
}

fn function_value_body<'a>(f: Node<'a>) -> Option<Node<'a>> {
    first_child_of_kind(f, "function_body").and_then(|b| kids(b).into_iter().next())
}

/// The class or object a function is a member of (none for top-level and local functions).
fn owner<'a>(f: Node<'a>) -> Option<Node<'a>> {
    let mut p = f.parent();
    // a getter / setter sits in a property declaration
    while let Some(n) = p {
        match n.kind() {
            "property_declaration" | "companion_object" => p = n.parent(),
            "class_body" => return n.parent().filter(|o| TYPES.contains(&o.kind())).or_else(|| n.parent().and_then(|c| enclosing(c, TYPES))),
            _ => return None,
        }
    }
    None
}

fn declared_name(src: &[u8], decl: Node) -> Option<String> {
    first_child_of_kind(decl, "identifier").map(|n| text(src, n))
}

impl Kotlin {
    fn field_names(src: &[u8], class: Node) -> Vec<String> {
        let mut out = vec![];
        for k in kids(class) {
            match k.kind() {
                "primary_constructor" => {
                    for p in kids(k).into_iter().flat_map(kids).filter(|p| p.kind() == "class_parameter") {
                        if text(src, p).split_whitespace().any(|w| w == "val" || w == "var")
                            && let Some(n) = declared_name(src, p)
                        {
                            out.push(n);
                        }
                    }
                }
                "class_body" => {
                    for m in kids(k).into_iter().filter(|m| m.kind() == "property_declaration") {
                        out.extend(first_child_of_kind(m, "variable_declaration").and_then(|d| declared_name(src, d)));
                    }
                }
                _ => {}
            }
        }
        out
    }
}

impl Spec for Kotlin {
    fn is_subscript(&self, n: Node) -> bool {
        n.kind() == "index_expression"
    }

    fn expr_kind(&self, n: Node) -> StmtKind {
        match n.kind() {
            "call_expression" => StmtKind::Call,
            "assignment" => StmtKind::Assign,
            _ => StmtKind::Other,
        }
    }

    fn is_function(&self, n: Node) -> bool {
        matches!(
            n.kind(),
            "function_declaration" | "secondary_constructor" | "anonymous_function" | "lambda_literal" | "getter" | "setter" | "anonymous_initializer"
        )
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = match f.kind() {
            // `val g = { x: Int -> .. }` is named after the variable
            "lambda_literal" | "anonymous_function" => f
                .parent()
                .filter(|p| p.kind() == "property_declaration")
                .and_then(|p| first_child_of_kind(p, "variable_declaration"))
                .and_then(|d| declared_name(src, d))
                .unwrap_or_else(|| "<lambda>".into()),
            "getter" | "setter" => {
                let prop = f.parent().and_then(|p| first_child_of_kind(p, "variable_declaration")).and_then(|d| declared_name(src, d)).unwrap_or_else(|| "<property>".into());
                format!("{prop}.{}", if f.kind() == "getter" { "get" } else { "set" })
            }
            "secondary_constructor" => owner(f).and_then(|c| c.child_by_field_name("name")).map(|n| text(src, n)).unwrap_or_else(|| "<init>".into()),
            "anonymous_initializer" => "<init>".into(),
            _ => f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into()),
        };
        let parents = [("class_declaration", "name"), ("object_declaration", "name"), ("function_declaration", "name")];
        qualify(src, f, ".", base, &parents)
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        match f.kind() {
            "lambda_literal" => Some(f),
            "secondary_constructor" | "anonymous_initializer" => first_child_of_kind(f, "block"),
            _ => function_value_body(f),
        }
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        match f.kind() {
            "lambda_literal" => lambda_statements(f).into_iter().next_back().filter(|l| !matches!(l.kind(), "property_declaration" | "for_statement" | "while_statement" | "do_while_statement" | "assignment")),
            "function_declaration" | "getter" | "anonymous_function" => function_value_body(f).filter(|b| b.kind() != "block"),
            _ => None,
        }
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        if n.kind() != "import" {
            return vec![];
        }
        let line = n.start_position().row + 1;
        let Some(path) = first_child_of_kind(n, "qualified_identifier").or_else(|| first_child_of_kind(n, "identifier")) else { return vec![] };
        let wildcard = text(src, n).trim_end().ends_with('*');
        let m = text(src, path);
        vec![Import::module(if wildcard { format!("{m}.*") } else { m }, line)]
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "identifier" | "this_expression")
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        if n.kind() != "call_expression" {
            return None;
        }
        let parts = kids(n);
        let function = *parts.first()?;
        let receiver = (function.kind() == "navigation_expression").then(|| kids(function).into_iter().next()).flatten();
        let (mut args, mut names) = (vec![], vec![]);
        for p in &parts[1..] {
            match p.kind() {
                "value_arguments" => {
                    for a in kids(*p).into_iter().filter(|a| a.kind() == "value_argument") {
                        let inner = kids(a);
                        // `name = value`
                        let named = inner.len() >= 2 && inner[0].kind() == "identifier";
                        names.push(named.then(|| text(src, inner[0])));
                        if let Some(v) = inner.last() {
                            args.push(*v);
                        }
                    }
                }
                // a trailing lambda: `xs.forEach { .. }`
                "annotated_lambda" => {
                    if let Some(l) = kids(*p).into_iter().find(|l| l.kind() == "lambda_literal") {
                        names.push(None);
                        args.push(l);
                    }
                }
                _ => {}
            }
        }
        if names.iter().all(Option::is_none) {
            names.clear();
        }
        Some(CallParts { callee: text(src, function), receiver, args, names })
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        match f.kind() {
            "lambda_literal" => match first_child_of_kind(f, "lambda_parameters") {
                Some(ps) => kids(ps)
                    .into_iter()
                    .map(|d| match d.kind() {
                        "multi_variable_declaration" => kids(d).into_iter().filter_map(|v| declared_name(src, v)).collect(),
                        _ => declared_name(src, d).into_iter().collect(),
                    })
                    .collect(),
                // `xs.map { it.length }`
                None => vec![vec!["it".to_string()]],
            },
            "setter" => declared_name(src, f).map(|n| vec![vec![n]]).unwrap_or_default(),
            _ => first_child_of_kind(f, "function_value_parameters")
                .map(|ps| kids(ps).into_iter().filter(|p| p.kind() == "parameter").filter_map(|p| declared_name(src, p)).map(|n| vec![n]).collect())
                .unwrap_or_default(),
        }
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        if !matches!(f.kind(), "lambda_literal" | "anonymous_function") {
            return vec![];
        }
        let mut declared: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let mut written = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if n.kind() == "variable_declaration" {
                declared.extend(declared_name(src, n));
            } else if n.kind() == "assignment"
                && let Some(l) = n.child_by_field_name("left").filter(|l| matches!(l.kind(), "index_expression" | "navigation_expression"))
            {
                written.push(text(src, l).split('[').next().unwrap_or("").to_string());
            }
        });
        written.into_iter().filter(|p| !declared.contains(p.split('.').next().unwrap_or(p))).collect()
    }

    fn receiver(&self, _src: &[u8], f: Node) -> Option<String> {
        if matches!(f.kind(), "lambda_literal" | "anonymous_function") {
            return None;
        }
        owner(f).map(|_| "this".to_string())
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = first_child_of_kind(f, "function_value_parameters") {
            for p in kids(ps).into_iter().filter(|p| p.kind() == "parameter") {
                let k = kids(p);
                if let (Some(n), Some(t)) = (k.first().filter(|n| n.kind() == "identifier"), k.iter().find(|t| is_type(t.kind()))) {
                    out.push((text(src, *n), text(src, *t)));
                }
            }
        }
        let ret = (f.kind() == "function_declaration").then(|| kids(f).into_iter().find(|t| is_type(t.kind()))).flatten().map(|t| text(src, t));
        (out, ret)
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let typed = |d: Node| -> Option<(String, String)> {
            let k = kids(d);
            Some((text(src, *k.first().filter(|n| n.kind() == "identifier")?), text(src, *k.iter().find(|t| is_type(t.kind()))?)))
        };
        let (mut locals, mut fields) = (vec![], vec![]);
        if let Some(body) = self.function_body(f) {
            let stop = |k: Node| self.is_function(k) || TYPES.contains(&k.kind());
            super::common::collect_nodes(body, &stop, &mut |n| {
                if n.kind() == "property_declaration"
                    && let Some(one) = first_child_of_kind(n, "variable_declaration").and_then(typed)
                {
                    locals.extend(super::common::scoped(vec![one], n));
                }
            });
        }
        if let Some(c) = owner(f) {
            for k in kids(c) {
                match k.kind() {
                    "primary_constructor" => {
                        for p in kids(k).into_iter().flat_map(kids).filter(|p| p.kind() == "class_parameter") {
                            fields.extend(typed(p));
                        }
                    }
                    "class_body" => {
                        for m in kids(k).into_iter().filter(|m| m.kind() == "property_declaration") {
                            fields.extend(first_child_of_kind(m, "variable_declaration").and_then(typed));
                        }
                    }
                    _ => {}
                }
            }
        }
        (locals, fields)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut out = vec![];
        let Some(c) = owner(f) else { return out };
        for specs in kids(c).into_iter().filter(|k| k.kind() == "delegation_specifiers") {
            for d in kids(specs) {
                // `Base()` is a constructor invocation of the superclass, `IFoo` a bare type
                let t = first_child_of_kind(d, "user_type").or_else(|| first_child_of_kind(d, "constructor_invocation").and_then(|c| first_child_of_kind(c, "user_type")));
                if let Some(name) = t.and_then(|t| first_child_of_kind(t, "identifier")) {
                    out.push(text(src, name));
                }
            }
        }
        out
    }

    fn type_decl_name(&self, src: &[u8], n: Node) -> Option<String> {
        TYPES.contains(&n.kind()).then(|| n.child_by_field_name("name").map(|x| text(src, x))).flatten()
    }

    fn implicit_fields(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut fields = owner(f).map(|c| Self::field_names(src, c)).unwrap_or_default();
        // locals, parameters, catch and loop variables shadow fields
        let mut locals: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let mut stack = vec![f];
        while let Some(n) = stack.pop() {
            if n.kind() == "variable_declaration" {
                locals.extend(declared_name(src, n));
            }
            stack.extend(named_children(n));
        }
        fields.retain(|n| !locals.contains(n));
        fields
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "navigation_expression" {
            return None;
        }
        let k = kids(n);
        Some((*k.first()?, text(src, *k.last().filter(|_| k.len() >= 2)?)))
    }

    fn binary_op(&self, src: &[u8], n: Node) -> Option<String> {
        (n.kind() == "binary_expression").then(|| operator_token(src, n, false)).flatten()
    }

    fn assignment<'a>(&self, src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        match n.kind() {
            "assignment" => {
                let op = operator_token(src, n, false).unwrap_or_default();
                Some(AssignParts { targets: vec![n.child_by_field_name("left")?], values: n.child_by_field_name("right").into_iter().collect(), augmented: op != "=" })
            }
            // `val x: T = value`, `val (a, b) = pair`
            "property_declaration" => {
                let k = kids(n);
                let decl = k.iter().position(|c| matches!(c.kind(), "variable_declaration" | "multi_variable_declaration"))?;
                let target = k[decl];
                let targets: Vec<Node<'a>> = if target.kind() == "multi_variable_declaration" { kids(target) } else { vec![target] };
                let targets = targets.into_iter().filter_map(|t| first_child_of_kind(t, "identifier")).collect();
                let value = k[decl + 1..].iter().find(|c| !matches!(c.kind(), "getter" | "setter" | "property_delegate" | "type_constraints" | "modifiers")).copied();
                Some(AssignParts { targets, values: value.into_iter().collect(), augmented: false })
            }
            // `for (x in xs)`
            "for_statement" => {
                let k = kids(n);
                let decl = k.iter().position(|c| c.kind() == "variable_declaration")?;
                Some(AssignParts { targets: first_child_of_kind(k[decl], "identifier").into_iter().collect(), values: k.get(decl + 1).copied().into_iter().collect(), augmented: false })
            }
            _ => None,
        }
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        match n.kind() {
            // `val r = if (c) a else b`
            "if_expression" => {
                let k = kids(n);
                let cond = n.child_by_field_name("condition").or_else(|| k.first().copied())?;
                let rest: Vec<Node<'a>> = k.into_iter().filter(|c| c.id() != cond.id()).collect();
                match rest.as_slice() {
                    [then, els] => Some(ExprCtl::Ternary { cond, then: *then, els: *els }),
                    _ => Some(ExprCtl::Stmt),
                }
            }
            "when_expression" | "try_expression" => Some(ExprCtl::Stmt),
            "binary_expression" => {
                let and = match operator_token(src, n, false)?.as_str() {
                    "&&" => true,
                    "||" | "?:" => false,
                    _ => return None,
                };
                Some(ExprCtl::Short { lhs: n.child_by_field_name("left")?, rhs: n.child_by_field_name("right")?, and })
            }
            _ => None,
        }
    }

    fn top_level(&self) -> bool {
        true
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        match n.kind() {
            "source_file" | "block" | "statements" => Ctl::Block(kids(n)),
            "lambda_literal" => Ctl::Block(lambda_statements(n)),
            "package_header" | "import" | "import_list" | "class_declaration" | "object_declaration" | "companion_object" | "type_alias" | "function_declaration" | "secondary_constructor"
            | "anonymous_initializer" | "file_annotation" => Ctl::Skip,
            "if_expression" => {
                let k = kids(n);
                let cond = n.child_by_field_name("condition").or_else(|| k.first().copied());
                let rest: Vec<Node<'a>> = k.into_iter().filter(|c| Some(c.id()) != cond.map(|x| x.id())).collect();
                Ctl::If { pre: vec![], cond, then: rest.first().copied(), els: rest.get(1).copied() }
            }
            "for_statement" => {
                let k = kids(n);
                let body = k.last().copied().filter(|b| matches!(b.kind(), "block") || k.len() > 2);
                Ctl::Loop { label: None, pre: vec![], kind: LoopKind::Each, cond: None, body, update: vec![] }
            }
            "while_statement" => Ctl::Loop { label: None, pre: vec![], kind: LoopKind::Cond, cond: n.child_by_field_name("condition"), body: kids(n).into_iter().rfind(|c| c.kind() == "block"), update: vec![] },
            "do_while_statement" => Ctl::DoWhile { body: first_child_of_kind(n, "block"), cond: n.child_by_field_name("condition") },
            "when_expression" => {
                let subject = first_child_of_kind(n, "when_subject");
                let mut has_else = false;
                let cases = kids(n)
                    .into_iter()
                    .filter(|e| e.kind() == "when_entry")
                    .map(|e| {
                        let conditions: Vec<Node<'a>> = (0..e.child_count()).filter(|i| e.field_name_for_child(*i) == Some("condition")).filter_map(|i| e.child(i)).collect();
                        has_else |= conditions.is_empty();
                        let body = kids(e).into_iter().filter(|c| !conditions.iter().any(|x| x.id() == c.id())).collect();
                        Case { labels: conditions, guard: None, body }
                    })
                    .collect();
                let _ = subject;
                Ctl::Switch { cases, breakable: false, fallthrough: false, exhaustive: has_else }
            }
            "try_expression" => Ctl::Try {
                pre: vec![],
                closes: vec![],
                body: first_child_of_kind(n, "block"),
                handlers: kids(n).into_iter().filter(|c| c.kind() == "catch_block").map(|c| Handler { head: c, body: first_child_of_kind(c, "block") }).collect(),
                finally: first_child_of_kind(n, "finally_block").and_then(|c| first_child_of_kind(c, "block")),
            },
            "return_expression" => Ctl::Return,
            "throw_expression" => Ctl::Throw,
            // `break` and `continue` are parsed as identifiers; with a label (`break@outer`) a labeled expression
            "identifier" if text(src, n) == "break" => Ctl::Break(None),
            "identifier" if text(src, n) == "continue" => Ctl::Continue(None),
            "labeled_expression" => {
                let label = first_child_of_kind(n, "label").map(|l| text(src, l));
                match (label.as_deref(), n.named_child(1)) {
                    (Some("break@"), Some(l)) => Ctl::Break(Some(text(src, l))),
                    (Some("continue@"), Some(l)) => Ctl::Continue(Some(text(src, l))),
                    _ => Ctl::Simple(StmtKind::Other),
                }
            }
            "call_expression" => Ctl::Simple(StmtKind::Call),
            "assignment" | "property_declaration" => Ctl::Simple(StmtKind::Assign),
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
