use super::common::{
    AssignParts, CallParts, Case, Ctl, ExprCtl, Handler, Import, LoopKind, Spec, children_by_field, enclosing,
    first_child_of_kind, named_children, qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct CSharp;

const TYPES: &[&str] = &["class_declaration", "struct_declaration", "interface_declaration", "record_declaration", "record_struct_declaration", "enum_declaration"];

fn is_statement(k: &str) -> bool {
    k.ends_with("_statement") || k == "block"
}

/// The expression inside an `argument` (past a `name:` label and `ref` / `out` / `in`).
fn argument_value<'a>(arg: Node<'a>) -> Option<Node<'a>> {
    named_children(arg).into_iter().rfind(|c| c.kind() != "name_colon" && !c.kind().contains("comment"))
}

fn arguments<'a>(src: &[u8], n: Node<'a>) -> (Vec<Node<'a>>, Vec<Option<String>>) {
    let (mut args, mut names) = (vec![], vec![]);
    let Some(list) = n.child_by_field_name("arguments") else { return (args, names) };
    for a in named_children(list).into_iter().filter(|a| a.kind() == "argument") {
        let Some(v) = argument_value(a) else { continue };
        names.push(first_child_of_kind(a, "name_colon").and_then(|c| c.named_child(0)).map(|c| text(src, c)));
        args.push(v);
    }
    if names.iter().all(Option::is_none) {
        names.clear();
    }
    (args, names)
}

impl CSharp {
    fn is_static(src: &[u8], f: Node) -> bool {
        named_children(f).into_iter().any(|c| c.kind() == "modifier" && text(src, c) == "static")
    }

    fn field_names(src: &[u8], class: Node) -> Vec<String> {
        let mut out = vec![];
        let Some(body) = class.child_by_field_name("body") else { return out };
        for m in named_children(body) {
            match m.kind() {
                "field_declaration" => {
                    for d in named_children(m).into_iter().flat_map(named_children).filter(|d| d.kind() == "variable_declarator") {
                        out.extend(d.child_by_field_name("name").map(|n| text(src, n)));
                    }
                }
                "property_declaration" => out.extend(m.child_by_field_name("name").map(|n| text(src, n))),
                _ => {}
            }
        }
        out
    }
}

impl Spec for CSharp {
    fn is_subscript(&self, n: Node) -> bool {
        n.kind() == "element_access_expression"
    }

    fn expr_kind(&self, n: Node) -> StmtKind {
        match n.kind() {
            "invocation_expression" | "object_creation_expression" => StmtKind::Call,
            "assignment_expression" => StmtKind::Assign,
            _ => StmtKind::Other,
        }
    }

    fn is_function(&self, n: Node) -> bool {
        matches!(
            n.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "destructor_declaration"
                | "operator_declaration"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
                | "accessor_declaration"
        )
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = match f.kind() {
            // `Func<int> g = () => ..` is named after the variable
            "lambda_expression" | "anonymous_method_expression" => f
                .parent()
                .filter(|p| p.kind() == "variable_declarator")
                .and_then(|p| p.child_by_field_name("name"))
                .map(|n| text(src, n))
                .unwrap_or_else(|| "<lambda>".into()),
            // `get` / `set` of a property: `Prop.get`
            "accessor_declaration" => {
                let kind = f.child_by_field_name("name").map(|n| text(src, n)).or_else(|| f.child(0).map(|c| text(src, c))).unwrap_or_else(|| "accessor".into());
                let prop = enclosing(f, &["property_declaration", "indexer_declaration"]).and_then(|p| p.child_by_field_name("name")).map(|n| text(src, n)).unwrap_or_else(|| "<property>".into());
                format!("{prop}.{kind}")
            }
            "destructor_declaration" => format!("~{}", f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_default()),
            "operator_declaration" => format!("operator {}", f.child_by_field_name("operator").map(|n| text(src, n)).unwrap_or_default()),
            _ => f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into()),
        };
        let parents = [
            ("class_declaration", "name"),
            ("struct_declaration", "name"),
            ("interface_declaration", "name"),
            ("record_declaration", "name"),
            ("record_struct_declaration", "name"),
            ("enum_declaration", "name"),
            ("method_declaration", "name"),
            ("constructor_declaration", "name"),
            ("local_function_statement", "name"),
        ];
        qualify(src, f, ".", base, &parents)
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        if n.kind() != "using_directive" {
            return vec![];
        }
        let line = n.start_position().row + 1;
        // `using A.B;`, `using static A.B;`, `using Alias = A.B;` (the target is what is imported)
        let alias = n.child_by_field_name("name");
        let target = named_children(n).into_iter().rev().find(|c| matches!(c.kind(), "identifier" | "qualified_name" | "alias_qualified_name" | "generic_name") && Some(c.id()) != alias.map(|a| a.id()));
        target.map(|t| vec![Import::module(text(src, t), line)]).unwrap_or_default()
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "identifier" | "this")
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        match n.kind() {
            "invocation_expression" => {
                let function = n.child_by_field_name("function")?;
                let receiver = (function.kind() == "member_access_expression").then(|| function.child_by_field_name("expression")).flatten();
                let (args, names) = arguments(src, n);
                Some(CallParts { callee: text(src, function), receiver, args, names })
            }
            "object_creation_expression" => {
                let (args, names) = arguments(src, n);
                Some(CallParts { callee: text(src, n.child_by_field_name("type")?), receiver: None, args, names })
            }
            _ => None,
        }
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        let Some(ps) = f.child_by_field_name("parameters") else { return vec![] };
        // lambdas: `x => ..` (implicit_parameter), `(a, b) => ..` (parameter_list)
        if ps.kind() == "implicit_parameter" || ps.kind() == "identifier" {
            return vec![vec![text(src, ps)]];
        }
        named_children(ps)
            .into_iter()
            .filter(|p| p.kind() == "parameter" || p.kind() == "implicit_parameter")
            .map(|p| p.child_by_field_name("name").map(|n| vec![text(src, n)]).unwrap_or_else(|| vec![text(src, p)]))
            .collect()
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        if !matches!(f.kind(), "lambda_expression" | "anonymous_method_expression") {
            return vec![];
        }
        let mut declared: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let mut written = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if n.kind() == "variable_declarator" {
                declared.extend(n.child_by_field_name("name").map(|x| text(src, x)));
            } else if n.kind() == "assignment_expression"
                && let Some(l) = n.child_by_field_name("left").filter(|l| matches!(l.kind(), "element_access_expression" | "member_access_expression"))
            {
                written.push(text(src, l).split('[').next().unwrap_or("").to_string());
            }
        });
        written.into_iter().filter(|p| !declared.contains(p.split('.').next().unwrap_or(p))).collect()
    }

    fn receiver(&self, src: &[u8], f: Node) -> Option<String> {
        if matches!(f.kind(), "lambda_expression" | "anonymous_method_expression" | "local_function_statement") {
            return None;
        }
        (!Self::is_static(src, f)).then(|| "this".to_string())
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = f.child_by_field_name("parameters").filter(|p| p.kind() == "parameter_list") {
            for p in named_children(ps).into_iter().filter(|p| p.kind() == "parameter") {
                if let (Some(n), Some(t)) = (p.child_by_field_name("name"), p.child_by_field_name("type")) {
                    out.push((text(src, n), text(src, t)));
                }
            }
        }
        let ret = (f.kind() == "method_declaration").then(|| f.child_by_field_name("returns")).flatten().map(|t| text(src, t));
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
            let stop = |k: Node| matches!(k.kind(), "lambda_expression" | "method_declaration" | "local_function_statement") || TYPES.contains(&k.kind());
            super::common::collect_nodes(body, &stop, &mut |n| {
                if n.kind() == "variable_declaration" {
                    let mut one = vec![];
                    decl(n, &mut one);
                    locals.extend(super::common::scoped(one, n));
                }
            });
        }
        if let Some(cb) = enclosing(f, TYPES).and_then(|c| c.child_by_field_name("body")) {
            for m in named_children(cb) {
                match m.kind() {
                    "field_declaration" => named_children(m).into_iter().filter(|v| v.kind() == "variable_declaration").for_each(|v| decl(v, &mut fields)),
                    "property_declaration" => {
                        if let (Some(n), Some(t)) = (m.child_by_field_name("name"), m.child_by_field_name("type")) {
                            fields.push((text(src, n), text(src, t)));
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
        let Some(c) = enclosing(f, TYPES) else { return out };
        for k in named_children(c).into_iter().filter(|k| k.kind() == "base_list") {
            super::common::base_names(src, k, &mut out);
        }
        out
    }

    fn type_decl_name(&self, src: &[u8], n: Node) -> Option<String> {
        TYPES.contains(&n.kind()).then(|| n.child_by_field_name("name").map(|x| text(src, x))).flatten()
    }

    fn implicit_fields(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut fields = enclosing(f, TYPES).map(|c| Self::field_names(src, c)).unwrap_or_default();
        // locals, parameters, catch and foreach variables shadow fields
        let mut locals: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let mut stack = vec![f];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "variable_declarator" | "catch_declaration" | "parameter" => locals.extend(n.child_by_field_name("name").map(|x| text(src, x))),
                "foreach_statement" => locals.extend(n.child_by_field_name("left").map(|x| text(src, x))),
                _ => {}
            }
            stack.extend(named_children(n));
        }
        fields.retain(|n| !locals.contains(n));
        fields
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        let body = f.child_by_field_name("body")?;
        match body.kind() {
            "block" => None,
            "arrow_expression_clause" => body.named_child(0),
            _ => Some(body),
        }
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "member_access_expression" {
            return None;
        }
        Some((n.child_by_field_name("expression")?, text(src, n.child_by_field_name("name")?)))
    }

    fn assignment<'a>(&self, src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        let (target, values, augmented) = match n.kind() {
            // `T x = value`: the value is the child after the name
            "variable_declarator" => {
                let name = f("name")?;
                let rest: Vec<Node<'a>> = named_children(n).into_iter().filter(|c| c.id() != name.id() && !c.kind().contains("comment") && c.kind() != "bracketed_argument_list").collect();
                (name, rest.into_iter().take(1).collect(), false)
            }
            "assignment_expression" => {
                let op = f("operator").map(|o| text(src, o)).unwrap_or_default();
                (f("left")?, f("right").into_iter().collect(), op != "=")
            }
            "foreach_statement" => (f("left")?, f("right").into_iter().collect(), false),
            _ => return None,
        };
        Some(AssignParts { targets: vec![target], values, augmented })
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "conditional_expression" => Some(ExprCtl::Ternary { cond: f("condition")?, then: f("consequence")?, els: f("alternative")? }),
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

    fn top_level(&self) -> bool {
        true
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "block" | "compilation_unit" | "global_statement" => Ctl::Block(named_children(n)),
            "using_directive" | "extern_alias_directive" | "namespace_declaration" | "file_scoped_namespace_declaration" | "delegate_declaration"
            | "local_function_statement" => Ctl::Skip,
            k if TYPES.contains(&k) => Ctl::Skip,
            "arrow_expression_clause" => Ctl::Simple(match n.named_child(0).map(|c| c.kind()) {
                Some("invocation_expression" | "object_creation_expression") => StmtKind::Call,
                Some("assignment_expression") => StmtKind::Assign,
                _ => StmtKind::Other,
            }),
            "lock_statement" | "unsafe_statement" | "checked_statement" | "fixed_statement" => {
                Ctl::Header(StmtKind::Other, f("body").or_else(|| first_child_of_kind(n, "block")).into_iter().collect())
            }
            "using_statement" => {
                let body = f("body");
                let resources: Vec<Node<'a>> = named_children(n).into_iter().filter(|c| Some(c.id()) != body.map(|b| b.id())).collect();
                Ctl::Try { pre: resources.clone(), closes: resources, body, handlers: vec![], finally: None }
            }
            "if_statement" => Ctl::If { pre: vec![], cond: f("condition"), then: f("consequence"), els: f("alternative") },
            "for_statement" => {
                let cond = f("condition");
                Ctl::Loop {
                    label: None,
                    pre: children_by_field(n, "initializer"),
                    kind: if cond.is_some() { LoopKind::Cond } else { LoopKind::Infinite },
                    cond,
                    body: f("body"),
                    update: children_by_field(n, "update"),
                }
            }
            "foreach_statement" => Ctl::Loop { label: None, pre: vec![], kind: LoopKind::Each, cond: None, body: f("body"), update: vec![] },
            "while_statement" => Ctl::Loop { label: None, pre: vec![], kind: LoopKind::Cond, cond: f("condition"), body: f("body"), update: vec![] },
            "do_statement" => Ctl::DoWhile { body: f("body"), cond: f("condition") },
            "switch_statement" => {
                let sections = f("body").map(named_children).unwrap_or_default();
                let cases = sections
                    .into_iter()
                    .filter(|s| s.kind() == "switch_section")
                    .map(|s| {
                        let kids = named_children(s);
                        Case {
                            // labels are what is not a statement (`case 1:`, `case int x when ..:`); `default:` has none
                            labels: kids.iter().copied().filter(|k| !is_statement(k.kind()) && !k.kind().contains("comment")).collect(),
                            guard: None,
                            body: kids.into_iter().filter(|k| is_statement(k.kind())).collect(),
                        }
                    })
                    .collect();
                Ctl::Switch { cases, breakable: true, fallthrough: false, exhaustive: false }
            }
            "try_statement" => Ctl::Try {
                pre: vec![],
                closes: vec![],
                body: f("body"),
                handlers: named_children(n).into_iter().filter(|c| c.kind() == "catch_clause").map(|c| Handler { head: c, body: c.child_by_field_name("body") }).collect(),
                finally: first_child_of_kind(n, "finally_clause").and_then(|c| first_child_of_kind(c, "block")),
            },
            "return_statement" => Ctl::Return,
            "throw_statement" => Ctl::Throw,
            "break_statement" => Ctl::Break(None),
            "continue_statement" => Ctl::Continue(None),
            "labeled_statement" => match n.named_child(0) {
                Some(l) => Ctl::Labeled { label: text(src, l), stmt: n.named_child(1) },
                None => Ctl::Skip,
            },
            "expression_statement" => Ctl::Simple(match n.named_child(0).map(|c| c.kind()) {
                Some("invocation_expression" | "object_creation_expression") => StmtKind::Call,
                Some("await_expression") => StmtKind::Call,
                Some("assignment_expression") => StmtKind::Assign,
                _ => StmtKind::Other,
            }),
            "local_declaration_statement" => Ctl::Simple(StmtKind::Assign),
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
