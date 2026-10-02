//! C and C++ share one spec; C++-only node kinds simply never occur in C.
use super::common::{enclosing, 
    AssignParts, CallParts, Case, Ctl, ExprCtl, Handler, Import, ImportKind, LoopKind, Spec, bound_names,
    children_by_field, children_excluding, declarator_name, named_children, qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct CLike;

impl Spec for CLike {
    fn is_function(&self, n: Node) -> bool {
        matches!(n.kind(), "function_definition" | "lambda_expression")
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = if f.kind() == "lambda_expression" { "<lambda>".into() } else { declarator_name(src, f) };
        let parents = [
            ("class_specifier", "name"),
            ("struct_specifier", "name"),
            ("namespace_definition", "name"),
            ("function_definition", "declarator"),
        ];
        // `function_definition` ancestors name via their declarator chain.
        let mut q = qualify(src, f, "::", base.clone(), &parents[..3]);
        if f.kind() == "lambda_expression"
            && let Some(n) = enclosing(f, &["function_definition"])
        {
            q = format!("{}::{base}", declarator_name(src, n));
        }
        q
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        if n.kind() != "preproc_include" {
            return vec![];
        }
        let Some(p) = n.child_by_field_name("path") else { return vec![] };
        let t = text(src, p);
        let kind = if p.kind() == "system_lib_string" { ImportKind::SystemInclude } else { ImportKind::LocalInclude };
        let module = t.trim().trim_matches(|c| c == '"' || c == '<' || c == '>').to_string();
        vec![Import { module, names: vec![], line: n.start_position().row + 1, kind }]
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        if n.kind() != "call_expression" {
            return None;
        }
        let func = n.child_by_field_name("function")?;
        let receiver = (func.kind() == "field_expression").then(|| func.child_by_field_name("argument")).flatten();
        let args = n
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.kind() != "comment")
            .collect();
        Some(CallParts { callee: text(src, func), receiver, args, names: vec![] })
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "identifier" | "this")
    }

    fn receiver(&self, _src: &[u8], f: Node) -> Option<String> {
        // C++ member functions: defined inside a class, or out of line as `A::f`
        let qualified = {
            let mut d = f.child_by_field_name("declarator");
            let mut q = false;
            while let Some(x) = d {
                q |= x.kind() == "qualified_identifier";
                d = x.child_by_field_name("declarator");
            }
            q
        };
        let mut p = f.parent();
        let mut in_class = false;
        while let Some(n) = p {
            in_class |= matches!(n.kind(), "class_specifier" | "struct_specifier");
            p = n.parent();
        }
        (qualified || in_class).then(|| "this".to_string())
    }

    fn capture_initializers<'a>(&self, f: Node<'a>) -> Vec<(Node<'a>, Node<'a>)> {
        named_children(f).into_iter().filter(|n| n.kind() == "lambda_capture_specifier")
            .flat_map(named_children).filter(|n| n.kind() == "lambda_capture_initializer")
            .filter_map(|n| Some((n.child_by_field_name("left")?, n.child_by_field_name("right")?))).collect()
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        if f.kind() != "lambda_expression" { return vec![]; }
        let capture = named_children(f).into_iter().find(|n| n.kind() == "lambda_capture_specifier")
            .map(|n| text(src, n)).unwrap_or_default();
        let default_ref = capture.trim_start_matches('[').trim_start().starts_with('&')
            && capture.trim_start_matches('[').trim_start()[1..].trim_start().starts_with([',', ']']);
        let mut declared: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        declared.extend(self.capture_initializers(f).into_iter().map(|(name, _)| text(src, name)));
        let mut written = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if n.kind() == "declaration" {
                let mut cursor = n.walk();
                for d in n.children_by_field_name("declarator", &mut cursor) {
                    let d = d.child_by_field_name("declarator").unwrap_or(d);
                    declared.extend(bound_names(self, src, d));
                }
            } else if n.kind() == "init_declarator" {
                if let Some(d) = n.child_by_field_name("declarator") { declared.extend(bound_names(self, src, d)); }
            } else if n.kind() == "assignment_expression"
                && let Some(l) = n.child_by_field_name("left").filter(|l| l.kind() == "identifier") {
                    written.push(text(src, l));
            }
        });
        super::common::undeclared(written, &declared).into_iter().filter(|v| {
            let parts: Vec<_> = capture.trim_matches(['[', ']']).split(',').map(str::trim).collect();
            parts.iter().any(|p| p.strip_prefix('&').is_some_and(|p| p.trim() == v))
                || (default_ref && !parts.iter().any(|p| *p == v))
        }).collect()
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        // the parameter list hangs off the (possibly pointer-wrapped) function declarator
        let mut d = f.child_by_field_name("declarator");
        let mut list = None;
        while let Some(x) = d {
            if let Some(p) = x.child_by_field_name("parameters") {
                list = Some(p);
                break;
            }
            d = x.child_by_field_name("declarator");
        }
        let Some(list) = list else { return vec![] };
        named_children(list)
            .into_iter()
            .filter(|p| matches!(p.kind(), "parameter_declaration" | "optional_parameter_declaration"))
            .map(|p| p.child_by_field_name("declarator").map(|d| bound_names(self, src, d)).unwrap_or_default())
            .collect()
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        let mut d = f.child_by_field_name("declarator");
        while let Some(x) = d {
            if let Some(list) = x.child_by_field_name("parameters") {
                for p in named_children(list).into_iter().filter(|p| p.kind() == "parameter_declaration") {
                    if let (Some(t), Some(d)) = (p.child_by_field_name("type"), p.child_by_field_name("declarator")) {
                        out.extend(bound_names(self, src, d).into_iter().map(|n| (n, text(src, t))));
                    }
                }
                break;
            }
            d = x.child_by_field_name("declarator");
        }
        (out, f.child_by_field_name("type").map(|t| text(src, t)))
    }

    fn declarations_of(&self, src: &[u8], n: Node, out: &mut super::common::Declarations) {
        match n.kind() {
            "class_specifier" | "struct_specifier" => {
                let (Some(name), Some(body)) = (n.child_by_field_name("name"), n.child_by_field_name("body")) else { return };
                let mut fields = vec![];
                for m in named_children(body).into_iter().filter(|m| m.kind() == "field_declaration") {
                    let Some(t) = m.child_by_field_name("type").map(|t| text(src, t)) else { continue };
                    for d in children_by_field(m, "declarator") {
                        let (mut x, mut is_method) = (d, d.kind() == "function_declarator");
                        while let Some(i) = x.child_by_field_name("declarator") {
                            x = i;
                            is_method |= x.kind() == "function_declarator";
                        }
                        if x.kind() == "field_identifier" && !is_method {
                            fields.push((text(src, x), t.clone()));
                        }
                    }
                }
                out.types.push((text(src, name), fields));
            }
            // `using R = Runner;`
            "alias_declaration" => {
                if let (Some(name), Some(t)) = (n.child_by_field_name("name"), n.child_by_field_name("type")) {
                    out.aliases.push((text(src, name), text(src, t)));
                }
            }
            // `typedef Runner R;`
            "type_definition" => {
                if let (Some(t), Some(d)) = (n.child_by_field_name("type"), n.child_by_field_name("declarator"))
                    && d.kind() == "type_identifier"
                {
                    out.aliases.push((text(src, d), text(src, t)));
                }
            }
            _ => {}
        }
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let decl = |n: Node, out: &mut super::common::Typed| {
            let Some(t) = n.child_by_field_name("type") else { return };
            let mut cursor = n.walk();
            for d in n.children_by_field_name("declarator", &mut cursor) {
                let d = if d.kind() == "init_declarator" { d.child_by_field_name("declarator").unwrap_or(d) } else { d };
                if !super::common::contains_kind(d, "function_declarator", &[]) {
                    let mut leaf = d;
                    while let Some(inner) = leaf.child_by_field_name("declarator") { leaf = inner; }
                    let names = if leaf.kind() == "field_identifier" { vec![text(src, leaf)] } else { bound_names(self, src, d) };
                    out.extend(names.into_iter().map(|name| (name, text(src, t))));
                }
            }
        };
        let mut locals = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if n.kind() == "declaration" {
                let mut one = vec![];
                decl(n, &mut one);
                locals.extend(super::common::scoped(one, n));
            }
        });
        let mut fields = vec![];
        let name = self.function_name(src, f);
        let class = name.rsplit_once("::").map(|(c, _)| c.rsplit("::").next().unwrap_or(c));
        let mut root = f;
        while let Some(p) = root.parent() { root = p; }
        super::common::collect_nodes(root, &|n| self.is_function(n), &mut |n| {
            if matches!(n.kind(), "class_specifier" | "struct_specifier")
                && n.child_by_field_name("name").map(|n| text(src, n)).as_deref() == class
                && let Some(body) = n.child_by_field_name("body")
            {
                for field in named_children(body).into_iter().filter(|n| n.kind() == "field_declaration") { decl(field, &mut fields); }
            }
        });
        (locals, fields)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut out = vec![];
        if let Some(c) = super::common::enclosing(f, &["class_specifier", "struct_specifier"]) {
            for k in named_children(c).into_iter().filter(|k| k.kind() == "base_class_clause") {
                super::common::base_names(src, k, &mut out);
            }
        }
        out
    }

    fn implicit_fields(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut fields = vec![];
        let mut p = f.parent();
        while let Some(n) = p {
            if matches!(n.kind(), "class_specifier" | "struct_specifier") {
                if let Some(body) = n.child_by_field_name("body") {
                    for m in named_children(body).into_iter().filter(|m| m.kind() == "field_declaration") {
                        let mut c = m.walk();
                        for d in m.children_by_field_name("declarator", &mut c) {
                            // methods are `function_declarator`s; fields are (wrapped) field identifiers
                            let mut x = d;
                            while let Some(i) = x.child_by_field_name("declarator") {
                                x = i;
                            }
                            if x.kind() == "field_identifier" {
                                fields.push(text(src, x));
                            }
                        }
                    }
                }
                break;
            }
            p = n.parent();
        }
        let mut locals: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let mut stack = vec![f];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "init_declarator" => {
                    if let Some(d) = n.child_by_field_name("declarator") {
                        locals.extend(bound_names(self, src, d));
                    }
                }
                "declaration" => {
                    let mut c = n.walk();
                    for d in n.children_by_field_name("declarator", &mut c) {
                        if d.kind() != "init_declarator" {
                            locals.extend(bound_names(self, src, d));
                        }
                    }
                }
                "for_range_loop" => {
                    if let Some(d) = n.child_by_field_name("declarator") {
                        locals.extend(bound_names(self, src, d));
                    }
                }
                _ => {}
            }
            stack.extend(named_children(n));
        }
        fields.retain(|n| !locals.contains(n));
        fields
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "field_expression" {
            return None;
        }
        Some((n.child_by_field_name("argument")?, text(src, n.child_by_field_name("field")?)))
    }

    fn assignment<'a>(&self, src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        let (target, value, augmented) = match n.kind() {
            "init_declarator" => (f("declarator")?, f("value"), false),
            "assignment_expression" => {
                let op = f("operator").map(|o| text(src, o)).unwrap_or_default();
                (f("left")?, f("right"), op != "=")
            }
            "for_range_loop" => (f("declarator")?, f("right"), false),
            _ => return None,
        };
        Some(AssignParts { targets: vec![target], values: value.into_iter().collect(), augmented })
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "conditional_expression" => Some(ExprCtl::Ternary {
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
            "compound_statement" | "else_clause" => Ctl::Block(named_children(n)),
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
                    pre: f("initializer").into_iter().collect(),
                    kind: if cond.is_some() { LoopKind::Cond } else { LoopKind::Infinite },
                    cond,
                    body: f("body"),
                    update: f("update").into_iter().collect(),
                }
            }
            "for_range_loop" => Ctl::Loop {
                label: None, pre: vec![], kind: LoopKind::Each,
                cond: None, body: f("body"), update: vec![],
            },
            "while_statement" => Ctl::Loop {
                label: None, pre: vec![], kind: LoopKind::Cond,
                cond: f("condition"), body: f("body"), update: vec![],
            },
            "do_statement" => Ctl::DoWhile { body: f("body"), cond: f("condition") },
            "switch_statement" => {
                let cases = f("body")
                    .map(named_children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|c| c.kind() == "case_statement")
                    .map(|c| Case {
                        labels: c.child_by_field_name("value").into_iter().collect(),
                        guard: None,
                        body: children_excluding(c, &["value"]),
                    })
                    .collect();
                Ctl::Switch { cases, breakable: true, fallthrough: true, exhaustive: false }
            }
            "try_statement" => Ctl::Try {
                pre: vec![],
                closes: vec![],
                body: f("body"),
                handlers: named_children(n)
                    .into_iter()
                    .filter(|c| c.kind() == "catch_clause")
                    .map(|c| Handler { head: c, body: c.child_by_field_name("body") })
                    .collect(),
                finally: None,
            },
            "return_statement" | "co_return_statement" => Ctl::Return,
            "throw_statement" => Ctl::Throw,
            "break_statement" => Ctl::Break(None),
            "continue_statement" => Ctl::Continue(None),
            "goto_statement" => match f("label") {
                Some(l) => Ctl::Goto(text(src, l)),
                None => Ctl::Skip,
            },
            "labeled_statement" => match f("label") {
                Some(l) => Ctl::Labeled { label: text(src, l), stmt: n.named_child(1) },
                None => Ctl::Skip,
            },
            "expression_statement" => Ctl::Simple(match n.named_child(0).map(|c| c.kind()) {
                Some("call_expression") => StmtKind::Call,
                Some("assignment_expression") => StmtKind::Assign,
                Some("throw_expression") => return Ctl::Throw,
                _ => StmtKind::Other,
            }),
            "declaration" => Ctl::Simple(StmtKind::Assign),
            "preproc_include" | "preproc_def" | "preproc_function_def" | "preproc_call"
            | "type_definition" | "empty_statement" => Ctl::Skip,
            k if k.starts_with("preproc_") => Ctl::Block(named_children(n)),
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
