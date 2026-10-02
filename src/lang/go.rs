use super::common::{type_name, 
    AssignParts, CallParts, Case, Ctl, ExprCtl, Import, LoopKind, Spec, children_by_field, children_excluding,
    first_child_of_kind, named_children, qualify, text, unquote,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct Go;

impl Spec for Go {
    fn is_function(&self, n: Node) -> bool {
        matches!(n.kind(), "function_declaration" | "method_declaration" | "func_literal")
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into());
        if f.kind() == "method_declaration" {
            // `func (t *T) M()` -> `T.M`
            let recv = f
                .child_by_field_name("receiver")
                .and_then(|r| first_child_of_kind(r, "parameter_declaration"))
                .and_then(|p| p.child_by_field_name("type"))
                .map(|t| text(src, t));
            if let Some(r) = recv {
                return format!("{}.{base}", type_name(&r));
            }
        }
        qualify(src, f, ".", base, &[("function_declaration", "name"), ("method_declaration", "name")])
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        if n.kind() != "import_spec" {
            return vec![];
        }
        n.child_by_field_name("path")
            .into_iter()
            .map(|p| Import::module(unquote(&text(src, p)), n.start_position().row + 1))
            .collect()
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        if n.kind() != "call_expression" {
            return None;
        }
        let func = n.child_by_field_name("function")?;
        let receiver = (func.kind() == "selector_expression").then(|| func.child_by_field_name("operand")).flatten();
        let args = n
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.kind() != "comment")
            .collect();
        Some(CallParts { callee: text(src, func), receiver, args, names: vec![] })
    }

    fn receiver(&self, src: &[u8], f: Node) -> Option<String> {
        if f.kind() != "method_declaration" {
            return None;
        }
        let r = first_child_of_kind(f.child_by_field_name("receiver")?, "parameter_declaration")?;
        let name = text(src, r.child_by_field_name("name")?);
        (name != "_").then_some(name)
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        let Some(ps) = f.child_by_field_name("parameters") else { return vec![] };
        let mut out = vec![];
        for p in named_children(ps) {
            if !matches!(p.kind(), "parameter_declaration" | "variadic_parameter_declaration") {
                continue;
            }
            let names = children_by_field(p, "name");
            if names.is_empty() {
                out.push(vec![]); // unnamed parameter: still occupies a position
            }
            // `a, b int` declares two parameters
            out.extend(names.into_iter().map(|n| vec![text(src, n)]));
        }
        out
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = f.child_by_field_name("parameters") {
            for p in named_children(ps).into_iter().filter(|p| p.kind() == "parameter_declaration") {
                if let Some(t) = p.child_by_field_name("type") {
                    out.extend(children_by_field(p, "name").into_iter().map(|n| (text(src, n), text(src, t))));
                }
            }
        }
        let ret = f.child_by_field_name("result").and_then(|r| {
            if r.kind() == "parameter_list" {
                named_children(r).first().and_then(|p| p.child_by_field_name("type"))
            } else {
                Some(r)
            }
        });
        (out, ret.map(|t| text(src, t)))
    }

    fn declarations_of(&self, src: &[u8], n: Node, out: &mut super::common::Declarations) {
        if !matches!(n.kind(), "type_spec" | "type_alias") {
            return;
        }
        let (Some(name), Some(t)) = (n.child_by_field_name("name"), n.child_by_field_name("type")) else { return };
        let name = text(src, name);
        if t.kind() == "struct_type" {
            let mut fields = vec![];
            let mut embedded = vec![];
            for fl in named_children(t).into_iter().filter(|x| x.kind() == "field_declaration_list") {
                for fd in named_children(fl).into_iter().filter(|x| x.kind() == "field_declaration") {
                    if let Some(ft) = fd.child_by_field_name("type") {
                        let names = children_by_field(fd, "name");
                        if names.is_empty() {
                            embedded.push(text(src, ft));
                        }
                        fields.extend(names.into_iter().map(|x| (text(src, x), text(src, ft))));
                    }
                }
            }
            if !embedded.is_empty() {
                out.embeds.push((name.clone(), embedded));
            }
            out.types.push((name, fields));
        } else if t.kind() == "interface_type" {
            let (mut methods, mut embeds) = (vec![], vec![]);
            for e in named_children(t) {
                match e.kind() {
                    "method_elem" => methods.extend(e.child_by_field_name("name").map(|m| text(src, m))),
                    "type_elem" => embeds.extend(named_children(e).into_iter().filter(|x| x.kind() == "type_identifier").map(|x| text(src, x))),
                    _ => {}
                }
            }
            out.interfaces.push((name, methods, embeds));
        } else if n.kind() == "type_alias" {
            out.aliases.push((name, text(src, t)));
        } else if t.kind() == "type_identifier" {
            // `type R T`: a new type with T's fields, not an alias
            out.defined.push((name, text(src, t)));
        }
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let mut locals = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if n.kind() == "var_spec" {
                let t = n.child_by_field_name("type").map(|t| text(src, t)).unwrap_or_default();
                let one = children_by_field(n, "name").into_iter().map(|name| (text(src, name), t.clone())).collect();
                locals.extend(super::common::scoped(one, n));
            }
            // `x := ..` declares without a type
            if n.kind() == "short_var_declaration" && let Some(left) = n.child_by_field_name("left") {
                let one = named_children(left).into_iter().filter(|x| x.kind() == "identifier").map(|name| (text(src, name), String::new())).collect();
                locals.extend(super::common::scoped(one, n));
            }
        });
        let mut fields = vec![];
        let class = self.function_name(src, f).rsplit_once('.').map(|(c, _)| c.to_string());
        let mut root = f;
        while let Some(p) = root.parent() { root = p; }
        super::common::collect_nodes(root, &|n| self.is_function(n), &mut |n| {
            if n.kind() == "type_spec" && n.child_by_field_name("name").map(|n| text(src, n)) == class
                && let Some(body) = n.child_by_field_name("type").filter(|n| n.kind() == "struct_type")
            {
                super::common::collect_nodes(body, &|_| false, &mut |field| {
                    if field.kind() == "field_declaration" && let Some(t) = field.child_by_field_name("type") {
                        fields.extend(children_by_field(field, "name").into_iter().map(|name| (text(src, name), text(src, t))));
                    }
                });
            }
        });
        (locals, fields)
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        use super::common::{undeclared, walk_scope};
        let mut written = vec![];
        let mut declared: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let idents = |n: Option<Node>| -> Vec<String> {
            n.map(|l| if l.kind() == "identifier" { vec![text(src, l)] } else { named_children(l).into_iter().filter(|c| c.kind() == "identifier").map(|c| text(src, c)).collect() })
                .unwrap_or_default()
        };
        walk_scope(self, f, &mut |n| match n.kind() {
            "short_var_declaration" => declared.extend(idents(n.child_by_field_name("left"))),
            "var_spec" | "const_spec" => declared.extend(children_by_field(n, "name").into_iter().map(|x| text(src, x))),
            "assignment_statement" => written.extend(idents(n.child_by_field_name("left")).into_iter().filter(|w| w != "_")),
            _ => {}
        });
        undeclared(written, &declared)
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "selector_expression" {
            return None;
        }
        Some((n.child_by_field_name("operand")?, text(src, n.child_by_field_name("field")?)))
    }

    fn assignment<'a>(&self, src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        // `a, b := x, y` holds expression lists; split them into their items
        let items = |l: Option<Node<'a>>| -> Vec<Node<'a>> {
            match l {
                Some(x) if x.kind() == "expression_list" => named_children(x),
                Some(x) => vec![x],
                None => vec![],
            }
        };
        let (targets, values, augmented) = match n.kind() {
            "short_var_declaration" | "range_clause" => (items(f("left")), items(f("right")), false),
            "assignment_statement" => {
                let op = f("operator").map(|o| text(src, o)).unwrap_or_default();
                (items(f("left")), items(f("right")), op != "=")
            }
            "var_spec" => (children_by_field(n, "name"), items(f("value")), false),
            _ => return None,
        };
        Some(AssignParts { targets, values, augmented })
    }

    fn recovers(&self, src: &[u8], defer: Node) -> bool {
        text(src, defer).contains("recover()")
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        if n.kind() != "binary_expression" {
            return None;
        }
        let and = match text(src, n.child_by_field_name("operator")?).as_str() {
            "&&" => true,
            "||" => false,
            _ => return None,
        };
        Some(ExprCtl::Short {
            lhs: n.child_by_field_name("left")?,
            rhs: n.child_by_field_name("right")?,
            and,
        })
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "block" | "statement_list" => Ctl::Block(named_children(n)),
            "if_statement" => Ctl::If {
                pre: f("initializer").into_iter().collect(),
                cond: f("condition"),
                then: f("consequence"),
                els: f("alternative"),
            },
            "for_statement" => {
                let body = f("body");
                let head = named_children(n).into_iter().find(|c| Some(*c) != body);
                match head {
                    None => Ctl::simple_loop(LoopKind::Infinite, None, body),
                    Some(h) if h.kind() == "for_clause" => {
                        let cond = h.child_by_field_name("condition");
                        Ctl::Loop {
                            label: None,
                            pre: h.child_by_field_name("initializer").into_iter().collect(),
                            kind: if cond.is_some() { LoopKind::Cond } else { LoopKind::Infinite },
                            cond,
                            body,
                            update: h.child_by_field_name("update").into_iter().collect(),
                        }
                    }
                    Some(h) if h.kind() == "range_clause" => Ctl::simple_loop(LoopKind::Each, None, body),
                    Some(h) => Ctl::simple_loop(LoopKind::Cond, Some(h), body),
                }
            }
            "expression_switch_statement" | "type_switch_statement" | "select_statement" => {
                let cases = named_children(n)
                    .into_iter()
                    .filter_map(|c| {
                        let label_field = match c.kind() {
                            "expression_case" => "value",
                            "type_case" => "type", // `case A, B:` has several
                            "communication_case" => "communication",
                            "default_case" => "",
                            _ => return None,
                        };
                        Some(Case {
                            labels: children_by_field(c, label_field).into_iter().filter(|x| x.is_named()).collect(),
                            guard: None,
                            body: children_excluding(c, &[label_field]),
                        })
                    })
                    .collect();
                // `select` blocks until a case is ready, so nothing "falls past" it.
                Ctl::Switch {
                    cases,
                    breakable: true,
                    fallthrough: false,
                    exhaustive: n.kind() == "select_statement",
                }
            }
            "return_statement" => Ctl::Return,
            "break_statement" => Ctl::Break(first_child_of_kind(n, "label_name").map(|l| text(src, l))),
            "continue_statement" => Ctl::Continue(first_child_of_kind(n, "label_name").map(|l| text(src, l))),
            "goto_statement" => match first_child_of_kind(n, "label_name") {
                Some(l) => Ctl::Goto(text(src, l)),
                None => Ctl::Skip,
            },
            "labeled_statement" => match f("label") {
                Some(l) => Ctl::Labeled { label: text(src, l), stmt: n.named_child(1) },
                None => Ctl::Skip,
            },
            "fallthrough_statement" => Ctl::Fallthrough,
            "defer_statement" => Ctl::Defer,
            "go_statement" => Ctl::Simple(StmtKind::Call),
            "short_var_declaration" | "assignment_statement" | "inc_statement" | "dec_statement"
            | "var_declaration" | "const_declaration" => Ctl::Simple(StmtKind::Assign),
            "expression_statement" => match n.named_child(0) {
                Some(c) if c.kind() == "call_expression" => {
                    let callee = c.child_by_field_name("function").map(|x| text(src, x));
                    if callee.as_deref() == Some("panic") { Ctl::Throw } else { Ctl::Simple(StmtKind::Call) }
                }
                _ => Ctl::Simple(StmtKind::Other),
            },
            "type_declaration" | "empty_statement" => Ctl::Skip,
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
