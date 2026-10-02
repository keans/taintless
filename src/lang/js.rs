//! JavaScript and TypeScript (the TS grammars reuse the JS node kinds).
use super::common::{
    AssignParts, CallParts, Case, Ctl, ExprCtl, Handler, Import, LoopKind, Spec, bound_names,
    children_by_field, named_children, qualify, text, unquote,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct Js;

fn unwrap_expr(n: Option<Node>) -> Option<Node> {
    n.filter(|c| c.kind() != "empty_statement")
        .map(|c| if c.kind() == "expression_statement" { c.named_child(0).unwrap_or(c) } else { c })
}

/// The type written in a TypeScript annotation node (`: Runner` -> `Runner`).
fn annotation(src: &[u8], t: Node) -> String {
    text(src, t).trim_start_matches(':').trim().to_string()
}

impl Spec for Js {
    fn is_function(&self, n: Node) -> bool {
        matches!(
            n.kind(),
            "function_declaration"
                | "function_expression"
                | "function"
                | "generator_function"
                | "generator_function_declaration"
                | "arrow_function"
                | "method_definition"
        )
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let mut base = f.child_by_field_name("name").map(|n| text(src, n));
        // `const f = () => {}`, `{ f: function() {} }`, `a.f = () => {}`
        if base.is_none()
            && let Some(p) = f.parent()
        {
            base = ["name", "key", "left", "property"]
                .iter()
                .find_map(|field| p.child_by_field_name(field))
                .map(|n| text(src, n));
        }
        let parents = [("class_declaration", "name"), ("class", "name"), ("abstract_class_declaration", "name")];
        qualify(src, f, ".", base.unwrap_or_else(|| "<anon>".into()), &parents)
    }

    fn top_level(&self) -> bool {
        true
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "ternary_expression" => Some(ExprCtl::Ternary {
                cond: f("condition")?,
                then: f("consequence")?,
                els: f("alternative")?,
            }),
            "binary_expression" => {
                let and = match text(src, f("operator")?).as_str() {
                    "&&" => true,
                    "||" | "??" => false,
                    _ => return None,
                };
                Some(ExprCtl::Short { lhs: f("left")?, rhs: f("right")?, and })
            }
            // `a?.b`, `a?.[i]`, `a?.()`
            "member_expression" | "subscript_expression" | "call_expression" => {
                f("optional_chain")?;
                Some(ExprCtl::Optional { obj: f("object").or_else(|| f("function"))? })
            }
            _ => None,
        }
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        let line = n.start_position().row + 1;
        let source = |n: Node| n.child_by_field_name("source").map(|s| unquote(&text(src, s)));
        match n.kind() {
            // `import x from "m"` / `export * from "m"`
            "import_statement" | "export_statement" => source(n).map(|m| vec![Import::module(m, line)]).unwrap_or_default(),
            // `require("m")` and dynamic `import("m")`
            "call_expression" => {
                let Some(f) = n.child_by_field_name("function") else { return vec![] };
                let is_require = f.kind() == "identifier" && text(src, f) == "require";
                if !(is_require || f.kind() == "import") {
                    return vec![];
                }
                let arg = n.child_by_field_name("arguments").and_then(|a| a.named_child(0));
                match arg {
                    Some(a) if a.kind() == "string" => vec![Import::module(unquote(&text(src, a)), line)],
                    _ => vec![],
                }
            }
            _ => vec![],
        }
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(
            n.kind(),
            "identifier" | "this" | "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
        )
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        let callee_node = match n.kind() {
            "call_expression" => n.child_by_field_name("function")?,
            "new_expression" => n.child_by_field_name("constructor")?,
            _ => return None,
        };
        let receiver = (callee_node.kind() == "member_expression")
            .then(|| callee_node.child_by_field_name("object"))
            .flatten();
        let args = n
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.kind() != "comment")
            .map(|a| if a.kind() == "spread_element" { a.named_child(0).unwrap_or(a) } else { a })
            .collect();
        Some(CallParts { callee: text(src, callee_node), receiver, args, names: vec![] })
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        // `x => ...` has a single `parameter`, everything else `formal_parameters`
        if let Some(p) = f.child_by_field_name("parameter") {
            return vec![bound_names(self, src, p)];
        }
        let Some(ps) = f.child_by_field_name("parameters") else { return vec![] };
        named_children(ps)
            .into_iter()
            .filter(|p| !p.kind().contains("comment"))
            .map(|p| match p.kind() {
                "required_parameter" | "optional_parameter" => {
                    bound_names(self, src, p.child_by_field_name("pattern").unwrap_or(p))
                }
                "assignment_pattern" => bound_names(self, src, p.child_by_field_name("left").unwrap_or(p)),
                _ => bound_names(self, src, p),
            })
            .collect()
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = f.child_by_field_name("parameters") {
            for p in named_children(ps).into_iter().filter(|p| matches!(p.kind(), "required_parameter" | "optional_parameter")) {
                if let (Some(pat), Some(t)) = (p.child_by_field_name("pattern"), p.child_by_field_name("type")) {
                    out.extend(bound_names(self, src, pat).into_iter().map(|n| (n, annotation(src, t))));
                }
            }
        }
        (out, f.child_by_field_name("return_type").map(|t| annotation(src, t)))
    }

    fn declarations_of(&self, src: &[u8], n: Node, out: &mut super::common::Declarations) {
        // `type R = Runner;`
        if n.kind() == "type_alias_declaration"
            && let (Some(name), Some(t)) = (n.child_by_field_name("name"), n.child_by_field_name("value"))
        {
            out.aliases.push((text(src, name), text(src, t)));
        }
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let (mut locals, mut fields) = (vec![], vec![]);
        if let Some(body) = f.child_by_field_name("body") {
            let stop = |k: Node| self.is_function(k);
            super::common::collect_nodes(body, &stop, &mut |n| {
                if n.kind() == "variable_declarator"
                    && let Some(name) = n.child_by_field_name("name")
                    && name.kind() == "identifier"
                {
                    // an untyped `let` / `const` still declares the name in its block
                    let lexical = n.parent().is_some_and(|p| p.kind() == "lexical_declaration");
                    match n.child_by_field_name("type") {
                        Some(t) => locals.extend(super::common::scoped(vec![(text(src, name), annotation(src, t))], n)),
                        None if lexical => locals.extend(super::common::scoped(vec![(text(src, name), String::new())], n)),
                        None => {}
                    }
                }
            });
        }
        let class = super::common::enclosing(f, &["class_declaration", "class", "abstract_class_declaration"]);
        if let Some(cb) = class.and_then(|c| c.child_by_field_name("body")) {
            for m in named_children(cb).into_iter().filter(|m| matches!(m.kind(), "public_field_definition" | "field_definition")) {
                if let (Some(name), Some(t)) = (m.child_by_field_name("name"), m.child_by_field_name("type")) {
                    fields.push((text(src, name), annotation(src, t)));
                }
            }
        }
        (locals, fields)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut out = vec![];
        let Some(c) = super::common::enclosing(f, &["class_declaration", "class", "abstract_class_declaration", "interface_declaration"]) else {
            return out;
        };
        for k in named_children(c) {
            if matches!(k.kind(), "class_heritage" | "extends_type_clause") {
                super::common::base_names(src, k, &mut out);
            }
        }
        out
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        use super::common::{undeclared, walk_scope};
        let mut written = vec![];
        let mut declared: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        walk_scope(self, f, &mut |n| match n.kind() {
            "variable_declarator" => {
                if let Some(x) = n.child_by_field_name("name") {
                    declared.extend(bound_names(self, src, x));
                }
            }
            "function_declaration" | "generator_function_declaration" | "class_declaration" => {
                declared.extend(n.child_by_field_name("name").map(|x| text(src, x)));
            }
            "catch_clause" => {
                if let Some(x) = n.child_by_field_name("parameter") {
                    declared.extend(bound_names(self, src, x));
                }
            }
            "assignment_expression" | "augmented_assignment_expression" => {
                if let Some(l) = n.child_by_field_name("left").filter(|l| l.kind() == "identifier") {
                    written.push(text(src, l));
                }
            }
            _ => {}
        });
        undeclared(written, &declared)
    }

    fn receiver(&self, _src: &[u8], f: Node) -> Option<String> {
        (f.kind() == "method_definition").then(|| "this".to_string())
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body").filter(|b| b.kind() != "statement_block")
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "member_expression" {
            return None;
        }
        Some((n.child_by_field_name("object")?, text(src, n.child_by_field_name("property")?)))
    }

    fn key_path(&self, key: &str) -> String {
        key.strip_prefix("['").and_then(|k| k.strip_suffix("']"))
            .map_or_else(|| key.to_string(), |name| format!(".{name}"))
    }

    fn assignment<'a>(&self, _src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        let (target, value, augmented) = match n.kind() {
            "variable_declarator" => (f("name")?, f("value"), false),
            "assignment_expression" => (f("left")?, f("right"), false),
            "augmented_assignment_expression" => (f("left")?, f("right"), true),
            "for_in_statement" => (f("left")?, f("right"), false),
            _ => return None,
        };
        Some(AssignParts { targets: vec![target], values: value.into_iter().collect(), augmented })
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "program" | "statement_block" | "else_clause" | "export_statement" => {
                Ctl::Block(named_children(n))
            }
            "with_statement" => Ctl::Header(StmtKind::Other, f("body").into_iter().collect()),
            "if_statement" => Ctl::If {
                pre: vec![],
                cond: f("condition"),
                then: f("consequence"),
                els: f("alternative"),
            },
            "for_statement" => {
                let cond = unwrap_expr(f("condition"));
                Ctl::Loop {
                    label: None,
                    pre: f("initializer").filter(|i| i.kind() != "empty_statement").into_iter().collect(),
                    kind: if cond.is_some() { LoopKind::Cond } else { LoopKind::Infinite },
                    cond,
                    body: f("body"),
                    update: f("increment").into_iter().collect(),
                }
            }
            "for_in_statement" => Ctl::Loop {
                label: None,
                pre: vec![],
                kind: LoopKind::Each,
                cond: None,
                body: f("body"),
                update: vec![],
            },
            "while_statement" => Ctl::Loop {
                label: None,
                pre: vec![],
                kind: LoopKind::Cond,
                cond: f("condition"),
                body: f("body"),
                update: vec![],
            },
            "do_statement" => Ctl::DoWhile { body: f("body"), cond: f("condition") },
            "switch_statement" => {
                let cases = f("body")
                    .map(named_children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|c| matches!(c.kind(), "switch_case" | "switch_default"))
                    .map(|c| Case {
                        labels: c.child_by_field_name("value").into_iter().collect(),
                        guard: None,
                        body: children_by_field(c, "body"),
                    })
                    .collect();
                Ctl::Switch { cases, breakable: true, fallthrough: true, exhaustive: false }
            }
            "try_statement" => Ctl::Try {
                pre: vec![],
                closes: vec![],
                body: f("body"),
                handlers: f("handler")
                    .map(|h| Handler { head: h, body: h.child_by_field_name("body") })
                    .into_iter()
                    .collect(),
                finally: f("finalizer").and_then(|c| c.child_by_field_name("body")),
            },
            "return_statement" => Ctl::Return,
            "throw_statement" => Ctl::Throw,
            "break_statement" => Ctl::Break(f("label").map(|l| text(src, l))),
            "continue_statement" => Ctl::Continue(f("label").map(|l| text(src, l))),
            "labeled_statement" => match f("label") {
                Some(l) => Ctl::Labeled { label: text(src, l), stmt: f("body") },
                None => Ctl::Skip,
            },
            "expression_statement" => Ctl::Simple(match n.named_child(0).map(|c| c.kind()) {
                Some("call_expression" | "await_expression" | "new_expression") => StmtKind::Call,
                Some("assignment_expression" | "augmented_assignment_expression") => StmtKind::Assign,
                _ => StmtKind::Other,
            }),
            "lexical_declaration" | "variable_declaration" => Ctl::Simple(StmtKind::Assign),
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "type_alias_declaration"
            | "enum_declaration"
            | "import_statement"
            | "internal_module"
            | "module"
            | "ambient_declaration"
            | "empty_statement" => Ctl::Skip,
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
