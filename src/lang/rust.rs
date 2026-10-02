use super::common::{
    AssignParts, CallParts, Case, Ctl, ExprCtl, Import, ImportKind, LoopKind, Spec, bound_names,
    children_excluding, contains_kind, first_child_of_kind, named_children, qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct RustSpec;

const CONTROL_VALUES: &[&str] = &[
    "if_expression",
    "match_expression",
    "loop_expression",
    "while_expression",
    "for_expression",
    "block",
    "unsafe_block",
];

impl Spec for RustSpec {
    fn is_function(&self, n: Node) -> bool {
        matches!(n.kind(), "function_item" | "closure_expression" | "async_block")
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = if f.kind() == "async_block" {
            "<async>".into()
        } else if f.kind() == "closure_expression" {
            // `let add = |a, b| ...` is named after the binding.
            f.parent()
                .filter(|p| p.kind() == "let_declaration")
                .and_then(|p| p.child_by_field_name("pattern"))
                .map(|n| text(src, n))
                .unwrap_or_else(|| "<closure>".into())
        } else {
            f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into())
        };
        let parents = [
            ("impl_item", "type"),
            ("trait_item", "name"),
            ("mod_item", "name"),
            ("function_item", "name"),
        ];
        qualify(src, f, "::", base, &parents)
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        match f.kind() {
            "async_block" => first_child_of_kind(f, "block"),
            _ => f.child_by_field_name("body"),
        }
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        let line = n.start_position().row + 1;
        match n.kind() {
            "use_declaration" => {
                let Some(arg) = n.child_by_field_name("argument") else { return vec![] };
                let (module, names) = split_use(&text(src, arg));
                vec![Import { module, names, line, kind: ImportKind::Module }]
            }
            // `mod name;` (no body) lives in its own file
            "mod_item" if n.child_by_field_name("body").is_none() => n
                .child_by_field_name("name")
                .map(|x| vec![Import { module: text(src, x), names: vec![], line, kind: ImportKind::ModDecl }])
                .unwrap_or_default(),
            _ => vec![],
        }
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "identifier" | "self")
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        match n.kind() {
            "call_expression" => {
                let func = n.child_by_field_name("function")?;
                let receiver =
                    (func.kind() == "field_expression").then(|| func.child_by_field_name("value")).flatten();
                let args = n
                    .child_by_field_name("arguments")
                    .map(named_children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|a| !a.kind().contains("comment"))
                    .collect();
                Some(CallParts { callee: text(src, func), receiver, args, names: vec![] })
            }
            // `format!(...)`, `println!(...)`: the token tree is the argument
            "macro_invocation" => Some(CallParts {
                callee: text(src, n.child_by_field_name("macro")?),
                receiver: None,
                args: named_children(n).into_iter().filter(|c| c.kind() == "token_tree").collect(),
                names: vec![],
            }),
            _ => None,
        }
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        let Some(ps) = f.child_by_field_name("parameters") else { return vec![] };
        named_children(ps)
            .into_iter()
            .filter(|p| matches!(p.kind(), "parameter" | "identifier")) // not `self`
            .map(|p| match p.kind() {
                "parameter" => p.child_by_field_name("pattern").map(|x| bound_names(self, src, x)).unwrap_or_default(),
                _ => vec![text(src, p)],
            })
            .collect()
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = f.child_by_field_name("parameters") {
            for p in named_children(ps).into_iter().filter(|p| p.kind() == "parameter") {
                if let (Some(pat), Some(t)) = (p.child_by_field_name("pattern"), p.child_by_field_name("type")) {
                    out.extend(bound_names(self, src, pat).into_iter().map(|n| (n, text(src, t))));
                }
            }
        }
        (out, f.child_by_field_name("return_type").map(|t| text(src, t)))
    }

    fn declarations_of(&self, src: &[u8], n: Node, out: &mut super::common::Declarations) {
        let Some(name) = n.child_by_field_name("name").map(|x| text(src, x)) else { return };
        match n.kind() {
            "struct_item" => {
                let fields = n
                    .child_by_field_name("body")
                    .map(|b| named_children(b).into_iter().filter(|x| x.kind() == "field_declaration").collect::<Vec<_>>())
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|fd| Some((text(src, fd.child_by_field_name("name")?), text(src, fd.child_by_field_name("type")?))))
                    .collect();
                out.types.push((name, fields));
            }
            "type_item" => {
                if let Some(t) = n.child_by_field_name("type") {
                    out.aliases.push((name, text(src, t)));
                }
            }
            _ => {}
        }
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let mut locals = vec![];
        super::common::walk_scope(self, f, &mut |n| {
            if n.kind() == "let_declaration"
                && let Some(p) = n.child_by_field_name("pattern")
            {
                // an untyped `let` still declares the name (its scope tells shadowing variables apart)
                let t = n.child_by_field_name("type").map(|t| text(src, t)).unwrap_or_default();
                let one = bound_names(self, src, p).into_iter().map(|name| (name, t.clone())).collect();
                locals.extend(super::common::scoped(one, n));
            }
        });
        let mut fields = vec![];
        let class = super::common::enclosing(f, &["impl_item"]).and_then(|n| n.child_by_field_name("type"))
            .map(|n| super::common::type_name(&text(src, n)));
        let mut root = f;
        while let Some(p) = root.parent() { root = p; }
        super::common::collect_nodes(root, &|n| self.is_function(n), &mut |n| {
            if n.kind() == "struct_item" && n.child_by_field_name("name").map(|n| text(src, n)) == class
                && let Some(body) = n.child_by_field_name("body")
            {
                for field in named_children(body) {
                    if let (Some(name), Some(t)) = (field.child_by_field_name("name"), field.child_by_field_name("type")) {
                        fields.push((text(src, name), text(src, t)));
                    }
                }
            }
        });
        (locals, fields)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let mut out = vec![];
        match super::common::enclosing(f, &["impl_item", "trait_item"]) {
            Some(i) if i.kind() == "impl_item" => {
                if let Some(t) = i.child_by_field_name("trait") {
                    super::common::base_names(src, t, &mut out);
                }
            }
            Some(t) => {
                if let Some(b) = t.child_by_field_name("bounds") {
                    super::common::base_names(src, b, &mut out);
                }
            }
            None => {}
        }
        out
    }

    fn free_writes(&self, src: &[u8], f: Node) -> Vec<String> {
        use super::common::{undeclared, walk_scope};
        let mut written = vec![];
        let mut declared: std::collections::HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        walk_scope(self, f, &mut |n| match n.kind() {
            "let_declaration" => {
                if let Some(x) = n.child_by_field_name("pattern") {
                    declared.extend(bound_names(self, src, x));
                }
            }
            "assignment_expression" | "compound_assignment_expr" => {
                if let Some(l) = n.child_by_field_name("left").filter(|l| l.kind() == "identifier") {
                    written.push(text(src, l));
                }
            }
            _ => {}
        });
        undeclared(written, &declared)
    }

    fn receiver(&self, _src: &[u8], f: Node) -> Option<String> {
        let ps = f.child_by_field_name("parameters")?;
        named_children(ps).iter().any(|p| p.kind() == "self_parameter").then(|| "self".to_string())
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        let body = self.function_body(f)?;
        if body.kind() != "block" {
            return Some(body); // `|x| x + 1`
        }
        // the tail expression: a last child that is not a statement
        named_children(body).into_iter().last().filter(|l| {
            let k = l.kind();
            !(k == "expression_statement"
                || k == "let_declaration"
                || k == "empty_statement"
                || k == "return_expression"
                || k.contains("comment")
                || k.ends_with("_item"))
        })
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "field_expression" {
            return None;
        }
        Some((n.child_by_field_name("value")?, text(src, n.child_by_field_name("field")?)))
    }

    fn assignment<'a>(&self, _src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        let (target, value, augmented) = match n.kind() {
            "let_declaration" | "let_condition" => (f("pattern")?, f("value"), false),
            "assignment_expression" => (f("left")?, f("right"), false),
            "compound_assignment_expr" => (f("left")?, f("right"), true),
            "for_expression" => (f("pattern")?, f("value"), false),
            _ => return None,
        };
        Some(AssignParts { targets: vec![target], values: value.into_iter().collect(), augmented })
    }

    /// `?` in this node's own expressions. Nested blocks and arms are separate
    /// statements that check themselves, so they are not searched.
    fn early_exit(&self, n: Node) -> bool {
        const STOP: &[&str] = &[
            "closure_expression", "function_item", "async_block", "block", "match_block", "else_clause",
        ];
        n.kind() == "try_expression" || contains_kind(n, "try_expression", STOP)
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        match n.kind() {
            "if_expression" | "match_expression" | "loop_expression" | "while_expression"
            | "for_expression" | "block" | "unsafe_block" => Some(ExprCtl::Stmt),
            "binary_expression" => {
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
            _ => None,
        }
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        let label = || first_child_of_kind(n, "label").map(|l| text(src, l));
        match n.kind() {
            "block" | "unsafe_block" | "else_clause" | "expression_statement" => {
                Ctl::Block(named_children(n))
            }
            // `let Some(x) = e else { diverge };`
            "let_declaration" if f("alternative").is_some() => {
                Ctl::If { pre: vec![], cond: None, then: None, els: f("alternative") }
            }
            "let_declaration" => match f("value") {
                Some(v) if CONTROL_VALUES.contains(&v.kind()) => Ctl::Header(StmtKind::Assign, vec![v]),
                _ => Ctl::Simple(StmtKind::Assign),
            },
            "if_expression" => Ctl::If {
                pre: vec![],
                cond: f("condition"),
                then: f("consequence"),
                els: f("alternative"),
            },
            "while_expression" => Ctl::Loop {
                label: label(),
                pre: vec![],
                kind: LoopKind::Cond,
                cond: f("condition"),
                body: f("body"),
                update: vec![],
            },
            "loop_expression" => Ctl::Loop {
                label: label(),
                pre: vec![],
                kind: LoopKind::Infinite,
                cond: None,
                body: f("body"),
                update: vec![],
            },
            "for_expression" => Ctl::Loop {
                label: label(),
                pre: vec![],
                kind: LoopKind::Each,
                cond: None,
                body: f("body"),
                update: vec![],
            },
            "match_expression" => {
                let cases = f("body")
                    .map(named_children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|a| a.kind() == "match_arm")
                    .map(|arm| {
                        // `pattern if guard`: the guard is a field of the pattern node.
                        let mp = arm.child_by_field_name("pattern");
                        let guard = mp.and_then(|m| m.child_by_field_name("condition"));
                        let inner = mp.map(|m| children_excluding(m, &["condition"])).unwrap_or_default();
                        let wildcard = guard.is_none() && mp.is_some_and(|m| text(src, m).trim() == "_");
                        Case {
                            labels: if wildcard {
                                vec![]
                            } else if inner.is_empty() {
                                mp.into_iter().collect()
                            } else {
                                inner
                            },
                            guard,
                            body: arm.child_by_field_name("value").into_iter().collect(),
                        }
                    })
                    .collect();
                Ctl::Switch { cases, breakable: false, fallthrough: false, exhaustive: true }
            }
            "return_expression" => Ctl::Return,
            "break_expression" => Ctl::Break(first_child_of_kind(n, "label").map(|l| text(src, l))),
            "continue_expression" => Ctl::Continue(first_child_of_kind(n, "label").map(|l| text(src, l))),
            "macro_invocation" => match f("macro").map(|m| text(src, m)).as_deref() {
                Some("panic" | "unreachable" | "todo" | "unimplemented") => Ctl::Throw,
                _ => Ctl::Simple(StmtKind::Call),
            },
            "call_expression" | "try_expression" | "await_expression" => Ctl::Simple(StmtKind::Call),
            "assignment_expression" | "compound_assignment_expr" => Ctl::Simple(StmtKind::Assign),
            "use_declaration" | "empty_statement" => Ctl::Skip,
            k if k.ends_with("_item") => Ctl::Skip,
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}

/// `crate::a::{b, c as d, e::f}` -> (`crate::a`, [`b`, `c`, `e`]);
/// `std::io` -> (`std::io`, []); `a::b::*` -> (`a::b`, [`*`]).
fn split_use(arg: &str) -> (String, Vec<String>) {
    let t: String = arg.chars().filter(|c| !c.is_whitespace()).collect();
    let Some(open) = t.find('{') else {
        let t = t.split("as").next().unwrap_or(&t).to_string();
        return match t.strip_suffix("::*") {
            Some(m) => (m.to_string(), vec!["*".into()]),
            None => (t, vec![]),
        };
    };
    let module = t[..open].trim_end_matches("::").to_string();
    // top-level items of the brace list (nested braces stay inside their item)
    let inner = t[open + 1..].trim_end_matches('}');
    let (mut names, mut depth, mut cur) = (vec![], 0, String::new());
    for c in inner.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                names.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    names.push(cur);
    let names = names
        .into_iter()
        .map(|n| n.split("::").next().unwrap_or("").split("as").next().unwrap_or("").to_string())
        .filter(|n| !n.is_empty() && n != "self")
        .collect();
    (module, names)
}
