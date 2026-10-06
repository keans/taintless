use super::common::{operator_token, unlabelled_if_none, kids_without_comments as kids, 
    AssignParts, BoolOp, CallParts, Case, Ctl, ExprCtl, Handler, Import, LoopKind, Spec, children_by_field, element_key, enclosing, named_children,
    qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct Php;

const TYPES: &[&str] = &["class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"];

/// A name as the analysis spells it: `\App\helper` is `App.helper`, `Runner::build` is `Runner.build`.
fn dotted(t: &str) -> String {
    t.trim_start_matches('\\').replace("::", ".").replace("->", ".").replace("?.", ".").replace('\\', ".")
}

/// The operator of a binary expression: the token between the operands.
fn operator(src: &[u8], n: Node) -> Option<String> {
    if let Some(o) = n.child_by_field_name("operator") {
        return Some(text(src, o));
    }
    operator_token(src, n, true)
}

/// The values of an `arguments` list: `name: value` reduced to the value and its name.
fn arguments<'a>(src: &[u8], n: Node<'a>) -> (Vec<Node<'a>>, Vec<Option<String>>) {
    let (mut args, mut names) = (vec![], vec![]);
    let Some(list) = n.child_by_field_name("arguments").or_else(|| named_children(n).into_iter().find(|c| c.kind() == "arguments")) else { return (args, names) };
    for a in kids(list) {
        match a.kind() {
            "argument" => {
                let name = a.child_by_field_name("name").map(|x| text(src, x));
                let value = named_children(a).into_iter().rfind(|c| Some(c.id()) != a.child_by_field_name("name").map(|x| x.id()));
                if let Some(v) = value {
                    args.push(v);
                    names.push(name);
                }
            }
            "variadic_unpacking" => {
                if let Some(x) = a.named_child(0) {
                    args.push(x);
                    names.push(None);
                }
            }
            _ => {}
        }
    }
    unlabelled_if_none(args, names)
}

fn param_name(src: &[u8], p: Node) -> Option<String> {
    matches!(p.kind(), "simple_parameter" | "property_promotion_parameter" | "variadic_parameter").then(|| p.child_by_field_name("name").map(|n| text(src, n))).flatten()
}

impl Spec for Php {
    fn is_subscript(&self, n: Node) -> bool {
        n.kind() == "subscript_expression"
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "variable_name" | "name" | "relative_scope")
    }

    fn expr_kind(&self, n: Node) -> StmtKind {
        match n.kind() {
            "function_call_expression" | "member_call_expression" | "nullsafe_member_call_expression" | "scoped_call_expression" | "object_creation_expression" => StmtKind::Call,
            "assignment_expression" | "augmented_assignment_expression" | "reference_assignment_expression" => StmtKind::Assign,
            _ => StmtKind::Other,
        }
    }

    fn is_function(&self, n: Node) -> bool {
        matches!(n.kind(), "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function")
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = match f.kind() {
            // `$f = function ($x) { .. };` is named after the variable
            "anonymous_function" | "arrow_function" => f
                .parent()
                .filter(|p| p.kind() == "assignment_expression")
                .and_then(|p| p.child_by_field_name("left"))
                .filter(|l| l.kind() == "variable_name")
                .map(|n| text(src, n).trim_start_matches('$').to_string())
                .unwrap_or_else(|| "<closure>".into()),
            _ => f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into()),
        };
        qualify(src, f, ".", base, &[("class_declaration", "name"), ("interface_declaration", "name"), ("trait_declaration", "name"), ("enum_declaration", "name"), ("function_definition", "name"), ("method_declaration", "name")])
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        (f.kind() == "arrow_function").then(|| f.child_by_field_name("body")).flatten()
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        let line = n.start_position().row + 1;
        match n.kind() {
            // `use App\Models\User;`, `use App\{A, B};`, `use function strlen;`
            "namespace_use_declaration" => {
                let group_prefix = n.child_by_field_name("prefix").or_else(|| named_children(n).into_iter().find(|c| c.kind() == "namespace_name")).map(|p| dotted(&text(src, p)).replace('.', "/"));
                let mut out = vec![];
                for clause in named_children(n).into_iter().flat_map(|c| if c.kind() == "namespace_use_group" { named_children(c) } else { vec![c] }) {
                    if clause.kind() != "namespace_use_clause" {
                        continue;
                    }
                    let Some(name) = named_children(clause).into_iter().find(|c| matches!(c.kind(), "qualified_name" | "name")) else { continue };
                    let path = dotted(&text(src, name)).replace('.', "/");
                    let module = match &group_prefix {
                        Some(p) if clause.parent().is_some_and(|g| g.kind() == "namespace_use_group") => format!("{p}/{path}"),
                        _ => path,
                    };
                    out.push(Import::module(module, line));
                }
                out
            }
            // `require 'lib/helper.php';`, `include __DIR__ . '/x.php';`
            "include_expression" | "include_once_expression" | "require_expression" | "require_once_expression" => {
                let Some(arg) = n.named_child(0) else { return vec![] };
                // the last string literal of a concatenation names the file
                let mut lit = None;
                super::common::collect_nodes(arg, &|_| false, &mut |k| {
                    if matches!(k.kind(), "string" | "encapsed_string") {
                        lit = Some(k);
                    }
                });
                let lit = if matches!(arg.kind(), "string" | "encapsed_string") { Some(arg) } else { lit };
                let Some(lit) = lit else { return vec![] };
                if kids(lit).iter().any(|c| !matches!(c.kind(), "string_content" | "string_value")) {
                    return vec![];
                }
                let name = super::common::unquote(&text(src, lit));
                let relative = !name.starts_with('/') && !name.contains("://");
                let module = if name.starts_with('.') || !relative { name } else { format!("./{name}") };
                vec![Import::module(module.replacen("./.", ".", 1).replace("//", "/"), line)]
            }
            _ => vec![],
        }
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        match n.kind() {
            "function_call_expression" => {
                let function = n.child_by_field_name("function")?;
                let (args, names) = arguments(src, n);
                Some(CallParts { callee: dotted(&text(src, function)), receiver: None, args, names })
            }
            "member_call_expression" | "nullsafe_member_call_expression" => {
                let object = n.child_by_field_name("object")?;
                let name = text(src, n.child_by_field_name("name")?);
                let (args, names) = arguments(src, n);
                Some(CallParts { callee: format!("{}.{name}", dotted(&text(src, object))), receiver: Some(object), args, names })
            }
            "scoped_call_expression" => {
                let scope = n.child_by_field_name("scope")?;
                let name = text(src, n.child_by_field_name("name")?);
                let (args, names) = arguments(src, n);
                Some(CallParts { callee: format!("{}.{name}", dotted(&text(src, scope))), receiver: None, args, names })
            }
            "object_creation_expression" => {
                let class = named_children(n).into_iter().find(|c| matches!(c.kind(), "name" | "qualified_name"))?;
                let (args, names) = arguments(src, n);
                Some(CallParts { callee: dotted(&text(src, class)), receiver: None, args, names })
            }
            // the language constructs that take data like a function: `echo $x`, `include $f`
            "echo_statement" => Some(CallParts { callee: "echo".into(), receiver: None, args: kids(n), names: vec![] }),
            "print_intrinsic" => Some(CallParts { callee: "print".into(), receiver: None, args: kids(n), names: vec![] }),
            "include_expression" | "include_once_expression" | "require_expression" | "require_once_expression" => {
                let callee = n.kind().trim_end_matches("_expression").to_string();
                Some(CallParts { callee, receiver: None, args: kids(n), names: vec![] })
            }
            "shell_command_expression" => {
                let mut vars = vec![];
                super::common::collect_nodes(n, &|_| false, &mut |k| {
                    if k.kind() == "variable_name" {
                        vars.push(k);
                    }
                });
                Some(CallParts { callee: "shell_exec".into(), receiver: None, args: vars, names: vec![] })
            }
            _ => None,
        }
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        match n.kind() {
            "member_access_expression" | "nullsafe_member_access_expression" => Some((n.child_by_field_name("object")?, text(src, n.child_by_field_name("name")?))),
            // `self::$count`, `Config::$key`
            "scoped_property_access_expression" => Some((n.child_by_field_name("scope")?, text(src, n.child_by_field_name("name")?).trim_start_matches('$').to_string())),
            _ => None,
        }
    }

    fn assignment<'a>(&self, _src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "assignment_expression" | "reference_assignment_expression" | "augmented_assignment_expression" => {
                Some(AssignParts { targets: vec![f("left")?], values: f("right").into_iter().collect(), augmented: n.kind() == "augmented_assignment_expression" })
            }
            // `foreach ($items as $k => $v)`: the variables take what the collection holds
            "foreach_statement" => {
                let parts: Vec<Node<'a>> = kids(n).into_iter().filter(|c| Some(c.id()) != f("body").map(|b| b.id())).collect();
                let (collection, binding) = (*parts.first()?, parts.get(1).copied()?);
                let targets = if binding.kind() == "pair" { kids(binding) } else { vec![binding] };
                Some(AssignParts { targets, values: vec![collection], augmented: false })
            }
            _ => None,
        }
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        let Some(ps) = f.child_by_field_name("parameters") else { return vec![] };
        kids(ps).into_iter().filter_map(|p| param_name(src, p)).map(|n| vec![n]).collect()
    }

    fn receiver(&self, _src: &[u8], f: Node) -> Option<String> {
        (f.kind() == "method_declaration" && !kids(f).iter().any(|c| c.kind() == "static_modifier")).then(|| "$this".to_string())
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        if let Some(ps) = f.child_by_field_name("parameters") {
            for p in kids(ps) {
                if let (Some(name), Some(t)) = (param_name(src, p), p.child_by_field_name("type")) {
                    out.push((name, text(src, t)));
                }
            }
        }
        (out, f.child_by_field_name("return_type").map(|t| text(src, t)))
    }

    fn declared_vars(&self, src: &[u8], f: Node) -> (super::common::Scoped, super::common::Typed) {
        let mut fields = vec![];
        if let Some(body) = enclosing(f, TYPES).and_then(|c| c.child_by_field_name("body")) {
            for m in kids(body) {
                if m.kind() != "property_declaration" {
                    continue;
                }
                let Some(t) = m.child_by_field_name("type").map(|t| text(src, t)) else { continue };
                for e in kids(m).into_iter().filter(|e| e.kind() == "property_element") {
                    if let Some(n) = e.child_by_field_name("name") {
                        fields.push((text(src, n).trim_start_matches('$').to_string(), t.clone()));
                    }
                }
            }
        }
        (vec![], fields)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let Some(class) = enclosing(f, TYPES) else { return vec![] };
        kids(class)
            .into_iter()
            .filter(|c| matches!(c.kind(), "base_clause" | "class_interface_clause"))
            .flat_map(|c| kids(c).into_iter().map(|n| dotted(&text(src, n))))
            .collect()
    }

    fn type_decl_name(&self, src: &[u8], n: Node) -> Option<String> {
        TYPES.contains(&n.kind()).then(|| n.child_by_field_name("name").map(|x| text(src, x))).flatten()
    }

    fn sequence_elements<'a>(&self, n: Node<'a>) -> Option<Vec<Node<'a>>> {
        if n.kind() != "array_creation_expression" {
            return None;
        }
        let items = kids(n);
        // only a list: `[a, b]`, not `['k' => v]`
        if items.iter().any(|i| i.kind() != "array_element_initializer" || i.named_child_count() != 1) || items.len() > 32 {
            return None;
        }
        items.into_iter().map(|i| i.named_child(0)).collect()
    }

    fn mapping_entries<'a>(&self, src: &[u8], n: Node<'a>) -> Option<Vec<(String, Node<'a>)>> {
        if n.kind() != "array_creation_expression" {
            return None;
        }
        let mut out = vec![];
        for i in kids(n) {
            if i.kind() != "array_element_initializer" || i.named_child_count() != 2 {
                return None;
            }
            let (k, v) = (i.named_child(0)?, i.named_child(1)?);
            out.push((element_key(&text(src, k), false)?, v));
        }
        (!out.is_empty() && out.len() <= 32).then_some(out)
    }

    fn binary_op(&self, src: &[u8], n: Node) -> Option<String> {
        (n.kind() == "binary_expression").then(|| operator(src, n)).flatten()
    }

    fn bool_op<'a>(&self, src: &[u8], n: Node<'a>) -> Option<BoolOp<'a>> {
        match n.kind() {
            "binary_expression" => {
                let (l, r) = (n.child_by_field_name("left")?, n.child_by_field_name("right")?);
                match operator(src, n)?.to_ascii_lowercase().as_str() {
                    "&&" | "and" => Some(BoolOp::And(l, r)),
                    "||" | "or" => Some(BoolOp::Or(l, r)),
                    _ => None,
                }
            }
            "unary_op_expression" if operator(src, n).as_deref() == Some("!") => Some(BoolOp::Not(n.child_by_field_name("argument")?)),
            _ => None,
        }
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "conditional_expression" => Some(ExprCtl::Ternary { cond: f("condition")?, then: f("body")?, els: f("alternative")? }),
            "binary_expression" => {
                let (lhs, rhs) = (f("left")?, f("right")?);
                match operator(src, n)?.to_ascii_lowercase().as_str() {
                    "&&" | "and" => Some(ExprCtl::Short { lhs, rhs, and: true }),
                    "||" | "or" | "??" => Some(ExprCtl::Short { lhs, rhs, and: false }),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn top_level(&self) -> bool {
        true
    }

    fn classify<'a>(&self, _src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "program" | "compound_statement" | "colon_block" | "declaration_list" | "switch_block" => Ctl::Block(kids(n).into_iter().filter(|c| !matches!(c.kind(), "php_tag" | "text_interpolation" | "text")).collect()),
            "php_tag" | "text" | "text_interpolation" | "namespace_use_declaration" | "function_definition" | "method_declaration" | "const_declaration" => Ctl::Skip,
            k if TYPES.contains(&k) => Ctl::Skip,
            "namespace_definition" => match f("body") {
                Some(b) => Ctl::Block(vec![b]),
                None => Ctl::Skip,
            },
            "expression_statement" => match n.named_child(0).map(|c| c.kind()) {
                Some("assignment_expression" | "augmented_assignment_expression" | "reference_assignment_expression") => Ctl::Simple(StmtKind::Assign),
                Some("throw_expression") => Ctl::Throw,
                Some(k) if k.ends_with("call_expression") || matches!(k, "object_creation_expression" | "print_intrinsic" | "include_expression" | "include_once_expression" | "require_expression" | "require_once_expression" | "shell_command_expression") => Ctl::Simple(StmtKind::Call),
                _ => Ctl::Simple(StmtKind::Other),
            },
            "echo_statement" => Ctl::Simple(StmtKind::Call),
            "if_statement" => Ctl::If { pre: vec![], cond: f("condition"), then: f("body"), els: children_by_field(n, "alternative").into_iter().next() },
            // the remaining `elseif` / `else` clauses chain through next siblings
            "else_if_clause" => Ctl::If { pre: vec![], cond: f("condition"), then: f("body"), els: n.next_named_sibling().filter(|s| matches!(s.kind(), "else_if_clause" | "else_clause")) },
            "else_clause" => Ctl::Block(f("body").into_iter().collect()),
            "while_statement" => Ctl::simple_loop(LoopKind::Cond, f("condition"), f("body")),
            "do_statement" => Ctl::DoWhile { body: f("body"), cond: f("condition") },
            "for_statement" => {
                let cond = children_by_field(n, "condition").into_iter().next();
                Ctl::Loop { label: None, pre: children_by_field(n, "initialize"), kind: if cond.is_some() { LoopKind::Cond } else { LoopKind::Infinite }, cond, body: f("body"), update: children_by_field(n, "update") }
            }
            "foreach_statement" => Ctl::simple_loop(LoopKind::Each, None, f("body")),
            "switch_statement" => {
                let cases = f("body")
                    .map(kids)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|c| match c.kind() {
                        "case_statement" => {
                            let value = c.child_by_field_name("value");
                            let body = kids(c).into_iter().filter(|k| Some(k.id()) != value.map(|v| v.id())).collect();
                            Some(Case { labels: value.into_iter().collect(), guard: None, body })
                        }
                        "default_statement" => Some(Case { labels: vec![], guard: None, body: kids(c) }),
                        _ => None,
                    })
                    .collect();
                Ctl::Switch { cases, breakable: true, fallthrough: true, exhaustive: false }
            }
            "try_statement" => Ctl::Try {
                pre: vec![],
                closes: vec![],
                body: f("body"),
                handlers: kids(n).into_iter().filter(|c| c.kind() == "catch_clause").map(|c| Handler { head: c, body: c.child_by_field_name("body") }).collect(),
                finally: kids(n).into_iter().find(|c| c.kind() == "finally_clause").and_then(|c| c.child_by_field_name("body")),
            },
            "return_statement" => Ctl::Return,
            "break_statement" => Ctl::Break(None),
            "continue_statement" => Ctl::Continue(None),
            "exit_statement" => Ctl::Return,
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
