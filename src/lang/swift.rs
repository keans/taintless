use super::common::{has_modifier, operator_token, unlabelled_if_none, kids_without_comments as kids, 
    AssignParts, BoolOp, CallParts, Case, Ctl, ExprCtl, Handler, Import, LoopKind, Spec, children_by_field, element_key, enclosing, first_child_of_kind,
    named_children, qualify, text,
};
use crate::ir::StmtKind;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Swift;

const TYPES: &[&str] = &["class_declaration", "protocol_declaration"];

/// A name as the analysis spells it: `a?.b!.c` is `a.b.c`.
fn dotted(t: &str) -> String {
    t.replace("?.", ".").replace("!.", ".").replace(['?', '!'], "")
}

fn is_static(src: &[u8], f: Node) -> bool {
    has_modifier(src, f, &["static", "class"])
}

/// The variable names a `pattern` binds.
fn bound(src: &[u8], p: Node) -> Vec<String> {
    let mut out = vec![];
    if let Some(b) = p.child_by_field_name("bound_identifier") {
        out.push(text(src, b));
    }
    for k in kids(p).into_iter().filter(|k| k.kind() == "pattern") {
        out.extend(bound(src, k));
    }
    out
}

/// The `statements` of a construct (its body), the last one when there are several.
fn body_of<'a>(n: Node<'a>) -> Option<Node<'a>> {
    kids(n).into_iter().rfind(|c| c.kind() == "statements")
}

/// The bindings of a condition (`if let w = y, let z = f()`): each bound name with its value.
fn bindings<'a>(n: Node<'a>) -> (Vec<Node<'a>>, Vec<Node<'a>>) {
    let (mut targets, mut values) = (vec![], vec![]);
    let mut c = n.walk();
    if !c.goto_first_child() {
        return (targets, values);
    }
    let mut pending: Option<Node<'a>> = None;
    loop {
        let k = c.node();
        if k.is_named() {
            match c.field_name() {
                Some("bound_identifier") => pending = Some(k),
                Some("condition") if k.kind() != "value_binding_pattern" => {
                    if let Some(t) = pending.take() {
                        targets.push(t);
                        values.push(k);
                    }
                }
                _ => {}
            }
        }
        if !c.goto_next_sibling() {
            break;
        }
    }
    (targets, values)
}

/// The arguments of a call: values and their labels, with a trailing closure last.
fn arguments<'a>(src: &[u8], n: Node<'a>) -> (Vec<Node<'a>>, Vec<Option<String>>) {
    let (mut args, mut names) = (vec![], vec![]);
    for suffix in kids(n).into_iter().filter(|c| matches!(c.kind(), "call_suffix" | "constructor_suffix")) {
        for k in kids(suffix) {
            match k.kind() {
                "value_arguments" => {
                    for a in kids(k).into_iter().filter(|a| a.kind() == "value_argument") {
                        let Some(v) = a.child_by_field_name("value") else { continue };
                        args.push(v);
                        names.push(a.child_by_field_name("name").and_then(|l| l.named_child(0)).map(|l| text(src, l)));
                    }
                }
                "lambda_literal" => {
                    args.push(k);
                    names.push(None);
                }
                _ => {}
            }
        }
    }
    unlabelled_if_none(args, names)
}

fn field_names(src: &[u8], class: Node) -> Vec<String> {
    let mut out = vec![];
    for body in kids(class).into_iter().filter(|c| c.kind().ends_with("class_body") || c.kind() == "protocol_body") {
        for m in kids(body).into_iter().filter(|m| m.kind() == "property_declaration") {
            if let Some(p) = m.child_by_field_name("name") {
                out.extend(bound(src, p));
            }
        }
    }
    out
}

impl Spec for Swift {
    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "simple_identifier" | "self_expression")
    }

    fn expr_kind(&self, n: Node) -> StmtKind {
        match n.kind() {
            "call_expression" | "constructor_expression" => StmtKind::Call,
            "assignment" => StmtKind::Assign,
            _ => StmtKind::Other,
        }
    }

    fn is_function(&self, n: Node) -> bool {
        matches!(n.kind(), "function_declaration" | "init_declaration" | "deinit_declaration" | "lambda_literal")
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = match f.kind() {
            // `let g = { (a: Int) in .. }` is named after the variable
            "lambda_literal" => f
                .parent()
                .filter(|p| p.kind() == "property_declaration")
                .and_then(|p| p.child_by_field_name("name"))
                .and_then(|p| bound(src, p).into_iter().next())
                .unwrap_or_else(|| "<closure>".into()),
            "init_declaration" => "init".into(),
            "deinit_declaration" => "deinit".into(),
            _ => f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into()),
        };
        qualify(src, f, ".", base, &[("class_declaration", "name"), ("protocol_declaration", "name"), ("function_declaration", "name")])
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        match f.kind() {
            "lambda_literal" => Some(f),
            _ => f.child_by_field_name("body"),
        }
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        let statements = match f.kind() {
            "lambda_literal" => body_of(f),
            _ => f.child_by_field_name("body").and_then(|b| first_child_of_kind(b, "statements")),
        }?;
        // the one expression of a short function or closure is what it returns
        let stmts = kids(statements);
        let [last] = stmts.as_slice() else { return None };
        let last = *last;
        (!matches!(last.kind(), "control_transfer_statement" | "property_declaration" | "assignment" | "if_statement" | "guard_statement" | "for_statement" | "while_statement" | "switch_statement" | "do_statement")).then_some(last)
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        if n.kind() != "import_declaration" {
            return vec![];
        }
        n.named_child(0).map(|m| vec![Import::module(text(src, m), n.start_position().row + 1)]).unwrap_or_default()
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        // `HMAC<SHA256>(key: k)`: a constructor call of a generic type
        if n.kind() == "constructor_expression" {
            let class = n.child_by_field_name("constructed_type")?;
            let name = text(src, class);
            let callee = dotted(name.split('<').next().unwrap_or(&name));
            let (args, names) = arguments(src, n);
            return Some(CallParts { callee, receiver: None, args, names });
        }
        if n.kind() != "call_expression" {
            return None;
        }
        let callee_node = n.named_child(0)?;
        let receiver = (callee_node.kind() == "navigation_expression").then(|| callee_node.child_by_field_name("target")).flatten();
        let (args, names) = arguments(src, n);
        Some(CallParts { callee: dotted(&text(src, callee_node)), receiver, args, names })
    }

    fn member_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<(Node<'a>, String)> {
        if n.kind() != "navigation_expression" {
            return None;
        }
        let suffix = n.child_by_field_name("suffix")?;
        Some((n.child_by_field_name("target")?, text(src, suffix.child_by_field_name("suffix").or_else(|| suffix.named_child(0))?)))
    }

    fn assignment<'a>(&self, src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        match n.kind() {
            "assignment" => {
                let target = n.child_by_field_name("target")?;
                let target = if target.kind() == "directly_assignable_expression" { target.named_child(0).unwrap_or(target) } else { target };
                let augmented = operator_token(src, n, true).is_some_and(|o| o != "=");
                Some(AssignParts { targets: vec![target], values: n.child_by_field_name("result").into_iter().collect(), augmented })
            }
            // `let x = value`, `var y: T = value`
            "property_declaration" => {
                let pattern = n.child_by_field_name("name")?;
                let target = pattern.child_by_field_name("bound_identifier")?;
                Some(AssignParts { targets: vec![target], values: n.child_by_field_name("value").into_iter().collect(), augmented: false })
            }
            "for_statement" => {
                let item = n.child_by_field_name("item")?;
                let target = item.child_by_field_name("bound_identifier").unwrap_or(item);
                Some(AssignParts { targets: vec![target], values: n.child_by_field_name("collection").into_iter().collect(), augmented: false })
            }
            // `if let w = y`, `guard let z = f()`: the names bind the values
            "if_statement" | "guard_statement" | "while_statement" => {
                let (targets, values) = bindings(n);
                (!targets.is_empty()).then_some(AssignParts { targets, values, augmented: false })
            }
            _ => None,
        }
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        match f.kind() {
            "lambda_literal" => {
                let list = f.child_by_field_name("type").and_then(|t| first_child_of_kind(t, "lambda_function_type_parameters"));
                list.map(|l| kids(l).into_iter().filter_map(|p| p.child_by_field_name("name").map(|n| vec![text(src, n)])).collect()).unwrap_or_default()
            }
            _ => kids(f).into_iter().filter(|p| p.kind() == "parameter").filter_map(|p| p.child_by_field_name("name").map(|n| vec![text(src, n)])).collect(),
        }
    }

    fn receiver(&self, src: &[u8], f: Node) -> Option<String> {
        match f.kind() {
            "init_declaration" | "deinit_declaration" => Some("self".into()),
            "function_declaration" if enclosing(f, TYPES).is_some() && !is_static(src, f) => Some("self".into()),
            _ => None,
        }
    }

    /// The properties of the type a method belongs to are fields of `self`, unless the method declares
    /// a variable or parameter of the same name.
    fn implicit_fields(&self, src: &[u8], f: Node) -> Vec<String> {
        let Some(class) = enclosing(f, TYPES) else { return vec![] };
        let mut fields = field_names(src, class);
        let mut locals: HashSet<String> = self.params(src, f).into_iter().flatten().collect();
        let mut stack = vec![f];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "property_declaration" => locals.extend(n.child_by_field_name("name").map(|p| bound(src, p)).unwrap_or_default()),
                "for_statement" => locals.extend(n.child_by_field_name("item").map(|p| bound(src, p)).unwrap_or_default()),
                "if_statement" | "guard_statement" | "while_statement" => {
                    locals.extend(children_by_field(n, "bound_identifier").into_iter().map(|b| text(src, b)));
                }
                _ => {}
            }
            stack.extend(named_children(n));
        }
        fields.retain(|n| !locals.contains(n));
        fields
    }

    fn declared_types(&self, src: &[u8], f: Node) -> (Vec<(String, String)>, Option<String>) {
        let mut out = vec![];
        for p in kids(f).into_iter().filter(|p| p.kind() == "parameter") {
            let names = children_by_field(p, "name");
            if let [n, t, ..] = names.as_slice() {
                out.push((text(src, *n), text(src, *t)));
            }
        }
        let ret = kids(f).into_iter().find(|c| matches!(c.kind(), "user_type" | "optional_type" | "array_type" | "dictionary_type" | "tuple_type")).map(|t| text(src, t));
        (out, ret)
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let Some(class) = enclosing(f, TYPES) else { return vec![] };
        kids(class).into_iter().filter(|c| c.kind() == "inheritance_specifier").filter_map(|c| c.child_by_field_name("inherits_from").map(|t| text(src, t))).collect()
    }

    fn type_decl_name(&self, src: &[u8], n: Node) -> Option<String> {
        TYPES.contains(&n.kind()).then(|| n.child_by_field_name("name").map(|x| text(src, x))).flatten()
    }

    fn sequence_elements<'a>(&self, n: Node<'a>) -> Option<Vec<Node<'a>>> {
        if n.kind() != "array_literal" {
            return None;
        }
        let elems = children_by_field(n, "element");
        (elems.len() <= 32).then_some(elems)
    }

    fn mapping_entries<'a>(&self, src: &[u8], n: Node<'a>) -> Option<Vec<(String, Node<'a>)>> {
        if n.kind() != "dictionary_literal" {
            return None;
        }
        let (keys, values) = (children_by_field(n, "key"), children_by_field(n, "value"));
        if keys.len() != values.len() || keys.len() > 32 {
            return None;
        }
        keys.into_iter().zip(values).map(|(k, v)| Some((element_key(&text(src, k), false)?, v))).collect()
    }

    fn binary_op(&self, src: &[u8], n: Node) -> Option<String> {
        matches!(
            n.kind(),
            "additive_expression" | "multiplicative_expression" | "comparison_expression" | "equality_expression" | "conjunction_expression" | "disjunction_expression" | "range_expression" | "bitwise_operation"
        )
        .then(|| operator_token(src, n, true))
        .flatten()
    }

    fn bool_op<'a>(&self, _src: &[u8], n: Node<'a>) -> Option<BoolOp<'a>> {
        match n.kind() {
            "conjunction_expression" => Some(BoolOp::And(n.child_by_field_name("lhs")?, n.child_by_field_name("rhs")?)),
            "disjunction_expression" => Some(BoolOp::Or(n.child_by_field_name("lhs")?, n.child_by_field_name("rhs")?)),
            "prefix_expression" if n.child_by_field_name("operation").is_some_and(|o| o.kind() == "bang") => Some(BoolOp::Not(n.child_by_field_name("target")?)),
            _ => None,
        }
    }

    fn expr_flow<'a>(&self, _src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "ternary_expression" => Some(ExprCtl::Ternary { cond: f("condition")?, then: f("if_true")?, els: f("if_false")? }),
            "conjunction_expression" => Some(ExprCtl::Short { lhs: f("lhs")?, rhs: f("rhs")?, and: true }),
            "disjunction_expression" => Some(ExprCtl::Short { lhs: f("lhs")?, rhs: f("rhs")?, and: false }),
            "nil_coalescing_expression" => Some(ExprCtl::Short { lhs: f("value")?, rhs: f("if_nil")?, and: false }),
            _ => None,
        }
    }

    fn top_level(&self) -> bool {
        true
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "source_file" | "statements" | "function_body" | "lambda_literal" | "computed_property" => Ctl::Block(kids(n).into_iter().filter(|c| !matches!(c.kind(), "lambda_function_type" | "capture_list")).collect()),
            "import_declaration" | "protocol_declaration" | "typealias_declaration" | "function_declaration" | "init_declaration" | "deinit_declaration" | "subscript_declaration" | "operator_declaration" => Ctl::Skip,
            k if TYPES.contains(&k) => Ctl::Skip,
            "property_declaration" | "assignment" => Ctl::Simple(StmtKind::Assign),
            "call_expression" | "constructor_expression" => Ctl::Simple(StmtKind::Call),
            "try_expression" | "await_expression" => Ctl::Simple(if kids(n).iter().any(|c| c.kind() == "call_expression") { StmtKind::Call } else { StmtKind::Other }),
            "if_statement" => {
                let els = kids(n).into_iter().skip_while(|c| c.kind() != "else").skip(1).find(|c| matches!(c.kind(), "if_statement" | "statements"));
                let then = kids(n).into_iter().find(|c| c.kind() == "statements");
                // the head statement holds the conditions and the bindings (`if let w = y`)
                Ctl::If { pre: vec![], cond: None, then, els }
            }
            "guard_statement" => Ctl::If { pre: vec![], cond: None, then: None, els: body_of(n) },
            "while_statement" => Ctl::Loop { label: None, pre: vec![], kind: LoopKind::Cond, cond: None, body: body_of(n), update: vec![] },
            "repeat_while_statement" => Ctl::DoWhile { body: body_of(n), cond: f("condition") },
            "for_statement" => Ctl::simple_loop(LoopKind::Each, None, body_of(n)),
            "switch_statement" => {
                let cases = kids(n)
                    .into_iter()
                    .filter(|c| c.kind() == "switch_entry")
                    .map(|c| Case {
                        labels: kids(c).into_iter().filter(|k| k.kind() == "switch_pattern").collect(),
                        guard: None,
                        body: kids(c).into_iter().filter(|k| k.kind() == "statements").collect(),
                    })
                    .collect();
                Ctl::Switch { cases, breakable: true, fallthrough: false, exhaustive: false }
            }
            "do_statement" => Ctl::Try {
                pre: vec![],
                closes: vec![],
                body: kids(n).into_iter().find(|c| c.kind() == "statements"),
                handlers: kids(n).into_iter().filter(|c| c.kind() == "catch_block").map(|c| Handler { head: c, body: body_of(c) }).collect(),
                finally: None,
            },
            "control_transfer_statement" => {
                let t = text(src, n);
                let word = t.split_whitespace().next().unwrap_or("");
                match word {
                    "return" => Ctl::Return,
                    "throw" => Ctl::Throw,
                    "break" => Ctl::Break(None),
                    "continue" => Ctl::Continue(None),
                    _ => Ctl::Simple(StmtKind::Other),
                }
            }
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
