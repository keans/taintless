use super::common::{unlabelled_if_none, kids_without_comments as kids, 
    AssignParts, BoolOp, CallParts, Case, Ctl, ExprCtl, Handler, Import, LoopKind, Spec, children_by_field, element_key, enclosing,
    first_child_of_kind, qualify, text,
};
use crate::ir::StmtKind;
use tree_sitter::Node;

pub struct Ruby;

const SCOPES: &[&str] = &["class", "module", "singleton_class"];

/// Does `n` have a `rescue` clause (an `else` belongs to one)?
fn has_rescue(n: Node) -> bool {
    first_child_of_kind(n, "rescue").is_some()
}

fn is_rescue_part(k: &str) -> bool {
    matches!(k, "rescue" | "ensure")
}

fn has_handlers(n: Node) -> bool {
    kids(n).iter().any(|c| is_rescue_part(c.kind()))
}

/// The statements of a `begin` or a method body that come before its `rescue` / `ensure`.
fn main_statements<'a>(n: Node<'a>) -> Vec<Node<'a>> {
    let handled = has_rescue(n);
    kids(n).into_iter().filter(|c| !is_rescue_part(c.kind()) && !(c.kind() == "else" && handled)).collect()
}

/// The arguments of a call: values, with `key: v` reduced to the value and its name, and the
/// block (a function) after them.
fn arguments<'a>(src: &[u8], n: Node<'a>) -> (Vec<Node<'a>>, Vec<Option<String>>) {
    let (mut args, mut names) = (vec![], vec![]);
    if let Some(list) = n.child_by_field_name("arguments") {
        for a in kids(list) {
            match a.kind() {
                "pair" => {
                    let name = a.child_by_field_name("key").filter(|k| k.kind() == "hash_key_symbol").map(|k| text(src, k));
                    if let Some(v) = a.child_by_field_name("value") {
                        args.push(v);
                        names.push(name);
                    }
                }
                "splat_argument" | "hash_splat_argument" | "block_argument" => {
                    if let Some(x) = a.named_child(0) {
                        args.push(x);
                        names.push(None);
                    }
                }
                _ => {
                    args.push(a);
                    names.push(None);
                }
            }
        }
    }
    if let Some(block) = n.child_by_field_name("block") {
        args.push(block);
        names.push(None);
    }
    unlabelled_if_none(args, names)
}

/// The last statement of a body: what a method or block returns when it has no `return`.
fn last_value<'a>(body: Node<'a>) -> Option<Node<'a>> {
    let last = *main_statements(body).last()?;
    const CONTROL: &[&str] = &[
        "if", "unless", "case", "case_match", "while", "until", "for", "begin", "return", "break", "next", "redo", "retry", "class", "module", "method", "singleton_method", "else",
    ];
    (!CONTROL.contains(&last.kind())).then_some(last)
}

fn param_names(src: &[u8], list: Node) -> Vec<Vec<String>> {
    kids(list)
        .into_iter()
        .filter_map(|p| match p.kind() {
            "identifier" => Some(vec![text(src, p)]),
            "optional_parameter" | "keyword_parameter" | "splat_parameter" | "hash_splat_parameter" | "block_parameter" => p.child_by_field_name("name").map(|n| vec![text(src, n)]),
            _ => None,
        })
        .collect()
}

impl Spec for Ruby {
    fn is_subscript(&self, n: Node) -> bool {
        n.kind() == "element_reference"
    }

    fn is_ident(&self, n: Node) -> bool {
        matches!(n.kind(), "identifier" | "instance_variable" | "class_variable" | "global_variable" | "constant" | "self")
    }

    fn expr_kind(&self, n: Node) -> StmtKind {
        match n.kind() {
            "call" => StmtKind::Call,
            "assignment" | "operator_assignment" => StmtKind::Assign,
            _ => StmtKind::Other,
        }
    }

    fn is_function(&self, n: Node) -> bool {
        matches!(n.kind(), "method" | "singleton_method" | "block" | "do_block" | "lambda")
    }

    fn function_name(&self, src: &[u8], f: Node) -> String {
        let base = match f.kind() {
            // `add = ->(a, b) { .. }` is named after the variable
            "lambda" | "block" | "do_block" => f
                .parent()
                .filter(|p| p.kind() == "assignment")
                .and_then(|p| p.child_by_field_name("left"))
                .filter(|l| l.kind() == "identifier")
                .map(|n| text(src, n))
                .unwrap_or_else(|| if f.kind() == "lambda" { "<lambda>".into() } else { "<block>".into() }),
            _ => f.child_by_field_name("name").map(|n| text(src, n)).unwrap_or_else(|| "<anon>".into()),
        };
        qualify(src, f, ".", base, &[("class", "name"), ("module", "name"), ("method", "name"), ("singleton_method", "name")])
    }

    fn function_body<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        f.child_by_field_name("body")
    }

    fn implicit_return<'a>(&self, f: Node<'a>) -> Option<Node<'a>> {
        let body = f.child_by_field_name("body")?;
        match body.kind() {
            "body_statement" | "block_body" => last_value(body),
            // a lambda body is itself a block
            "block" | "do_block" => body.child_by_field_name("body").and_then(last_value),
            // an endless method: `def build(x) = new(x)`
            _ => Some(body),
        }
    }

    fn imports_of(&self, src: &[u8], n: Node) -> Vec<Import> {
        if n.kind() != "call" || n.child_by_field_name("receiver").is_some() {
            return vec![];
        }
        let method = n.child_by_field_name("method").map(|m| text(src, m)).unwrap_or_default();
        if !matches!(method.as_str(), "require" | "require_relative" | "load" | "autoload" | "require_dependency") {
            return vec![];
        }
        let line = n.start_position().row + 1;
        let Some(arg) = n.child_by_field_name("arguments").and_then(|a| kids(a).into_iter().rfind(|x| x.kind() == "string")) else { return vec![] };
        // a string with interpolation names no file
        if kids(arg).iter().any(|c| c.kind() == "interpolation") {
            return vec![];
        }
        let name = super::common::unquote(&text(src, arg));
        let module = if method == "require_relative" && !name.starts_with('.') { format!("./{name}") } else { name };
        vec![Import::module(module, line)]
    }

    fn call_parts<'a>(&self, src: &[u8], n: Node<'a>) -> Option<CallParts<'a>> {
        if n.kind() != "call" {
            return None;
        }
        let method = text(src, n.child_by_field_name("method")?);
        let receiver = n.child_by_field_name("receiver");
        let callee = match receiver {
            Some(r) => format!("{}.{method}", text(src, r)),
            None => method,
        };
        let (args, names) = arguments(src, n);
        // `Job.new(..)` builds an object: the class is not a receiver whose fields the call sets
        let receiver = receiver.filter(|r| !(callee.ends_with(".new") && matches!(r.kind(), "constant" | "scope_resolution")));
        Some(CallParts { callee, receiver, args, names })
    }

    fn assignment<'a>(&self, _src: &[u8], n: Node<'a>) -> Option<AssignParts<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        let (targets, values, augmented) = match n.kind() {
            "assignment" => {
                let left = f("left")?;
                let targets = if left.kind() == "left_assignment_list" { kids(left) } else { vec![left] };
                let right = f("right")?;
                let values = if right.kind() == "right_assignment_list" { kids(right) } else { vec![right] };
                (targets, values, false)
            }
            "operator_assignment" => (vec![f("left")?], f("right").into_iter().collect(), true),
            "for" => (vec![f("pattern")?], f("value").and_then(|v| v.named_child(0)).into_iter().collect(), false),
            _ => return None,
        };
        Some(AssignParts { targets, values, augmented })
    }

    fn params(&self, src: &[u8], f: Node) -> Vec<Vec<String>> {
        f.child_by_field_name("parameters").map(|p| param_names(src, p)).unwrap_or_default()
    }

    fn receiver(&self, _src: &[u8], f: Node) -> Option<String> {
        (f.kind() == "method" && enclosing(f, SCOPES).is_some()).then(|| "self".to_string())
    }

    /// Every instance variable of the class a method belongs to is a field of `self`.
    fn implicit_fields(&self, src: &[u8], f: Node) -> Vec<String> {
        let Some(class) = enclosing(f, SCOPES) else { return vec![] };
        let mut out: Vec<String> = vec![];
        super::common::collect_nodes(class, &|_| false, &mut |n| {
            if n.kind() == "instance_variable" {
                let name = text(src, n);
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        });
        out
    }

    fn class_bases(&self, src: &[u8], f: Node) -> Vec<String> {
        let Some(class) = enclosing(f, &["class"]) else { return vec![] };
        class.child_by_field_name("superclass").and_then(|s| s.named_child(0)).map(|c| vec![text(src, c)]).unwrap_or_default()
    }

    fn type_decl_name(&self, src: &[u8], n: Node) -> Option<String> {
        matches!(n.kind(), "class" | "module").then(|| n.child_by_field_name("name").map(|x| text(src, x))).flatten()
    }

    fn return_value<'a>(&self, n: Node<'a>) -> Option<Node<'a>> {
        let args = n.named_child(0)?;
        if args.kind() == "argument_list" && args.named_child_count() == 1 { args.named_child(0) } else { Some(args) }
    }

    fn mapping_entries<'a>(&self, src: &[u8], n: Node<'a>) -> Option<Vec<(String, Node<'a>)>> {
        if n.kind() != "hash" {
            return None;
        }
        let mut out = vec![];
        for e in kids(n) {
            if e.kind() != "pair" {
                return None;
            }
            let (k, v) = (e.child_by_field_name("key")?, e.child_by_field_name("value")?);
            let t = text(src, k);
            let key = match k.kind() {
                "hash_key_symbol" => element_key(&t, true)?,
                "simple_symbol" => element_key(t.trim_start_matches(':'), true)?,
                _ => element_key(&t, false)?,
            };
            out.push((key, v));
        }
        (out.len() <= 32).then_some(out)
    }

    fn binary_op(&self, src: &[u8], n: Node) -> Option<String> {
        (n.kind() == "binary").then(|| n.child_by_field_name("operator").map(|o| text(src, o))).flatten()
    }

    fn bool_op<'a>(&self, src: &[u8], n: Node<'a>) -> Option<BoolOp<'a>> {
        match n.kind() {
            "binary" => {
                let (l, r) = (n.child_by_field_name("left")?, n.child_by_field_name("right")?);
                match text(src, n.child_by_field_name("operator")?).as_str() {
                    "&&" | "and" => Some(BoolOp::And(l, r)),
                    "||" | "or" => Some(BoolOp::Or(l, r)),
                    _ => None,
                }
            }
            "unary" if matches!(text(src, n.child_by_field_name("operator")?).as_str(), "!" | "not") => Some(BoolOp::Not(n.child_by_field_name("operand")?)),
            _ => None,
        }
    }

    fn expr_flow<'a>(&self, src: &[u8], n: Node<'a>) -> Option<ExprCtl<'a>> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "conditional" => Some(ExprCtl::Ternary { cond: f("condition")?, then: f("consequence")?, els: f("alternative")? }),
            "binary" => {
                let and = match text(src, f("operator")?).as_str() {
                    "&&" | "and" => true,
                    "||" | "or" => false,
                    _ => return None,
                };
                Some(ExprCtl::Short { lhs: f("left")?, rhs: f("right")?, and })
            }
            _ => None,
        }
    }

    fn try_else<'a>(&self, n: Node<'a>) -> Option<Node<'a>> {
        first_child_of_kind(n, "rescue").and_then(|_| first_child_of_kind(n, "else"))
    }

    fn top_level(&self) -> bool {
        true
    }

    fn classify<'a>(&self, src: &[u8], n: Node<'a>) -> Ctl<'a> {
        let f = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "program" | "block_body" | "then" | "else" | "do" | "ensure" | "parenthesized_statements" | "begin_block" | "end_block" => Ctl::Block(kids(n)),
            // statements that may `rescue` / `ensure`: they run first, and a failure reaches the handlers
            "body_statement" | "begin" if has_handlers(n) => Ctl::Try {
                pre: main_statements(n),
                closes: vec![],
                body: None,
                handlers: kids(n).into_iter().filter(|c| c.kind() == "rescue").map(|c| Handler { head: c, body: c.child_by_field_name("body") }).collect(),
                finally: first_child_of_kind(n, "ensure"),
            },
            "body_statement" | "begin" => Ctl::Block(kids(n)),
            "if" | "elsif" => Ctl::If { pre: vec![], cond: f("condition"), then: f("consequence"), els: f("alternative") },
            "unless" => Ctl::If { pre: vec![], cond: f("condition"), then: f("alternative"), els: f("consequence") },
            "if_modifier" => Ctl::If { pre: vec![], cond: f("condition"), then: f("body"), els: None },
            "unless_modifier" => Ctl::If { pre: vec![], cond: f("condition"), then: None, els: f("body") },
            "while" | "until" | "while_modifier" | "until_modifier" => Ctl::simple_loop(LoopKind::Cond, f("condition"), f("body")),
            "for" => Ctl::simple_loop(LoopKind::Each, None, f("body")),
            "case" | "case_match" => {
                let cases = kids(n)
                    .into_iter()
                    .filter_map(|c| match c.kind() {
                        "when" => Some(Case { labels: children_by_field(c, "pattern"), guard: None, body: c.child_by_field_name("body").into_iter().collect() }),
                        "in_clause" => Some(Case {
                            labels: c.child_by_field_name("pattern").into_iter().collect(),
                            guard: c.child_by_field_name("guard").and_then(|g| g.child_by_field_name("condition")),
                            body: c.child_by_field_name("body").into_iter().collect(),
                        }),
                        "else" => Some(Case { labels: vec![], guard: None, body: vec![c] }),
                        _ => None,
                    })
                    .collect();
                Ctl::Switch { cases, breakable: false, fallthrough: false, exhaustive: false }
            }
            "return" => Ctl::Return,
            "break" => Ctl::Break(None),
            "next" => Ctl::Continue(None),
            "class" | "module" | "singleton_class" | "method" | "singleton_method" => Ctl::Skip,
            "assignment" | "operator_assignment" => Ctl::Simple(StmtKind::Assign),
            "call" => {
                let raise = n.child_by_field_name("receiver").is_none() && matches!(f("method").map(|m| text(src, m)).as_deref(), Some("raise" | "fail"));
                if raise { Ctl::Throw } else { Ctl::Simple(StmtKind::Call) }
            }
            _ => Ctl::Simple(StmtKind::Other),
        }
    }
}
