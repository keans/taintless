use crate::analysis::dataflow::{DataFlow, EdgeKind, NodeKind};
use super::dot::{arrow, esc, header};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;

fn label(df: &DataFlow, n: NodeIndex) -> String {
    let node = &df.graph[n];
    let at = if node.line > 0 { format!(":{}", node.line) } else { String::new() };
    match node.kind {
        NodeKind::Param => format!("param {}", node.var),
        NodeKind::Def => format!("{}{at}", node.var),
        NodeKind::Call => format!("{}(){at}", node.var),
        NodeKind::Return => format!("return{at}"),
        NodeKind::Free => node.var.clone(),
        NodeKind::Branch => format!("if {}", node.var),
        NodeKind::Field => format!("field {}", node.var),
    }
}

/// The nodes to show: `keep` (a slice) intersected with the functions whose
/// qualified name contains `function`.
pub fn select(df: &DataFlow, keep: Option<&HashSet<NodeIndex>>, function: Option<&str>) -> Vec<NodeIndex> {
    df.graph
        .node_indices()
        .filter(|n| keep.is_none_or(|k| k.contains(n)))
        .filter(|n| function.is_none_or(|f| df.functions[df.graph[*n].func].name.contains(f)))
        .collect()
}

fn by_function(df: &DataFlow, nodes: &[NodeIndex]) -> BTreeMap<usize, Vec<NodeIndex>> {
    let mut m: BTreeMap<usize, Vec<NodeIndex>> = BTreeMap::new();
    for &n in nodes.iter().filter(|&&n| df.graph[n].kind != NodeKind::Field) {
        m.entry(df.graph[n].func).or_default().push(n);
    }
    m
}

/// One line per node with what flows into it, grouped by function.
pub fn to_text(df: &DataFlow, nodes: &[NodeIndex]) -> String {
    let shown: HashSet<_> = nodes.iter().copied().collect();
    let mut s = String::new();
    for &n in nodes.iter().filter(|&&n| df.graph[n].kind == NodeKind::Field) {
        let mut from: Vec<String> = df
            .graph
            .edges_directed(n, petgraph::Direction::Incoming)
            .filter(|e| shown.contains(&e.source()))
            .map(|e| label(df, e.source()))
            .collect();
        from.sort();
        let arrow = arrow("<-", &from);
        let _ = writeln!(s, "{}{arrow}", label(df, n));
    }
    for (f, ns) in by_function(df, nodes) {
        let m = &df.functions[f];
        let _ = writeln!(s, "{} ({}:{})", m.name, m.file.display(), m.line);
        for n in ns {
            if matches!(df.graph[n].kind, NodeKind::Free | NodeKind::Param) && df.graph.edges_directed(n, petgraph::Direction::Incoming).next().is_none() {
                let _ = writeln!(s, "  {}", label(df, n));
                continue;
            }
            let mut from: Vec<String> = df
                .graph
                .edges_directed(n, petgraph::Direction::Incoming)
                .filter(|e| shown.contains(&e.source()))
                .map(|e| {
                    let src = &df.graph[e.source()];
                    let l = label(df, e.source());
                    if src.func != df.graph[n].func { format!("{l} [{}]", df.functions[src.func].name) } else { l }
                })
                .collect();
            from.sort();
            from.dedup();
            let arrow = arrow("<-", &from);
            let _ = writeln!(s, "  {}{arrow}", label(df, n));
        }
    }
    s
}

/// One cluster per function. Dashed edges cross function boundaries: blue into
/// a parameter, brown out of a return.
pub fn to_dot(df: &DataFlow, nodes: &[NodeIndex]) -> String {
    let shown: HashSet<_> = nodes.iter().copied().collect();
    let mut s = header("dataflow");
    for (f, ns) in by_function(df, nodes) {
        let m = &df.functions[f];
        let _ = writeln!(s, "  subgraph cluster_{f} {{\n    label=\"{}\"; bgcolor=\"#fafbfc\";", esc(&m.name));
        for n in ns {
            let style = match df.graph[n].kind {
                NodeKind::Param => " shape=ellipse fillcolor=\"#d7efdc\"",
                NodeKind::Free => " shape=ellipse fillcolor=\"#f6e3c5\" color=\"#b7791f\"",
                NodeKind::Call => " fillcolor=\"#d6e4f5\"",
                NodeKind::Return => " fillcolor=\"#eadbd0\" color=\"#8d6e63\"",
                NodeKind::Branch => " shape=diamond fillcolor=\"#fff3c4\" color=\"#b7791f\"",
                NodeKind::Def | NodeKind::Field => "",
            };
            let _ = writeln!(s, "    n{} [label=\"{}\"{style}];", n.index(), esc(&label(df, n)));
        }
        s.push_str("  }\n");
    }
    for &n in nodes.iter().filter(|&&n| df.graph[n].kind == NodeKind::Field) {
        let _ = writeln!(s, "  n{} [label=\"{}\" shape=hexagon fillcolor=\"#e6dff3\" color=\"#6a4c93\"];", n.index(), esc(&label(df, n)));
    }
    for e in df.graph.edge_references() {
        if !shown.contains(&e.source()) || !shown.contains(&e.target()) {
            continue;
        }
        let attrs = match (e.weight().kind, &e.weight().label) {
            (EdgeKind::Flow, _) => String::new(),
            (EdgeKind::Arg, l) => {
                format!(" [style=dashed color=\"#1565c0\"{}]", l.as_ref().map(|l| format!(" label=\"{}\"", esc(l))).unwrap_or_default())
            }
            (EdgeKind::Ret, _) => " [style=dashed color=\"#8d6e63\"]".to_string(),
            (EdgeKind::Control, l) => {
                format!(" [style=dotted color=\"#b7791f\"{}]", l.as_ref().map(|l| format!(" label=\"{}\"", esc(l))).unwrap_or_default())
            }
        };
        let _ = writeln!(s, "  n{} -> n{}{attrs};", e.source().index(), e.target().index());
    }
    s.push_str("}\n");
    s
}

pub fn to_json(df: &DataFlow, nodes: &[NodeIndex]) -> Value {
    let shown: HashSet<_> = nodes.iter().copied().collect();
    json!({
        "functions": df.functions.iter().enumerate().map(|(i, m)| json!({
            "id": i, "name": m.name, "file": m.file.display().to_string(), "line": m.line,
        })).collect::<Vec<_>>(),
        "nodes": nodes.iter().map(|&n| {
            let x = &df.graph[n];
            json!({
                "id": n.index(), "function": x.func, "var": x.var, "line": x.line,
                "kind": match x.kind {
                    NodeKind::Param => "param", NodeKind::Def => "def", NodeKind::Call => "call",
                    NodeKind::Return => "return", NodeKind::Free => "free", NodeKind::Field => "field", NodeKind::Branch => "branch",
                },
            })
        }).collect::<Vec<_>>(),
        "edges": df.graph.edge_references()
            .filter(|e| shown.contains(&e.source()) && shown.contains(&e.target()))
            .map(|e| json!({
                "from": e.source().index(), "to": e.target().index(),
                "kind": match e.weight().kind { EdgeKind::Flow => "flow", EdgeKind::Arg => "arg", EdgeKind::Ret => "ret", EdgeKind::Control => "control" },
                "param": e.weight().label,
            })).collect::<Vec<_>>(),
    })
}
