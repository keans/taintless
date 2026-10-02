use crate::analysis::deps::DepGraph;
use super::dot::esc;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fmt::Write;

fn name(g: &DepGraph, n: NodeIndex) -> String {
    g.graph[n].display().to_string()
}

/// Per file: what it imports, what it calls into, who depends on it; then
/// import cycles and, optionally, the external modules.
pub fn to_text(g: &DepGraph, external: bool) -> String {
    let mut s = String::new();
    let mut nodes: Vec<NodeIndex> = g.graph.node_indices().collect();
    nodes.sort_by_key(|&n| name(g, n));
    for n in nodes {
        let out: Vec<_> = g.graph.edges(n).collect();
        let incoming: Vec<_> = g.graph.edges_directed(n, petgraph::Direction::Incoming).collect();
        if out.is_empty() && incoming.is_empty() {
            continue;
        }
        let _ = writeln!(s, "{}", name(g, n));
        let mut out = out;
        out.sort_by_key(|e| name(g, e.target()));
        for e in out {
            let w = e.weight();
            let mut how = vec![];
            if !w.imports.is_empty() {
                let lines: Vec<String> = w.imports.iter().map(|(l, m)| format!("{m} @{l}")).collect();
                how.push(format!("imports {}", lines.join(", ")));
            }
            if w.calls > 0 {
                how.push(format!("{} call{} ({})", w.calls, if w.calls == 1 { "" } else { "s" }, w.examples.join("; ")));
            }
            let _ = writeln!(s, "  -> {}  [{}]", name(g, e.target()), how.join("; "));
        }
        let mut by: Vec<String> = incoming.iter().map(|e| name(g, e.source())).collect();
        by.sort();
        if !by.is_empty() {
            let _ = writeln!(s, "  <- used by {} file{}: {}", by.len(), if by.len() == 1 { "" } else { "s" }, by.join(", "));
        }
    }
    let cycles = g.cycles();
    if cycles.is_empty() {
        let _ = writeln!(s, "\nno dependency cycles");
    } else {
        let _ = writeln!(s, "\ndependency cycles ({}):", cycles.len());
        for c in cycles {
            let names: Vec<String> = c.iter().map(|&n| name(g, n)).collect();
            let _ = writeln!(s, "  {}", names.join(" <-> "));
        }
    }
    let mut ranked: Vec<(usize, String)> = g
        .graph
        .node_indices()
        .map(|n| (g.graph.edges_directed(n, petgraph::Direction::Incoming).count(), name(g, n)))
        .filter(|(c, _)| *c > 0)
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    if !ranked.is_empty() {
        let _ = writeln!(s, "most depended on:");
        for (c, n) in ranked.into_iter().take(5) {
            let _ = writeln!(s, "  {n} ({c})");
        }
    }
    if external {
        let mut ext: Vec<_> = g.external.iter().collect();
        ext.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
        let _ = writeln!(s, "external or unresolved modules ({}):", ext.len());
        for (m, users) in ext.into_iter().take(50) {
            let _ = writeln!(s, "  {m} ({} file{})", users.len(), if users.len() == 1 { "" } else { "s" });
        }
    }
    s
}

/// Solid edges are imports (labelled with call counts); dashed edges are calls
/// without an import. Files in a cycle are red.
pub fn to_dot(g: &DepGraph) -> String {
    let in_cycle: HashSet<NodeIndex> = g.cycles().into_iter().flatten().collect();
    let mut s = String::from(
        "digraph deps {\n  rankdir=LR;\n  newrank=true;\n  node [shape=box style=\"rounded,filled\" fillcolor=\"#f4f6f8\" color=\"#8a94a6\" fontname=\"Menlo\" fontsize=10];\n  \
         edge [fontname=\"Helvetica\" fontsize=9 color=\"#5b6573\"];\n",
    );
    for n in g.graph.node_indices() {
        let fill = if in_cycle.contains(&n) { " fillcolor=\"#f4d6d6\" color=\"#c62828\"" } else { "" };
        let _ = writeln!(s, "  n{} [label=\"{}\"{fill}];", n.index(), esc(&name(g, n)));
    }
    for e in g.graph.edge_references() {
        let w = e.weight();
        let mut attrs = vec![];
        if w.imports.is_empty() {
            attrs.push("style=dashed".to_string());
        }
        if w.calls > 0 {
            attrs.push(format!("label=\"{}\"", w.calls));
        }
        let _ = writeln!(s, "  n{} -> n{} [{}];", e.source().index(), e.target().index(), attrs.join(" "));
    }
    s.push_str("}\n");
    s
}

pub fn to_json(g: &DepGraph) -> Value {
    json!({
        "files": g.graph.node_indices().map(|n| json!({ "id": n.index(), "path": name(g, n) })).collect::<Vec<_>>(),
        "edges": g.graph.edge_references().map(|e| json!({
            "from": e.source().index(),
            "to": e.target().index(),
            "imports": e.weight().imports.iter().map(|(l, m)| json!({ "line": l, "module": m })).collect::<Vec<_>>(),
            "calls": e.weight().calls,
            "examples": e.weight().examples,
        })).collect::<Vec<_>>(),
        "cycles": g.cycles().into_iter().map(|c| c.into_iter().map(|n| n.index()).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "external": g.external.iter().map(|(m, users)| (m.clone(), json!(users))).collect::<serde_json::Map<_, _>>(),
    })
}
