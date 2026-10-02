use crate::analysis::callgraph::CallGraph;
use super::dot::{arrow, esc, header};
use petgraph::visit::EdgeRef;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;

/// The functions of each file, in file order.
fn by_file(g: &petgraph::graph::DiGraph<crate::analysis::callgraph::FnNode, crate::analysis::callgraph::CallEdge>) -> BTreeMap<String, Vec<petgraph::graph::NodeIndex>> {
    let mut by_file: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for n in g.node_indices() {
        by_file.entry(g[n].file.display().to_string()).or_default().push(n);
    }
    by_file
}

/// One line per function: `name (file:line) -> callees`, then roots and cycles.
pub fn to_text(cg: &CallGraph, external: bool) -> String {
    let g = &cg.graph;
    let mut s = String::new();
    let by_file = by_file(g);
    for (file, nodes) in by_file {
        let _ = writeln!(s, "{file}");
        for n in nodes {
            // in the order the calls appear in the function
            let mut out: Vec<_> = g.edges(n).collect();
            out.sort_by_key(|e| (e.weight().line, e.target().index()));
            let callees: Vec<String> = out
                .into_iter()
                .map(|e| {
                    let w = e.weight();
                    let sites = if w.sites > 1 { format!(" x{}", w.sites) } else { String::new() };
                    let by_ref = if w.callback_lines.len() == w.sites { " [by reference]" } else { "" };
                    format!("{}{sites}{by_ref}", g[e.target()].name)
                })
                .collect();
            let arrow = arrow("->", &callees);
            let _ = writeln!(s, "  {} (line {}){arrow}", g[n].name, g[n].line);
        }
    }
    let roots: Vec<_> = cg.roots().into_iter().map(|n| g[n].name.as_str()).collect();
    let _ = writeln!(s, "\nnot called by any scanned function ({}): {}", roots.len(), roots.join(", "));
    let rec = cg.recursive_groups();
    if !rec.is_empty() {
        let _ = writeln!(s, "recursive:");
        for grp in rec {
            let names: Vec<_> = grp.iter().map(|&n| g[n].name.as_str()).collect();
            let _ = writeln!(s, "  {}", names.join(" <-> "));
        }
    }
    if external {
        let mut ext: Vec<_> = cg.external.iter().collect();
        ext.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let _ = writeln!(s, "external calls (top 30):");
        for (name, n) in ext.into_iter().take(30) {
            let _ = writeln!(s, "  {name} x{n}");
        }
    }
    s
}

/// One cluster per file; entry points are green, recursive functions red.
pub fn to_dot(cg: &CallGraph) -> String {
    let g = &cg.graph;
    let roots: HashSet<_> = cg.roots().into_iter().collect();
    let rec: HashSet<_> = cg.recursive_groups().into_iter().flatten().collect();
    let mut s = header("calls");
    let by_file = by_file(g);
    for (i, (file, nodes)) in by_file.into_iter().enumerate() {
        let _ = writeln!(s, "  subgraph cluster_{i} {{\n    label=\"{}\"; bgcolor=\"#fafbfc\";", esc(&file));
        for n in nodes {
            let fill = if rec.contains(&n) {
                " fillcolor=\"#f4d6d6\" color=\"#c62828\""
            } else if roots.contains(&n) {
                " fillcolor=\"#d7efdc\""
            } else {
                ""
            };
            let _ = writeln!(s, "    f{} [label=\"{}\"{fill}];", n.index(), esc(&g[n].name));
        }
        s.push_str("  }\n");
    }
    for e in g.edge_references() {
        let label = if e.weight().sites > 1 { format!(" [label=\"x{}\"]", e.weight().sites) } else { String::new() };
        let _ = writeln!(s, "  f{} -> f{}{label};", e.source().index(), e.target().index());
    }
    s.push_str("}\n");
    s
}

pub fn to_json(cg: &CallGraph) -> Value {
    let g = &cg.graph;
    json!({
        "functions": g.node_indices().map(|n| json!({
            "id": n.index(), "name": g[n].name, "file": g[n].file.display().to_string(), "line": g[n].line,
        })).collect::<Vec<_>>(),
        "calls": g.edge_references().map(|e| json!({
            "from": e.source().index(), "to": e.target().index(),
            "sites": e.weight().sites, "line": e.weight().line,
            "lines": e.weight().lines, "callbacks": e.weight().callback_lines,
        })).collect::<Vec<_>>(),
        "roots": cg.roots().into_iter().map(|n| n.index()).collect::<Vec<_>>(),
        "recursive": cg.recursive_groups().into_iter()
            .map(|grp| grp.into_iter().map(|n| n.index()).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "external": cg.external,
    })
}
