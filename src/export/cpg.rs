//! Export of the code property graph: JSON, GraphML, Graphviz DOT and Neo4j CSV.
//!
//! `id` is the graph's own index: it only identifies a node within one export.
//! `stable_id` identifies it across runs and exports: file path, source range and
//! grammar node kind (`MethodReturn` and other synthetic nodes hang off their method).

use super::dot::esc;
use crate::cpg::Cpg;
use crate::cpg::graph::EdgeKind;
use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;

/// The edges (and the nodes they touch) to export.
pub struct Selection {
    pub nodes: Vec<NodeIndex>,
    pub edges: Vec<petgraph::stable_graph::EdgeIndex>,
}

/// Edges of the given kinds (all when empty). With `function`, only nodes inside
/// functions whose name contains that text (and the edges between them).
/// Nodes are the endpoints of the selected edges.
pub fn select(cpg: &Cpg, kinds: &[EdgeKind], function: Option<&str>) -> Selection {
    let inside = |n: NodeIndex| match function {
        None => true,
        Some(f) => cpg.graph[cpg.enclosing_method(n)].name.as_deref().is_some_and(|name| name.contains(f)),
    };
    let mut edges = vec![];
    let mut nodes = BTreeSet::new();
    for e in (&cpg.graph).edge_references() {
        if (kinds.is_empty() || kinds.contains(&e.weight().kind)) && inside(e.source()) && inside(e.target()) {
            edges.push(e.id());
            nodes.insert(e.source());
            nodes.insert(e.target());
        }
    }
    Selection { nodes: nodes.into_iter().collect(), edges }
}

fn file_of(cpg: &Cpg, n: NodeIndex) -> String {
    cpg.files[cpg.graph[n].file].path.display().to_string()
}

/// A name for every node that is the same on every run over the same sources.
pub fn stable_ids(cpg: &Cpg) -> HashMap<NodeIndex, String> {
    let mut ids = HashMap::new();
    for n in cpg.graph.node_indices() {
        if let Some(i) = cpg.graph[n].id {
            let depth = if i.depth > 0 { format!(":{}", i.depth) } else { String::new() };
            ids.insert(n, format!("{}:{}-{}:{}{depth}", file_of(cpg, n), i.start, i.end, i.kind));
        }
    }
    // synthetic nodes: named after their method, numbered when several share a position
    let mut seen: HashMap<String, usize> = HashMap::new();
    for n in cpg.graph.node_indices() {
        if ids.contains_key(&n) {
            continue;
        }
        let x = &cpg.graph[n];
        let owner = cpg.enclosing_method(n);
        let base = match ids.get(&owner) {
            Some(m) if owner != n => format!("{m}#{}:{}:{}", x.kind.as_str(), x.line, x.col),
            _ => format!("{}#{}:{}:{}", file_of(cpg, n), x.kind.as_str(), x.line, x.col),
        };
        let k = seen.entry(base.clone()).or_default();
        ids.insert(n, if *k == 0 { base } else { format!("{base}:{k}") });
        *k += 1;
    }
    ids
}

pub fn to_json(cpg: &Cpg, sel: &Selection) -> Value {
    let stable = stable_ids(cpg);
    let nodes: Vec<Value> = sel
        .nodes
        .iter()
        .map(|&n| {
            let x = &cpg.graph[n];
            json!({
                "id": n.index(),
                "stable_id": stable[&n],
                "kind": x.kind.as_str(),
                "name": x.name,
                "code": x.code,
                "file": x.file,
                "line": x.line,
                "col": x.col,
                "span": x.id.map(|i| [i.start, i.end]),
            })
        })
        .collect();
    let edges: Vec<Value> = sel
        .edges
        .iter()
        .map(|&e| {
            let (a, b) = cpg.graph.edge_endpoints(e).expect("edge");
            let w = &cpg.graph[e];
            json!({"from": a.index(), "to": b.index(), "kind": w.kind.as_str(), "label": w.label, "var": w.var, "order": w.order})
        })
        .collect();
    let files: Vec<Value> = cpg.files.iter().enumerate().map(|(i, f)| json!({"id": i, "path": f.path.display().to_string()})).collect();
    json!({"files": files, "nodes": nodes, "edges": edges})
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn to_graphml(cpg: &Cpg, sel: &Selection) -> String {
    let stable = stable_ids(cpg);
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    for (id, target, name, ty) in [
        ("sid", "node", "stable_id", "string"),
        ("kind", "node", "kind", "string"),
        ("name", "node", "name", "string"),
        ("code", "node", "code", "string"),
        ("file", "node", "file", "string"),
        ("line", "node", "line", "int"),
        ("col", "node", "col", "int"),
        ("ekind", "edge", "kind", "string"),
        ("label", "edge", "label", "string"),
        ("var", "edge", "var", "string"),
        ("order", "edge", "order", "int"),
    ] {
        let _ = writeln!(s, "  <key id=\"{id}\" for=\"{target}\" attr.name=\"{name}\" attr.type=\"{ty}\"/>");
    }
    s.push_str("  <graph id=\"cpg\" edgedefault=\"directed\">\n");
    for &n in &sel.nodes {
        let x = &cpg.graph[n];
        let _ = write!(s, "    <node id=\"n{}\"><data key=\"sid\">{}</data><data key=\"kind\">{}</data>", n.index(), xml(&stable[&n]), x.kind.as_str());
        if let Some(name) = &x.name {
            let _ = write!(s, "<data key=\"name\">{}</data>", xml(name));
        }
        let _ = writeln!(
            s,
            "<data key=\"code\">{}</data><data key=\"file\">{}</data><data key=\"line\">{}</data><data key=\"col\">{}</data></node>",
            xml(&x.code),
            xml(&file_of(cpg, n)),
            x.line,
            x.col
        );
    }
    for &e in &sel.edges {
        let (a, b) = cpg.graph.edge_endpoints(e).expect("edge");
        let w = &cpg.graph[e];
        let _ = write!(s, "    <edge source=\"n{}\" target=\"n{}\"><data key=\"ekind\">{}</data>", a.index(), b.index(), w.kind.as_str());
        if let Some(l) = w.label {
            let _ = write!(s, "<data key=\"label\">{l}</data>");
        }
        if let Some(v) = &w.var {
            let _ = write!(s, "<data key=\"var\">{}</data>", xml(v));
        }
        let _ = writeln!(s, "<data key=\"order\">{}</data></edge>", w.order);
    }
    s.push_str("  </graph>\n</graphml>\n");
    s
}

fn edge_style(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Ast => "color=\"#b0b7c3\"",
        EdgeKind::Contains => "color=\"#8a94a6\" style=dashed",
        EdgeKind::Cfg => "color=\"#1565c0\"",
        EdgeKind::Cdg => "color=\"#c62828\" style=dashed",
        EdgeKind::Reaching => "color=\"#2e7d32\"",
        EdgeKind::ParamIn | EdgeKind::ReturnOut => "color=\"#2e7d32\" style=dashed penwidth=2",
        EdgeKind::Call => "color=\"#6a1b9a\" penwidth=2",
        EdgeKind::Argument | EdgeKind::Receiver => "color=\"#ef6c00\"",
        EdgeKind::Imports => "color=\"#00838f\"",
        EdgeKind::TypeOf => "color=\"#8e24aa\" style=dotted",
        EdgeKind::Scope => "color=\"#8a94a6\" style=dotted",
        EdgeKind::Ref => "color=\"#00897b\" style=dashed",
        EdgeKind::Inherits => "color=\"#6a1b9a\" style=dashed",
        EdgeKind::ParamOut | EdgeKind::Capture => "color=\"#2e7d32\" style=dotted penwidth=2",
    }
}

pub fn to_dot(cpg: &Cpg, sel: &Selection) -> String {
    let mut s = String::from("digraph cpg {\n  node [shape=box style=\"rounded,filled\" fillcolor=\"#f4f6f8\" fontname=\"Menlo\" fontsize=10];\n  edge [fontname=\"Helvetica\" fontsize=9];\n");
    for &n in &sel.nodes {
        let x = &cpg.graph[n];
        let code: String = x.code.chars().take(50).collect();
        let _ = writeln!(s, "  n{} [label=\"{}\\n{}\\n{}:{}\"];", n.index(), x.kind.as_str(), esc(&code), x.line, x.col);
    }
    for &e in &sel.edges {
        let (a, b) = cpg.graph.edge_endpoints(e).expect("edge");
        let w = &cpg.graph[e];
        let label = w.var.as_deref().or(w.label).map(|l| format!(" label=\"{}\"", esc(l))).unwrap_or_default();
        let _ = writeln!(s, "  n{} -> n{} [{}{label}];", a.index(), b.index(), edge_style(w.kind));
    }
    s.push_str("}\n");
    s
}

fn csv(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

/// `Method`, `MethodReturn`, `FieldAccess`, ...
fn label(kind: &str) -> String {
    kind.split('_').map(|w| w[..1].to_uppercase() + &w[1..]).collect()
}

/// Neo4j `neo4j-admin import` files: `(nodes.csv, edges.csv)`. Nodes are keyed by `stable_id`,
/// labelled `Node` plus their kind; relationships are typed by the upper-case edge kind.
pub fn to_neo4j(cpg: &Cpg, sel: &Selection) -> (String, String) {
    let stable = stable_ids(cpg);
    let mut nodes = String::from("id:ID,:LABEL,kind,name,code,file,line:int,col:int\n");
    for &n in &sel.nodes {
        let x = &cpg.graph[n];
        let _ = writeln!(
            nodes,
            "{},{},{},{},{},{},{},{}",
            csv(&stable[&n]),
            csv(&format!("Node;{}", label(x.kind.as_str()))),
            x.kind.as_str(),
            csv(x.name.as_deref().unwrap_or("")),
            csv(&x.code),
            csv(&file_of(cpg, n)),
            x.line,
            x.col
        );
    }
    let mut edges = String::from(":START_ID,:END_ID,:TYPE,var,label,order:int\n");
    for &e in &sel.edges {
        let (a, b) = cpg.graph.edge_endpoints(e).expect("edge");
        let w = &cpg.graph[e];
        let _ = writeln!(
            edges,
            "{},{},{},{},{},{}",
            csv(&stable[&a]),
            csv(&stable[&b]),
            w.kind.as_str().to_uppercase(),
            csv(w.var.as_deref().unwrap_or("")),
            csv(w.label.unwrap_or("")),
            w.order
        );
    }
    (nodes, edges)
}
