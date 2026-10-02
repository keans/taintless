use crate::ir::{Cfg, EdgeKind, StmtKind};
use petgraph::visit::{Dfs, EdgeRef, IntoEdgeReferences};
use std::collections::HashSet;
use std::fmt::Write;

const MAX_STMT_CHARS: usize = 60;

const GRAPH_DEFAULTS: &str = "\
  graph [fontname=\"Helvetica\" fontsize=12 style=\"rounded\" color=\"#b0b7c3\" labeljust=l];
  node [shape=box style=\"rounded,filled\" fillcolor=\"#f4f6f8\" color=\"#8a94a6\" fontname=\"Menlo\" fontsize=10];
  edge [fontname=\"Helvetica\" fontsize=9 color=\"#5b6573\"];
";

/// Opening of a `digraph` with the shared graph, node and edge styling.
pub(super) fn header(name: &str) -> String {
    format!(
        "digraph {name} {{\n  rankdir=LR;\n  newrank=true;\n  graph [fontname=\"Helvetica\" style=\"rounded\" color=\"#b0b7c3\" labeljust=l];\n  \
         node [shape=box style=\"rounded,filled\" fillcolor=\"#f4f6f8\" color=\"#8a94a6\" fontname=\"Menlo\" fontsize=10];\n  \
         edge [fontname=\"Helvetica\" fontsize=9 color=\"#5b6573\"];\n"
    )
}

/// ` -> a, b` (or ` <- a, b`), empty when there is nothing to list.
pub(super) fn arrow(sym: &str, items: &[String]) -> String {
    if items.is_empty() { String::new() } else { format!(" {sym} {}", items.join(", ")) }
}

pub(super) fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_STMT_CHARS {
        return s.to_string();
    }
    let cut: String = s.chars().take(MAX_STMT_CHARS - 1).collect();
    format!("{cut}…")
}

/// Edge label and style attributes for each kind.
fn edge_style(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Normal => "",
        EdgeKind::True => "label=\"true\" color=\"#2e7d32\" fontcolor=\"#2e7d32\"",
        EdgeKind::False => "label=\"false\" color=\"#c62828\" fontcolor=\"#c62828\"",
        EdgeKind::Back => "label=\"back\" color=\"#1565c0\" fontcolor=\"#1565c0\" style=dashed",
        EdgeKind::Break => "label=\"break\" color=\"#ef6c00\" fontcolor=\"#ef6c00\"",
        EdgeKind::Continue => "label=\"continue\" color=\"#ef6c00\" fontcolor=\"#ef6c00\"",
        EdgeKind::Return => "label=\"return\" color=\"#6d4c41\" fontcolor=\"#6d4c41\"",
        EdgeKind::Exception => "label=\"exc\" color=\"#7b1fa2\" fontcolor=\"#7b1fa2\" style=dashed",
    }
}

/// Node and edge lines of one CFG; node ids are `{prefix}{index}`.
fn write_body(s: &mut String, cfg: &Cfg, prefix: &str, indent: &str) {
    let mut dfs = Dfs::new(&cfg.graph, cfg.entry);
    let mut reachable = HashSet::new();
    while let Some(n) = dfs.next(&cfg.graph) {
        reachable.insert(n);
    }

    for idx in cfg.graph.node_indices() {
        let blk = &cfg.graph[idx];
        let id = idx.index();
        let attrs = if idx == cfg.entry || idx == cfg.exit {
            let (name, fill) = if idx == cfg.entry { ("entry", "#d7efdc") } else { ("exit", "#f4d6d6") };
            format!("label=\"{name}\" shape=oval fillcolor=\"{fill}\"")
        } else if blk.stmts.is_empty() {
            // Join points carry no code: draw them as small dots.
            "label=\"\" shape=circle width=0.12 height=0.12 fixedsize=true fillcolor=\"#8a94a6\"".to_string()
        } else {
            let mut label = String::new();
            for st in &blk.stmts {
                let _ = write!(label, "{}: {}\\l", st.line, esc(&truncate(&st.text)));
            }
            let fill = if blk.stmts.iter().any(|st| st.kind == StmtKind::Branch) {
                "#fff4d1"
            } else if blk.stmts.iter().any(|st| st.kind == StmtKind::Call) {
                "#dcebfa"
            } else {
                "#f4f6f8"
            };
            format!("label=\"{label}\" fillcolor=\"{fill}\"")
        };
        let dead = if reachable.contains(&idx) {
            ""
        } else {
            " style=\"rounded,filled,dashed\" color=\"#c62828\" fontcolor=\"#c62828\""
        };
        let _ = writeln!(s, "{indent}{prefix}{id} [{attrs}{dead}];");
    }
    for e in cfg.graph.edge_references() {
        let _ = writeln!(
            s,
            "{indent}{prefix}{} -> {prefix}{} [{}];",
            e.source().index(),
            e.target().index(),
            edge_style(*e.weight())
        );
    }
}

/// Render one CFG as a Graphviz digraph.
pub fn to_dot(cfg: &Cfg) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "digraph \"{}\" {{", esc(&cfg.name));
    s.push_str(GRAPH_DEFAULTS);
    write_body(&mut s, cfg, "n", "  ");
    s.push_str("}\n");
    s
}

/// One file's functions: `(file label, [(function name, cfg)])`.
pub type FileCfgs<'a> = (String, Vec<(&'a str, &'a Cfg)>);

/// Render many CFGs as a single digraph: one cluster per file containing one
/// cluster per function. One document, because concatenated digraphs yield
/// broken SVG.
pub fn to_dot_all<'a>(files: impl IntoIterator<Item = FileCfgs<'a>>) -> String {
    let mut s = String::from("digraph taintless {\n  compound=true;\n");
    s.push_str(GRAPH_DEFAULTS);
    let mut f = 0;
    for (fi, (file, funcs)) in files.into_iter().enumerate() {
        let _ = writeln!(
            s,
            "  subgraph cluster_file{fi} {{\n    label=<<b>{}</b>>; fontsize=14; bgcolor=\"#fafbfc\";",
            html_esc(&file)
        );
        for (name, cfg) in funcs {
            let _ = writeln!(
                s,
                "    subgraph cluster_{f} {{\n      label=\"{}()\"; bgcolor=white; color=\"#8a94a6\";",
                esc(name)
            );
            write_body(&mut s, cfg, &format!("f{f}_n"), "      ");
            s.push_str("    }\n");
            f += 1;
        }
        s.push_str("  }\n");
    }
    s.push_str("}\n");
    s
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
