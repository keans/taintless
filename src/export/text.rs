use crate::ir::Cfg;
use petgraph::visit::{Dfs, EdgeRef};
use std::collections::HashSet;
use std::fmt::Write;

/// Compact, diff-friendly dump: one line per block and per edge.
/// Blocks unreachable from entry are marked `!dead`.
pub fn to_text(cfg: &Cfg) -> String {
    let mut dfs = Dfs::new(&cfg.graph, cfg.entry);
    let mut live = HashSet::new();
    while let Some(n) = dfs.next(&cfg.graph) {
        live.insert(n);
    }
    let mut s = String::new();
    let _ = writeln!(s, "fn {}", cfg.name);
    for idx in cfg.graph.node_indices() {
        let blk = &cfg.graph[idx];
        let name = match blk.label {
            Some(l) => l.to_string(),
            None => format!("b{}", idx.index()),
        };
        let dead = if live.contains(&idx) { "" } else { " !dead" };
        let stmts: Vec<String> = blk.stmts.iter().map(|st| format!("{}:{}", st.line, st.text)).collect();
        let _ = writeln!(s, "  {name}{dead} [{}]", stmts.join(" | "));
    }
    for idx in cfg.graph.node_indices() {
        let mut out: Vec<_> = cfg.graph.edges(idx).collect();
        out.sort_by_key(|e| e.target().index());
        for e in out {
            let _ = writeln!(s, "  {} -{}-> {}", idx.index(), e.weight().as_str(), e.target().index());
        }
    }
    s
}
