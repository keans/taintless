//! Code that no path from the function entry can reach.

use super::{Finding, Severity};
use crate::ir::Cfg;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::Dfs;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub fn analyze(cfg: &Cfg, file: &Path, out: &mut Vec<Finding>) {
    let mut live = HashSet::new();
    let mut dfs = Dfs::new(&cfg.graph, cfg.entry);
    while let Some(n) = dfs.next(&cfg.graph) {
        live.insert(n);
    }
    // `finally` bodies and deferred calls are copied onto several paths: a
    // dead copy of a statement that is reachable elsewhere is not dead code.
    let live_pos: HashSet<(usize, usize)> = live
        .iter()
        .flat_map(|n| cfg.graph[*n].stmts.iter().map(|s| (s.line, s.col)))
        .collect();

    let dead: Vec<NodeIndex> = cfg.graph.node_indices().filter(|n| !live.contains(n) && *n != cfg.exit).collect();
    if dead.is_empty() {
        return;
    }
    // group dead blocks that are connected to each other into one region
    let mut parent: HashMap<NodeIndex, NodeIndex> = dead.iter().map(|n| (*n, *n)).collect();
    fn find(p: &mut HashMap<NodeIndex, NodeIndex>, x: NodeIndex) -> NodeIndex {
        let px = p[&x];
        if px == x {
            return x;
        }
        let r = find(p, px);
        p.insert(x, r);
        r
    }
    for &n in &dead {
        for m in cfg.graph.neighbors_undirected(n) {
            if parent.contains_key(&m) {
                let (a, b) = (find(&mut parent, n), find(&mut parent, m));
                parent.insert(a, b);
            }
        }
    }
    let mut regions: HashMap<NodeIndex, Vec<(usize, usize, String)>> = HashMap::new();
    for &n in &dead {
        let root = find(&mut parent, n);
        for s in &cfg.graph[n].stmts {
            if !live_pos.contains(&(s.line, s.col)) {
                regions.entry(root).or_default().push((s.line, s.col, s.text.clone()));
            }
        }
    }
    for (_, mut stmts) in regions {
        stmts.sort();
        stmts.dedup_by_key(|s| (s.0, s.1));
        let (line, col, _) = stmts[0].clone();
        let last = stmts.last().map_or(line, |s| s.0);
        out.push(Finding {
            rule: "unreachable-code",
            cwe: "CWE-561",
            severity: Severity::Low,
            message: format!(
                "unreachable code ({} statement{}, lines {line}-{last})",
                stmts.len(),
                if stmts.len() == 1 { "" } else { "s" }
            ),
            file: file.to_path_buf(),
            function: cfg.name.clone(),
            line,
            col,
            origin: None,
        });
    }
}
