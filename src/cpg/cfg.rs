//! Statement-level CFG: one node per statement instead of one per block, so
//! every statement has its own successors. Derived from a [`Cfg`]; the block
//! graph stays the lowering's output.

use crate::ir::{Cfg, EdgeKind};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{EdgeRef, NodeIndexable};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SNode {
    Entry,
    Exit,
    /// Statement `idx` of block `block` of the [`Cfg`] this graph came from.
    Stmt { block: NodeIndex<u32>, idx: usize },
}

#[derive(Debug)]
pub struct StmtGraph {
    pub graph: DiGraph<SNode, EdgeKind>,
    pub entry: NodeIndex,
    pub exit: NodeIndex,
}

/// Statements of each block are chained with `Normal` edges; the block's
/// outgoing edges leave its last statement and enter the first statement of
/// the target. Blocks without statements (joins, loop heads, `entry`) are
/// skipped over: an edge into one continues along that block's own edges, and
/// keeps the more specific kind of the two (`True` beats `Normal`).
pub fn stmt_graph(cfg: &Cfg) -> StmtGraph {
    let mut graph = DiGraph::new();
    let entry = graph.add_node(SNode::Entry);
    let exit = graph.add_node(SNode::Exit);
    let mut first = vec![None; cfg.graph.node_bound()];
    let mut last = vec![None; cfg.graph.node_bound()];
    for b in cfg.graph.node_indices() {
        let mut prev: Option<NodeIndex> = None;
        for idx in 0..cfg.graph[b].stmts.len() {
            let n = graph.add_node(SNode::Stmt { block: b, idx });
            match prev {
                Some(p) => {
                    graph.add_edge(p, n, EdgeKind::Normal);
                }
                None => first[b.index()] = Some(n),
            }
            prev = Some(n);
        }
        last[b.index()] = prev;
    }
    first[cfg.entry.index()] = Some(entry);
    last[cfg.entry.index()] = Some(entry);
    first[cfg.exit.index()] = Some(exit);

    // Where an edge into block `b` really lands: statements, or through empty blocks.
    let targets = |b: NodeIndex<u32>, kind: EdgeKind| {
        let mut out = vec![];
        let mut seen = HashSet::new();
        let mut stack = vec![(b, kind)];
        while let Some((b, kind)) = stack.pop() {
            if let Some(n) = first[b.index()] {
                out.push((n, kind));
            } else if seen.insert(b) {
                for e in cfg.graph.edges(b) {
                    stack.push((e.target(), if *e.weight() == EdgeKind::Normal { kind } else { *e.weight() }));
                }
            }
        }
        out
    };
    let mut added = HashSet::new();
    for b in cfg.graph.node_indices() {
        let Some(from) = last[b.index()] else { continue };
        for e in cfg.graph.edges(b) {
            for (to, kind) in targets(e.target(), *e.weight()) {
                if added.insert((from, to, kind as u8)) {
                    graph.add_edge(from, to, kind);
                }
            }
        }
    }
    StmtGraph { graph, entry, exit }
}

impl StmtGraph {
    /// The statement behind node `n`, if it is one.
    pub fn stmt<'a>(&self, cfg: &'a Cfg, n: NodeIndex) -> Option<&'a crate::ir::Stmt> {
        match self.graph[n] {
            SNode::Stmt { block, idx } => Some(&cfg.graph[block].stmts[idx]),
            _ => None,
        }
    }
}
