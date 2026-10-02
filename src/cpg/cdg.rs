//! Control dependence (Ferrante, Ottenstein, Warren): statement `b` depends on
//! branch `a` when `a` decides whether `b` runs, i.e. some edge `a -> s` has `b`
//! on every path from `s` to the exit while `b` does not post-dominate `a`.

use super::cfg::StmtGraph;
use crate::ir::EdgeKind;
use petgraph::algo::dominators::simple_fast;
use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, Reversed};

/// `(controller, dependent, edge kind taken)`: `dependent` runs only when the
/// branch at `controller` leaves along an edge of that kind (a loop head
/// controls itself). Statements nothing else controls depend on `Entry`.
/// Statements that cannot reach the exit (infinite loops) are left out.
pub fn control_dependence(g: &StmtGraph) -> Vec<(NodeIndex, NodeIndex, EdgeKind)> {
    let post = simple_fast(Reversed(&g.graph), g.exit);
    let mut out = vec![];
    for a in g.graph.node_indices() {
        let succ: Vec<_> = g.graph.edges(a).collect();
        let Some(stop) = post.immediate_dominator(a) else { continue };
        // A single way out decides nothing.
        if succ.iter().map(|e| e.target()).collect::<std::collections::HashSet<_>>().len() < 2 {
            continue;
        }
        for e in succ {
            let mut runner = Some(e.target());
            while let Some(r) = runner {
                if r == stop {
                    break;
                }
                if !out.contains(&(a, r, *e.weight())) {
                    out.push((a, r, *e.weight()));
                }
                runner = post.immediate_dominator(r);
            }
        }
    }
    let controlled: std::collections::HashSet<_> = out.iter().map(|&(_, d, _)| d).collect();
    for n in g.graph.node_indices() {
        if n != g.entry && n != g.exit && !controlled.contains(&n) && post.immediate_dominator(n).is_some() {
            out.push((g.entry, n, EdgeKind::Normal));
        }
    }
    out
}
