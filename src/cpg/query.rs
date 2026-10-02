//! Traversal helpers over the [`Cpg`].

use super::graph::{Cpg, EdgeKind};
use super::node::NodeKind;
use petgraph::Direction;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::HashSet;

impl Cpg {
    /// `n` and every AST node below it, parents first.
    pub fn subtree(&self, n: NodeIndex) -> Vec<NodeIndex> {
        let node = &self.graph[n];
        match node.ast {
            Some(i) => {
                let info = &self.files[node.file];
                info.ast.subtree(i).into_iter().map(|j| info.nodes[j]).collect()
            }
            None => vec![n],
        }
    }

    /// The statement `n` is part of: the nearest node, `n` itself first and then
    /// its AST ancestors, that has control-flow edges. Falls back to the
    /// enclosing method.
    pub fn statement_of(&self, n: NodeIndex) -> NodeIndex {
        let has_cfg = |x: NodeIndex| {
            self.graph.edges_directed(x, Direction::Outgoing).chain(self.graph.edges_directed(x, Direction::Incoming)).any(|e| e.weight().kind == EdgeKind::Cfg)
        };
        let node = &self.graph[n];
        let Some(mut i) = node.ast else { return n };
        let info = &self.files[node.file];
        loop {
            let g = info.nodes[i];
            if has_cfg(g) {
                return g;
            }
            match info.ast.nodes[i].parent {
                Some(p) => i = p,
                None => return self.enclosing_method(n),
            }
        }
    }

    /// The nodes whose values can flow into the value of `root`: its AST subtree,
    /// except the statements nested in a compound statement (`if`, loops, ...),
    /// nested functions, and the insides of calls to scanned functions
    /// (the value of such a call is what the callee returns, found through
    /// `ReturnOut` edges, not what the arguments are). Calls to unknown
    /// functions pass their arguments on.
    pub fn flow_nodes(&self, root: NodeIndex) -> Vec<NodeIndex> {
        self.flow_nodes_until(root, |_| false)
    }

    pub(crate) fn flow_nodes_until(&self, root: NodeIndex, stop: impl Fn(NodeIndex) -> bool) -> Vec<NodeIndex> {
        let node = &self.graph[root];
        let Some(start) = node.ast else { return vec![root] };
        let info = &self.files[node.file];
        let is_stmt = |g: NodeIndex| self.graph.edges_directed(g, Direction::Outgoing).any(|e| e.weight().kind == EdgeKind::Cfg);
        let resolved = |g: NodeIndex| self.graph.edges_directed(g, Direction::Outgoing).any(|e| e.weight().kind == EdgeKind::Call && e.weight().label.is_none());
        let compound = node.kind == NodeKind::Control;
        let mut out = vec![];
        let mut stack = vec![start];
        while let Some(i) = stack.pop() {
            let g = info.nodes[i];
            if stop(g) {
                continue;
            }
            out.push(g);
            if resolved(g) {
                continue;
            }
            // the index of an assignment target (`d[k] = v`) is read, but it is not part of what is stored
            let index_of_target = info.ast.nodes[i].parent.is_some_and(|p| {
                let pn = &info.ast.nodes[p];
                pn.kind == NodeKind::Assign && pn.children.first() == Some(&i) && {
                    let raw = info.ast.raw_kind(i);
                    ["subscript", "index", "element_access", "array_access"].iter().any(|w| raw.contains(w))
                }
            });
            // comprehension parts are statements of the CFG but belong to the statement around them
            stack.extend(info.ast.nodes[i].children.iter().enumerate().rev().filter_map(|(pos, &c)| {
                let k = info.nodes[c];
                (self.graph[k].kind != NodeKind::Method && !(compound && is_stmt(k)) && !(index_of_target && pos > 0)).then_some(c)
            }));
        }
        out
    }

    /// Everything reachable from `from` over edges of `kinds`, `from` included.
    pub fn reachable(&self, from: impl IntoIterator<Item = NodeIndex>, kinds: &[EdgeKind], dir: Direction) -> HashSet<NodeIndex> {
        let mut seen: HashSet<NodeIndex> = HashSet::new();
        let mut stack: Vec<NodeIndex> = from.into_iter().collect();
        while let Some(n) = stack.pop() {
            if !seen.insert(n) {
                continue;
            }
            for e in self.graph.edges_directed(n, dir).filter(|e| kinds.contains(&e.weight().kind)) {
                stack.push(if dir == Direction::Outgoing { e.target() } else { e.source() });
            }
        }
        seen
    }

    /// Argument expressions of the call `n`, in order.
    pub fn arguments(&self, n: NodeIndex) -> Vec<NodeIndex> {
        let mut a: Vec<(u32, NodeIndex)> =
            self.graph.edges_directed(n, Direction::Outgoing).filter(|e| e.weight().kind == EdgeKind::Argument).map(|e| (e.weight().order, e.target())).collect();
        a.sort();
        a.into_iter().map(|x| x.1).collect()
    }

    /// All nodes of `kind`.
    pub fn nodes_of(&self, kind: NodeKind) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.node_indices().filter(move |&n| self.graph[n].kind == kind)
    }
}
