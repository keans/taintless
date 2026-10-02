use super::{Block, Cfg, EdgeKind, Stmt};
use petgraph::stable_graph::{NodeIndex, StableDiGraph};

/// Incrementally builds a [`Cfg`]. `cur` is `None` after a terminator
/// (return/break/continue), meaning following code is unreachable.
pub struct CfgBuilder {
    graph: StableDiGraph<Block, EdgeKind>,
    entry: NodeIndex,
    exit: NodeIndex,
    cur: Option<NodeIndex>,
    /// (continue target, break target)
    loops: Vec<(NodeIndex, NodeIndex)>,
}

impl CfgBuilder {
    pub fn new() -> Self {
        let mut graph = StableDiGraph::new();
        let entry = graph.add_node(Block { label: Some("entry"), stmts: vec![] });
        let exit = graph.add_node(Block { label: Some("exit"), stmts: vec![] });
        // `entry` stays empty: the function's first statement (often a branch
        // condition) lives in its own block, so it is always visible.
        let first = graph.add_node(Block::default());
        graph.add_edge(entry, first, EdgeKind::Normal);
        Self { graph, entry, exit, cur: Some(first), loops: vec![] }
    }

    pub fn new_block(&mut self) -> NodeIndex {
        self.graph.add_node(Block::default())
    }

    pub fn current(&self) -> Option<NodeIndex> {
        self.cur
    }

    pub fn set_current(&mut self, n: Option<NodeIndex>) {
        self.cur = n;
    }

    pub fn edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind) {
        self.graph.add_edge(from, to, kind);
    }

    /// Current block, creating a detached (unreachable) one if needed so that
    /// dead code still shows up in the graph.
    pub fn ensure_current(&mut self) -> NodeIndex {
        match self.cur {
            Some(n) => n,
            None => {
                let n = self.new_block();
                self.cur = Some(n);
                n
            }
        }
    }

    /// The most recently added statement of block `n`.
    pub fn last_stmt_mut(&mut self, n: NodeIndex) -> Option<&mut Stmt> {
        self.graph[n].stmts.last_mut()
    }

    pub fn push_stmt(&mut self, stmt: Stmt) {
        let n = self.ensure_current();
        self.graph[n].stmts.push(stmt);
    }

    /// Edge from the current block (if reachable) to `to`, then continue in `to`.
    pub fn goto(&mut self, to: NodeIndex, kind: EdgeKind) {
        if let Some(c) = self.cur {
            self.edge(c, to, kind);
        }
        self.cur = Some(to);
    }

    pub fn enter_loop(&mut self, cont: NodeIndex, brk: NodeIndex) {
        self.loops.push((cont, brk));
    }

    pub fn leave_loop(&mut self) {
        self.loops.pop();
    }

    pub fn exit_node(&self) -> NodeIndex {
        self.exit
    }

    /// Edge from the current block to `to`, after which code is unreachable.
    pub fn jump(&mut self, to: NodeIndex, kind: EdgeKind) {
        if let Some(c) = self.cur.take() {
            self.edge(c, to, kind);
        }
    }

    pub fn do_return(&mut self) {
        if let Some(c) = self.cur.take() {
            self.edge(c, self.exit, EdgeKind::Return);
        }
    }

    /// Exception edges from the current block to each handler; with no
    /// handlers the exception escapes to the function exit.
    pub fn do_raise(&mut self, handlers: &[NodeIndex]) {
        if let Some(c) = self.cur.take() {
            if handlers.is_empty() {
                self.edge(c, self.exit, EdgeKind::Exception);
            }
            for &h in handlers {
                self.edge(c, h, EdgeKind::Exception);
            }
        }
    }

    pub fn do_break(&mut self) {
        if let (Some(c), Some(&(_, brk))) = (self.cur.take(), self.loops.last()) {
            self.edge(c, brk, EdgeKind::Break);
        }
    }

    pub fn do_continue(&mut self) {
        if let (Some(c), Some(&(cont, _))) = (self.cur.take(), self.loops.last()) {
            self.edge(c, cont, EdgeKind::Continue);
        }
    }

    pub fn finish(mut self, name: String, line: usize, params: Vec<Vec<String>>) -> Cfg {
        if let Some(c) = self.cur {
            self.graph.add_edge(c, self.exit, EdgeKind::Normal);
        }
        Cfg { source: std::sync::Arc::from(""), name, line, col: 0, span: (0, 0), node_kind: 0, params, receiver: None, param_types: vec![], class_bases: vec![], class_decls: vec![], free_writes: vec![], ret_type: None, local_types: vec![], local_decls: vec![], local_scopes: vec![], field_types: vec![], iface_methods: vec![], graph: self.graph, entry: self.entry, exit: self.exit }
    }
}

impl Default for CfgBuilder {
    fn default() -> Self {
        Self::new()
    }
}
