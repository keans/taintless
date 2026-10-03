//! Data-flow output is a view of the code property graph.
//! The CPG resolves definitions, aliases, calls and interprocedural effects; this
//! module owns the public result types and the source-based builder.

use super::ProjectFile;
use anyhow::{Context, Result};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A function parameter.
    Param,
    /// A variable or field that is assigned.
    Def,
    /// A call: it joins its arguments and produces a result.
    Call,
    /// A `return` (or implicit return).
    Return,
    /// A value defined outside the function: a global, `request.args`, ...
    Free,
    /// A branch: the test of an `if` / loop; with `control`, it points to what it decides.
    Branch,
    /// A field of a class (`Job.cmd`), shared by all its methods: what methods
    /// store in `self.cmd` flows into what other methods read from it.
    Field,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Inside one function.
    Flow,
    /// Call argument -> callee parameter.
    Arg,
    /// Callee return -> call.
    Ret,
    /// Branch -> a statement that only runs depending on it.
    Control,
}

#[derive(Debug, Clone)]
pub struct Node {
    /// Index into [`DataFlow::functions`].
    pub func: usize,
    pub kind: NodeKind,
    /// The variable, parameter, callee or path this node stands for.
    pub var: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub kind: EdgeKind,
    /// For `Arg` edges: the callee parameter that receives the value.
    pub label: Option<String>,
}

pub struct FnMeta {
    pub name: String,
    pub file: PathBuf,
    pub line: usize,
}

pub struct DataFlow {
    pub functions: Vec<FnMeta>,
    pub graph: DiGraph<Node, Edge>,
}

fn root(path: &str) -> &str {
    path.split(['.', '[', '-']).next().unwrap_or(path)
}

fn last_segment(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

/// Build the data-flow view from the original sources retained by each CFG.
/// Files with no functions are read from disk so their imports remain in the CPG.
pub fn build(files: &[ProjectFile], control: bool) -> Result<DataFlow> {
    let sources: Vec<String> = files
        .iter()
        .map(|f| match f.cfgs.first().map(|c| c.source.as_ref()).filter(|s| !s.is_empty()) {
            Some(source) => Ok(source.to_string()),
            None => std::fs::read_to_string(f.file)
                .with_context(|| format!("reading source for {}", f.file.display())),
        })
        .collect::<Result<_>>()?;
    let inputs: Vec<crate::cpg::SourceFile> = files.iter().zip(&sources).map(|(f, src)| crate::cpg::SourceFile {
        path: f.file, lang: f.lang, src, cfgs: f.cfgs, imports: f.imports,
    }).collect();
    let cpg = crate::cpg::Cpg::build(&inputs)?;
    Ok(crate::cpg::flow::flow_graph(&cpg, &inputs, control))
}

impl DataFlow {
    /// Keep what the nodes matching `name` (variable, callee or parameter) may
    /// flow into, following edges across functions.
    pub fn slice_from(&self, name: &str) -> HashSet<NodeIndex> {
        let g = &self.graph;
        let mut seen: HashSet<NodeIndex> = g
            .node_indices()
            .filter(|&n| {
                let v = &g[n].var;
                v == name || root(v) == name || last_segment(v) == name
            })
            .collect();
        let mut stack: Vec<NodeIndex> = seen.iter().copied().collect();
        while let Some(n) = stack.pop() {
            for m in g.neighbors(n) {
                if seen.insert(m) {
                    stack.push(m);
                }
            }
        }
        seen
    }
}
