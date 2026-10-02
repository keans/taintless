//! Code property graph: AST, CFG, dependence and call edges in one graph.
//! Built so far: stable node ids, the AST layer, statement-level CFG, control
//! dependence, and the unified [`Cpg`] with AST / CFG / CDG / call / import edges.
pub mod ast;
pub mod cdg;
pub mod cfg;
pub mod ddg;
pub mod flow;
pub mod graph;
pub mod node;
pub mod query;
pub mod taint;

pub use graph::{Cpg, SourceFile};
