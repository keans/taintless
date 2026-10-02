use crate::ir::{CallFlow, Cfg, Flow};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde_json::{Value, json};

/// Serialize a CFG as `{name, entry, exit, blocks, edges}`.
pub fn to_json(cfg: &Cfg) -> Value {
    let blocks: Vec<Value> = cfg
        .graph
        .node_indices()
        .map(|i| {
            let b = &cfg.graph[i];
            json!({
                "id": i.index(),
                "label": b.label,
                "stmts": b.stmts.iter().map(|s| json!({
                    "kind": s.kind.as_str(), "line": s.line, "col": s.col, "text": s.text,
                    "assigns": s.assigns.iter().map(|a| json!({
                        "target": a.target, "strong": a.strong, "value": flow_json(&a.value),
                    })).collect::<Vec<_>>(),
                    "calls": s.calls.iter().map(call_json).collect::<Vec<_>>(),
                    "returns": s.ret.as_ref().map(flow_json),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let edges: Vec<Value> = cfg
        .graph
        .edge_references()
        .map(|e| {
            json!({
                "from": e.source().index(),
                "to": e.target().index(),
                "kind": e.weight().as_str(),
            })
        })
        .collect();
    json!({
        "name": cfg.name,
        "line": cfg.line,
        "params": cfg.params,
        "entry": cfg.entry.index(),
        "exit": cfg.exit.index(),
        "blocks": blocks,
        "edges": edges,
    })
}

fn call_json(c: &CallFlow) -> Value {
    json!({
        "callee": c.callee, "line": c.line, "col": c.col,
        "receiver": c.recv.as_ref().map(flow_json),
        "arg_names": c.arg_names,
        "args": c.args.iter().map(flow_json).collect::<Vec<_>>(),
    })
}

/// Compact symbolic form: `"x"` for a variable, `{"call": ...}`, `{"join": [...]}`.
fn flow_json(f: &Flow) -> Value {
    match f {
        Flow::Clean => Value::Null,
        Flow::Path(p) => json!(p),
        Flow::Call(c) => json!({ "call": call_json(c) }),
        Flow::Join(v) => json!({ "join": v.iter().map(flow_json).collect::<Vec<_>>() }),
    }
}
