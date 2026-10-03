//! The code property graph as two tables, and the questions asked of them.
//!
//! `nodes` are keyed by the stable id of `export::cpg::stable_ids` (file, byte range, grammar
//! kind), so ids are the same across runs and exports. The graph is replaced as a whole when the
//! project fingerprint changes: cross-file edges (calls, imports, interprocedural data flow)
//! depend on files other than the one they start in, so partial replacement could not be exact.

use super::Store;
use crate::cpg::Cpg;
use crate::export::cpg::{csv, label, stable_ids, xml};
use anyhow::Result;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use rusqlite::params;
use serde_json::{Value, json};
use std::collections::HashMap;
use super::PRESENT;
use std::fmt::Write;

pub struct NodeRow {
    id: String,
    kind: &'static str,
    name: Option<String>,
    code: String,
    file: String,
    line: i64,
    col: i64,
    /// Stable id of the enclosing method.
    method: String,
}

pub struct EdgeRow {
    src: String,
    dst: String,
    kind: &'static str,
    label: Option<&'static str>,
    var: Option<String>,
    order: i64,
}

/// The rows of `cpg`.
pub fn rows(cpg: &Cpg) -> (Vec<NodeRow>, Vec<EdgeRow>) {
    let ids = stable_ids(cpg);
    let nodes = cpg
        .graph
        .node_indices()
        .map(|n| {
            let x = &cpg.graph[n];
            NodeRow {
                id: ids[&n].clone(),
                kind: x.kind.as_str(),
                name: x.name.clone(),
                code: x.code.clone(),
                file: cpg.files[x.file].path.display().to_string(),
                line: x.line as i64,
                col: x.col as i64,
                method: ids[&cpg.enclosing_method(n)].clone(),
            }
        })
        .collect();
    let edges = (&cpg.graph)
        .edge_references()
        .map(|e| EdgeRow {
            src: ids[&e.source()].clone(),
            dst: ids[&e.target()].clone(),
            kind: e.weight().kind.as_str(),
            label: e.weight().label,
            var: e.weight().var.clone(),
            order: i64::from(e.weight().order),
        })
        .collect();
    (nodes, edges)
}

impl Store {
    /// The fingerprint of the project the stored graph was built from.
    pub fn graph_key(&self) -> Option<String> {
        self.meta("graph_key").ok().flatten()
    }

    /// Replace the stored graph, in one transaction.
    pub fn replace_graph(&mut self, key: &str, nodes: &[NodeRow], edges: &[EdgeRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute_batch("DELETE FROM edges; DELETE FROM nodes;")?;
        {
            let mut n = tx.prepare("INSERT OR REPLACE INTO nodes VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
            for x in nodes {
                n.execute(params![x.id, x.kind, x.name, x.code, x.file, x.line, x.col, x.method])?;
            }
            let mut e = tx.prepare("INSERT INTO edges VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
            for x in edges {
                e.execute(params![x.src, x.dst, x.kind, x.label, x.var, x.order])?;
            }
        }
        tx.execute("INSERT OR REPLACE INTO meta VALUES ('graph_key', ?1)", [key])?;
        tx.commit()?;
        Ok(())
    }

    /// Fail with a hint when no graph is stored.
    pub fn require_graph(&self) -> Result<()> {
        if self.graph_key().is_none() {
            anyhow::bail!("no graph stored; run `taintless index <path>` first (a rebuilt tool or `clear-cache` empties it)");
        }
        Ok(())
    }

    fn rows(&self, sql: &str, args: &[&dyn rusqlite::ToSql], map: impl Fn(&rusqlite::Row) -> rusqlite::Result<Value>) -> Result<Vec<Value>> {
        let mut st = self.conn.prepare(sql)?;
        let rows = st.query_map(args, map)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Calls to functions whose name contains `name` (`callers`), or made by functions whose
    /// name contains `name` (`callees`): `{function, file, line, callee, call_file, call_line}`.
    pub fn calls(&self, name: &str, callers: bool) -> Result<Vec<Value>> {
        self.require_graph()?;
        let filter = if callers { "t.name" } else { "m.name" };
        self.rows(
            &format!(
                "SELECT DISTINCT m.name, m.file, m.line, t.name, c.file, c.line
                 FROM edges e JOIN nodes c ON c.id = e.src JOIN nodes t ON t.id = e.dst JOIN nodes m ON m.id = c.method
                 WHERE e.kind = 'call' AND instr({filter}, ?1) > 0 ORDER BY m.file, c.line, m.name, t.name"
            ),
            &[&name],
            |r| {
                Ok(json!({
                    "function": r.get::<_, Option<String>>(0)?, "file": r.get::<_, String>(1)?, "line": r.get::<_, i64>(2)?,
                    "callee": r.get::<_, Option<String>>(3)?, "call_file": r.get::<_, String>(4)?, "call_line": r.get::<_, i64>(5)?,
                }))
            },
        )
    }

    /// Flow nodes (statements) whose code contains `to` that data from one whose code contains
    /// `from` can reach, following reaching definitions (also across calls). Each answer has the
    /// shortest `path` of statements. An over-approximation: the flow graph does not know which
    /// calls sanitize.
    pub fn reachable(&self, from: &str, to: &str) -> Result<Vec<Value>> {
        self.require_graph()?;
        const FLOW: &str = "('reaching','param_in','return_out','param_out','capture')";
        let ids = |code: &str, flow_src: bool| -> Result<Vec<String>> {
            let extra = if flow_src { format!("AND id IN (SELECT src FROM edges WHERE kind IN {FLOW})") } else { String::new() };
            let mut st = self.conn.prepare(&format!("SELECT id FROM nodes WHERE kind NOT IN ('method','file','type_decl') AND instr(code, ?1) > 0 {extra}"))?;
            let rows = st.query_map([code], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<std::result::Result<_, _>>()?)
        };
        let starts = ids(from, true)?;
        let targets: std::collections::HashSet<String> = ids(to, false)?.into_iter().collect();
        let mut next: HashMap<String, Vec<String>> = HashMap::new();
        let mut st = self.conn.prepare(&format!("SELECT src, dst FROM edges WHERE kind IN {FLOW}"))?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (a, b) = r?;
            next.entry(a).or_default().push(b);
        }
        // breadth first from every start at once: the first way to reach a node is a shortest one
        let mut parent: HashMap<String, Option<String>> = starts.iter().map(|s| (s.clone(), None)).collect();
        let mut queue: std::collections::VecDeque<String> = starts.into_iter().collect();
        while let Some(n) = queue.pop_front() {
            for m in next.get(&n).into_iter().flatten() {
                if !parent.contains_key(m) {
                    parent.insert(m.clone(), Some(n.clone()));
                    queue.push_back(m.clone());
                }
            }
        }
        let describe = |id: &str| -> Result<Value> {
            Ok(self.conn.query_row("SELECT file, line, code FROM nodes WHERE id = ?1", [id], |r| {
                let code: String = r.get(2)?;
                Ok(json!({"file": r.get::<_, String>(0)?, "line": r.get::<_, i64>(1)?, "code": code.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(100).collect::<String>()}))
            })?)
        };
        let mut out = vec![];
        for t in targets.iter().filter(|t| matches!(parent.get(*t), Some(Some(_)))) {
            let mut chain = vec![t.clone()];
            while let Some(Some(p)) = parent.get(chain.last().expect("non-empty")) {
                chain.push(p.clone());
            }
            chain.reverse();
            let path: Vec<Value> = chain.iter().map(|id| describe(id)).collect::<Result<_>>()?;
            let mut target = path.last().cloned().unwrap_or_default();
            target["path"] = Value::Array(path);
            out.push(target);
        }
        out.sort_by(|a, b| (a["file"].as_str(), a["line"].as_i64()).cmp(&(b["file"].as_str(), b["line"].as_i64())));
        Ok(out)
    }

    /// Open stored findings counted by `rule` or by directory: `{group, count}`.
    pub fn findings_by(&self, dir: bool) -> Result<Vec<Value>> {
        let key = if dir { "CASE WHEN instr(file, '/') > 0 THEN replace(file, ltrim(file, replace(file, '/', '')), '') ELSE '.' END" } else { "rule" };
        self.rows(
            &format!("SELECT {key}, count(*) FROM findings WHERE {PRESENT} AND status = 'open' GROUP BY {key} ORDER BY count(*) DESC, 1"),
            &[],
            |r| Ok(json!({"group": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?})),
        )
    }

    /// Neo4j `neo4j-admin import` files from the stored graph: `(nodes.csv, edges.csv)`.
    pub fn neo4j(&self) -> Result<(String, String)> {
        let mut nodes = String::from("id:ID,:LABEL,kind,name,code,file,line:int,col:int\n");
        let mut st = self.conn.prepare("SELECT id, kind, name, code, file, line, col FROM nodes ORDER BY id")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let (id, kind, name, code, file): (String, String, Option<String>, String, String) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
            let _ = writeln!(
                nodes,
                "{},{},{kind},{},{},{},{},{}",
                csv(&id),
                csv(&format!("Node;{}", label(&kind))),
                csv(name.as_deref().unwrap_or("")),
                csv(&code),
                csv(&file),
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?
            );
        }
        let mut edges = String::from(":START_ID,:END_ID,:TYPE,var,label,order:int\n");
        let mut st = self.conn.prepare("SELECT src, dst, kind, var, label, ord FROM edges ORDER BY rowid")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let (src, dst, kind): (String, String, String) = (r.get(0)?, r.get(1)?, r.get(2)?);
            let (var, lab): (Option<String>, Option<String>) = (r.get(3)?, r.get(4)?);
            let _ = writeln!(
                edges,
                "{},{},{},{},{},{}",
                csv(&src),
                csv(&dst),
                kind.to_uppercase(),
                csv(var.as_deref().unwrap_or("")),
                csv(lab.as_deref().unwrap_or("")),
                r.get::<_, i64>(5)?
            );
        }
        Ok((nodes, edges))
    }

    /// GraphML of the stored graph; node ids are the stable ids.
    pub fn graphml(&self) -> Result<String> {
        let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
        for (id, target, name, ty) in [
            ("kind", "node", "kind", "string"),
            ("name", "node", "name", "string"),
            ("code", "node", "code", "string"),
            ("file", "node", "file", "string"),
            ("line", "node", "line", "int"),
            ("col", "node", "col", "int"),
            ("ekind", "edge", "kind", "string"),
            ("label", "edge", "label", "string"),
            ("var", "edge", "var", "string"),
            ("order", "edge", "order", "int"),
        ] {
            let _ = writeln!(s, "  <key id=\"{id}\" for=\"{target}\" attr.name=\"{name}\" attr.type=\"{ty}\"/>");
        }
        s.push_str("  <graph id=\"cpg\" edgedefault=\"directed\">\n");
        let mut st = self.conn.prepare("SELECT id, kind, name, code, file, line, col FROM nodes ORDER BY id")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let _ = write!(s, "    <node id=\"{}\"><data key=\"kind\">{}</data>", xml(&r.get::<_, String>(0)?), r.get::<_, String>(1)?);
            if let Some(name) = r.get::<_, Option<String>>(2)? {
                let _ = write!(s, "<data key=\"name\">{}</data>", xml(&name));
            }
            let _ = writeln!(
                s,
                "<data key=\"code\">{}</data><data key=\"file\">{}</data><data key=\"line\">{}</data><data key=\"col\">{}</data></node>",
                xml(&r.get::<_, String>(3)?),
                xml(&r.get::<_, String>(4)?),
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?
            );
        }
        let mut st = self.conn.prepare("SELECT src, dst, kind, label, var, ord FROM edges ORDER BY rowid")?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let _ = write!(
                s,
                "    <edge source=\"{}\" target=\"{}\"><data key=\"ekind\">{}</data>",
                xml(&r.get::<_, String>(0)?),
                xml(&r.get::<_, String>(1)?),
                r.get::<_, String>(2)?
            );
            if let Some(l) = r.get::<_, Option<String>>(3)? {
                let _ = write!(s, "<data key=\"label\">{}</data>", xml(&l));
            }
            if let Some(v) = r.get::<_, Option<String>>(4)? {
                let _ = write!(s, "<data key=\"var\">{}</data>", xml(&v));
            }
            let _ = writeln!(s, "<data key=\"order\">{}</data></edge>", r.get::<_, i64>(5)?);
        }
        s.push_str("  </graph>\n</graphml>\n");
        Ok(s)
    }
}
