//! Persistent cache of per-file facts in one SQLite file.
//!
//! A file's lowered IR (CFGs, imports, declarations) depends only on its content, its
//! language and the lowering code, so it is stored under a hash of those. Anything that
//! depends on other files (declaration linking, summaries, findings) is recomputed.
//!
//! The database is stamped with [`stamp`] (schema version plus tool version); a stored
//! file written by another stamp is cleared, so a change to the analysis code can never
//! serve stale facts. Writes of one run share one transaction: an interrupted run leaves
//! the previous state.

pub mod graph;

use crate::analysis::Finding;
use crate::ir::Cfg;
use crate::lang::{Language, common::{Declarations, Import}};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Bump when the stored layout or the meaning of the stored facts changes.
const SCHEMA: u32 = 3;

/// Schema version plus a hash of the sources this binary was built from (see `build.rs`):
/// any change to the analysis code invalidates every stored result.
fn stamp() -> String {
    format!("schema={SCHEMA};build={}", env!("TAINTLESS_BUILD"))
}

/// What lowering a file produces, before declarations are linked across files.
#[derive(Serialize, Deserialize)]
pub struct FileFacts {
    pub cfgs: Vec<Cfg>,
    pub imports: Vec<Import>,
    pub decls: Declarations,
}

impl FileFacts {
    /// Restore what the stored form leaves out: the retained source and the block labels.
    fn restore(mut self, src: &str) -> Self {
        let source: std::sync::Arc<str> = src.into();
        for cfg in &mut self.cfgs {
            cfg.source = source.clone();
            cfg.restore_labels();
        }
        self
    }
}

/// Key of a file's facts: its language and exact content.
pub fn facts_key(lang: Language, src: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(format!("{lang:?}\0").as_bytes());
    h.update(src.as_bytes());
    h.finalize().to_hex().to_string()
}

/// Entries of the facts and results tables not used for this many runs are deleted.
const KEEP_RUNS: i64 = 30;

/// SQL condition: the finding was reported by the latest `security --store` run.
pub(crate) const PRESENT: &str = "seen_run = (SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'findings_run')";

/// A stored finding's triage state.
pub struct Triage {
    pub status: String,
    pub reason: Option<String>,
}

pub struct Store {
    conn: Connection,
    path: std::path::PathBuf,
    /// Counts the runs that used this database (for pruning).
    run: i64,
}

impl Store {
    /// Open (creating it if needed) the database at `path`. Results written by a different
    /// [`stamp`] are dropped; the findings history is kept.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            // the cache is local state, not something to commit
            let ignore = dir.join(".gitignore");
            if !ignore.exists() {
                let _ = std::fs::write(ignore, "*\n");
            }
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS findings (
                 id TEXT PRIMARY KEY, rule TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
                 file TEXT NOT NULL, function TEXT NOT NULL, line INTEGER NOT NULL,
                 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, seen_run INTEGER NOT NULL DEFAULT 0,
                 status TEXT NOT NULL DEFAULT 'open', reason TEXT);",
        )?;
        let mut store = Self { conn, path: path.to_path_buf(), run: 0 };
        let stamp = stamp();
        if store.meta("stamp")?.as_deref() != Some(stamp.as_str()) {
            // other code may have written other columns: start the result tables afresh
            store.conn.execute_batch("DROP TABLE IF EXISTS facts; DROP TABLE IF EXISTS results; DROP TABLE IF EXISTS edges; DROP TABLE IF EXISTS nodes; DROP TABLE IF EXISTS file_graph; DROP TABLE IF EXISTS summaries; DELETE FROM meta WHERE key = 'graph_key';")?;
            store.conn.execute("INSERT OR REPLACE INTO meta VALUES ('stamp', ?1)", [stamp])?;
        }
        store.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS facts (key TEXT PRIMARY KEY, payload BLOB NOT NULL, used INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS results (key TEXT PRIMARY KEY, payload BLOB NOT NULL, used INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS nodes (
                 id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT, code TEXT NOT NULL, file TEXT NOT NULL,
                 line INTEGER NOT NULL, col INTEGER NOT NULL, method TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS edges (src TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL, label TEXT, var TEXT, ord INTEGER NOT NULL, file TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS file_graph (file TEXT PRIMARY KEY, hash TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS summaries (id INTEGER PRIMARY KEY CHECK (id = 1), payload BLOB NOT NULL);
             CREATE INDEX IF NOT EXISTS edges_file ON edges (file);
             CREATE INDEX IF NOT EXISTS nodes_file ON nodes (file);
             CREATE INDEX IF NOT EXISTS edges_src ON edges (kind, src);
             CREATE INDEX IF NOT EXISTS edges_dst ON edges (kind, dst);
             CREATE INDEX IF NOT EXISTS nodes_name ON nodes (kind, name);",
        )?;
        store.run = store.meta("run")?.and_then(|v| v.parse().ok()).unwrap_or(0);
        Ok(store)
    }

    fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    /// Count this run, for pruning entries nothing has used for a long time.
    pub fn begin_run(&mut self) -> Result<()> {
        self.run += 1;
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('run', ?1)", [self.run.to_string()])?;
        Ok(())
    }

    fn prune(&self) -> Result<()> {
        for table in ["facts", "results"] {
            self.conn.execute(&format!("DELETE FROM {table} WHERE used < ?1"), [self.run - KEEP_RUNS])?;
        }
        Ok(())
    }

    /// Drop every stored result and the stored graph; the findings history stays.
    pub fn clear(&self) -> Result<()> {
        self.conn.execute_batch("DELETE FROM facts; DELETE FROM results; DELETE FROM edges; DELETE FROM nodes; DELETE FROM file_graph; DELETE FROM summaries; DELETE FROM meta WHERE key = 'graph_key';")?;
        Ok(())
    }

    /// What the database holds, one line per table, and its size on disk.
    pub fn status(&self) -> Result<Vec<String>> {
        let count = |sql: &str| -> Result<(i64, i64)> { Ok(self.conn.query_row(sql, [], |r| Ok((r.get(0)?, r.get(1)?)))?) };
        let (files, file_bytes) = count("SELECT count(*), coalesce(sum(length(payload)), 0) FROM facts")?;
        let (runs, run_bytes) = count("SELECT count(*), coalesce(sum(length(payload)), 0) FROM results")?;
        let (nodes, edges) = count("SELECT (SELECT count(*) FROM nodes), (SELECT count(*) FROM edges)")?;
        let (findings, open) = count(&format!("SELECT count(*), coalesce(sum(status = 'open' AND {PRESENT}), 0) FROM findings"))?;
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        Ok(vec![
            format!("{}: {} KiB on disk, {} runs recorded (entries unused for {KEEP_RUNS} runs are pruned)", self.path.display(), size / 1024, self.run),
            format!("parsed files: {files} ({} KiB)", file_bytes / 1024),
            format!("project results: {runs} ({} KiB)", run_bytes / 1024),
            format!("graph: {nodes} nodes, {edges} edges{}", if self.graph_key().is_some() { "" } else { " (none stored; run `taintless index`)" }),
            format!("findings history: {findings} ({open} open and still reported)"),
        ])
    }

    /// The raw payload stored under `key`.
    pub fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.conn.query_row("SELECT payload FROM facts WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    /// The findings stored for a project fingerprint, if every config / manifest file read
    /// when they were computed still holds what it did. With the number of files and
    /// functions the run covered.
    pub fn get_findings(&self, key: &str) -> Option<(Vec<Finding>, usize, usize)> {
        let blob: Vec<u8> = self.conn.query_row("SELECT payload FROM results WHERE key = ?1", [key], |r| r.get(0)).optional().ok()??;
        let stored: StoredRun = postcard::from_bytes(&blob).ok()?;
        if !crate::inputs::unchanged(&stored.inputs) {
            return None;
        }
        let _ = self.conn.execute("UPDATE results SET used = ?2 WHERE key = ?1", params![key, self.run]);
        Some((stored.findings, stored.files, stored.functions))
    }

    /// The summaries an earlier analysis left (see `analysis::Persisted`), as bytes.
    pub fn get_summaries(&self) -> Option<Vec<u8>> {
        self.conn.query_row("SELECT payload FROM summaries WHERE id = 1", [], |r| r.get(0)).optional().ok()?
    }

    /// Keep the summaries of the latest analysis, replacing the earlier ones.
    pub fn put_summaries(&mut self, payload: &[u8]) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO summaries VALUES (1, ?1)", [payload])?;
        Ok(())
    }

    /// Store a run's findings with the inputs it read, replacing any earlier run of the
    /// same project fingerprint.
    pub fn put_findings(&mut self, key: &str, findings: &[Finding], files: usize, functions: usize) -> Result<()> {
        let run = StoredRun { inputs: crate::inputs::snapshot(), files, functions, findings: findings.to_vec() };
        let payload = postcard::to_stdvec(&run)?;
        self.conn.execute("INSERT OR REPLACE INTO results VALUES (?1, ?2, ?3)", params![key, payload, self.run])?;
        self.prune()
    }

    /// Record the findings of a run: new ones get `first_seen`, all of them `last_seen`; the
    /// ones not reported are fixed. A finding that comes back after a run without it is open
    /// again, whatever it was triaged as. One transaction.
    pub fn record_findings(&mut self, ids: &[String], findings: &[Finding], today: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        let previous: i64 = tx.query_row("SELECT coalesce((SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'findings_run'), 0)", [], |r| r.get(0))?;
        let current = previous + 1;
        tx.execute("INSERT OR REPLACE INTO meta VALUES ('findings_run', ?1)", [current.to_string()])?;
        {
            let mut up = tx.prepare(
                "INSERT INTO findings (id, rule, severity, message, file, function, line, first_seen, last_seen, seen_run)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET severity = ?3, file = ?5, function = ?6, line = ?7, last_seen = ?8,
                     status = CASE WHEN seen_run < ?10 THEN 'open' ELSE status END,
                     reason = CASE WHEN seen_run < ?10 THEN NULL ELSE reason END,
                     seen_run = ?9",
            )?;
            for (id, f) in ids.iter().zip(findings) {
                up.execute(params![id, f.rule, f.severity.as_str(), f.message, crate::analysis::rel_path(&f.file), f.function, f.line as i64, today, current, previous])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The findings whose status is not `open`, by id.
    pub fn triaged(&self) -> Result<std::collections::HashMap<String, Triage>> {
        let mut st = self.conn.prepare("SELECT id, status, reason FROM findings WHERE status != 'open'")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, Triage { status: r.get(1)?, reason: r.get(2)? })))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Set the status of the findings that match every given selector: `ids` (any of them),
    /// `rule`, and `file` (a substring of the path). Returns how many changed.
    pub fn set_status(&self, status: &str, reason: Option<&str>, ids: &[String], rule: Option<&str>, file: Option<&str>) -> Result<usize> {
        let mut conds: Vec<String> = vec![];
        let mut args: Vec<rusqlite::types::Value> = vec![status.to_string().into(), reason.map(str::to_string).into()];
        if !ids.is_empty() {
            conds.push(format!("id IN ({})", vec!["?"; ids.len()].join(",")));
            args.extend(ids.iter().map(|i| i.clone().into()));
        }
        if let Some(r) = rule {
            conds.push("rule = ?".into());
            args.push(r.to_string().into());
        }
        if let Some(f) = file {
            conds.push("instr(file, ?) > 0".into());
            args.push(f.to_string().into());
        }
        anyhow::ensure!(!conds.is_empty(), "name findings by id, --rule or --file");
        let sql = format!("UPDATE findings SET status = ?1, reason = ?2 WHERE {}", conds.join(" AND "));
        Ok(self.conn.execute(&sql, rusqlite::params_from_iter(args))?)
    }

    /// Stored findings as text rows: `id status first_seen last_seen rule file:line message`.
    pub fn history(&self, all: bool) -> Result<Vec<String>> {
        let filter = if all { String::new() } else { format!("WHERE {PRESENT}") };
        let sql = format!("SELECT id, status, first_seen, last_seen, {PRESENT}, rule, file, line, message, reason FROM findings {filter} ORDER BY file, line");
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map([], |r| {
            let (id, status, first, last, present, rule, file, line, msg, reason): (String, String, String, String, bool, String, String, i64, String, Option<String>) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?);
            let gone = if present { "" } else { " (fixed)" };
            let why = reason.map(|r| format!(" -- {r}")).unwrap_or_default();
            Ok(format!("{id}  {status}{gone}  {first}..{last}  {rule}  {file}:{line}  {msg}{why}"))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Store several files' facts in one transaction, mark the ones used (`hits`) in this
    /// run, and prune what has not been used for a long time.
    pub fn put_all(&mut self, items: &[(String, Vec<u8>)], hits: &[String]) -> Result<()> {
        let run = self.run;
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare("INSERT OR REPLACE INTO facts VALUES (?1, ?2, ?3)")?;
            for (key, payload) in items {
                stmt.execute(params![key, payload, run])?;
            }
            let mut touch = tx.prepare("UPDATE facts SET used = ?2 WHERE key = ?1")?;
            for key in hits {
                touch.execute(params![key, run])?;
            }
        }
        tx.commit()?;
        self.prune()
    }
}

/// Facts back from a stored payload, restored for source `src`. A payload that no longer
/// decodes counts as a miss.
pub fn decode(payload: &[u8], src: &str) -> Option<FileFacts> {
    postcard::from_bytes::<FileFacts>(payload).ok().map(|f| f.restore(src))
}

/// The stored form of `facts`.
pub fn encode(facts: &FileFacts) -> Result<Vec<u8>> {
    Ok(postcard::to_stdvec(facts)?)
}

#[derive(Serialize, Deserialize)]
struct StoredRun {
    inputs: Vec<crate::inputs::Input>,
    files: usize,
    functions: usize,
    findings: Vec<Finding>,
}

/// Fingerprint of everything a project analysis depends on besides the files it reads
/// while running: the working directory (paths are matched relative to it), the sources
/// and the configuration files in play.
pub fn project_key(files: &[(&Path, &str)], config_files: &[&Path]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(std::env::current_dir().unwrap_or_default().to_string_lossy().as_bytes());
    for (path, key) in files {
        h.update(b"\0f");
        h.update(path.to_string_lossy().as_bytes());
        h.update(key.as_bytes());
    }
    for c in config_files {
        h.update(b"\0c");
        h.update(c.to_string_lossy().as_bytes());
    }
    h.finalize().to_hex().to_string()
}
