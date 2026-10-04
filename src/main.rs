use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use ignore::WalkBuilder;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use taintless::{
    analysis::{self, Finding, crypto, Severity, baseline::Baseline, callgraph, config, deps, suppress},
    export::{
        callgraph as cg_export,
        cpg as cpg_export,
        crypto as crypto_export,
        dataflow as df_export,
        deps as deps_export,
        dot::to_dot_all,
        findings,
        json::to_json,
        text::to_text,
    },
    ir::Cfg,
    lang::{self, Language},
    store,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(about = "Multi-language code scanner: control-flow graphs, security checks, call graph")]
struct Cli {
    /// Do not read or write the cache of parsed files.
    #[arg(long, global = true)]
    no_cache: bool,
    /// The cache database (default: `.taintless/db.sqlite` in the project root, the nearest
    /// directory above the scanned path (or the working directory) that has a cache, a `.git` or a
    /// `.taintless.toml`).
    #[arg(long, global = true)]
    cache: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum CfgFormat {
    Dot,
    Json,
    /// Compact text, one line per block and edge.
    Text,
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Text,
    Json,
    /// SARIF 2.1.0 for GitHub code scanning and IDEs.
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum CallFormat {
    Text,
    Dot,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum CryptoFormat {
    Text,
    Json,
    /// CycloneDX 1.6 cryptographic bill of materials.
    Cbom,
    /// SARIF 2.1.0 results for weak algorithms and problems in the arguments.
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum CpgFormat {
    Json,
    Graphml,
    Dot,
    /// `nodes.csv` and `edges.csv` for `neo4j-admin import` (needs `--out`).
    Neo4j,
}

fn parse_edge_kind(s: &str) -> Result<taintless::cpg::graph::EdgeKind, String> {
    taintless::cpg::graph::EdgeKind::parse(s).ok_or_else(|| format!("unknown edge kind `{s}`"))
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    /// One node per file.
    File,
    /// One node per directory: a bird's-eye view of big trees.
    Dir,
}

#[derive(Subcommand)]
enum Query {
    /// Who calls the functions whose name contains NAME.
    Callers { name: String },
    /// What the functions whose name contains NAME call.
    Callees { name: String },
    /// Statements containing TO that data from statements containing FROM can reach, with the
    /// shortest chain of statements. An over-approximation: it does not know which calls sanitize.
    Reach { from: String, to: String },
    /// Stored findings (see `security --store`) counted by rule or by directory.
    Findings {
        #[arg(long)]
        by_dir: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum QueryFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum StoredFormat {
    Neo4j,
    Graphml,
}

#[derive(Clone, Copy, ValueEnum)]
enum TriageStatus {
    Open,
    Accepted,
    FalsePositive,
}

impl TriageStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::FalsePositive => "false-positive",
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum MinSeverity {
    Low,
    Medium,
    High,
}

impl From<MinSeverity> for Severity {
    fn from(s: MinSeverity) -> Self {
        match s {
            MinSeverity::Low => Severity::Low,
            MinSeverity::Medium => Severity::Medium,
            MinSeverity::High => Severity::High,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Delete every stored result of the cache (triage data is kept).
    ClearCache,
    /// Set the status of stored findings (see `security --store`, `history`): by id, or all
    /// those of a rule or file. A finding that returns after being fixed is open again.
    Triage {
        #[arg(value_enum)]
        status: TriageStatus,
        /// Ids of findings (as printed by `security --store` and `history`).
        ids: Vec<String>,
        /// Every finding of this rule.
        #[arg(long)]
        rule: Option<String>,
        /// Every finding whose path contains this text.
        #[arg(long)]
        file: Option<String>,
        /// Why (shown by `history`, kept in SARIF).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Show what the cache database holds and how big it is.
    CacheStatus,
    /// Store the code property graph of a project in the cache database, for `query` and `export-graph`.
    Index { path: PathBuf },
    /// Ask the stored graph (see `index`) a question.
    Query {
        #[command(subcommand)]
        what: Query,
        #[arg(long, value_enum, default_value = "text", global = true)]
        format: QueryFormat,
    },
    /// Write the stored graph (see `index`) for graph tools; node ids are stable across exports.
    ExportGraph {
        #[arg(long, value_enum)]
        format: StoredFormat,
        /// Directory for the files of `--format neo4j`; GraphML goes to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List the findings recorded by `security --store`.
    History {
        /// Include findings that are no longer reported.
        #[arg(long)]
        all: bool,
    },
    /// Print per-function control-flow graphs.
    Cfg {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "dot")]
        format: CfgFormat,
    },
    /// Find security problems: untrusted data reaching dangerous calls,
    /// unsafe functions, unreachable code.
    ///
    /// Exit code: 0 clean, 1 findings, 2 some file could not be analyzed.
    Security {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Hide findings below this severity.
        #[arg(long, value_enum, default_value = "low")]
        min_severity: MinSeverity,
        /// Project configuration (default: `.taintless.toml` next to the scanned path or in the working directory).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Report every finding, ignoring `taintless: ignore` comments.
        #[arg(long)]
        no_suppress: bool,
        /// Hide the findings recorded in this baseline file; only new ones count.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Record the current findings as a baseline and exit successfully.
        #[arg(long)]
        write_baseline: Option<PathBuf>,
        /// With `--write-baseline`: the entries stop hiding findings after this many days.
        #[arg(long, value_name = "DAYS", requires = "write_baseline")]
        review_after: Option<u64>,
        /// Record the findings in the cache database with first/last seen dates, and hide
        /// those triaged as accepted or false positive.
        #[arg(long)]
        store: bool,
    },
    /// Show which file depends on which: imports, includes and calls across files.
    Deps {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "dot")]
        format: CallFormat,
        #[arg(long, value_enum, default_value = "file")]
        level: Level,
        /// Also list modules that are not part of the scanned code.
        #[arg(long)]
        external: bool,
    },
    /// Show how values flow: from parameters and assignments through calls to
    /// returns, inside functions and across them.
    Flow {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "dot")]
        format: CallFormat,
        /// Only what the variable, callee or parameter with this name flows into.
        #[arg(long)]
        from: Option<String>,
        /// Only functions whose name contains this text.
        #[arg(long)]
        function: Option<String>,
        /// Also show which branch decides whether a statement runs.
        #[arg(long)]
        control: bool,
    },
    /// Export the code property graph: AST, control flow, control and data
    /// dependence, calls and imports in one graph.
    Cpg {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "json")]
        format: CpgFormat,
        /// Edge kinds to export (default: all): ast, contains, cfg, cdg, reaching, call, argument, receiver, imports.
        #[arg(long, value_delimiter = ',', value_parser = parse_edge_kind)]
        edges: Vec<taintless::cpg::graph::EdgeKind>,
        /// Only inside functions whose name contains this text.
        #[arg(long)]
        function: Option<String>,
        /// Directory for the files of `--format neo4j`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List the crypto libraries a project imports and the crypto functions it calls.
    Crypto {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: CryptoFormat,
        /// Only list weak algorithms and problems in the arguments (no libraries, no plain calls).
        #[arg(long)]
        only_weak: bool,
        /// Exit with status 1 when a weak algorithm or a problem in the arguments is found.
        #[arg(long)]
        fail_on_weak: bool,
        /// Only list weak algorithms and problems of at least this severity (implies `--only-weak`).
        #[arg(long, value_enum)]
        min_severity: Option<MinSeverity>,
        /// Project configuration whose `[crypto]` tables extend the built-in ones (default: `.taintless.toml`
        /// next to the scanned path or in the working directory).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show which function calls which.
    Calls {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: CallFormat,
        /// Also list the most frequent calls that leave the scanned code.
        #[arg(long)]
        external: bool,
    },
}

struct Loaded {
    file: PathBuf,
    lang: Language,
    cfgs: Vec<Cfg>,
    /// What the file imports (needed to resolve calls and for `deps`).
    imports: Vec<lang::common::Import>,
    /// The structs / classes and type aliases the file declares (linked to methods in other files).
    decls: lang::common::Declarations,
    /// Key of the file's stored facts: its language and content.
    key: String,
}

fn source_of(l: &Loaded) -> std::io::Result<String> {
    match l.cfgs.first() {
        Some(cfg) => Ok(cfg.source.to_string()),
        None => std::fs::read_to_string(&l.file),
    }
}

type Parsed = (PathBuf, Result<(Language, String, store::FileFacts)>);

struct Pipeline {
    store: Option<store::Store>,
    /// The findings of an identical earlier run, found before any file was decoded (`ok` is then empty).
    cached: Option<Vec<Finding>>,
    /// Files and functions scanned (known without `ok` when `cached`).
    counts: (usize, usize),
    ok: Vec<Loaded>,
    failed: bool,
    skipped: usize,
    started: Instant,
}

/// Print the result in the chosen format.
fn emit(format: CallFormat, text: impl FnOnce() -> String, dot: impl FnOnce() -> String, json: impl FnOnce() -> serde_json::Value) -> Result<()> {
    match format {
        CallFormat::Text => print!("{}", text()),
        CallFormat::Dot => print!("{}", dot()),
        CallFormat::Json => println!("{}", serde_json::to_string_pretty(&json())?),
    }
    Ok(())
}

impl Pipeline {
    /// Fingerprint of the loaded sources and the configuration files in play.
    fn run_key(&self, config_files: &[PathBuf]) -> String {
        let files: Vec<(&Path, &str)> = self.ok.iter().map(|l| (l.file.as_path(), l.key.as_str())).collect();
        let configs: Vec<&Path> = config_files.iter().map(PathBuf::as_path).collect();
        store::project_key(&files, &configs)
    }

    fn exit_if_failed(&self) {
        if self.failed {
            std::process::exit(1);
        }
    }

    fn project(&self) -> Vec<analysis::ProjectFile<'_>> {
        self.ok.iter().map(|l| analysis::ProjectFile { lang: l.lang, file: &l.file, cfgs: &l.cfgs, imports: &l.imports }).collect()
    }

    fn dep_files(&self) -> Vec<deps::DepFile<'_>> {
        self.ok.iter().map(|l| deps::DepFile { path: &l.file, lang: l.lang, imports: l.imports.clone(), cfgs: &l.cfgs }).collect()
    }

    fn cpg_sources(&self) -> std::io::Result<Vec<String>> {
        self.ok.iter().map(source_of).collect()
    }

    fn cpg_files<'a>(&'a self, sources: &'a [String]) -> Vec<taintless::cpg::SourceFile<'a>> {
        self.ok
            .iter()
            .zip(sources)
            .map(|(l, src)| taintless::cpg::SourceFile { path: &l.file, lang: l.lang, src, cfgs: &l.cfgs, imports: &l.imports })
            .collect()
    }
}

/// Parse one already-read file into CFGs.
fn analyze(lang: Language, src: &str) -> Result<store::FileFacts> {
    Ok(store::FileFacts {
        cfgs: lang::build_cfgs(lang, src)?,
        imports: lang::imports(lang, src).unwrap_or_default(),
        decls: lang::declarations(lang, src).unwrap_or_default(),
    })
}

/// A bar for one stage; hidden automatically when stderr is not a terminal.
fn stage_bar(len: usize, stage: &str) -> Result<ProgressBar> {
    let tpl = format!("{{spinner:.green}} {stage:<10} [{{bar:40.cyan/blue}}] {{pos}}/{{len}} files  {{elapsed_precise}}  {{msg}}");
    Ok(ProgressBar::new(len as u64).with_style(ProgressStyle::with_template(&tpl)?.progress_chars("=> ")))
}

/// Discover, read and lower every supported file under `path`.
/// With `configs`, the stored findings of an identical earlier run are looked up first (see
/// `Pipeline::cached`); `configs` are the configuration files in play.
fn load(path: &Path, cache: Option<&Path>, configs: Option<&[PathBuf]>) -> Result<Pipeline> {
    let started = Instant::now();

    // Stage 0: discover files. The total is unknown, so show a spinner with a count.
    let spinner = ProgressBar::new_spinner()
        .with_style(ProgressStyle::with_template("{spinner:.green} discovering {pos} files  {elapsed_precise}")?);
    spinner.enable_steady_tick(Duration::from_millis(80));
    let mut files: Vec<PathBuf> = vec![];
    let mut failed = false;
    for entry in WalkBuilder::new(path).build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("{e}");
                failed = true;
                continue;
            }
        };
        if entry.file_type().is_some_and(|t| t.is_file()) {
            files.push(entry.into_path());
            spinner.inc(1);
        }
    }
    spinner.finish_and_clear();
    files.sort();
    let total = files.len();
    files.retain(|f| lang::Language::detect(f).is_some());
    let skipped = total - files.len();

    // Stage 1: read every file (I/O bound).
    let bar = stage_bar(files.len(), "reading")?;
    let sources: Vec<(PathBuf, Result<String>)> = files
        .par_iter()
        .progress_with(bar.clone())
        .map(|p| (p.clone(), std::fs::read_to_string(p).map_err(Into::into)))
        .collect();
    bar.finish_and_clear();

    // Stage 2: parse and build CFGs (CPU bound), unless the cache holds the file's facts.
    // `collect` keeps the walk order so output is stable.
    let mut store = cache.and_then(|p| match store::Store::open(p).and_then(|mut s| s.begin_run().map(|()| s)) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("warning: cache disabled: {e:#}");
            None
        }
    });
    // (path, language, key, source or read error)
    let prepared: Vec<_> = sources
        .into_par_iter()
        .map(|(p, src)| match src {
            Ok(s) => {
                let lang = lang::Language::detect_with_source(&p, &s).expect("filtered by detect");
                let key = store::facts_key(lang, &s);
                (p, Ok((lang, key, s)))
            }
            Err(e) => (p, Err(e)),
        })
        .collect();
    let stored: Vec<Option<Vec<u8>>> = prepared
        .iter()
        .map(|(_, r)| match (&store, r) {
            (Some(st), Ok((_, key, _))) => st.get_raw(key).ok().flatten(),
            _ => None,
        })
        .collect();
    if let (Some(configs), Some(st)) = (configs, store.as_mut())
        && prepared.iter().all(|(_, r)| r.is_ok())
    {
        let files: Vec<(&Path, &str)> = prepared.iter().filter_map(|(p, r)| r.as_ref().ok().map(|(_, key, _)| (p.as_path(), key.as_str()))).collect();
        let configs: Vec<&Path> = configs.iter().map(PathBuf::as_path).collect();
        if let Some((found, nfiles, nfns)) = st.get_findings(&store::project_key(&files, &configs)) {
            // the files' own entries count as used too, or they would age out behind a long run of hits
            let keys: Vec<String> = files.iter().map(|(_, k)| k.to_string()).collect();
            if let Err(e) = st.put_all(&[], &keys) {
                eprintln!("warning: cache not updated: {e:#}");
            }
            return Ok(Pipeline { store, cached: Some(found), counts: (nfiles, nfns), ok: vec![], failed: false, skipped, started });
        }
    }
    let caching = store.is_some();
    let bar = stage_bar(prepared.len(), "analyzing")?;
    // `Some((key, None))`: the facts came from the cache; `Some((key, Some(bytes)))`: they are new
    let results: Vec<(Parsed, Option<(String, Option<Vec<u8>>)>)> = prepared
        .par_iter()
        .zip(stored.par_iter())
        .progress_with(bar.clone())
        .map(|((p, r), blob)| {
            bar.set_message(p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
            let (lang, key, s) = match r {
                Ok(v) => v,
                Err(e) => return ((p.clone(), Err(anyhow::anyhow!("{e:#}"))), None),
            };
            if let Some(f) = blob.as_deref().and_then(|b| store::decode(b, s)) {
                return ((p.clone(), Ok((*lang, key.clone(), f))), Some((key.clone(), None)));
            }
            match analyze(*lang, s) {
                Ok(f) => {
                    let new = caching.then(|| store::encode(&f).ok().map(|b| (key.clone(), Some(b)))).flatten();
                    ((p.clone(), Ok((*lang, key.clone(), f))), new)
                }
                Err(e) => ((p.clone(), Err(e)), None),
            }
        })
        .collect();
    bar.finish_and_clear();
    let (results, fresh): (Vec<Parsed>, Vec<_>) = results.into_iter().unzip();
    if let Some(st) = store.as_mut() {
        let (mut new, mut hits) = (vec![], vec![]);
        for (key, payload) in fresh.into_iter().flatten() {
            match payload {
                Some(payload) => new.push((key, payload)),
                None => hits.push(key),
            }
        }
        if let Err(e) = st.put_all(&new, &hits) {
            eprintln!("warning: cache not updated: {e:#}");
        }
    }

    let mut ok = vec![];
    for (file, res) in results {
        match res {
            Ok((lang, key, f)) => ok.push(Loaded { file, lang, cfgs: f.cfgs, imports: f.imports, decls: f.decls, key }),
            Err(e) => {
                eprintln!("{}: {e:#}", file.display());
                failed = true;
            }
        }
    }
    // methods learn the fields of structs / classes declared in other files; aliases are resolved
    let mut linked: Vec<_> = ok.iter_mut().map(|l| (l.lang, &mut l.cfgs, &l.decls)).collect();
    analysis::link::link_declarations(&mut linked);
    let counts = (ok.len(), ok.iter().map(|l| l.cfgs.len()).sum());
    Ok(Pipeline { store, cached: None, counts, ok, failed, skipped, started })
}

fn summary(p: &Pipeline) {
    eprintln!(
        "scanned {} files ({} functions) in {:.2?}, skipped {} unsupported",
        p.counts.0,
        p.counts.1,
        p.started.elapsed(),
        p.skipped
    );
}

/// One answer of `query` as text.
fn query_text(what: &Query, row: &serde_json::Value) -> String {
    let (str_of, int_of) = (|k: &str| row[k].as_str().unwrap_or("").to_string(), |k: &str| row[k].as_i64().unwrap_or(0));
    match what {
        Query::Callers { .. } | Query::Callees { .. } => format!(
            "{} ({}:{}) calls {} at {}:{}\n",
            str_of("function"), str_of("file"), int_of("line"), str_of("callee"), str_of("call_file"), int_of("call_line")
        ),
        Query::Reach { .. } => {
            let mut s = format!("{}:{}: {}\n", str_of("file"), int_of("line"), str_of("code"));
            for step in row["path"].as_array().into_iter().flatten() {
                s += &format!("    via {}:{}: {}\n", step["file"].as_str().unwrap_or(""), step["line"].as_i64().unwrap_or(0), step["code"].as_str().unwrap_or(""));
            }
            s
        }
        Query::Findings { .. } => format!("{}  {}\n", int_of("count"), str_of("group")),
    }
}

/// Where the cache database lives: an existing one above `start`, else next to the nearest
/// `.git` or `.taintless.toml`, else in `start` itself (a file's directory).
fn default_cache(start: &Path) -> PathBuf {
    const DB: &str = ".taintless/db.sqlite";
    let abs = start.canonicalize().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(start));
    let dir = if abs.is_dir() { abs.clone() } else { abs.parent().map(Path::to_path_buf).unwrap_or(abs) };
    let up = || dir.ancestors();
    up().find(|d| d.join(DB).exists())
        .or_else(|| up().find(|d| d.join(".git").exists() || d.join(".taintless.toml").exists()))
        .unwrap_or(&dir)
        .join(DB)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let scanned = match &cli.cmd {
        Cmd::Cfg { path, .. } | Cmd::Security { path, .. } | Cmd::Deps { path, .. } | Cmd::Flow { path, .. } | Cmd::Cpg { path, .. } | Cmd::Calls { path, .. } | Cmd::Crypto { path, .. } | Cmd::Index { path } => path.clone(),
        _ => PathBuf::from("."),
    };
    let db_path = cli.cache.clone().unwrap_or_else(|| default_cache(&scanned));
    let cache = (!cli.no_cache).then_some(db_path.as_path());
    if cache.is_some() {
        // configuration is read before the cache opens, so recording starts here
        taintless::inputs::enable();
    }
    match cli.cmd {
        Cmd::Triage { status, ids, rule, file, reason } => {
            let n = store::Store::open(&db_path)?.set_status(status.as_str(), reason.as_deref(), &ids, rule.as_deref(), file.as_deref())?;
            if n == 0 {
                anyhow::bail!("no stored finding matches (run `security --store`, then `history`)");
            }
            eprintln!("{n} finding(s) set to {}", status.as_str());
        }
        Cmd::CacheStatus => {
            for line in store::Store::open(&db_path)?.status()? {
                println!("{line}");
            }
        }
        Cmd::Index { path } => {
            let mut p = load(&path, cache, None)?;
            summary(&p);
            let mut db = p.store.take().ok_or_else(|| anyhow::anyhow!("`index` needs the cache (not --no-cache)"))?;
            let key = p.run_key(&[]);
            if db.graph_key().as_deref() == Some(key.as_str()) {
                eprintln!("graph is up to date");
            } else {
                let sources = p.cpg_sources()?;
                let files = p.cpg_files(&sources);
                let cpg = taintless::cpg::Cpg::build(&files)?;
                let (nodes, edges) = store::graph::rows(&cpg);
                db.replace_graph(&key, &nodes, &edges)?;
                eprintln!("stored {} nodes and {} edges in {}", nodes.len(), edges.len(), db_path.display());
            }
            p.exit_if_failed();
        }
        Cmd::Query { what, format } => {
            let db = store::Store::open(&db_path)?;
            let rows = match &what {
                Query::Callers { name } => db.calls(name, true)?,
                Query::Callees { name } => db.calls(name, false)?,
                Query::Reach { from, to } => db.reachable(from, to)?,
                Query::Findings { by_dir } => db.findings_by(*by_dir)?,
            };
            match format {
                QueryFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
                QueryFormat::Text => {
                    for r in &rows {
                        print!("{}", query_text(&what, r));
                    }
                }
            }
        }
        Cmd::ExportGraph { format, out } => {
            let db = store::Store::open(&db_path)?;
            match format {
                StoredFormat::Graphml => print!("{}", db.graphml()?),
                StoredFormat::Neo4j => {
                    let dir = out.ok_or_else(|| anyhow::anyhow!("--format neo4j needs --out <directory>"))?;
                    let (nodes, edges) = db.neo4j()?;
                    std::fs::create_dir_all(&dir)?;
                    std::fs::write(dir.join("nodes.csv"), nodes)?;
                    std::fs::write(dir.join("edges.csv"), edges)?;
                    eprintln!("wrote {0}/nodes.csv and {0}/edges.csv", dir.display());
                }
            }
        }
        Cmd::History { all } => {
            for row in store::Store::open(&db_path)?.history(all)? {
                println!("{row}");
            }
        }
        Cmd::ClearCache => {
            if db_path.exists() {
                store::Store::open(&db_path)?.clear()?;
            }
            eprintln!("cleared {}", db_path.display());
        }
        Cmd::Cfg { path, format } => {
            let p = load(&path, cache, None)?;
            summary(&p);
            match format {
                // One document: concatenated digraphs would give invalid SVG in `dot`.
                CfgFormat::Dot => {
                    let files = p.ok.iter().map(|l| {
                        (l.file.display().to_string(), l.cfgs.iter().map(|c| (c.name.as_str(), c)).collect())
                    });
                    print!("{}", to_dot_all(files));
                }
                CfgFormat::Text => {
                    for l in &p.ok {
                        for c in &l.cfgs {
                            println!("# {}", l.file.display());
                            print!("{}", to_text(c));
                        }
                    }
                }
                CfgFormat::Json => {
                    let out: Vec<_> = p
                        .ok
                        .iter()
                        .map(|l| {
                            json!({
                                "file": l.file.display().to_string(),
                                "functions": l.cfgs.iter().map(to_json).collect::<Vec<_>>(),
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
            if p.failed {
                std::process::exit(1);
            }
        }
        Cmd::Security { path, format, min_severity, config: config_path, no_suppress, baseline, write_baseline, review_after, store: keep } => {
            // the configuration shapes the rules, so it is installed before anything is analyzed
            let config_file = config_path.or_else(|| config::discover(&path));
            let mut config_paths: Vec<PathBuf> = config_file.iter().cloned().collect();
            let setup = (|| -> anyhow::Result<bool> {
                let root = config_file.as_deref().map(config::load).transpose()?;
                let nested = config::discover_nested(&path, config_file.as_deref())?;
                config_paths.extend(nested.iter().map(|(dir, _)| config::nested_file(dir)));
                if root.is_none() && nested.is_empty() {
                    return Ok(false);
                }
                config::install_with(root.unwrap_or_default(), nested)?;
                Ok(true)
            })();
            match setup {
                Ok(true) => {
                    if let Some(file) = &config_file {
                        eprintln!("using configuration {}", file.display());
                    }
                }
                Ok(false) => {}
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(2);
                }
            }
            let mut p = load(&path, cache, Some(&config_paths))?;
            let mut store = p.store.take();
            let cached = p.cached.take();
            // Stage 3: taint and rule analysis per file.
            let project = p.project();
            let bar = ProgressBar::new(analysis::function_count(&project) as u64).with_style(
                ProgressStyle::with_template("{spinner:.green} checking   [{bar:40.cyan/blue}] {pos}/{len} functions  {elapsed_precise}")?
                    .progress_chars("=> "),
            );
            let min: Severity = min_severity.into();
            // A run over the same sources, configuration and manifests is served from the cache.
            let mut found: Vec<Finding> = match cached {
                Some(f) => f,
                None => {
                    let f = analysis::check_project(&project, &|| bar.inc(1));
                    // an incomplete scan is not stored: a hit must mean every file was analyzed
                    if !p.failed
                        && let Some(s) = store.as_mut()
                        && let Err(e) = s.put_findings(&p.run_key(&config_paths), &f, p.counts.0, p.counts.1)
                    {
                        eprintln!("warning: cache not updated: {e:#}");
                    }
                    f
                }
            };
            found.retain(|f| f.severity >= min);
            bar.finish_and_clear();
            let mut notes = vec![];
            if !no_suppress {
                let (kept, n, expired) = suppress::apply_on(found, &|f| std::fs::read_to_string(f).ok(), &suppress::today());
                found = kept;
                if n > 0 {
                    notes.push(format!("{n} suppressed by `taintless: ignore` comments"));
                }
                if expired > 0 {
                    notes.push(format!("{expired} reported again because their `taintless: ignore ... until=` date has passed"));
                }
            }
            if let Some(file) = &write_baseline {
                if p.failed {
                    eprintln!("cannot write baseline: scan is incomplete");
                    std::process::exit(2);
                }
                Baseline::build(&found, &|f| std::fs::read_to_string(f).ok(), review_after).save(file)?;
                eprintln!("wrote baseline with {} findings to {}", found.len(), file.display());
                return Ok(());
            }
            if let Some(file) = &baseline {
                let (new, known, expired) =
                    Baseline::load(file)?.filter_on(found, &|f| std::fs::read_to_string(f).ok(), &suppress::today());
                found = new;
                notes.push(format!("{known} already in the baseline"));
                if expired > 0 {
                    notes.push(format!("{expired} reported again because their baseline entry is past its review date"));
                }
            }
            found.sort_by(|a, b| (&a.file, a.line, a.col, a.rule).cmp(&(&b.file, b.line, b.col, b.rule)));
            let mut stored = findings::Stored::default();
            if keep {
                match store.as_mut() {
                    None => eprintln!("warning: --store needs the cache (not --no-cache)"),
                    Some(s) => {
                        let ids = analysis::baseline::finding_ids(&found, &|f| std::fs::read_to_string(f).ok());
                        match s.record_findings(&ids, &found, &suppress::today()) {
                            Ok(()) => {
                                // after recording: a finding that came back is open again
                                let triaged = s.triaged().unwrap_or_default();
                                let (mut shown, mut shown_ids) = (vec![], vec![]);
                                for (finding, id) in std::mem::take(&mut found).into_iter().zip(ids) {
                                    match triaged.get(&id) {
                                        Some(t) => stored.triaged.push(findings::Triaged { finding, id, status: t.status.clone(), reason: t.reason.clone() }),
                                        None => {
                                            shown.push(finding);
                                            shown_ids.push(id);
                                        }
                                    }
                                }
                                found = shown;
                                stored.ids = shown_ids;
                                if !stored.triaged.is_empty() {
                                    notes.push(format!("{} triaged as accepted or false positive", stored.triaged.len()));
                                }
                            }
                            Err(e) => eprintln!("warning: findings not stored: {e:#}"),
                        }
                    }
                }
            }
            summary(&p);
            let count = |s: Severity| found.iter().filter(|f| f.severity == s).count();
            eprintln!(
                "{} findings ({} high, {} medium, {} low){}",
                found.len(),
                count(Severity::High),
                count(Severity::Medium),
                count(Severity::Low),
                if notes.is_empty() { String::new() } else { format!("; {}", notes.join("; ")) }
            );
            match format {
                ReportFormat::Text => print!("{}", findings::to_text_with(&found, &stored)),
                ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&findings::to_json_with(&found, &stored))?),
                ReportFormat::Sarif => println!("{}", serde_json::to_string_pretty(&findings::to_sarif_with(&found, &stored))?),
            }
            if p.failed {
                std::process::exit(2);
            }
            if !found.is_empty() {
                std::process::exit(1);
            }
        }
        Cmd::Deps { path, format, level, external } => {
            let p = load(&path, cache, None)?;
            summary(&p);
            let files = p.dep_files();
            let mut graph = deps::build(&files);
            if matches!(level, Level::Dir) {
                graph = graph.by_dir();
            }
            emit(format, || deps_export::to_text(&graph, external), || deps_export::to_dot(&graph), || deps_export::to_json(&graph))?;
            p.exit_if_failed();
        }
        Cmd::Flow { path, format, from, function, control } => {
            let p = load(&path, cache, None)?;
            summary(&p);
            // CFGs retain their source so the CPG view also works for in-memory projects.
            let sources = p.cpg_sources()?;
            let files = p.cpg_files(&sources);
            let cpg = taintless::cpg::Cpg::build(&files)?;
            let df = taintless::cpg::flow::flow_graph(&cpg, &files, control);
            let keep = from.as_deref().map(|name| df.slice_from(name));
            let nodes = df_export::select(&df, keep.as_ref(), function.as_deref());
            emit(format, || df_export::to_text(&df, &nodes), || df_export::to_dot(&df, &nodes), || df_export::to_json(&df, &nodes))?;
            p.exit_if_failed();
        }
        Cmd::Cpg { path, format, edges, function, out } => {
            let p = load(&path, cache, None)?;
            summary(&p);
            // The syntax trees are built from the sources retained by the CFGs.
            let sources = p.cpg_sources()?;
            let files = p.cpg_files(&sources);
            let cpg = taintless::cpg::Cpg::build(&files)?;
            let sel = cpg_export::select(&cpg, &edges, function.as_deref());
            match format {
                CpgFormat::Json => println!("{}", serde_json::to_string_pretty(&cpg_export::to_json(&cpg, &sel))?),
                CpgFormat::Graphml => print!("{}", cpg_export::to_graphml(&cpg, &sel)),
                CpgFormat::Dot => print!("{}", cpg_export::to_dot(&cpg, &sel)),
                CpgFormat::Neo4j => {
                    let dir = out.ok_or_else(|| anyhow::anyhow!("--format neo4j needs --out <directory>"))?;
                    let (nodes, edges) = cpg_export::to_neo4j(&cpg, &sel);
                    std::fs::create_dir_all(&dir)?;
                    std::fs::write(dir.join("nodes.csv"), nodes)?;
                    std::fs::write(dir.join("edges.csv"), edges)?;
                    eprintln!("wrote {0}/nodes.csv and {0}/edges.csv", dir.display());
                }
            }
            p.exit_if_failed();
        }
        Cmd::Crypto { path, format, only_weak, fail_on_weak, min_severity, config: config_path } => {
            if let Some(file) = config_path.or_else(|| config::discover(&path)) {
                let extra = match config::load(&file) {
                    Ok(c) => c.crypto,
                    Err(e) => {
                        eprintln!("error: {e:#}");
                        std::process::exit(2);
                    }
                };
                if !extra.is_empty() {
                    eprintln!("using crypto tables from {}", file.display());
                    if let Err(e) = crypto::tables::install(extra) {
                        eprintln!("error: {e}");
                        std::process::exit(2);
                    }
                }
            }
            let p = load(&path, cache, None)?;
            summary(&p);
            let files: Vec<crypto::ScanFile> = p.ok.iter().map(|l| crypto::ScanFile { lang: l.lang, file: &l.file, imports: &l.imports, cfgs: &l.cfgs }).collect();
            let mut uses = crypto::scan_project(&files);
            // manifests, key material and settings: every readable file under the path
            let mut declared = vec![];
            let mut seen = std::collections::HashSet::new();
            for e in WalkBuilder::new(&path).build().filter_map(Result::ok).filter(|e| e.file_type().is_some_and(|t| t.is_file())) {
                if e.metadata().is_ok_and(|m| m.len() > 8 << 20) {
                    continue;
                }
                let Ok(bytes) = std::fs::read(e.path()) else { continue };
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    declared.extend(crypto::scan_manifest(e.path(), text));
                }
                // an included configuration file is reported once, wherever it is reached from
                for u in crypto::scan_artifact(e.path(), &bytes) {
                    if seen.insert((u.file.clone(), u.line, u.col, u.name.clone(), u.algorithm.clone())) {
                        uses.push(u);
                    }
                }
            }
            let only_weak = only_weak || min_severity.is_some();
            if let Some(min) = min_severity {
                let min = Severity::from(min);
                uses.retain(|u| u.severity().is_some_and(|s| s >= min));
            }
            let flagged = uses.iter().any(crypto::CryptoUse::flagged);
            if only_weak {
                uses.retain(crypto::CryptoUse::flagged);
            }
            crypto::mark_used(&mut declared, &uses);
            if only_weak {
                declared.clear();
            }
            match format {
                CryptoFormat::Text => print!("{}", crypto_export::to_text(&uses, &declared)),
                CryptoFormat::Json => println!("{}", serde_json::to_string_pretty(&crypto_export::to_json(&uses, &declared))?),
                CryptoFormat::Cbom => println!("{}", serde_json::to_string_pretty(&crypto_export::to_cbom(&uses, &declared))?),
                CryptoFormat::Sarif => println!("{}", serde_json::to_string_pretty(&crypto_export::to_sarif(&uses))?),
            }
            p.exit_if_failed();
            if fail_on_weak && flagged {
                std::process::exit(1);
            }
        }
        Cmd::Calls { path, format, external } => {
            let p = load(&path, cache, None)?;
            summary(&p);
            // imports decide between same-named functions
            let dep_files = p.dep_files();
            let refs: Vec<(&Path, Language, &[Cfg])> = p.ok.iter().map(|l| (l.file.as_path(), l.lang, l.cfgs.as_slice())).collect();
            let graph = callgraph::build_refs(&refs, Some(deps::visibility(&dep_files)));
            emit(format, || cg_export::to_text(&graph, external), || cg_export::to_dot(&graph), || cg_export::to_json(&graph))?;
            p.exit_if_failed();
        }
    }
    Ok(())
}
