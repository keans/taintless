use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use ignore::WalkBuilder;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use taintless::{
    analysis::{self, Finding, Severity, baseline::Baseline, callgraph, config, deps, suppress},
    export::{
        callgraph as cg_export,
        cpg as cpg_export,
        dataflow as df_export,
        deps as deps_export,
        dot::to_dot_all,
        findings,
        json::to_json,
        text::to_text,
    },
    ir::Cfg,
    lang::{self, Language},
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(about = "Multi-language code scanner: control-flow graphs, security checks, call graph")]
struct Cli {
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
}

type Parsed = (PathBuf, Result<(Language, Vec<Cfg>, Vec<lang::common::Import>, lang::common::Declarations)>);

struct Pipeline {
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
}

/// Parse one already-read file into CFGs.
fn analyze(path: &Path, src: &str) -> Result<(Language, Vec<Cfg>, Vec<lang::common::Import>, lang::common::Declarations)> {
    let l = lang::Language::detect_with_source(path, src).expect("filtered by detect");
    Ok((l, lang::build_cfgs(l, src)?, lang::imports(l, src).unwrap_or_default(), lang::declarations(l, src).unwrap_or_default()))
}

/// A bar for one stage; hidden automatically when stderr is not a terminal.
fn stage_bar(len: usize, stage: &str) -> Result<ProgressBar> {
    let tpl = format!("{{spinner:.green}} {stage:<10} [{{bar:40.cyan/blue}}] {{pos}}/{{len}} files  {{elapsed_precise}}  {{msg}}");
    Ok(ProgressBar::new(len as u64).with_style(ProgressStyle::with_template(&tpl)?.progress_chars("=> ")))
}

/// Discover, read and lower every supported file under `path`.
fn load(path: &Path) -> Result<Pipeline> {
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

    // Stage 2: parse and build CFGs (CPU bound). `collect` keeps the walk
    // order so output is stable.
    let bar = stage_bar(sources.len(), "analyzing")?;
    let results: Vec<Parsed> = sources
        .par_iter()
        .progress_with(bar.clone())
        .map(|(p, src)| {
            bar.set_message(p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
            let res = match src {
                Ok(s) => analyze(p, s),
                Err(e) => Err(anyhow::anyhow!("{e:#}")),
            };
            (p.clone(), res)
        })
        .collect();
    bar.finish_and_clear();

    let mut ok = vec![];
    for (file, res) in results {
        match res {
            Ok((lang, cfgs, imports, decls)) => ok.push(Loaded { file, lang, cfgs, imports, decls }),
            Err(e) => {
                eprintln!("{}: {e:#}", file.display());
                failed = true;
            }
        }
    }
    // methods learn the fields of structs / classes declared in other files; aliases are resolved
    let mut linked: Vec<_> = ok.iter_mut().map(|l| (l.lang, &mut l.cfgs, &l.decls)).collect();
    analysis::link::link_declarations(&mut linked);
    Ok(Pipeline { ok, failed, skipped, started })
}

fn summary(p: &Pipeline) {
    eprintln!(
        "scanned {} files ({} functions) in {:.2?}, skipped {} unsupported",
        p.ok.len(),
        p.ok.iter().map(|l| l.cfgs.len()).sum::<usize>(),
        p.started.elapsed(),
        p.skipped
    );
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Cfg { path, format } => {
            let p = load(&path)?;
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
        Cmd::Security { path, format, min_severity, config: config_path, no_suppress, baseline, write_baseline, review_after } => {
            // the configuration shapes the rules, so it is installed before anything is analyzed
            let config_file = config_path.or_else(|| config::discover(&path));
            let setup = (|| -> anyhow::Result<bool> {
                let root = config_file.as_deref().map(config::load).transpose()?;
                let nested = config::discover_nested(&path, config_file.as_deref())?;
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
            let p = load(&path)?;
            // Stage 3: taint and rule analysis per file.
            let project = p.project();
            let bar = ProgressBar::new(analysis::function_count(&project) as u64).with_style(
                ProgressStyle::with_template("{spinner:.green} checking   [{bar:40.cyan/blue}] {pos}/{len} functions  {elapsed_precise}")?
                    .progress_chars("=> "),
            );
            let min: Severity = min_severity.into();
            let mut found: Vec<Finding> = analysis::check_project(&project, &|| bar.inc(1));
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
                ReportFormat::Text => print!("{}", findings::to_text(&found)),
                ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&findings::to_json(&found))?),
                ReportFormat::Sarif => println!("{}", serde_json::to_string_pretty(&findings::to_sarif(&found))?),
            }
            if p.failed {
                std::process::exit(2);
            }
            if !found.is_empty() {
                std::process::exit(1);
            }
        }
        Cmd::Deps { path, format, level, external } => {
            let p = load(&path)?;
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
            let p = load(&path)?;
            summary(&p);
            // the flow graph is drawn from the code property graph, which parses the files again
            let sources: Vec<String> = p.ok.iter().map(|l| std::fs::read_to_string(&l.file)).collect::<std::io::Result<_>>()?;
            let files: Vec<taintless::cpg::SourceFile> = p
                .ok
                .iter()
                .zip(&sources)
                .map(|(l, src)| taintless::cpg::SourceFile { path: &l.file, lang: l.lang, src, cfgs: &l.cfgs, imports: &l.imports })
                .collect();
            let cpg = taintless::cpg::Cpg::build(&files)?;
            let df = taintless::cpg::flow::flow_graph(&cpg, &files, control);
            let keep = from.as_deref().map(|name| df.slice_from(name));
            let nodes = df_export::select(&df, keep.as_ref(), function.as_deref());
            emit(format, || df_export::to_text(&df, &nodes), || df_export::to_dot(&df, &nodes), || df_export::to_json(&df, &nodes))?;
            p.exit_if_failed();
        }
        Cmd::Cpg { path, format, edges, function, out } => {
            let p = load(&path)?;
            summary(&p);
            // the syntax trees are built again here: `load` keeps only the CFGs
            let sources: Vec<String> = p.ok.iter().map(|l| std::fs::read_to_string(&l.file)).collect::<std::io::Result<_>>()?;
            let files: Vec<taintless::cpg::SourceFile> = p
                .ok
                .iter()
                .zip(&sources)
                .map(|(l, src)| taintless::cpg::SourceFile { path: &l.file, lang: l.lang, src, cfgs: &l.cfgs, imports: &l.imports })
                .collect();
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
        Cmd::Calls { path, format, external } => {
            let p = load(&path)?;
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
