# TODO

Open work only. See [README.md](README.md) for implemented behavior and
[docs/concept.md](docs/concept.md) for the roadmap.

## Types, aliases, and calls

- [ ] Call graph: infer possible element keys from branches and parameters. Literal keys and locals assigned one constant pick one element; unknown keys conservatively read the whole container. Go embed-only structs are indexed.

## Code property graph

- [ ] Make `dataflow` a view of the CPG. The interprocedural `Reaching` edges it needs exist (`param_in`, `return`, `param_out`, `field`); what is left is drawing `flow`'s output from them (its shared `field Class.f` nodes, per-instance limits and callback edges differ from the CPG's; `dataflow::build` still has its own value graph and resolution). `callgraph` and `deps` are done: `Cpg::build` resolves imports and calls once and `Cpg::call_graph()` / `Cpg::dep_graph()` return what its `Call` and `Imports` edges were drawn from; the `calls` and `deps` commands still run the resolver directly because building the whole CPG for them would be far slower.
- [ ] Finish CPG taint parity with `analysis/taint.rs`. The query reports exactly the same findings on every fixture, file by file and directory by directory (`tests/cpg.rs`; `tests/iface` waits for interface dispatch in the single-file analysis). Still open: per-argument sanitizers, source/sink messages and call chains in findings, and the differences on real code (this repository's own Rust sources: a few `path-traversal` findings around closures passed to iterator methods). Then retire `analysis/taint.rs` or keep it as the reference.

## Storage and incremental analysis

Goal: re-run on changed files only, and explore the results as a graph. Design discussion: one SQLite file (`.taintless/db.sqlite`) holds per-file results and the graph; Neo4j and similar stay an optional export target.

- [ ] Decide the schema and the invalidation key: file content hash plus a hash of the config, rule tables and tool/analysis version. Version the schema; any change to rules, config or analysis code invalidates stored results.
- [ ] Persist per-file facts: derive `serde` on the IR (`Cfg`, `Stmt`, `Flow`, declared types, imports) and store them by content hash, so unchanged files skip parsing and lowering.
- [ ] Persist function summaries (`Summary`, callbacks, receiver state, captured writes, field facts) and recompute only affected functions: re-resolve calls and imports for changed files and their dependents, recompute summaries callers-up and stop where a summary comes out unchanged (reuse the call graph and `Summary` equality).
- [ ] Write results in one transaction per run, so an interrupted run never leaves a half-updated database.
- [ ] Equivalence test: a warm run (change one file, re-scan) must give exactly the findings of a clean `--no-cache` run; run it on the fixtures and the external corpora. Add a `--no-cache` switch and a way to clear the cache.
- [ ] Store the CPG as tables (`nodes`, `edges` keyed by the stable `NodeId`: file + byte span + kind + depth), replacing one file's rows when it changes; cross-file edges (`Call`, `Imports`, interprocedural `Reaching`) are recomputed for the file and its dependents.
- [ ] Graph exploration: a `taintless query` command with canned traversals (callers / callees, reachable from a source to a sink, findings by rule / directory) over the stored graph, using indexes and recursive queries.
- [ ] Export for graph tools: Neo4j / Memgraph CSV (and GraphML), written from the stored graph on demand; node ids stable across exports.
- [ ] Findings history and triage: a `findings` table with a stable id (the baseline fingerprint: rule, message, source-line hash), `first_seen` / `last_seen`, and a status (open, accepted, false positive) with a reason; an optional `--store` target next to the existing baseline and SARIF outputs.
- [ ] Decide where the data lives: in the repository (`.taintless/`, gitignored), in a CI cache, or on a shared server; document how to share or reset it.

## Deliberate limits

- JS/TS `await`/`yield` suspension, Rust drops and `?` through `Drop`, and C++ `noexcept` do not change a function's modeled CFG.
- C/C++ computed goto is not parsed by the current grammars. GNU `case 1 ... 5:` uses error recovery; its flow is modeled despite the split range.
