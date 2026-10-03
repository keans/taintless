# TODO

Open work only. See [README.md](README.md) for implemented behavior and
[docs/concept.md](docs/concept.md) for the roadmap.

## Storage and incremental analysis

Per-file IR caching, a project-results cache with pruning, graph indexing,
queries, exports, and findings triage (including SARIF) are implemented. The
remaining work is:

- [ ] Cache function summaries and recompute only affected functions after a
  change. Re-resolve imports and calls for changed files and dependents, then
  propagate summary changes through callers until they stabilize. Today a
  changed project re-analyzes every function.
- [ ] Update stored CPG nodes and edges per changed file. Recompute cross-file
  `Call`, `Imports`, and interprocedural `Reaching` edges for affected files.
  Today `index` replaces the whole graph when the project changes.
- [ ] Run cache equivalence tests on external corpora. Cold, warm, and
  edited-tree scans must match `--no-cache`; fixture tests already cover
  `security`, `calls`, `flow`, and `cfg`.

## Deliberate limits

- JS/TS `await`/`yield` suspension, Rust drops and `?` through `Drop`, and C++
  `noexcept` do not change a function's modeled CFG.
- C/C++ computed goto is not parsed by the current grammars. GNU `case 1 ...
  5:` uses error recovery; its flow is modeled despite the split range.
