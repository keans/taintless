# TODO

Open work only. See [README.md](README.md) for implemented behavior and
[docs/concept.md](docs/concept.md) for the roadmap.

## Storage and incremental analysis

Implemented: per-file IR cache, project-results cache, graph index, queries,
exports, triage (SARIF included). Open:

- [ ] Cache function summaries; after a change, re-resolve imports and calls
  for changed files and dependents and recompute only affected functions,
  propagating through callers until stable (today every function is
  re-analyzed).
- [ ] Update stored CPG nodes and edges per changed file, including
  cross-file `Call`, `Imports` and interprocedural `Reaching` edges (today
  `index` replaces the whole graph).
- [ ] Cache equivalence tests on external corpora: cold, warm and edited-tree
  scans must match `--no-cache` (fixtures already cover `security`, `calls`,
  `flow`, `cfg`).

## Crypto inventory

Implemented: `taintless crypto` and the `crypto-*-from-input` rules (see the
[guide](docs/guide.md#crypto-inventory) and
[limitations](docs/limitations.md)). Open:

- [ ] Languages: PHP, Ruby, Swift (grammar plus a `Spec`; see
  `src/lang/csharp.rs`).

## Deliberate limits

- JS/TS `await`/`yield` suspension, Rust drops and `?` through `Drop`, and C++
  `noexcept` do not change a function's modeled CFG.
- C/C++ computed goto is not parsed by the current grammars. GNU `case 1 ...
  5:` uses error recovery; its flow is modeled despite the split range.
