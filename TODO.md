# TODO

Open work only. See [README.md](README.md) for implemented behavior and
[docs/concept.md](docs/concept.md) for the roadmap.

## Storage and incremental analysis

Implemented: per-file IR cache, project-results cache, summary cache, graph
index with per-file updates, queries, exports, triage (SARIF included). Open:

- [ ] Cache equivalence tests on external corpora: cold, warm and edited-tree
  scans must match `--no-cache` (fixtures cover `security`, `calls`, `flow`,
  `cfg`).

## Crypto inventory

Implemented: `taintless crypto` and the `crypto-*-from-input` rules (see the
[guide](docs/guide.md#crypto-inventory) and
[limitations](docs/limitations.md)). Open:

- [ ] Widen `tables.toml` as projects need it (Ruby, PHP and Swift have the
  basics).

## C and C++ preprocessing

Implemented: macro expansion and conditionals, with macros from project
headers (see the [guide](docs/guide.md#c-and-c-macros)). Open:

- [ ] Take `-D`/`-U`/`-I` from a compilation database or the configuration.
- [ ] Read common system headers' macros (`NULL`, `EOF`, `S_IRUSR`, ...).

## Deliberate limits

- JS/TS `await`/`yield` suspension, Rust drops and `?` through `Drop`, and C++
  `noexcept` do not change a function's modeled CFG.
- C/C++ computed goto is not parsed by the current grammars. GNU `case 1 ...
  5:` uses error recovery; its flow is modeled despite the split range.
