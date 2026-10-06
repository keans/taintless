# taintless

`taintless` scans source code to show how functions call each other, how values
move through a project, and where untrusted input may reach dangerous code. It
works directly from source, without building or running the project.

- **Security findings** with CWE ids and the path from source to sink, across
  functions and files.
- **Call graph, dependencies, control flow** and a code property graph you can
  query or export.
- **Crypto inventory**: libraries, algorithms, keys and TLS settings, with a
  CycloneDX CBOM or SARIF output.
- **Incremental**: results are cached, and after an edit only the affected
  functions are analyzed again.

Languages: Python, JavaScript, TypeScript, Rust, Go, Java, Kotlin, C#, Ruby,
PHP, Swift, C and C++.

> **Status:** an experimental, proof of concept at an early stage,
> not production ready. Review security findings before acting on them.

## Install

Requires a recent Rust toolchain (edition 2024). Graphviz is optional for
rendering DOT graphs.

```sh
cargo install --path .
taintless --help
```

## Try it

Point a command at a file or directory:

```sh
taintless security path/to/project
taintless flow path/to/project --from user_id --format text
taintless calls path/to/project
taintless deps path/to/project --format text
taintless cfg path/to/file.py --format text
taintless cpg path/to/project > cpg.json
taintless crypto path/to/project
```

`security` reports possible unsafe flows and dangerous calls. `flow` traces
values, `calls` and `deps` show relationships between functions and files,
`cfg` shows control flow, and `cpg` exports the code property graph. `crypto`
inventories the cryptography in a project: the libraries imported or declared
in manifests and lock files, the crypto calls with their algorithms, key
material and TLS settings in files (PEM, DER, JWK, config files, keystores),
and algorithms found in compiled programs. It flags weak algorithms, hardcoded
keys and IVs, small keys, low work factors, committed private keys and
disabled certificate checks, follows crypto objects through functions, and can
write a CycloneDX CBOM or SARIF; `--fail-on-weak` makes it a CI gate.
`security` also reports untrusted input that chooses an algorithm, key or IV.
Commands can emit text, JSON or graph formats where supported.

A finding looks like this:

```text
app.py:12:5: high [sql-injection] SQL query built from untrusted input:
    `db.raw_query` (in `handler`, CWE-89)
    untrusted input from parameter `data` of handler() (line 11)
```

## Cache and stored results

Parsed files and unchanged security results are cached in
`.taintless/db.sqlite`. `--no-cache` skips scan caching; `--cache <file>`
selects another database. After an edit only the functions it can affect are
analyzed again (stored summaries), and `index` rewrites only the changed files'
rows of the stored graph.

```sh
taintless index path/to/project
taintless query callers handler
taintless query reach 'input()' os.system
taintless security path/to/project --store
taintless history
```

`index` stores a graph for queries and exports. `security --store` records
findings for triage. See the [user guide](docs/guide.md) for configuration,
baselines, graph exports, triage and output formats.

## Documentation

- [User guide](docs/guide.md): commands, findings, crypto inventory and
  stored results.
- [Known limitations](docs/limitations.md): precision and coverage.
- [Design notes](docs/concept.md): architecture and extension points.
- [Open work](TODO.md): remaining tasks.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Fixtures and snapshots live under `tests/`; CI also runs smoke tests on real
projects. See the [development guide](docs/guide.md#development) for more.
