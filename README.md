# taintless

`taintless` scans source code to show how functions call each other, how values
move through a project, and where untrusted input may reach dangerous code. It
works directly from source, without building or running the project.

It supports Python, JavaScript, TypeScript, Rust, Go, Java, C, and C++. This is
an experimental, AI-assisted proof of concept. Review security findings before
acting on them.

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
```

`security` reports possible unsafe flows and dangerous calls. `flow` traces
values, `calls` and `deps` show relationships between functions and files,
`cfg` shows control flow, and `cpg` exports the code property graph. Commands
can emit text, JSON or graph formats where supported.

## Cache and stored results

Parsed files and unchanged security results are cached in
`.taintless/db.sqlite`. `--no-cache` skips scan caching; `--cache <file>`
selects another database. A changed project is still re-analyzed as a whole.

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

- [User guide](docs/guide.md): commands, findings and stored results.
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
