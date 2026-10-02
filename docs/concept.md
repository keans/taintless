# taintless: concept

This document explains how `taintless` is built and why its analyses share a
common model. [README.md](../README.md) is the user manual;
[TODO.md](../TODO.md) lists the remaining work.

## 1. Purpose

`taintless` answers structural questions about source code in many languages
with one engine:

- **What can happen inside a function?**
  **Command:** `taintless cfg`
  **Result:** control-flow graph (DOT, text, JSON)

- **Where does untrusted data end up?**
  **Command:** `taintless security`
  **Result:** findings with CWE, call chain and origin (text, JSON, SARIF)

- **Where does a value go?**
  **Command:** `taintless flow`
  **Result:** data-flow graph, slices

- **Who calls whom?**
  **Command:** `taintless calls`
  **Result:** call graph, entry points, recursion

- **Which file depends on which?**
  **Command:** `taintless deps`
  **Result:** import / call graph of files, cycles

It is a **static, syntax-driven analyzer**: no compiler, no build, no type
checker, no network. It must work on a checkout it has never seen, on broken or
partial code, and on thousands of files in seconds. The price is that it
reasons about *what the source says* (names, declared types, imports), not
about what a compiler would resolve. Every design decision below follows from
that trade-off.

### Goals

- **One front end for every language.** Eight languages (Python, JavaScript,
  TypeScript/TSX, Rust, Go, Java, C, C++) lower to the same IR. Analyses use
  those facts or the CPG built from them.
- **Useful security findings at low noise.** Taint analysis that explains
  itself (source, path, sink) and can be adopted on an existing code base
  (baseline, suppressions, configuration).
- **Robust.** A parse error in one file never stops the others; no input may
  panic. Corpora of real projects are part of CI.
- **Deterministic and fast.** Parallel per file, stable output order, so
  results can be diffed and cached.
- **Honest about limits.** Gaps and deliberate limits are documented in
  [limitations.md](limitations.md) and [TODO.md](../TODO.md).

### Non-goals

- Proving the absence of bugs. The analyses are *may*-analyses tuned to find,
  not to certify.
- Type checking, build-system integration, running or instrumenting code.
- Whole-program precision for dynamic features (reflection, `eval`, monkey
  patching, dependency injection by configuration).
- Replacing a compiler's lints; findings are about flow and dangerous calls.

## 2. Architecture

```
source → tree-sitter → syntax tree → Spec → IR (Cfg per function)
                                                │
                   ┌────────────┬───────────────┼──────────────┐
                   ▼            ▼               ▼              ▼
                 export     call graph       data flow        taint
               DOT/JSON     file deps      reaching defs    summaries
                              │                               │
                           imports                     findings
                                                    suppress/baseline
                                                   SARIF/JSON/text

                    .taintless.toml configures the analyses
```

### 2.1 Front end: `src/lang/`

Each language is a **`Spec`**: a small table that tells the shared engine
(`lang/common.rs`) which tree-sitter node kinds are functions, which are
control flow (`If`, `Loop`, `Switch`, `Try`, ...), how to read calls,
assignments, members, parameters, imports, receivers, declared types and class
bases. The engine owns everything that is hard and the same everywhere:
building blocks and edges, inlining `finally` on every exit path, labeled
`break` / `continue`, `goto`, short-circuit conditions, `defer`,
expression-level control flow (`?:`, `&&`, `??`, `?.`, `switch` as an
expression), closures as their own functions.

*Why:* adding a language costs a table, not an analyzer. Language quirks stay
in the table; analyses never see syntax.

### 2.2 IR: `src/ir/`

- `Cfg`: one per function (also methods, closures, lambdas, async blocks, and a
  `<module>` function for top-level script code). A petgraph `StableDiGraph` of
  `Block`s with typed edges (`normal`, `true`, `false`, `back`, `break`,
  `continue`, `return`, `exception`). Dead code stays in the graph as
  unreachable blocks.
- `Stmt`: source position, text and the **facts** the analyses need: `assigns`
  (target, strong/weak, value) and `calls` (callee, receiver, arguments,
  keyword names, position).
- `Flow`: a deliberately small symbolic summary of an expression: `Clean`,
  `Path("a.b.c")`, `Call(..)`, or `Join(..)`. Analyses ask "what does this
  value depend on", never "what syntax is this".
- Per-function metadata: parameters, receiver name, declared parameter and
  return types, class bases.

*Why:* a language-neutral fact layer is cheap to build and supports the
summary-based analyses. The CPG adds expression-level AST nodes and shared
edges for queries; see §4.

### 2.3 Name resolution: `Resolver` and manifests

Call resolution uses `Resolver` (`analysis/callgraph.rs`). It maps a normalized
callee (`os.system`,
`self.step`, `Svc::new`) to the functions it may refer to, and says whether the
match is **exact** or only a **guess by method name**. Layers, in order:

1. qualified name suffixes, then constructors (`Job()` → `Job.__init__`);
2. class knowledge: own class (`self`/`this`), declared parameter types,
   variable classes from constructors / factories / declared returns; inherited
   methods, `super`, and **virtual dispatch** to overrides in subclasses;
3. imports: among same-named candidates, the ones the file can see (own file,
   imports two levels deep, same Go/Java package, the `.c` behind a header);
4. manifests: `tsconfig` `paths`, `package.json` workspaces / `exports`,
   `go.mod` / `go.work` / `replace`, `Cargo.toml` (`[lib]` / `[[bin]]` paths),
   `pyproject.toml` source roots, namespace packages.

Guesses never invent facts: a name-only match is not allowed to create taint
sources, only to propagate. This is the central precision/recall rule of the
project.

Calls through stored functions, callbacks, and literal container elements are
also indexed. Branches and parameters can supply several possible literal
keys; an unknown key reads the whole container. The CPG resolves imports and
calls once when built. The `calls` and `deps` CLI commands run the same
resolver directly to avoid building the full CPG for those views.

### 2.4 Analyses: `src/analysis/`

**Taint (`taint.rs`, `rules.rs`).** Interprocedural, summary-based
may-analysis. Declared locals and fields use the same `Types` inference as
`calls` and `flow`, including field chains, inherited fields and supported
generic wrappers. Go, Rust and C/C++ local and field declarations also feed
this inference.
A variable the function declares in several block scopes (JS / Rust / Go /
C-like shadowing) keeps one class per scope, also when the class comes from `x
= A()` rather than a declared type (`Cfg::type_key`); a variable given
different classes in one scope has, at each call, the class the control flow
gives it (`x = A(); x.run(); x = B(); x.run()`).

- *Within a function:* a worklist over the CFG; state = tainted **access
  paths** (`x`, `self.cmd`, `a.b.c`), a "definitely assigned" set (so a field
  read after a local write sees the local value), known classes of variables,
  and aliases of objects (`b = a`). Strong updates for plain variables;
  sanitizers, container mutators (`xs.append(t)`), field sensitivity.
- *Across functions:* callees are analyzed first (SCCs of the call graph,
  fixpoint for recursion). A **summary** per function records: parameter →
  sink, parameter → return value, source → return value, parameter → field, the
  **receiver's** state → sink / return value (`self.cmd` read in a method), and
  **callbacks**: which parameters are called as functions and with what, so a
  function or lambda passed in is followed into its sinks and return value.
  Functions *stored* in variables, containers, fields and module-level
  registries are tracked as function references (flow-sensitive per variable,
  project-wide per class field), so calling the holder calls them; the call
  graph used for summary ordering includes these edges. A closure summary also
  lists the variables of its creator's scope that it assigns (`nonlocal x`,
  outer assignments in JS / Rust / Go, C++ reference captures, Java
  captured-object mutations) and what flows into them. Nested capture
  dependencies retain their lexical depth. Calling a closure applies those
  writes to the caller; publishing one also records possible deferred writes to
  shared lexical cells. Callable stores through helper parameters and returned
  containers are summarized, and the data-flow graph shares callable
  parameter/return facts with the registry analysis. Callers apply summaries
  instead of re-analyzing, which is why findings name a call chain and work
  across files. Class-level field facts (`self.cmd = input()` read in another
  method) are found by extra whole-project rounds.
- *Sources, sinks, sanitizers* are tables per language family, extensible from
  `.taintless.toml`. Entry-point parameters can be sources (`[[entry]]`; Java
  `main`, C `argv` built in).
- *Rules without flow* (weak hashes, unsafe C functions, ...) and *unreachable
  code* are separate passes over the same CFGs.

**Call graph (`callgraph.rs`).** Built from the same `Resolver`, plus functions
passed as values (callbacks, `f = handler; f()`), per-edge call-site lists,
entry points and recursive groups.

**Dependencies (`deps.rs`, `manifest.rs`).**
Imports/includes/`use`/`require`/`mod` resolved to scanned files, plus
cross-file calls; import cycles; directory level view; external modules. The
same resolution feeds `Resolver` so that "which `helper`" is decided once.

**Data flow (`cpg::flow`).** Reaching definitions per function, argument →
parameter and return → call edges across functions, closures and callbacks;
slicing by variable or function. `analysis::dataflow::build` builds a CPG from
the input files, then draws the `flow` view from its edges.

**Findings pipeline.** Rules/taint → configuration filter (`disable`,
`exclude`, per-rule excludes, severity, nested configs) → suppression comments
(with `until=` review dates) → baseline (ignores line numbers, survives
renames, moves and both, review dates) → text / JSON / SARIF 2.1.0. Exit codes:
0 clean, 1 findings, 2 incomplete.

### 2.5 Output: `src/export/`, CLI: `src/main.rs`

Pure formatting of the structures above; no analysis lives here. The CLI
discovers files (`.gitignore`-aware), parses and lowers them in parallel,
installs the configuration before analysis, and prints progress only on a
terminal.

## 3. Design principles

1. **Facts over syntax.** Languages produce facts once; analyses consume facts.
2. **Prefer a silent miss to a noisy guess, but never hide that a guess was
   made.** Name-only call matches propagate taint but do not create it;
   ambiguity above a small threshold links nothing; `exact` is carried through
   the API.
3. **Declared information wins over inferred.** Constructors, factories,
   declared parameter and return types, imports and manifests are trusted;
   heuristics fill the gaps and rank below them.
4. **Shared facts, multiple graph views.** CFGs and the CPG hold common
   facts; call, dependency and data-flow views expose the relevant edges.
5. **Configuration is validated.** A typo in `.taintless.toml` is an error,
   never a silently ignored rule.
6. **Adoptable.** Baselines, suppressions with expiry and per-directory configs
   exist because the first run on a real code base finds hundreds of things.
7. **Tested at three levels:** snapshot tests of CFGs per language, behavior
   tests of analyses on small fixtures, and smoke runs on large real corpora
   (no panic, counts sane). CI also runs `clippy -D warnings`.

## 4. Code property graph

The CPG combines AST, CFG, control dependence, data dependence, calls, imports
and symbols in one project-wide graph. It supports queries and exports, while
the CLI can use cheaper direct paths for focused commands.

```
                 ┌──────────── Cpg (StableDiGraph) ────────────┐
 tree-sitter ──▶ │ nodes: File, TypeDecl, Method, Param, Local, │
 Spec / IR       │        Call, Identifier, Literal, ...        │
                 │ edges: Ast, Contains, Scope, Cfg, Cdg,       │
                 │        Reaching, Call, Argument, Receiver,   │
                 │        ParamIn, ReturnOut, ParamOut, Capture,│
                 │        TypeOf, Ref, Inherits, Imports        │
                 └───────────────┬──────────────────────────────┘
        views: cfg · flow · calls · deps · taint query
               export: json · graphml · neo4j
```

The graph uses stable node ids from file, span, grammar kind and depth. AST
nodes retain ordered children; synthetic `Param`, `Local`, `Field` and `Type`
nodes hold symbols. `Scope`, `Ref`, `TypeOf` and `Inherits` edges connect names
to declarations and types. Statement-level `Cfg` and `Cdg` edges describe
execution and control dependence.

`Reaching` edges track definitions through aliases, fields, literal container
elements and calls. Interprocedural labels include `param_in`, `return`,
`param_out` and `field`; `Capture` carries values into closures. The `flow`
view draws from these edges. `Cpg::call_graph()` and `Cpg::dep_graph()` expose
the graphs used to draw its `Call` and `Imports` edges.

The CPG taint query uses the same rule tables as `analysis/taint.rs`. It
matches that reference analysis on fixture files and directories and this
repository's Rust sources, including finding messages, origins and call
chains. Selected sink arguments respect sanitizers. `security` still uses the
summary-based analysis; the CPG query remains available for graph-backed
analysis. JSON, GraphML, DOT and Neo4j CSV exports are available.

Tests cover CFG snapshots, behavior fixtures, CPG snapshots, parity and smoke
runs on real code. [limitations.md](limitations.md) records precision limits;
the `tests/iface` single-file cases still await interface dispatch in the
reference analysis.

## 5. Next step: incremental storage

The remaining roadmap is in [TODO.md](../TODO.md). The planned SQLite store
would cache per-file IR, function summaries, CPG nodes and edges, and findings.
A content hash plus configuration and analysis version would invalidate stale
facts. Changes would trigger re-resolution of imports and calls, then summary
recomputation through affected callers until results stop changing.

The main correctness check is equivalence: after a file changes, a warm scan
must report the same findings as a clean scan. A stored graph could then serve
indexed queries and graph exports without rebuilding the project each time.
Storage location, schema and sharing remain design decisions.

## 6. Deliberate limits

`await`/`yield` suspension points, Rust drops and `?` through `Drop`, computed
`goto`, and `noexcept` do not change the modeled CFG as described in
[TODO.md](../TODO.md) and [limitations.md](limitations.md). Thread scheduling
and event ordering are also not modeled.

## 7. How to extend

- **A language**
  **Do this:** Implement `Spec` (functions, control shapes, calls, assignments,
  members, params, imports); add detection in `lang/mod.rs`, rules table,
  snapshots, a corpus
  **Touch:** `src/lang/`

- **A source / sink / sanitizer**
  **Do this:** Add it to the family's table, or to `.taintless.toml` for one
  project
  **Touch:** `analysis/rules.rs` / config

- **A rule that is not taint**
  **Do this:** A call rule with an `except` list, or a pass beside
  `unreachable.rs`
  **Touch:** `analysis/rules.rs`

- **A resolution hint (manifest, layout)**
  **Do this:** Read it in `Manifests`, use it in `Index`
  **Touch:** `analysis/manifest.rs`, `deps.rs`

- **An output format**
  **Do this:** A function from a result struct to text
  **Touch:** `src/export/`

- **A type fact**
  **Do this:** Extend `declared_types` in the language's `Spec`; the `Resolver`
  and taint pick it up
  **Touch:** `src/lang/*`, `callgraph.rs`

Every behavior change ships with a fixture under `tests/`. When it closes an
open item, remove that item from TODO.md or narrow it to the work that remains.
