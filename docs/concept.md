# taintless: concept

This document describes what `taintless` is meant to be, how its parts fit together
and where it is going. [README.md](../README.md) is the user manual;
[TODO.md](../TODO.md) is the detailed work list. Here the open TODO items are
placed in the bigger picture.

## 1. Purpose

`taintless` answers structural questions about source code in many languages
with one engine:

| Question | Command | Result |
|----------|---------|--------|
| What can happen inside a function? | `taintless cfg` | control-flow graph (DOT, text, JSON) |
| Where does untrusted data end up? | `taintless security` | findings with CWE, call chain and origin (text, JSON, SARIF) |
| Where does a value go? | `taintless flow` | data-flow graph, slices |
| Who calls whom? | `taintless calls` | call graph, entry points, recursion |
| Which file depends on which? | `taintless deps` | import / call graph of files, cycles |

It is a **static, syntax-driven analyzer**: no compiler, no build, no type
checker, no network. It must work on a checkout it has never seen, on broken
or partial code, and on thousands of files in seconds. The price is that it
reasons about *what the source says* (names, declared types, imports), not about
what a compiler would resolve. Every design decision below follows from that
trade-off.

### Goals

- **One model for every language.** Eight languages (Python, JavaScript,
  TypeScript/TSX, Rust, Go, Java, C, C++) lower to the same IR; every analysis is
  written once.
- **Useful security findings at low noise.** Taint analysis that explains itself
  (source, path, sink) and can be adopted on an existing code base
  (baseline, suppressions, configuration).
- **Robust.** A parse error in one file never stops the others; no input
  may panic. Corpora of real projects are part of CI.
- **Deterministic and fast.** Parallel per file, stable output order, so results can
  be diffed and cached.
- **Honest about limits.** What is not modeled is written down
  (TODO.md, "Decided not to model") rather than guessed.

### Non-goals

- Proving the absence of bugs. The analyses are *may*-analyses tuned to find,
  not to certify.
- Type checking, build-system integration, running or instrumenting code.
- Whole-program precision for dynamic features (reflection, `eval`, monkey
  patching, dependency injection by configuration).
- Replacing a compiler's lints; findings are about flow and dangerous calls.

## 2. Architecture

```
                       .taintless.toml  (rules, sources, sinks, excludes)
                            │
source ─ tree-sitter ─▶ syntax tree ─ per-language Spec ─▶ IR (Cfg per function)
                                                              │
        ┌───────────────┬───────────────┬─────────────────────┼───────────────┐
        ▼               ▼               ▼                     ▼               ▼
      export         call graph     file deps            data flow          taint
   (DOT/JSON/text)  (Resolver)   (Index, manifests)  (reaching defs)   (summaries)
                         ▲               │                     │               │
                         └── imports ────┘                     └──── Resolver ─┘
                                                                          │
                                                       findings ─ suppress ─ baseline ─ SARIF/JSON/text
```

### 2.1 Front end: `src/lang/`

Each language is a **`Spec`**: a small table that tells the shared engine
(`lang/common.rs`) which tree-sitter node kinds are functions, which are control
flow (`If`, `Loop`, `Switch`, `Try`, ...), how to read calls, assignments,
members, parameters, imports, receivers, declared types and class bases. The engine owns
everything that is hard and the same everywhere: building blocks and edges, inlining
`finally` on every exit path, labeled `break` / `continue`, `goto`, short-circuit
conditions, `defer`, expression-level control flow (`?:`, `&&`, `??`, `?.`,
`switch` as an expression), closures as their own functions.

*Why:* adding a language costs a table, not an analyzer. Language quirks stay in
the table; analyses never see syntax.

### 2.2 IR: `src/ir/`

- `Cfg`: one per function (also methods, closures, lambdas, async blocks, and a
  `<module>` function for top-level script code). A petgraph `StableDiGraph` of
  `Block`s with typed edges (`normal`, `true`, `false`, `back`, `break`, `continue`,
  `return`, `exception`). Dead code stays in the graph as unreachable blocks.
- `Stmt`: source position, text and the **facts** the analyses need:
  `assigns` (target, strong/weak, value) and `calls` (callee, receiver, arguments,
  keyword names, position).
- `Flow`: a deliberately small symbolic summary of an expression: `Clean`,
  `Path("a.b.c")`, `Call(..)`, or `Join(..)`. Analyses ask "what does this value
  depend on", never "what syntax is this".
- Per-function metadata: parameters, receiver name, declared parameter and return
  types, class bases.

*Why:* a language-neutral fact layer that is cheap to build and big enough for
interprocedural taint, but not an AST. (The CPG in phase 4 is where full
expression structure comes back; see §5.)

### 2.3 Name resolution: `Resolver` and manifests

All cross-function reasoning goes through one component, `Resolver`
(`analysis/callgraph.rs`). It maps a normalized callee (`os.system`,
`self.step`, `Svc::new`) to the functions it may refer to, and says whether the
match is **exact** or only a **guess by method name**. Layers, in order:

1. qualified name suffixes, then constructors (`Job()` → `Job.__init__`);
2. class knowledge: own class (`self`/`this`), declared parameter types, variable
   classes from constructors / factories / declared returns; inherited methods,
   `super`, and **virtual dispatch** to overrides in subclasses;
3. imports: among same-named candidates, the ones the file can see (own file,
   imports two levels deep, same Go/Java package, the `.c` behind a header);
4. manifests: `tsconfig` `paths`, `package.json` workspaces / `exports`, `go.mod` / `go.work` / `replace`, `Cargo.toml` (`[lib]` / `[[bin]]` paths), `pyproject.toml` source roots, namespace packages.

Guesses never invent facts: a name-only match is not allowed to create taint
sources, only to propagate. This is the central precision/recall rule of the
project.

### 2.4 Analyses: `src/analysis/`

**Taint (`taint.rs`, `rules.rs`).** Interprocedural, summary-based may-analysis.
Declared locals and fields use the same `Types` inference as `calls` and `flow`,
including field chains, inherited fields and supported generic wrappers. Go,
Rust and C/C++ extract local declarations and fields from the same source file;
joining type declarations in separate files remains open. A variable the function
declares in several block scopes (JS / Rust / Go / C-like shadowing) keeps one class per
scope, also when the class comes from `x = A()` rather than a declared type
(`Cfg::type_key`); a variable given different classes in one scope has, at each call,
the class the control flow gives it (`x = A(); x.run(); x = B(); x.run()`).

- *Within a function:* a worklist over the CFG; state = tainted **access paths**
  (`x`, `self.cmd`, `a.b.c`), a "definitely assigned" set (so a field read after a
  local write sees the local value), known classes of variables, and aliases
  of objects (`b = a`). Strong updates for plain variables; sanitizers, container
  mutators (`xs.append(t)`), field sensitivity.
- *Across functions:* callees are analyzed first (SCCs of the call graph, fixpoint
  for recursion). A **summary** per function records: parameter → sink,
  parameter → return value, source → return value, parameter → field, the
  **receiver's** state → sink / return value (`self.cmd` read in a method), and
  **callbacks**: which parameters are called as functions and with what, so a
  function or lambda passed in is followed into its sinks and return value.
  Functions *stored* in variables, containers, fields and module-level
  registries are tracked as function references (flow-sensitive per variable,
  project-wide per class field), so calling the holder calls them; the call graph
  used for summary ordering includes these edges.
  A closure summary also lists the variables of its creator's scope that it
  assigns (`nonlocal x`, outer assignments in JS / Rust / Go, C++ reference
  captures, Java captured-object mutations) and what flows into them. Nested
  capture dependencies retain their lexical depth. Calling a closure applies
  those writes to the caller; publishing one also records possible deferred
  writes to shared lexical cells. Callable stores through helper parameters and
  returned containers are summarized, and the data-flow graph shares callable
  parameter/return facts with the registry analysis. Callers
  apply summaries instead of re-analyzing, which is why findings name a call chain
  and work across files. Class-level field facts (`self.cmd = input()` read in
  another method) are found by extra whole-project rounds.
- *Sources, sinks, sanitizers* are tables per language family, extensible from
  `.taintless.toml`. Entry-point parameters can be sources (`[[entry]]`; Java `main`, C `argv`
  built in).
- *Rules without flow* (weak hashes, unsafe C functions, ...) and *unreachable code*
  are separate passes over the same CFGs.

**Call graph (`callgraph.rs`).** Built from the same `Resolver`, plus functions
passed as values (callbacks, `f = handler; f()`), per-edge call-site lists, entry
points and recursive groups.

**Dependencies (`deps.rs`, `manifest.rs`).** Imports/includes/`use`/`require`/`mod`
resolved to scanned files, plus cross-file calls; import cycles; directory level
view; external modules. The same resolution feeds `Resolver` so that "which `helper`"
is decided once.

**Data flow (`dataflow.rs`).** Reaching definitions per function, argument →
parameter and return → call edges across functions, closures and callbacks;
slicing by variable or function.

**Findings pipeline.** Rules/taint → configuration filter (`disable`, `exclude`,
per-rule excludes, severity, nested configs) → suppression comments (with
`until=` review dates) → baseline (ignores line numbers, survives renames, moves
and both, review dates) → text / JSON / SARIF 2.1.0. Exit codes: 0 clean, 1 findings, 2 incomplete.

### 2.5 Output: `src/export/`, CLI: `src/main.rs`

Pure formatting of the structures above; no analysis lives here. The CLI discovers
files (`.gitignore`-aware), parses and lowers them in parallel, installs the
configuration before analysis, and prints progress only on a terminal.

## 3. Design principles

1. **Facts over syntax.** Languages produce facts once; analyses consume facts.
2. **Prefer a silent miss to a noisy guess, but never hide that a guess was
   made.** Name-only call matches propagate taint but do not create it; ambiguity
   above a small threshold links nothing; `exact` is carried through the API.
3. **Declared information wins over inferred.** Constructors, factories, declared
   parameter and return types, imports and manifests are trusted; heuristics fill
   the gaps and rank below them.
4. **Everything is a graph with stable, small facts.** CFGs, call graph, file graph and
   flow graph are all petgraph structures that export the same way.
5. **Configuration is validated.** A typo in `.taintless.toml` is an error, never a
   silently ignored rule.
6. **Adoptable.** Baselines, suppressions with expiry and per-directory configs exist
   because the first run on a real code base finds hundreds of things.
7. **Tested at three levels:** snapshot tests of CFGs per language, behavior tests
   of analyses on small fixtures, and smoke runs on large real corpora (no
   panic, counts sane). CI also runs `clippy -D warnings`.

## 4. Where the project stands

| Phase | Content | State |
|-------|---------|-------|
| 1 | Skeleton, Python, DOT/JSON export, parallel scan | done |
| 2 | Seven more languages on the shared engine, expression-level flow, closures, corpora in CI | done |
| 3 | Security analysis, call graph, dependencies, configuration, baselines | done except the items in §5.1 |
| 4 | Code property graph | under way: ids, AST layer, statement CFG, control dependence, data dependence with aliases and interprocedural reaching, symbols, export, query and a taint query that matches `analysis/taint.rs` on every fixture exist; making `dataflow` a view remains (§5.2) |

## 5. Roadmap, derived from TODO.md

The open items are not independent. They fall into four themes.

### 5.1 Closing Phase 3: precision of "what is this object, and what does it call"

Most open Phase 3 items are one problem: **knowing the type of things** and
following **values that are not plain variables**.

| TODO item | Idea | Value |
|-----------|------|-------|
| Type declarations across files, aliases and lexical shadowing | Build a project-level type declaration index with scope identities | Resolve separate headers / implementations and shadowed names consistently |
| Aliasing through fields / containers / calls, per-instance fields of unknown classes, interface dispatch, maps / arrays by key | Generalize the alias groups (today: variables holding known instances) to access paths and element keys; later express them as `Reaching` edges | Fewer misses when objects are stored, passed and returned |
| Call graph: computed container keys, containers filled by callees, method-less Go structs that embed a type | Track elements by value ranges and callee writes; give declared structs a class of their own | More indirect calls resolve to their targets |

The remaining data-flow precision work concerns per-instance fields and aliases
through containers. Callable fields, JS member registries, and callable contents
crossing function boundaries now share function-reference facts between the
taint analysis and `taintless flow`. Deferred captured writes are conservative
may-effects; neither thread scheduling nor event ordering is modeled.

### 5.2 Phase 4: the code property graph

**Goal:** one project-wide graph merging AST, CFG, control and data dependence,
calls and symbols, so that taint, dependencies and future rules become *queries*
over one structure instead of separate engines that each re-derive facts.

```
                 ┌──────────── Cpg (StableDiGraph) ────────────┐
 tree-sitter ──▶ │ nodes: File, TypeDecl, Method, Param, Local, │
 Spec / IR       │        Call, Identifier, Literal, ...        │
                 │ edges: Ast, Contains, Scope, Cfg, Cdg,       │
                 │        Reaching, Call, Argument, Receiver,   │
                 │        ParamIn, ReturnOut, ParamOut, Capture,│
                 │        TypeOf, Ref, Inherits, Imports        │
                 └───────────────┬──────────────────────────────┘
        views:  cfg · flow · calls · deps · taint query · export (json/graphml/neo4j)
```

Build order from TODO.md (each step is independently testable, and the existing
snapshot and integration tests are the safety net, since views must produce
unchanged output):

1. **Stable node ids** (file + byte span + kind + depth) instead of `(line, col)`
   and closure markers. *Done* (`cpg::node`); `closure_marker` stays in taint and
   data flow until they move onto the CPG.
2. **AST layer:** every named node with ordered children and a normalized kind.
   *Done* (`cpg::ast`): operators with operand order, `Param` (one per bound name,
   bare lambda parameters included) and `TypeDecl` nodes; the graph adds a `Local`
   node per declared or first-assigned variable and a `Type` node per declared type
   (`TypeOf` edges from parameters and locals); parameters are defined at their
   `Param` node.
3. **Statement-level CFG edges** derived from existing blocks, keeping edge kinds.
   *Done* (`cpg::cfg`).
4. **Control dependence** (post-dominators on the reversed CFG). *Done*
   (`cpg::cdg`). Used for *implicit flows* in taint (`if secret: x = 1` taints `x`)
   when `implicit_flows = true` is set in `.taintless.toml`, in `analysis::taint` and
   in the CPG taint query.
5. **Unified `Cpg`**: *exists* (`cpg::graph`): AST, `Contains`, `Cfg`, `Cdg`,
   `Call` (with callback labels), `Imports`, `ParamIn` / `ReturnOut` / `ParamOut` /
   `Capture` edges on shared nodes. `callgraph` and `deps` are views of it already;
   still open: `dataflow`.
6. **Symbols:** *Done* (`cpg::graph::symbols`). `Scope` edges form the lexical tree
   (file, class, method, closure); `Field` nodes stand for the fields a class declares
   or assigns, with `TypeOf` edges to their declared `Type`; `Ref` edges link every
   identifier to the `Param`, `Local` or `Field` it names (a variable of an enclosing
   function is a captured variable; `self.f` and `x.f` with a declared class resolve to
   the field, through base classes); `Inherits` edges link a class to its bases.
7. **Aliasing** as `Reaching` edges: *Done* (`cpg::graph::effects`). `b = a`, `h.r = a` and
   `b = identity(a)` make a definition of `b.f` reach the reads of `a.f`; element keys
   (`xs[0]`) are part of a path, so `xs = [a, b]` keeps its elements apart. What a callee
   stores in the fields of an argument, its receiver, the object a constructor builds, or a
   captured variable reaches the call (`ParamOut`); a closure reads the variables of its
   creator at entry (`Capture`). Reaching edges between functions are labelled `param_in`,
   `return`, `param_out` and `field`.
8. **Export:** JSON, GraphML, DOT and Neo4j CSV exist; every node carries a
   `stable_id` (path, source range, grammar kind).
9. **Query API and CPG taint:** both exist, and the acceptance test holds: on every
   fixture file and every fixture directory (as one project) the query reports exactly
   the findings of `analysis/taint.rs` (`tests/cpg.rs`). Each fact carries the last calls
   it went through, so what `Req(input())` stores does not come out of `Req("ls")`.
   Open: per-argument sanitizers, source and sink messages and call chains in findings,
   and a few differences on real code (this repository's Rust sources, around closures
   passed to iterator methods); then retire `analysis/taint.rs` or keep it as the reference.
10. **Snapshots + external-corpus CPG smoke tests** (node/edge counts, no panic).
    A CPG smoke test on the repository's own Rust source already exists.

Closures capture enclosing variables: the `Ref` edge of a captured name leads to the
declaration in the enclosing function, and `Capture` edges carry its value in.

*Risk and mitigation:* the CPG is large for big projects. Keep nodes small
(ids and indices, strings interned or sliced from the source), build per file in
parallel and link afterwards, and keep the summary-based taint analysis as the
fast path until the query-based one matches it in findings *and* speed.

### 5.3 Product surface

- Rule coverage grows by tables, not code: sources, sinks and sanitizers per
  language family, user-extensible. New rule kinds (not flow-based) stay in
  `rules.rs`.
- Output stays stable: SARIF/JSON schemas are append-only so CI integrations
  do not break.
- Adoption features are complete: baselines survive renames, moves and both at
  once (source-line fingerprint) and can carry review dates; suppressions expire
  with `until=`; configs extend each other and nest per directory.

### 5.4 Deliberate limits (see TODO.md, "Decided not to model")

`await`/`yield` suspension points, Rust drops and `?` through `Drop`, computed
`goto`, `noexcept`. Each either does not change a function's own flow or is not
representable in the grammar. They stay out unless a concrete finding needs them.

## 6. How to extend

| To add... | Do this | Touch |
|-----------|---------|-------|
| A language | Implement `Spec` (functions, control shapes, calls, assignments, members, params, imports); add detection in `lang/mod.rs`, rules table, snapshots, a corpus | `src/lang/` |
| A source / sink / sanitizer | Add it to the family's table, or to `.taintless.toml` for one project | `analysis/rules.rs` / config |
| A rule that is not taint | A call rule with an `except` list, or a pass beside `unreachable.rs` | `analysis/rules.rs` |
| A resolution hint (manifest, layout) | Read it in `Manifests`, use it in `Index` | `analysis/manifest.rs`, `deps.rs` |
| An output format | A function from a result struct to text | `src/export/` |
| A type fact | Extend `declared_types` in the language's `Spec`; the `Resolver` and taint pick it up | `src/lang/*`, `callgraph.rs` |

Every behavior change ships with a fixture under `tests/`. When it closes an
open item, remove that item from TODO.md or narrow it to the work that remains.
