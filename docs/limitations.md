# Known limitations

What `taintless` does not do, does only partly, or does by approximation. Read it
together with the user manual ([README.md](../README.md)), the open work list
([TODO.md](../TODO.md)) and the design notes ([concept.md](concept.md)).

Legend: **by design** = a deliberate trade-off that will not change;
**gap** = could be improved, usually listed in TODO.md; **approximation** = the
analysis answers "may", so it errs on one side on purpose.

## 1. What kind of tool this is

| Limitation | Kind | Consequence |
|------------|------|-------------|
| Static and syntax-driven: no compiler, build, type checker or runtime | by design | It reasons about what the source says (names, declared types, imports), not what a compiler would resolve. |
| Findings are *may*-results: if any path keeps data tainted, the sink is reported | by design | False positives are expected; findings are leads to review, not proofs. |
| No proof of absence | by design | A clean run does not mean the code is safe; misses exist (see below). |
| No path sensitivity or constraint solving | by design | A branch that cannot happen (`if False:`, an impossible condition) still contributes its flow; conditions such as `if x.isdigit():` or `if os.path.exists(p):` are **not** recognized as validation. Only calls listed as sanitizers, or overwriting the variable, clean data. |
| No numeric, size or string-content reasoning | by design | `memcpy` with a tainted size is flagged; a bounds check before it is not understood. A constant-folded or regex-validated string stays tainted. |
| Sanitizers are not tied to a vulnerability class | gap | A call listed as a sanitizer cleans the value for every rule: `shlex.quote` also "cleans" data going to a SQL sink. Per-rule sanitizers are not modeled. |
| Rules match call names, not semantics | by design | `*.execute` is any method with that name; a look-alike method in your own code can match, and a wrapper with a different name does not (until it is analyzed as a function or configured as a sink). |
| Dynamic features are not followed | by design | `eval`-built names, `getattr` / reflection, monkey patching, dependency injection by configuration, decorators that rewrite functions, dynamically computed imports. |
| Eight languages only | by design | Python, JavaScript, TypeScript/TSX, Rust, Go, Java, C, C++. Files with other extensions are skipped. Dependencies never cross language families (a Python call is never linked to a Rust function). |
| No incremental analysis or cache | gap | Every run parses and analyzes the whole scanned tree. The whole project is held in memory. |

## 2. Parsing and control flow

| Limitation | Kind |
|------------|------|
| Tree-sitter grammars decide what parses. On syntax errors the file may be partly modeled; a file that cannot be parsed is reported (exit code 2) and the rest still run. | by design |
| C/C++ computed `goto *p` is not parsed by the grammars; GNU `case 1 ... 5:` is parsed with error recovery (the range shows as two statements; the flow is right). | by design |
| C/C++ preprocessing is not run: macros are not expanded, `#ifdef` branches are not selected, so macro-hidden control flow and calls are invisible. | by design |
| Rust macros other than the modeled ones (`panic!`, `?`) are not expanded. | by design |
| C++ templates are not instantiated; overload resolution and implicit conversions are not modeled; `noexcept` does not change the modeled CFG. | by design |
| `.h` files are guessed: parsed as C++ when they use C++ constructs, otherwise C. | approximation |
| JS/TS `await` / `yield` suspension points do not change the modeled flow; the exception edge from a `try` body covers them. Scheduling, thread interleaving and event ordering are not modeled. | by design |
| Rust drops and `?` through `Drop`: scope exit has no explicit control flow in the source, so none is modeled. | by design |
| Exceptions: explicit `throw` / `raise` and `try` bodies are modeled; implicit exceptions from arbitrary calls only through the `try` body edge. | approximation |
| Expression nesting beyond about 200 levels is ignored (generated or minified code). | by design |
| Comprehension, ternary and short-circuit lowering follows the common shapes; unusual forms of expression-level control flow may be flattened. | approximation |

## 3. Taint analysis

### 3.1 Precision of what is tracked

- **Resolution by name.** Calls are resolved by name within one language. Types
  are used only where they are declared, or a constructor or factory shows them.
  Among same-named functions the ones the calling file can see win (own file,
  imports two levels deep, same Go/Java package, the `.c` behind a header). A
  name shared by more than 3 functions is considered too ambiguous and links
  nothing. *gap / approximation*
- **Guesses never invent facts.** A method called on an unknown object keeps the
  default "the result depends on the receiver and arguments" but never
  contributes sources, sinks or summaries, unless it is explicitly passed as a
  callback. This costs recall (a real call into your code is missed when the
  receiver's class is unknown) in return for precision. *by design*
- **Declared types.** Declared types of parameters, returns and locals are used;
  generics and wrappers (`Optional<T>`, `Result<T, E>`) are not unwrapped. Type
  aliases are not resolved. Declarations are not joined across files for Go/Rust
  struct definitions and C++ headers. *gap (TODO)*
- **One type per name in `flow`.** A reassignment such as `x = B()` after
  `x = A()` in different scopes is not resolved per scope there (declared types
  are). *gap (TODO)*
- **Aliasing.** `b = a` is followed for known instances; aliases through fields,
  containers and calls are not. For languages with value semantics (Go structs,
  C++ objects, Rust moves) a plain copy is treated like a reference copy, which
  can create false positives. *gap / approximation*
- **Per class, not per instance.** Fields of objects that were not constructed in
  the function are tracked per class: one tainted instance makes the field
  tainted for every instance read through the class-level fact. *gap (TODO)*
- **Containers.** Individual array and map keys are not distinguished in
  taint (a literal key picks its element in the call graph; computed keys read
  the whole container). Unknown-object callback targets and container contents
  are conservative sets. *gap / approximation*
- **Only one level of `self` flows through summaries per mechanism.** Receiver
  state, parameters, return values, fields and callbacks are summarized; a flow
  that needs several of them to cooperate across more than a few call levels can
  be cut by the limits below.

### 3.2 Built-in caps (results are truncated, not wrong)

| Constant | Value | Effect when exceeded |
|----------|-------|----------------------|
| Causes kept per tainted value | 6 | Extra origins are dropped; the finding is still reported, with fewer origins. |
| Call chain length in a finding | 6 | Longer chains are not reported through that path. |
| Sinks recorded per parameter | 20 | Further sinks of that parameter are not added to the summary. |
| Rounds for a recursive group | 5 | Mutual recursion may not reach its fixpoint. |
| Extra whole-project passes for tainted fields | 3 (plus a budget for closure nesting) | Very long chains of "stored in a field, read elsewhere, stored again" can be cut. |
| Name ambiguity | 3 candidates | See above. |
| Fixpoint work budget per function | proportional to its size | Pathological graphs stop early. |

### 3.3 Sources, sinks and the rule set

- Sources, sinks and sanitizers are tables per language family
  (`src/analysis/rules.rs`), extendable with `.taintless.toml`. Anything not in a
  table or the config is invisible: custom framework request objects, ORMs,
  template engines, message queues, RPC layers.
- Environment variables and system properties are sources for commands and
  memory errors, **not** for paths, URLs, redirects or pages (by design: whoever
  runs the program sets them).
- SQL injection: only the query argument counts, not bound parameters, and
  query builders are not understood.
- Rules are call-based: there is no rule for logic flaws, authorization,
  secrets in code, insecure configuration, race conditions, or memory-safety
  problems beyond a fixed list of unsafe C functions and format strings.
- `implicit_flows` (control-dependence taint) is optional and noisy; it only
  applies from the root configuration, and calls under a tainted branch are not
  reported for that reason alone.
- Entry-point parameters are sources only where configured (`[[entry]]`) or
  built in (Java `main(args)`, C `argv`). Framework handlers (route functions,
  controllers) are not recognized automatically.

### 3.4 Closures and callbacks

- Closures run later (event handlers, threads, promises) are modeled
  conservatively; scheduling and ordering are not. Local shadowing stays
  separate.
- C++ captures by value do not rebind the outer variable; Java lambdas cannot
  reassign captured locals (they can mutate captured objects).
- A callback whose target cannot be found by name, type, or the stored-function
  tables is not followed.
- A container holding anything that cannot be resolved is not guessed at.

## 4. Call graph (`calls`)

- Resolved by name; class hierarchies are used for Python, Java, TypeScript /
  JavaScript, C++ base classes and Rust traits, with virtual dispatch to
  overrides.
- Go interfaces are structural: they link to types defining every listed method
  (embedded interfaces included) but not to anything outside the scanned code,
  and an interface known only from a declaration that is never called through
  has limited resolution. *gap (TODO)*
- Calls through containers follow what was put in them; computed keys read the
  whole container; containers a callee fills in place are not seen by its
  caller; `for k, v in d.items()` gives `k` what `v` holds; a Go struct with no
  methods of its own is not a known class, so what it embeds is not promoted
  through it. *gap (TODO)*
- Dynamic dispatch on values whose type cannot be inferred is by name only.

## 5. File dependencies (`deps`)

- Imports resolve to **scanned** files; everything else is reported as external.
  Anything outside the scanned path (including a vendored dependency you did not
  scan) is external.
- Manifest support: `tsconfig.json` / `jsconfig.json` (`baseUrl`, `paths`,
  relative `extends`), `go.mod`, `Cargo.toml` (crate names). **Not** supported:
  `package.json` workspaces and `exports`, `go.work` and `replace`, Python
  `pyproject` / `src` layouts beyond suffix matching, non-standard Cargo `[lib]`
  layouts in `use crate::`, conditional exports, package aliases from lockfiles.
  *gap (TODO)*
- Python relies on suffix matching of module paths; two packages with the same
  tail path can be confused when neither is nearer to the importer.
- Dynamic imports are found only with string literals (`import("./x")`,
  `importlib.import_module("a.b")`); computed module names are not.
- A baseline of "who uses what" is file-level: re-exports are followed two levels
  deep.

## 6. Data flow (`flow`)

- Elements (`a[i]`) count as `a`; field nodes are per class, not per instance.
- Aliases through containers, several assignments or calls are not followed; a
  variable assigned once from another is an alias.
- One type per variable name (see 3.1).
- The graph can be too large to draw for big projects; use `--from` and
  `--function`.
- Edges are "may flow", not "does flow"; there is no value or condition
  information on edges (except control edges with `--control`).

## 7. Code property graph (`cpg`)

The CPG is under construction (see TODO.md, Phase 4). Today:

- `dataflow`, `callgraph` and `deps` are **not yet views** of the CPG; `Cpg::build`
  calls them and copies their edges, so the project is resolved more than once.
- The AST layer has the basic node kinds only: operators with operand order,
  locals, type nodes and `Param` / `Local` nodes are open.
- Interprocedural `Reaching` edges, scoped symbols (`Ref`), declared field/local
  types and inheritance edges are partial or missing.
- Taint on the CPG is **not** at parity with `analysis/taint.rs` (constructor-built
  instances, aliases, callbacks and closures, keyword arguments, per-argument
  sanitizers, source/sink messages and call chains are open); the reference
  implementation for findings remains `analysis/taint.rs`.
- No persisted graph and no Neo4j CSV export yet; node ids in exports are
  per export.
- No snapshot tests for CPG output and no corpus smoke test on node/edge counts.

## 8. Findings workflow

- **Baseline.** Entries match on rule, file, function, message and a hash of the
  source line, in tiers, so renames, moves and both together are tolerated.
  Two different findings with identical rule, message and source-line text
  can be confused; changing the line of code itself makes the finding new
  again (intended). A baseline written without fingerprints (older versions)
  does not survive a rename plus a move.
- **Suppressions.** `taintless: ignore` comments cover the same line or the
  next line, or a whole file; there is no block range. `until=` uses the UTC
  date of the machine running the tool and an invalid date is ignored (the
  suppression then never expires).
- **Configuration.** `exclude` patterns in the root config are matched against
  paths relative to the **working directory**, not the config file's
  directory. Nested configs may only change `disable`, `exclude` and
  `severity`; sources, sinks, sanitizers, entry points and `implicit_flows`
  belong in the root. A `.taintless.toml` is found next to the scanned path or in
  the working directory, not by walking up further.
- **Severity** is a property of the rule (plus per-rule overrides); it is not
  adjusted by reachability, exposure or context.
- **Output.** SARIF 2.1.0 carries the finding, location and origin text, but not
  the full data-flow path as `codeFlows`; the call chain is in the message text.
- **Exit codes.** 0 clean, 1 findings, 2 incomplete (a file could not be read
  or parsed, or the configuration is invalid).

## 9. Performance and scale

- Whole-project analysis in memory; no streaming and no cache between runs.
- Parsing and per-file work are parallel; the interprocedural phase is
  parallel only across independent groups of the call graph, so one very large
  strongly connected group serializes.
- Large projects can produce `flow` and CPG outputs too big to render or load
  in a viewer; the filters exist for that reason.
- The smoke test scans this repository and any corpora listed in
  `TAINTLESS_CORPUS` (no panic). The large corpora run so far were Go, Python,
  Rust and C++; Java, JavaScript/TypeScript and C are covered by fixtures only.

## 10. How to treat the results

- Treat every finding as a lead, and check the printed origin and call chain.
- Expect misses in code that goes through frameworks, reflection, generated
  code, macros, or dynamically computed names.
- Expect noise from may-analysis in code with shared helper objects, wide
  containers, and name collisions.
- When a result surprises you, `taintless flow --from NAME` and
  `taintless calls` show what the analysis believed about a name; add a
  `[[source]]` / `[[sink]]` / `[[sanitizer]]` entry or a `taintless: ignore`
  with `until=` when the model is wrong for your code base.
