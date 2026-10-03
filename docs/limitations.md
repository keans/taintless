# Known limitations

What `taintless` does not do, does only partly, or does by approximation. Read
it together with the [user guide](guide.md), the open work
list ([TODO.md](../TODO.md)) and the design notes ([concept.md](concept.md)).

Legend: **by design** = a deliberate trade-off that will not change; **gap** =
could be improved, usually listed in TODO.md; **approximation** = the analysis
answers "may", so it errs on one side on purpose.

## 1. What kind of tool this is

- **Static and syntax-driven: no compiler, build, type checker or runtime**
  **Kind:** by design
  **Consequence:** It reasons about what the source says (names, declared
  types, imports), not what a compiler would resolve.

- **Findings are *may*-results: if any path keeps data tainted, the sink is
  reported**
  **Kind:** by design
  **Consequence:** False positives are expected; findings are leads to review,
  not proofs.

- **No proof of absence**
  **Kind:** by design
  **Consequence:** A clean run does not mean the code is safe; misses exist
  (see below).

- **No path sensitivity or constraint solving**
  **Kind:** by design
  **Consequence:** A branch that cannot happen (`if False:`, an impossible
  condition) still contributes its flow; conditions such as `if x.isdigit():`
  or `if os.path.exists(p):` are **not** recognized as validation. Only calls
  listed as sanitizers, or overwriting the variable, clean data.

- **No numeric, size or string-content reasoning**
  **Kind:** by design
  **Consequence:** `memcpy` with a tainted size is flagged; a bounds check
  before it is not understood. A constant-folded or regex-validated string
  stays tainted.

- **Sanitizers are not tied to a vulnerability class**
  **Kind:** gap
  **Consequence:** A call listed as a sanitizer cleans the value for every
  rule: `shlex.quote` also "cleans" data going to a SQL sink. Per-rule
  sanitizers are not modeled.

- **Rules match call names, not semantics**
  **Kind:** by design
  **Consequence:** `*.execute` is any method with that name; a look-alike
  method in your own code can match, and a wrapper with a different name does
  not (until it is analyzed as a function or configured as a sink).

- **Dynamic features are not followed**
  **Kind:** by design
  **Consequence:** `eval`-built names, `getattr` / reflection, monkey patching,
  dependency injection by configuration, decorators that rewrite functions,
  dynamically computed imports.

- **Eight languages only**
  **Kind:** by design
  **Consequence:** Python, JavaScript, TypeScript/TSX, Rust, Go, Java, C, C++.
  Files with other extensions are skipped. Dependencies never cross language
  families (a Python call is never linked to a Rust function).

- **Incremental work is limited**
  **Kind:** gap
  **Consequence:** Parsed files and whole-run security findings are cached.
  After any project change, interprocedural analysis still runs for every
  function. `index` rebuilds the whole stored graph after a change.

## 2. Parsing and control flow

- **Tree-sitter grammars decide what parses. On syntax errors the file may be
  partly modeled; a file that cannot be parsed is reported (exit code 2) and
  the rest still run.**
  **Kind:** by design

- **C/C++ computed `goto *p` is not parsed by the grammars; GNU `case 1 ... 5:`
  is parsed with error recovery (the range shows as two statements; the flow is
  right).**
  **Kind:** by design

- **C/C++ preprocessing is not run: macros are not expanded, `#ifdef` branches
  are not selected, so macro-hidden control flow and calls are invisible.**
  **Kind:** by design

- **Rust macros other than the modeled ones (`panic!`, `?`) are not expanded.**
  **Kind:** by design

- **C++ templates are not instantiated; overload resolution and implicit
  conversions are not modeled; `noexcept` does not change the modeled CFG.**
  **Kind:** by design

- **`.h` files are guessed: parsed as C++ when they use C++ constructs,
  otherwise C.**
  **Kind:** approximation

- **JS/TS `await` / `yield` suspension points do not change the modeled flow;
  the exception edge from a `try` body covers them. Scheduling, thread
  interleaving and event ordering are not modeled.**
  **Kind:** by design

- **Rust drops and `?` through `Drop`: scope exit has no explicit control flow
  in the source, so none is modeled.**
  **Kind:** by design

- **Exceptions: explicit `throw` / `raise` and `try` bodies are modeled;
  implicit exceptions from arbitrary calls only through the `try` body edge.**
  **Kind:** approximation

- **Expression nesting beyond about 200 levels is ignored (generated or
  minified code).**
  **Kind:** by design

- **Comprehension, ternary and short-circuit lowering follows the common
  shapes; unusual forms of expression-level control flow may be flattened.**
  **Kind:** approximation

## 3. Taint analysis

### 3.1 Precision of what is tracked

- **Resolution by name.** Calls are resolved within one language. Declared
  types, constructors, factories, imports and visibility narrow the targets.
  A name shared by more than three functions is considered too ambiguous.
  A method on an object of unknown class may remain unresolved. *approximation*
- **Guesses never invent facts.** A name-only method guess can propagate
  existing taint but cannot create a source, sink or summary. *by design*
- **Aliasing and fields.** Known aliases, including those through calls and
  containers, are followed. Shared fields of objects not constructed locally
  may be tracked per class rather than per instance; this can mix independent
  objects. Go struct copies, C++ objects and Rust moves can also be treated
  like reference copies. *approximation*
- **Containers.** Literal keys distinguish entries in Python, JS/TS and Go;
  unknown keys conservatively read the whole container. Dynamic contents and
  unknown callback targets remain conservative sets. *approximation*
- **Summary limits.** Parameters, receivers, returns, callbacks, fields and
  captures are summarized, but deep chains can hit the caps below.

### 3.2 Built-in caps (results are truncated, not wrong)

- **Causes kept per tainted value**
  **Value:** 6
  **Effect when exceeded:** Extra origins are dropped; the finding is still
  reported, with fewer origins.

- **Call chain length in a finding**
  **Value:** 6
  **Effect when exceeded:** Longer chains are not reported through that path.

- **Sinks recorded per parameter**
  **Value:** 20
  **Effect when exceeded:** Further sinks of that parameter are not added to
  the summary.

- **Rounds for a recursive group**
  **Value:** 5
  **Effect when exceeded:** Mutual recursion may not reach its fixpoint.

- **Extra whole-project passes for tainted fields**
  **Value:** 3 (plus a budget for closure nesting)
  **Effect when exceeded:** Very long chains of "stored in a field, read
  elsewhere, stored again" can be cut.

- **Name ambiguity**
  **Value:** 3 candidates
  **Effect when exceeded:** See above.

- **Fixpoint work budget per function**
  **Value:** proportional to its size
  **Effect when exceeded:** Pathological graphs stop early.

### 3.3 Sources, sinks and the rule set

- Sources, sinks and sanitizers are tables per language family
  (`src/analysis/rules.rs`), extendable with `.taintless.toml`. Anything not in
  a table or the config is invisible: custom framework request objects, ORMs,
  template engines, message queues, RPC layers.
- Environment variables and system properties are sources for commands and
  memory errors, **not** for paths, URLs, redirects or pages (by design:
  whoever runs the program sets them).
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

- Name and type resolution follows class hierarchies and overrides in the
  scanned project. Go interfaces include embedded methods and embedded
  structs. Calls into code outside the scanned path remain external.
- Literal container keys select entries; keys inferred from branches and
  parameters select each possible entry. Unknown keys read the whole
  container. A callable of unknown origin cannot be linked exactly.
- Reflection, dynamic method creation and arbitrary runtime dispatch are
  outside the model.

## 5. File dependencies (`deps`)

- Imports resolve to scanned files. A dependency outside the scanned path is
  external, even if it exists elsewhere on disk.
- Supported manifests include `tsconfig.json`, `jsconfig.json`, `go.mod`,
  `go.work`, `Cargo.toml`, `package.json` and Python project metadata. Dynamic
  module names, conditional exports and aliases defined only in lockfiles can
  remain unresolved.
- Re-exports are followed to a limited depth. Same-named packages with similar
  paths can still be confused when visibility does not distinguish them.

## 6. Data flow (`flow`)

- `flow` is a view drawn from the CPG's reaching and call edges. It follows
  known aliases and literal container elements; unknown keys are conservative.
- Fields shared between methods may be represented per class, so separate
  instances can appear to share a value.
- Edges mean a value *may* flow. They do not prove a feasible execution path.
  The graph can be large; use `--from` and `--function` to filter it.

## 7. Code property graph (`cpg`)

- The CPG has stable node ids, scoped symbols, interprocedural `Reaching`
  edges, calls and imports. It can be stored with `index` and exported as JSON,
  DOT, GraphML or Neo4j CSV.
- The CPG taint query matches the reference findings on fixtures and this
  repository's Rust sources. The `security` command still uses the separate
  summary-based implementation. Both analyses have finite budgets and inherit
  the language and rule limits above.
- A stored graph is rebuilt as a whole when the project changes. Queries over
  the stored graph are approximate; `query reach` does not model sanitizers.

## 8. Findings workflow

- **Baseline.** Entries match on rule, file, function, message and a hash of
  the source line, in tiers, so renames, moves and both together are tolerated.
  Two different findings with identical rule, message and source-line text can
  be confused; changing the line of code itself makes the finding new again
  (intended). A baseline written without fingerprints (older versions) does not
  survive a rename plus a move.
- **Suppressions.** `taintless: ignore` comments cover the same line or the
  next line, or a whole file; there is no block range. `until=` uses the UTC
  date of the machine running the tool and an invalid date is ignored (the
  suppression then never expires).
- **Configuration.** `exclude` patterns in the root config are matched against
  paths relative to the **working directory**, not the config file's directory.
  Nested configs may only change `disable`, `exclude` and `severity`; sources,
  sinks, sanitizers, entry points and `implicit_flows` belong in the root. A
  `.taintless.toml` is found next to the scanned path or in the working
  directory, not by walking up further.
- **Severity** is a property of the rule (plus per-rule overrides); it is not
  adjusted by reachability, exposure or context.
- **Output.** SARIF 2.1.0 carries the finding, location and origin text, but
  not the full data-flow path as `codeFlows`; the call chain is in the message
  text.
- **Exit codes.** 0 clean, 1 findings, 2 incomplete (a file could not be read
  or parsed, or the configuration is invalid).

## 9. Performance and scale

- Analysis still holds the project in memory. The cache skips parsing of
  unchanged files and reuses security findings for an unchanged project; it
  does not yet recompute only affected functions after an edit.
- Parsing and per-file work are parallel; the interprocedural phase is parallel
  only across independent groups of the call graph, so one very large strongly
  connected group serializes.
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
- When a result surprises you, `taintless flow --from NAME` and `taintless
  calls` show what the analysis believed about a name; add a `[[source]]` /
  `[[sink]]` / `[[sanitizer]]` entry or a `taintless: ignore` with `until=`
  when the model is wrong for your code base.
