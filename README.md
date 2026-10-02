# taintless

A multi-language code scanner in Rust. It parses source files with
[tree-sitter](https://tree-sitter.github.io/), lowers each function to a
control-flow graph (CFG) on [petgraph](https://docs.rs/petgraph), and builds on
those graphs to export them, find security problems with taint analysis, and
show which function calls which.

**Contents:** [Install](#install) · [Usage](#usage) · [Security](#what-security-finds) ·
[Dependencies](#file-dependencies) · [Call graph](#call-graph) · [CPG](#code-property-graph) ·
[How it works](#how-it-works) · [Development](#development)

## Status

Eight languages lower to CFGs. `security`, `flow`, `calls`, and `deps` analyze
functions across files; `cpg` exports their shared graph. See [TODO.md](TODO.md)
for remaining precision work and planned storage and incremental analysis.

| Language | Extensions |
|----------|------------|
| Python | `.py` |
| JavaScript | `.js` `.mjs` `.cjs` `.jsx` |
| TypeScript | `.ts` `.mts` `.cts` `.tsx` |
| Rust | `.rs` |
| Go | `.go` |
| Java | `.java` |
| C | `.c` `.h` |
| C++ | `.cc` `.cpp` `.cxx` `.hpp` `.hh` `.hxx` |

## Install

Requires a recent Rust toolchain (edition 2024). Graphviz (`dot`) is only
needed to render the diagrams.

```sh
cargo install --path .     # installs the `taintless` binary
taintless --help
```

The examples below use `cargo run --` so they work from a checkout; with the
installed binary, replace it with `taintless`.

## Usage

```sh
# --- control-flow graphs ------------------------------------------------
cargo run -- cfg path/to/file.py                      # Graphviz DOT: a cluster per file and function
cargo run -- cfg path/to/dir | dot -Tsvg -o cfg.svg   # needs Graphviz
cargo run -- cfg path/to/file.go --format text        # one line per block/edge, easy to diff
cargo run -- cfg path/to/dir --format json            # also carries per-statement assignments and calls

# --- security checks ----------------------------------------------------
cargo run -- security path/to/project                    # human-readable findings
cargo run -- security path/to/project --format sarif > taintless.sarif   # GitHub code scanning / IDEs
cargo run -- security path/to/project --min-severity high --format json
cargo run -- security path/to/project --config ci/taintless.toml          # default: .taintless.toml next to the path
cargo run -- security path/to/project --write-baseline .taintless-baseline.json   # accept today's findings
cargo run -- security path/to/project --baseline .taintless-baseline.json         # report only new ones

# --- how values flow ----------------------------------------------------
cargo run -- flow path/to/project --function handler | dot -Tsvg -o flow.svg   # one function (and its links)
cargo run -- flow path/to/project --from user_id --format text   # what a variable / callee / param flows into
cargo run -- flow path/to/project --control            # + which branch decides whether a statement runs
cargo run -- flow path/to/project --format json       # nodes and edges

# --- which file depends on which ---------------------------------------
cargo run -- deps path/to/project | dot -Tsvg -o deps.svg   # DOT is the default format
cargo run -- deps path/to/project --format text       # imports + cross-file calls, cycles
cargo run -- deps path/to/project --level dir         # one node per directory
cargo run -- deps path/to/project --external          # + modules outside the scanned code

# --- who calls whom -----------------------------------------------------
cargo run -- calls path/to/project                    # callers, entry points, recursion
cargo run -- calls path/to/project --format dot | dot -Tsvg -o calls.svg
cargo run -- calls path/to/project --external         # + most frequent library calls

# --- code property graph ------------------------------------------------
cargo run -- cpg path/to/project > cpg.json           # AST, control flow, dependence, calls, imports in one graph
cargo run -- cpg path/to/project --format graphml > cpg.graphml   # for Gephi, yEd, Neo4j / APOC import
cargo run -- cpg path/to/project --format neo4j --out csv/   # nodes.csv + edges.csv for neo4j-admin import
cargo run -- cpg path/to/file.py --function handler --edges cfg,reaching --format dot | dot -Tsvg -o h.svg
cargo run -- cpg path/to/project --edges ref,scope,inherits    # names -> declarations, lexical scopes, class hierarchy
```

`path` can be a file or a directory. Directories are walked recursively,
respecting `.gitignore`, and files with an unknown extension are skipped.
Files are sorted and parsed in parallel, so output order is stable; a one-line
summary goes to stderr. On a terminal, progress is shown for file discovery,
reading, analyzing and (for `security`) checking, naming the current file; it is
hidden when output is piped. If a file fails to parse, the error goes to stderr
and the other files are still processed.

**Exit codes of `security`:** `0` no findings, `1` findings (at or above
`--min-severity`), `2` some file could not be read or parsed (results are
incomplete). `cfg` and `calls` exit `1` if a file failed.

### Reading the diagram

Green edges are `true`, red are `false`; dashed blue is a loop back-edge, orange is
`break`/`continue`, brown is `return`, dashed purple is an exception. Yellow
blocks end in a branch, blue ones contain a call, small dots are join points,
and red dashed blocks are unreachable code. `entry` is always empty: the
function's first statement is the block it points to.

### What `security` finds

Each finding has a rule, a CWE, a severity, the function and position, and, for
taint findings, where the untrusted data came from (`request.args.get() (line 9)`).

| Rule | Examples |
|------|----------|
| command-injection | `os.system`, `subprocess.*`, `child_process.exec`, `Runtime.exec`, `exec.Command`, `Command::new(..).arg(..)`, `system`, `popen` |
| code-injection | `eval`, `exec`, `Function`, `setTimeout(str)`, `ScriptEngine.eval` |
| sql-injection | `cursor.execute(q)`, `db.query(q)`, `Statement.executeQuery(q)`, `db.Query(q)` (only the query argument counts, not bound parameters) |
| path-traversal, ssrf, open-redirect, xss | `open`, `fs.readFile`, `new File(..)`, `os.Open`; `requests.get`, `fetch`, `http.Get`; `redirect`; `res.send`, `document.write` |
| insecure-deserialization, weak-crypto | `pickle.loads`, `yaml.load`, `readObject`; `md5`, `sha1` |
| unsafe-function, format-string, insecure-temp-file | `gets`, `strcpy`, `sprintf`, `printf(user)`, `memcpy` with a tainted size, `mktemp` |
| unreachable-code | code after `return`/`throw`/`break`, after infinite loops |

Taint starts at **sources** (`input()`, `request.args`, `req.query`, `getenv`,
`argv`, `os.Args`, `getParameter`, ...), flows through assignments, string
building, calls and container methods such as `list.append`, and is removed by
**sanitizers** (`int()`, `shlex.quote`, `Integer.parseInt`, `strconv.Atoi`,
`atoi`, ...) or by overwriting the variable. It is a may-analysis: if any path
keeps the data tainted, the sink is reported. The rule tables live in
`src/analysis/rules.rs`.

**Closures.** Captured sources and parameters flow through nested closures, including
when the creator is itself a closure. Named nested functions, Java lambdas and
C++ lambdas (including init-captures) participate. Calling a closure applies its
writes to captured variables; C++ captures by value do not rebind the outer
variable. When a closure is returned, passed to another function, or stored in
a field/container, its captured writes may reach sibling handlers and later
reads of the same lexical cells. This is conservative: scheduling and thread
ordering are not modeled, and local shadowing stays separate. Java lambdas can
mutate captured objects/arrays but cannot reassign captured local variables.

**Across functions and files.** Every function gets a summary: which of its
parameters reach a sink (directly or through the functions it calls), which
flow into its return value, and whether its return value carries untrusted data
from a source. Callers apply the summary instead of guessing, so a sink hidden
behind a helper is found, a helper that sanitizes or ignores its argument makes
the call clean, and the finding names the chain:
`request.args.get() (line 7) via nested() at app.py:14 → run_cmd() at util.py:25`.
Functions are processed callees-first, recursion is solved to a fixpoint, and
independent groups run in parallel. Environment variables and system properties
are sources for commands and memory errors, but not for paths, URLs, redirects
or pages.

**Fields and objects.** State is tracked per access path, so `self.a` and
`self.b` are different and `self.x = clean` makes `self.x` clean again. Untrusted
data stored in a field of the object (`self.cmd = input()`, or a constructor that
stores its argument and is called with untrusted data) is remembered per class:
any other method of that class that reads the field sees it, unless it assigned
the field itself first. The whole project is re-analyzed until no new tainted field appears,
with a pass budget that also accounts for closure nesting. The object's own fields are the
receiver (`self`, `this`, the Go receiver); other objects are followed once a
variable is known to hold an instance (`r = Req(..)`, `new Svc(..)`, `S::new(..)`,
a copy `s = r`). A locally constructed object is judged by its own constructor
arguments, so `Req("ls").d` stays clean even if another `Req` holds untrusted
data, and a method call on it (`r.run()`) resolves exactly to `Req.run`. The
class of a variable also comes from declared return types (`NewServer()`,
`Foo.create()`) and declared parameter types, a call on a base type may reach
any override, and `b = a` makes writes through `b` visible through `a`. A method
also summarizes what its **receiver's** state does: if `run` passes `self.cmd`
to a sink, `r.cmd = input(); r.run()` is reported for that very object, and
`return self.cmd` hands the field's taint to the caller.

**Callbacks.** A parameter that is called as a function (`fn(x)`) is part of the
summary: which of the function's own inputs it is called with, and whether its
result is returned. When a caller passes a function, a method or a lambda for
it (`apply(sink, input())`, `xs.forEach(v => eval(v))`), the sinks inside that
function are reported with the chain `sink() via apply()`, and a returned
callback result carries its taint to the caller. A callback handed on through
another function is followed too. Functions that are *stored* are followed as
well: in a variable (`g = sink; g(x)`), a table or list (`handlers[k](x)`,
`for h in queue: h(x)`), a field of the object (`self.cb = f` in `__init__`,
called as `self.cb(x)` in another method) or a module-level registry
(`HANDLERS = {"run": run}`); reassigning the variable ends it. Stores through
other objects (`b.cb = sink`), callback setters through helpers, and containers
passed to or returned from functions carry their callable contents too.
A method explicitly passed as a callback (`apply(obj.handler, x)`) considers
visible implementations even when the object's class is unknown.

Limits: calls use inferred types where available and otherwise resolve by name
within one language. When several
functions share a name, the ones the calling file can see win: its own, what it
imports (two levels deep, so re-exporting `__init__`/`index` files work), its
own package in Go and Java, and the source file next to an included C header. A
method called on an unknown object is only a guess: it keeps the default "the
result depends on the receiver and arguments", but never contributes sources,
sinks or summaries unless it is explicitly passed as a callback. Go interfaces
dispatch through declared parameters, locals and fields. Aliases through calls,
fields and containers are followed, including literal list, map and object keys
in Python, JS/TS and Go. Dynamic keys remain conservative. Fields are generally shared
per class rather than tracked per instance. Unknown-object callback targets
and container contents are conservative sets.
Expect some false positives and misses. Treat findings as leads to review.

### Making `security` fit a real project

**Suppress one finding** with a comment on the same line or the line above, in
whatever comment syntax the language has:

```python
os.system(cmd)  # taintless: ignore                      every rule on this line
# taintless: ignore[command-injection, sql-injection]   those rules on the next line
os.system(cmd)  # taintless: ignore until=2026-12-31    review date: reported again after it
```

`taintless: ignore-file[rule]` anywhere in a file silences it for the whole file.
`--no-suppress` ignores all such comments (to audit them); the summary line says
how many findings were suppressed.

**Adopt it on existing code** with a baseline: `--write-baseline FILE` records
today's findings (and exits 0); later runs with `--baseline FILE` report only new
ones. Entries are keyed by rule, file, function and message, not by line, so
editing code above a known finding does not bring it back; repeated findings are
counted. Renaming a function or moving a file does not bring them back either,
and neither does doing both at once: each entry also stores a hash of the
finding's source line (whitespace-normalized), which is matched last. With
`--write-baseline FILE --review-after DAYS` the entries carry a review date;
past it they stop hiding their findings, which are reported again (and counted
in the summary), so accepted risk gets looked at.

**Teach it about your code** with `.taintless.toml`, found next to the scanned path
or in the working directory (or `--config FILE`). Mistakes in it are errors, not
silently ignored.

```toml
disable = ["weak-crypto"]               # rule ids (see the table above)
exclude = ["tests/**", "**/*_test.go"]  # findings in these paths are dropped

[severity]
unreachable-code = "medium"             # low | medium | high

[[source]]                              # untrusted data
language = "python"                     # optional; default: every language
call = "myapp.read_request"             # a call whose result is untrusted ...
# path = "ctx.params"                   # ... or a variable / member path

[[sanitizer]]                           # its result is safe
call = "myapp.clean"

[[sink]]                                # a dangerous call
call = "myapp.db.raw_query"
rule = "sql-injection"                  # a built-in rule: gives CWE, severity, message
arg = 0                                 # optional: only this argument counts

[[entry]]                               # parameters of these functions are untrusted
function = "handle_*"                   # * is a wildcard
params = ["data"]                       # optional: only these

extends = ["../base.toml"]              # configs merged underneath this one (paths relative to this file)
implicit_flows = true                   # also follow implicit flows (off by default)

[rule.command-injection]                # per rule: ignore findings in these paths
exclude = ["scripts/**"]
```

A `message = "..."` on a `[[source]]` is shown with the finding's origin. A
`.taintless.toml` in a subdirectory of the scanned path adds to the root one for the
files below it (`disable` and `exclude` accumulate, `severity` overrides); it
cannot define sources, sinks, sanitizers or entry points, or turn on `implicit_flows`.

With `implicit_flows = true`, a branch on untrusted data also taints what is
assigned or returned under it (control dependence, so nested branches and loops
count): `if secret == "x": cmd = "id"` makes `cmd` untrusted, and a callee that
returns different values depending on a parameter passes that parameter's taint
on. Calls made under such a branch are not reported for that reason alone, and
the setting adds findings (and noise) the data-flow rules do not give.

Call patterns work as in the built-in tables: `eval` is exactly that name,
`os.system` also matches behind more qualifiers, `*.execute` is any method with
that name. Java's `main(String[] args)` and C's `argv` are untrusted by default.

### File dependencies

`deps` answers "which file depends on which". An edge `A -> B` means A imports /
includes / `use`s / `require`s B, or calls a function defined in B (or both).
Imports are resolved to scanned files by path: relative paths exactly
(`./lib` -> `lib/index.ts`, `"util.h"`, `from .x import y`), module names by
matching the end of the path (`pkg.util`, `com.foo.Bar`, a Go import path ->
its directory, `crate::a::b` / `super::` / `mod x;` relative to the crate
root). What does not resolve is listed as external (`--external`). The report
shows, per file, what it uses and who uses it, **import cycles**, and the most
depended-on files; `--level dir` collapses files into directories for big
trees. In DOT, solid edges are imports (labelled with the number of calls),
dashed edges are calls without an import, and files in a cycle are red.
Manifests next to (or above) the scanned files sharpen this: `tsconfig.json` /
`jsconfig.json` (`baseUrl`, `paths`, a relative `extends`) resolve aliases like
`@app/x`; with a `go.mod`, only imports under a module path count as project
code (so `github.com/other/util` is not mistaken for your `util`); `Cargo.toml`
names, `[lib] path` and `[[bin]] path` let `use my_core::x` reach another crate
of a workspace and `crate::` / `mod` start at a non-standard root. `package.json`
workspaces resolve `@scope/pkg` through `exports` (subpaths, `*` patterns,
conditions) or `main`; `go.work` `use` and `go.mod` `replace ../dir` map module
paths to local directories; `pyproject.toml` source roots (`src`, setuptools
`package-dir` / `where`, poetry `from`, pytest `pythonpath`) name Python modules
exactly. Python namespace packages and `importlib.import_module("a.b")` work too.
Dependencies never cross language families (a Python call is never linked to a
Rust function). The same import information is used by
`calls` and `security` to choose between functions with the same name.

### Data flow

`flow` draws where values go: nodes are parameters, assignments, calls,
returns and free variables (globals, `request.args`), and an edge `a -> b`
means the value of `a` may flow into `b`. Inside a function the edges come from
reaching definitions over the CFG, so after `x = a; x = b` only `b` reaches a
later use of `x`, while both reach it after an `if`. Across functions, dashed
blue edges lead from a call argument to the callee's parameter and dashed brown
edges from a callee's `return` to the call; calls are resolved by name like in
`calls`. `--from NAME` keeps only what a variable, callee or parameter with that
name flows into (across functions), and `--function TEXT` keeps only functions
whose name contains the text. `--control` adds the branches (diamonds) and dotted edges from a branch to the
assignments, calls and returns that run only depending on it, labelled `true` /
`false` (control dependence, from `cpg::cdg`); a branch also reads its condition.
Use the filters on big projects: the full graph can be too large to draw.
Fields are tracked by path, so
`self.a` and `self.b` stay apart and `x.f = v` replaces the earlier `x.f`;
what one method stores in `self.f` reaches the other methods of the class
through a shared `field Class.f` node. A variable assigned once from another
(`b = a`) is an alias, so `b.f = v` defines `a.f`. A variable built by a
constructor (`j = Job(..)`) has a known class, so `j.run()` links to
`Job.run` and the receiver reaches its `self`. A function or lambda passed as an
argument (`apply(shout, x)`, `items.forEach(v => ..)`) is called with the other
arguments and the object, and its result flows back to the call. This also works when the function was
first stored in a variable that is assigned once (`cb = v => ..; xs.forEach(cb)`,
`h = sink; h(x)`). Module registries such as JS `handlers.run(x)`, callbacks
stored in other objects' fields, and callable containers crossing function
boundaries also link to their targets. `flow` follows aliases through calls,
fields, containers and returned arguments. Literal element keys stay separate;
dynamic keys may read the whole container. Field nodes are generally per class
rather than per instance.

### Call graph

`calls` links each function to the functions it calls, resolved by name across
all scanned files (qualified names first; a simple name shared by more than 3
functions is considered too ambiguous). It lists **entry points** (functions no
other scanned function calls), **recursive** groups, and optionally the
**external** calls that leave the scanned code.

Class hierarchies are understood (Python, Java, TypeScript/JavaScript, C++ base
classes, Rust traits): `self.step()` / `this->step()` and a call on a parameter
declared as `Base` link to the method **and every override in a subclass**,
inherited methods are found on the subclass, and `super.m()` goes to the base.
A function passed as an argument (`register(handler)`) or stored in a variable
(`f = handler; f()`) gets an edge too; `--format json` lists every call site
(`lines`) of an edge and which of them are by reference (`callbacks`).

The class of a variable is found from its declared type (parameters and locals
such as Go `var r Runner`, Rust `let r: Runner`, C/C++/Java `Runner r`, Python
`x: Foo`, and TypeScript `const x: Foo`), a constructor
(`r = Req()`), the declared return type of the function that produced it
(`r = make()` with `-> Runner`) or a copy of a typed variable. The class of a
field comes from its declaration (`private Runner r;`, `r: Runner`, `self.r: Runner`) or
from `self.f = <typed value>` in the class's methods. Go/Rust struct fields and
C/C++ class fields are linked across declarations and implementations, including
C++ headers. Nested wrappers such as `Option<Box<Runner>>`,
`Optional<Runner>` and `std::shared_ptr<Runner>` expose the payload type.
The call graph, taint analysis and data-flow graph share this type inference, so
`self.runner.run()` and `self.svc.runner.run()` link to `Runner.run` and not to
every `run`. A Go interface is structural: a parameter, local or struct field
declared `r Runner` links `r.Run()` to the types that define every method the
`interface` declaration lists (embedded interfaces included), whether or not
anything calls them. Calls through containers link to what was put in them:
`handlers[k]()`, `for h in hs: h()` and `self.hooks[0]()` reach the functions
stored by a literal, an assignment or `append` / `push` / `insert` (in the
function, at module level or in the class's methods), and `for r in rs: r.run()`
reaches the classes in `rs = [R(), S()]`. A literal key picks its element
(`table["a"]()`, `hs[1]()`, JS `t.open`), plus whatever was stored at a position
that is not a literal (`hs.append(f)`, `hs[i] = f`); any other key reads the whole
container. A key held in a local assigned one constant (`k = "a"; table[k]()`) also
picks that element; unknown keys read the whole container. Containers that a function returns (`t = make_table()`), is called with
(`run_all([f, g])`: the parameter holds what its callers pass) or hands out
through `.values()`, `.items()`, `.get(k)`, `enumerate(xs)` or `Object.values(xs)`
are followed too. A container holding anything that cannot be resolved is not
guessed at. A Go struct has the methods of the types it embeds, even if it defines
none of its own, so `Dog{Base}`
satisfies an interface that needs `Base.Wake`. Values of types that cannot be
inferred are still resolved by name only.

### Code property graph

`cpg` puts everything in one graph: the AST nodes of every file plus a few synthetic ones
(`MethodReturn`, `Local`, `Field`, `Type`), and edges of different kinds on them. Pick kinds
with `--edges` (`ast, contains, scope, cfg, cdg, reaching, call, argument, receiver, param_in,
return_out, param_out, capture, type_of, ref, inherits, imports`) and one function with `--function`.

- `scope` links a method or class to the one around it (file, class, method, closure), `ref` an
  identifier to the parameter, local or field it names (a variable of an enclosing function is a
  captured variable; `self.f` and `x.f` with a declared class resolve to the field, also through base
  classes), `inherits` a class to its bases, and `type_of` a parameter, local or field to its declared type.
- `reaching` edges lead from a definition to the statements that may read it. Aliases are resolved
  (`b = a`, `h.r = a`, `b = identity(a)`: a definition of `b.f` reaches the reads of `a.f`) and a
  literal element key is part of a path (`xs[0]`, the elements of `[a, b]`). Edges that carry a label
  run between functions: `param_in` (an argument reaches the parameter it binds, the object of a
  method call reaches the receiver), `return` (a returned value reaches the call and the variable
  it is assigned to), `param_out` (what a callee stores in a field of an argument, of its receiver,
  of the object a constructor builds, or in a captured variable reaches the call) and `field` (what a
  method stores in a field of its receiver reaches the other methods that read it). Calls through a
  variable or a parameter (`fn(x)` in `apply(fn, x)`) are calls like any other, so callbacks are
  covered; `capture` links a call or creation of a closure to the closure, which defines the
  variables it reads from its creator at entry.
- The taint query over this graph (`cpg::taint`) matches `security` on the
  fixture suites covered by the parity tests. Differences on real code and
  finding details remain open. It remembers the last calls a value went through, so `Req(input())` and
  `Req("ls")` build different objects and `ident(input())` and `ident("ls")` return different values.

## How it works

```
source ──tree-sitter──▶ syntax tree ──per-language lowering──▶ Cfg ──▶ DOT / JSON
```

- `src/lang/`: language detection and lowering. `common.rs` is a shared engine:
  a language implements `Spec` (find functions, map each syntax node to a `Ctl`
  shape such as `If`, `Loop`, `Switch`, `Try`), and the engine builds blocks and
  edges, inlines `finally`, and resolves labeled break/continue and `goto`.
  Every language uses it.
- `src/ir/`: the language-independent IR. A `Cfg` is a petgraph `StableDiGraph`
  of basic blocks (`Block`, holding `Stmt`s) joined by typed edges
  (`EdgeKind`: normal, true, false, back, break, continue, return, exception).
  `CfgBuilder` handles loop targets and terminators, so dead code after a
  `return` still appears in the graph as an unreachable block.
- `src/export/`: `dot.rs`, `json.rs`, `text.rs` (CFGs), `findings.rs` (text, JSON, SARIF), `callgraph.rs`, `deps.rs` and `dataflow.rs`.
- `src/analysis/`: `dataflow.rs` (reaching definitions, data flow graph), `rules.rs` (source / sink / sanitizer tables), `taint.rs` (data-flow plus function summaries), `unreachable.rs`, `callgraph.rs` (name resolution, call graph), `deps.rs` (import resolution, file graph).

### What is modeled

All languages: `if`/`else`, `for`/`while`/`do`, `switch`/`match` (fallthrough where
the language has it), `try`/`catch`/`finally` (the `finally` body is inlined on every
path that leaves its `try`), `return`, `throw`/`raise`, `break`/`continue` with labels,
and `goto`. Short-circuit `&&`/`||`/`!` (Python `and`/`or`/`not`) in conditions become
one branch per operand.

Also: Python loop `else`, `try/else`, `with`, comprehensions; Go `defer` (run on each
exit path in reverse order), `fallthrough`, `select`, `recover()` and `panic`; Rust `?`
(also in `if`/`match` heads), `let ... else`, labeled loops, `async` blocks, `panic!`;
Java try-with-resources (`close()` on every path); `match`/`case` guards; ternaries,
`&&`/`||`/`??` and `?.` outside conditions; `switch`/`match`/`if` used as expressions;
`finally` on the exception path of a `try` without a handler. Top-level script code in
Python and JS/TS becomes a `<module>` CFG (only when it contains more than
imports/declarations). Functions, methods, closures, lambdas and async blocks each get
their own CFG, named like `Class.method`, `Type::method` or `ns::Class::f`. `.h` headers
that use C++ constructs are parsed as C++.

Deliberately not modeled (await/yield, drops, computed goto, `noexcept`): see "Deliberate limits" in [TODO.md](TODO.md).

## Development

```sh
cargo test                                # snapshot + unit tests
INSTA_UPDATE=always cargo test            # accept changed snapshots (review the diff!)
cargo clippy --all-targets

# robustness on real code: lower every function, fail on any panic or error
TAINTLESS_CORPUS=/path/to/project:/another/project cargo test --release --test smoke -- --nocapture
```

CI (`.github/workflows/ci.yml`) runs the same checks. Fixtures live in `tests/fixtures/<language>/`; each one is snapshot-tested as DOT
in `tests/snapshots/`.
The code property graph of the fixture directories and language fixtures is
snapshotted too (node and edge counts per kind, and function-level calls;
`tests/cpg_snapshots.rs`). The ignored `tests/cpg_corpus.rs` test builds graphs
for projects under `SCAN_CORPUS`, checks their shape and determinism, and can pin
counts in a baseline (`SCAN_CORPUS_BASELINE`, `SCAN_CORPUS_UPDATE=1`). Run it with
`SCAN_CORPUS=/path/to/projects cargo test --release --test cpg_corpus -- --ignored`.

## Adding a language

1. Add the `tree-sitter-<lang>` dependency.
2. Add `src/lang/<lang>.rs` with a `Spec` impl: `is_function`, `function_name`,
   `function_body`, and `classify` (node kind -> `Ctl`).
3. Extend `Language` and `build_cfgs` in `src/lang/mod.rs` (extension detection
   and dispatch).
4. Add fixtures under `tests/fixtures/<lang>/` and a snapshot test.
