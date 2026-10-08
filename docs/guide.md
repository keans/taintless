# User guide

Install the tool from the repository root as described in
`README.md`. The commands below use `cargo run --`; replace that
with `taintless` after installation.

## Usage

```sh
# --- control-flow graphs ------------------------------------------------
# Graphviz DOT: a cluster per file and function
cargo run -- cfg path/to/file.py
cargo run -- cfg path/to/dir | dot -Tsvg -o cfg.svg   # needs Graphviz
# one line per block/edge, easy to diff
cargo run -- cfg path/to/file.go --format text
# also carries per-statement assignments and calls
cargo run -- cfg path/to/dir --format json

# --- security checks ----------------------------------------------------
# human-readable findings
cargo run -- security path/to/project
# GitHub code scanning / IDEs
cargo run -- security path/to/project --format sarif > taintless.sarif
cargo run -- security path/to/project --min-severity high --format json
# default: .taintless.toml next to the path
cargo run -- security path/to/project --config ci/taintless.toml
# accept today's findings
cargo run -- security path/to/project --write-baseline .taintless-baseline.json
# report only new ones
cargo run -- security path/to/project --baseline .taintless-baseline.json

# --- how values flow ----------------------------------------------------
# one function (and its links)
cargo run -- flow path/to/project --function handler | dot -Tsvg -o flow.svg
# what a variable / callee / param flows into
cargo run -- flow path/to/project --from user_id --format text
# + which branch decides whether a statement runs
cargo run -- flow path/to/project --control
cargo run -- flow path/to/project --format json       # nodes and edges

# --- which file depends on which ---------------------------------------
# DOT is the default format
cargo run -- deps path/to/project | dot -Tsvg -o deps.svg
# imports + cross-file calls, cycles
cargo run -- deps path/to/project --format text
cargo run -- deps path/to/project --level dir         # one node per directory
# + modules outside the scanned code
cargo run -- deps path/to/project --external

# --- who calls whom -----------------------------------------------------
# callers, entry points, recursion
cargo run -- calls path/to/project
cargo run -- calls path/to/project --format dot | dot -Tsvg -o calls.svg
# + most frequent library calls
cargo run -- calls path/to/project --external

# --- code property graph ------------------------------------------------
# AST, control flow, dependence, calls, imports in one graph
cargo run -- cpg path/to/project > cpg.json
# for Gephi, yEd, Neo4j / APOC import
cargo run -- cpg path/to/project --format graphml > cpg.graphml
# nodes.csv + edges.csv for neo4j-admin import
cargo run -- cpg path/to/project --format neo4j --out csv/
cargo run -- cpg path/to/file.py --function handler \
  --edges cfg,reaching --format dot | dot -Tsvg -o h.svg
# names -> declarations, lexical scopes, class hierarchy
cargo run -- cpg path/to/project --edges ref,scope,inherits
```

`path` can be a file or a directory. Directories are walked recursively,
respecting `.gitignore`, and files with an unknown extension are skipped. Files
are sorted and parsed in parallel, so output order is stable; a one-line
summary goes to stderr. On a terminal, progress is shown for file discovery,
reading, analyzing and (for `security`) checking, naming the current file; it
is hidden when output is piped. If a file fails to parse, the error goes to
stderr and the other files are still processed.

**Exit codes of `security`:** `0` no findings, `1` findings (at or above
`--min-severity`), `2` some file could not be read or parsed (results are
incomplete). `cfg` and `calls` exit `1` if a file failed.

### Reading the diagram

Green edges are `true`, red are `false`; dashed blue is a loop back-edge,
orange is `break`/`continue`, brown is `return`, dashed purple is an exception.
Yellow blocks end in a branch, blue ones contain a call, small dots are join
points, and red dashed blocks are unreachable code. `entry` is always empty:
the function's first statement is the block it points to.

### What `security` finds

Each finding has a rule, a CWE, a severity, the function and position, and, for
taint findings, where the untrusted data came from (`request.args.get() (line
9)`).

- **command-injection**
  **Examples:** `os.system`, `subprocess.*`, `child_process.exec`,
  `Runtime.exec`, `exec.Command`, `Command::new(..).arg(..)`, `system`, `popen`

- **code-injection**
  **Examples:** `eval`, `exec`, `Function`, `setTimeout(str)`,
  `ScriptEngine.eval`

- **sql-injection**
  **Examples:** `cursor.execute(q)`, `db.query(q)`,
  `Statement.executeQuery(q)`, `db.Query(q)` (only the query argument counts,
  not bound parameters)

- **path-traversal, ssrf, open-redirect, xss**
  **Examples:** `open`, `fs.readFile`, `new File(..)`, `os.Open`;
  `requests.get`, `fetch`, `http.Get`; `redirect`; `res.send`, `document.write`

- **insecure-deserialization, weak-crypto**
  **Examples:** `pickle.loads`, `yaml.load`, `readObject`; `md5`, `sha1`

- **crypto-algorithm-from-input, crypto-key-from-input,
  crypto-iv-from-input**
  **Examples:** `Cipher.getInstance(request.getParameter("alg"))`,
  `hashlib.new(request.args["alg"])`, `crypto.createHash(req.query.alg)`;
  `AES.new(request.form["key"], ..)`; an IV or nonce taken from the request.
  They come from the crypto tables (`algorithm` and `secret`), so entries
  added under `[[crypto.*]]` in `.taintless.toml` become sinks too. Keyword
  arguments count (`hashlib.new(name=x)`, `AES.new(key=x, iv=y)`), and so do
  properties of an object, dictionary or struct literal argument, one by one
  (`jwt.verify(t, k, { algorithms: [x] })`, `tls.connect({ minVersion: x })`,
  `tls.Dial(.., &tls.Config{MinVersion: x})`): another property holding
  untrusted data does not make the call a finding. Nested literals count
  (`{ secureContext: { minVersion: x } }`), and so does an options object
  built in a variable (`opts = { algorithm: x }; f(opts)`), passed on to
  a function that hands it to the sink, returned by a function
  (`f(build(req))`), kept in a field or nested in another literal, property
  by property. Keys and
  algorithms from environment variables do not count. A key from the request
  is only `low`: it is sometimes the design (a user-supplied password).

- **unsafe-function, format-string, insecure-temp-file**
  **Examples:** `gets`, `strcpy`, `sprintf`, `printf(user)`, `memcpy` with a
  tainted size, `mktemp`

- **unreachable-code**
  **Examples:** code after `return`/`throw`/`break`, after infinite loops

Taint starts at **sources** (`input()`, `request.args`, `req.query`, `getenv`,
`argv`, `os.Args`, `getParameter`, ...), flows through assignments, string
building, calls and container methods such as `list.append`, and is removed by
**sanitizers** (`int()`, `shlex.quote`, `Integer.parseInt`, `strconv.Atoi`,
`atoi`, ...) or by overwriting the variable. It is a may-analysis: if any path
keeps the data tainted, the sink is reported. The rule tables live in
`src/analysis/rules.rs`. Names an import introduces are resolved before a
call is matched, so `import os as o; o.system(x)`, `from os import system`,
`from subprocess import run as r` and `const { exec: run } =
require('child_process')` all hit the rules written for `os.system`,
`subprocess.run` and `child_process.exec` (the finding shows the call as
written).

**Closures.** Captured sources and parameters flow through nested closures,
including when the creator is itself a closure. Named nested functions, Java
lambdas and C++ lambdas (including init-captures) participate. Calling a
closure applies its writes to captured variables; C++ captures by value do not
rebind the outer variable. When a closure is returned, passed to another
function, or stored in a field/container, its captured writes may reach sibling
handlers and later reads of the same lexical cells. This is conservative:
scheduling and thread ordering are not modeled, and local shadowing stays
separate. Java lambdas can mutate captured objects/arrays but cannot reassign
captured local variables.

**Across functions and files.** Every function gets a summary: which of its
parameters reach a sink (directly or through the functions it calls), which
flow into its return value, and whether its return value carries untrusted data
from a source. Callers apply the summary instead of guessing, so a sink hidden
behind a helper is found, a helper that sanitizes or ignores its argument makes
the call clean, and the finding names the chain: `request.args.get() (line 7)
via nested() at app.py:14 → run_cmd() at util.py:25`. Functions are processed
callees-first, recursion is solved to a fixpoint, and independent groups run in
parallel. Environment variables and system properties are sources for commands
and memory errors, but not for paths, URLs, redirects or pages.

**Fields and objects.** State is tracked per access path, so `self.a` and
`self.b` are different and `self.x = clean` makes `self.x` clean again.
Untrusted data stored in a field of the object (`self.cmd = input()`, or a
constructor that stores its argument and is called with untrusted data) is
remembered per class: any other method of that class that reads the field sees
it, unless it assigned the field itself first. The whole project is re-analyzed
until no new tainted field appears, with a pass budget that also accounts for
closure nesting. The object's own fields are the receiver (`self`, `this`, the
Go receiver); other objects are followed once a variable is known to hold an
instance (`r = Req(..)`, `new Svc(..)`, `S::new(..)`, a copy `s = r`). A
locally constructed object is judged by its own constructor arguments, so
`Req("ls").d` stays clean even if another `Req` holds untrusted data, and a
method call on it (`r.run()`) resolves exactly to `Req.run`. The class of a
variable also comes from declared return types (`NewServer()`, `Foo.create()`)
and declared parameter types, a call on a base type may reach any override, and
`b = a` makes writes through `b` visible through `a`. A method also summarizes
what its **receiver's** state does: if `run` passes `self.cmd` to a sink,
`r.cmd = input(); r.run()` is reported for that very object, and `return
self.cmd` hands the field's taint to the caller.

**Callbacks.** A parameter that is called as a function (`fn(x)`) is part of
the summary: which of the function's own inputs it is called with, and whether
its result is returned. When a caller passes a function, a method or a lambda
for it (`apply(sink, input())`, `xs.forEach(v => eval(v))`), the sinks inside
that function are reported with the chain `sink() via apply()`, and a returned
callback result carries its taint to the caller. A callback handed on through
another function is followed too. Functions that are *stored* are followed as
well: in a variable (`g = sink; g(x)`), a table or list (`handlers[k](x)`, `for
h in queue: h(x)`), a field of the object (`self.cb = f` in `__init__`, called
as `self.cb(x)` in another method) or a module-level registry (`HANDLERS =
{"run": run}`); reassigning the variable ends it. Stores through other objects
(`b.cb = sink`), callback setters through helpers, and containers passed to or
returned from functions carry their callable contents too. A method explicitly
passed as a callback (`apply(obj.handler, x)`) considers visible
implementations even when the object's class is unknown.

Limits: calls use inferred types where available and otherwise resolve by name
within one language. When several functions share a name, the ones the calling
file can see win: its own, what it imports (two levels deep, so re-exporting
`__init__`/`index` files work), its own package in Go and Java, and the source
file next to an included C header. A method called on an unknown object is only
a guess: it keeps the default "the result depends on the receiver and
arguments", but never contributes sources, sinks or summaries unless it is
explicitly passed as a callback. Go interfaces dispatch through declared
parameters, locals and fields. Aliases through calls, fields and containers are
followed, including literal list, map and object keys in Python, JS/TS and Go.
Dynamic keys remain conservative. Fields are generally shared per class rather
than tracked per instance. Unknown-object callback targets and container
contents are conservative sets. Expect some false positives and misses. Treat
findings as leads to review.

### Making `security` fit a real project

**Suppress one finding** with a comment on the same line or the line above, in
whatever comment syntax the language has:

```python
os.system(cmd)  # taintless: ignore
# taintless: ignore[command-injection, sql-injection]
os.system(cmd)  # taintless: ignore until=2026-12-31
```

`taintless: ignore-file[rule]` anywhere in a file silences it for the whole
file. `--no-suppress` ignores all such comments (to audit them); the summary
line says how many findings were suppressed.

**Adopt it on existing code** with a baseline: `--write-baseline FILE` records
today's findings (and exits 0); later runs with `--baseline FILE` report only
new ones. Entries are keyed by rule, file, function and message, not by line,
so editing code above a known finding does not bring it back; repeated findings
are counted. Renaming a function or moving a file does not bring them back
either, and neither does doing both at once: each entry also stores a hash of
the finding's source line (whitespace-normalized), which is matched last. With
`--write-baseline FILE --review-after DAYS` the entries carry a review date;
past it they stop hiding their findings, which are reported again (and counted
in the summary), so accepted risk gets looked at.

**Teach it about your code** with `.taintless.toml`, found next to the scanned
path or in the working directory (or `--config FILE`). Mistakes in it are
errors, not silently ignored.

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
# a built-in rule: gives CWE, severity, message
rule = "sql-injection"
arg = 0                                 # optional: only this argument counts
keyword = "query"                       # optional: or passed by keyword

# parameters of these functions are untrusted
[[entry]]
function = "handle_*"                   # * is a wildcard
params = ["data"]                       # optional: only these

# configs merged underneath this one (paths relative to this file)
extends = ["../base.toml"]
# also follow implicit flows (off by default)
implicit_flows = true

# per rule: ignore findings in these paths
[rule.command-injection]
exclude = ["scripts/**"]
```

To leave files out of the scan altogether (they are not analyzed, unlike
`exclude`, which only drops findings), use `--exclude GLOB` on any command, as
often as needed. The glob is `.gitignore`-style and relative to the working
directory: `--exclude tests/ --exclude '**/*_test.go'`. A `.ignore` file in the
project root does the same without a flag.

A `message = "..."` on a `[[source]]` is shown with the finding's origin. A
`.taintless.toml` in a subdirectory of the scanned path adds to the root one
for the files below it (`disable` and `exclude` accumulate, `severity`
overrides); it cannot define sources, sinks, sanitizers or entry points, or
turn on `implicit_flows`.

With `implicit_flows = true`, a branch on untrusted data also taints what is
assigned or returned under it (control dependence, so nested branches and loops
count): `if secret == "x": cmd = "id"` makes `cmd` untrusted, and a callee that
returns different values depending on a parameter passes that parameter's taint
on. Calls made under such a branch are not reported for that reason alone, and
the setting adds findings (and noise) the data-flow rules do not give.

Call patterns work as in the built-in tables: `eval` is exactly that name,
`os.system` also matches behind more qualifiers, `*.execute` is any method with
that name. Java's `main(String[] args)` and C's `argv` are untrusted by
default.

### C and C++ macros

C and C++ files are preprocessed before they are parsed, so a call hidden
behind a macro is seen as the call it is:

```c
#define RUN(cmd) system(cmd)       /* RUN(argv[1]) is a system() call */
#define SHELL system               /* SHELL(x) too */
#define LAUNCH(a, b) a##b          /* LAUNCH(sys, tem)(x) as well */
```

- Object-like and function-like macros are expanded, with `#`, `##` and
  `__VA_ARGS__`. Strings and comments are left alone, and a macro is not
  expanded inside its own expansion.
- `#if`, `#ifdef`, `#elif` and `#else` pick their branch when the condition
  depends only on macros the code defines (`#if 0`, `#if MODE == 2`,
  `#ifdef __cplusplus`). A condition on a macro nothing defines (`_WIN32`,
  a build flag) keeps every branch, so all variants are analyzed.
- Macros from a header count when the header is part of the scanned project
  and the file includes it (`#include "config.h"`, or `<config.h>` when the
  path matches a project file). Headers outside the project (system headers)
  are not read.
- Line numbers stay as written; columns after an expansion can shift. The
  cache key of a file covers the headers it includes, so editing a header
  analyzes its includers again.

Macros passed on the compiler command line (`-DNAME=value`) are not known.

### File dependencies

`deps` answers "which file depends on which". An edge `A -> B` means A imports
/ includes / `use`s / `require`s B, or calls a function defined in B (or both).
Imports are resolved to scanned files by path: relative paths exactly (`./lib`
-> `lib/index.ts`, `"util.h"`, `from .x import y`), module names by matching
the end of the path (`pkg.util`, `com.foo.Bar`, a Go import path -> its
directory, `crate::a::b` / `super::` / `mod x;` relative to the crate root).
What does not resolve is listed as external (`--external`). The report shows,
per file, what it uses and who uses it, **import cycles**, and the most
depended-on files; `--level dir` collapses files into directories for big
trees. In DOT, solid edges are imports (labelled with the number of calls),
dashed edges are calls without an import, and files in a cycle are red.
Manifests next to (or above) the scanned files sharpen this: `tsconfig.json` /
`jsconfig.json` (`baseUrl`, `paths`, a relative `extends`) resolve aliases like
`@app/x`; with a `go.mod`, only imports under a module path count as project
code (so `github.com/other/util` is not mistaken for your `util`); `Cargo.toml`
names, `[lib] path` and `[[bin]] path` let `use my_core::x` reach another crate
of a workspace and `crate::` / `mod` start at a non-standard root.
`package.json` workspaces resolve `@scope/pkg` through `exports` (subpaths, `*`
patterns, conditions) or `main`; `go.work` `use` and `go.mod` `replace ../dir`
map module paths to local directories; `pyproject.toml` source roots (`src`,
setuptools `package-dir` / `where`, poetry `from`, pytest `pythonpath`) name
Python modules exactly. Python namespace packages and
`importlib.import_module("a.b")` work too. Dependencies never cross language
families (a Python call is never linked to a Rust function). The same import
information is used by `calls` and `security` to choose between functions with
the same name.

### Data flow

`flow` draws where values go: nodes are parameters, assignments, calls, returns
and free variables (globals, `request.args`), and an edge `a -> b` means the
value of `a` may flow into `b`. Inside a function the edges come from reaching
definitions over the CFG, so after `x = a; x = b` only `b` reaches a later use
of `x`, while both reach it after an `if`. Across functions, dashed blue edges
lead from a call argument to the callee's parameter and dashed brown edges from
a callee's `return` to the call; calls are resolved by name like in `calls`.
`--from NAME` keeps only what a variable, callee or parameter with that name
flows into (across functions), and `--function TEXT` keeps only functions whose
name contains the text. `--control` adds the branches (diamonds) and dotted
edges from a branch to the assignments, calls and returns that run only
depending on it, labelled `true` / `false` (control dependence, from
`cpg::cdg`); a branch also reads its condition. Use the filters on big
projects: the full graph can be too large to draw. Fields are tracked by path,
so `self.a` and `self.b` stay apart and `x.f = v` replaces the earlier `x.f`;
what one method stores in `self.f` reaches the other methods of the class
through a shared `field Class.f` node. A variable assigned once from another
(`b = a`) is an alias, so `b.f = v` defines `a.f`. A variable built by a
constructor (`j = Job(..)`) has a known class, so `j.run()` links to `Job.run`
and the receiver reaches its `self`. A function or lambda passed as an argument
(`apply(shout, x)`, `items.forEach(v => ..)`) is called with the other
arguments and the object, and its result flows back to the call. This also
works when the function was first stored in a variable that is assigned once
(`cb = v => ..; xs.forEach(cb)`, `h = sink; h(x)`). Module registries such as
JS `handlers.run(x)`, callbacks stored in other objects' fields, and callable
containers crossing function boundaries also link to their targets. `flow`
follows aliases through calls, fields, containers and returned arguments.
Literal element keys stay separate; dynamic keys may read the whole container.
Field nodes are generally per class rather than per instance.

### Call graph

`calls` links each function to the functions it calls, resolved by name across
all scanned files (qualified names first; a simple name shared by more than 3
functions is considered too ambiguous). It lists **entry points** (functions no
other scanned function calls), **recursive** groups, and optionally the
**external** calls that leave the scanned code.

Class hierarchies are understood (Python, Java, Kotlin, C#,
TypeScript/JavaScript, C++ base classes, Rust traits): `self.step()` /
`this->step()` and a call on a parameter declared as `Base` link to the method
**and every override in a subclass**, inherited methods are found on the
subclass, and `super.m()` goes to the base.
A function passed as an argument (`register(handler)`) or stored in a variable
(`f = handler; f()`) gets an edge too; `--format json` lists every call site
(`lines`) of an edge and which of them are by reference (`callbacks`).

The class of a variable is found from its declared type (parameters and locals
such as Go `var r Runner`, Rust `let r: Runner`, C/C++/Java `Runner r`, Python
`x: Foo`, and TypeScript `const x: Foo`), a constructor (`r = Req()`), the
declared return type of the function that produced it (`r = make()` with `->
Runner`) or a copy of a typed variable. The class of a field comes from its
declaration (`private Runner r;`, `r: Runner`, `self.r: Runner`) or from
`self.f = <typed value>` in the class's methods. Go/Rust struct fields and
C/C++ class fields are linked across declarations and implementations,
including C++ headers. Nested wrappers such as `Option<Box<Runner>>`,
`Optional<Runner>` and `std::shared_ptr<Runner>` expose the payload type. The
call graph, taint analysis and data-flow graph share this type inference, so
`self.runner.run()` and `self.svc.runner.run()` link to `Runner.run` and not to
every `run`. A Go interface is structural: a parameter, local or struct field
declared `r Runner` links `r.Run()` to the types that define every method the
`interface` declaration lists (embedded interfaces included), whether or not
anything calls them. Calls through containers link to what was put in them:
`handlers[k]()`, `for h in hs: h()` and `self.hooks[0]()` reach the functions
stored by a literal, an assignment or `append` / `push` / `insert` (in the
function, at module level or in the class's methods), and `for r in rs:
r.run()` reaches the classes in `rs = [R(), S()]`. A literal key picks its
element (`table["a"]()`, `hs[1]()`, JS `t.open`), plus whatever was stored at a
position that is not a literal (`hs.append(f)`, `hs[i] = f`); any other key
reads the whole container. Keys assigned in branches and keys passed as
parameters resolve to their possible elements at each call site; unknown keys
still read the whole container. JavaScript dot and literal bracket properties
name the same entry. Containers that a function returns (`t = make_table()`),
is called with (`run_all([f, g])`: the parameter holds what its callers pass)
or hands out through `.values()`, `.items()`, `.get(k)`, `enumerate(xs)` or
`Object.values(xs)` are followed too. A container holding anything that cannot
be resolved is not guessed at. A Go struct has the methods of the types it
embeds, even if it defines none of its own, so `Dog{Base}` satisfies an
interface that needs `Base.Wake`. Values of types that cannot be inferred are
still resolved by name only.

### Code property graph

`cpg` puts everything in one graph: the AST nodes of every file plus a few
synthetic ones (`MethodReturn`, `Local`, `Field`, `Type`), and edges of
different kinds on them. Pick kinds with `--edges` (`ast, contains, scope, cfg,
cdg, reaching, call, argument, receiver, param_in, return_out, param_out,
capture, type_of, ref, inherits, imports`) and one function with `--function`.

- `scope` links a method or class to the one around it (file, class, method,
  closure), `ref` an identifier to the parameter, local or field it names (a
  variable of an enclosing function is a captured variable; `self.f` and `x.f`
  with a declared class resolve to the field, also through base classes),
  `inherits` a class to its bases, and `type_of` a parameter, local or field to
  its declared type.
- `reaching` edges lead from a definition to the statements that may read it.
  Aliases are resolved (`b = a`, `h.r = a`, `b = identity(a)`: a definition of
  `b.f` reaches the reads of `a.f`) and a literal element key is part of a path
  (`xs[0]`, the elements of `[a, b]`). Edges that carry a label run between
  functions: `param_in` (an argument reaches the parameter it binds, the object
  of a method call reaches the receiver), `return` (a returned value reaches
  the call and the variable it is assigned to), `param_out` (what a callee
  stores in a field of an argument, of its receiver, of the object a
  constructor builds, or in a captured variable reaches the call) and `field`
  (what a method stores in a field of its receiver reaches the other methods
  that read it). Calls through a variable or a parameter (`fn(x)` in `apply(fn,
  x)`) are calls like any other, so callbacks are covered; `capture` links a
  call or creation of a closure to the closure, which defines the variables it
  reads from its creator at entry.
- The taint query over this graph (`cpg::taint`) matches `security` findings,
  including messages, origins and call chains, on the fixture suites and this
  repository's Rust sources. `TaintFlow::finding` produces the same report
  shape; the `security` command retains the summary-based analysis as its
  reference. The query remembers call context, so `Req(input())` and
  `Req("ls")` build different objects and `ident(input())` and `ident("ls")`
  return different values.

## Crypto inventory

```sh
taintless crypto path/to/project                      # text report
taintless crypto path/to/project --format json        # also: cbom, sarif
taintless crypto path/to/project --only-weak --fail-on-weak   # CI gate
taintless crypto path/to/project --min-severity high --fail-on-weak
taintless crypto path/to/project --config extra.toml  # extra library tables
```

`taintless crypto` lists the crypto libraries the code imports (OpenSSL,
`hashlib`, `node:crypto`, Go `crypto/*`, JCE, RustCrypto crates, ...) and the
crypto functions it calls, grouped by primitive (hash, cipher, mac, kdf,
signature, tls, random, prng, ...). Each call shows its arguments as written
and the algorithm, taken from the function name (`hashlib.sha256`) or from an
argument (`Cipher.getInstance("AES/CBC/..")`, `createHash('sha1')`). A constant
defined once in the same file stands for its value (`ALGO = "md5";
hashlib.new(ALGO)`); one written like a constant (`ALGO`, `Algo`) and defined
in another file of the same language (`Config.ALGO`, `settings.ALGO`) is looked
up there, if every file that defines it agrees. A constant defined as another
constant (`ALIAS2 = ALIAS = BASE = "MD5"`) is followed a few hops, and so is a
parameter: it is what its callers pass (`hash("MD5")` for `def hash(alg)`),
when there are up to six callers and they all pass the same literal.

**Coverage.** The built-in tables cover the standard libraries and the common
third-party ones of Python, JavaScript / TypeScript, Rust, Go, Java / Kotlin,
C#, Ruby, PHP, Swift and C / C++: for example `cryptography`, PyCryptodome,
PyNaCl, `node:crypto`, WebCrypto, `crypto-js`, `jose`, the RustCrypto crates,
`ring`, `rustls`, the `openssl` crate, Go `crypto/*` and `x/crypto`, JCE,
Bouncy Castle, Spring Security password encoders, Jasypt, Guava hashing, Tink,
JWT libraries, OpenSSL, mbedTLS, wolfSSL, libsodium and libgcrypt, and for .NET
`System.Security.Cryptography` (hashes, `Aes`, `RSA`, `Rfc2898DeriveBytes`,
`RandomNumberGenerator`, `CipherMode.ECB`, TLS protocol settings and
certificate callbacks), Bouncy Castle, BCrypt.Net, Konscious Argon2, NSec and
JWT. NuGet manifests (`*.csproj`, `packages.config`,
`Directory.Packages.props`) are read. `aes.Key = ..` and `aes.IV = ..` are
checked like constructor arguments. Calls that only make sense with a
particular library (a bare `sha256(..)`, `MD5.new(..)`) count only in files
that import it, and the report shows the library in brackets. Disabled
certificate checks (`ssl._create_unverified_context`,
`ssh.InsecureIgnoreHostKey`) and unsalted or single-round password hashing
(`StandardPasswordEncoder`, `NoOpPasswordEncoder`) are marked weak. Languages
without a parser here (PHP, Ruby, Swift) are not scanned.

**Aliases.** Names an import introduces are resolved before matching:
`import hashlib as h`, `from hashlib import md5, sha256 as s2`, `from hashlib
import *`, `const { createHash: ch } = require('crypto')`, `import * as cr
from 'node:crypto'`, an aliased Go package, Rust `use md5 as m`, and Java
static imports, nested Rust `use` groups, and the default import of a library
that calls patterns know by another name (`import CJ from 'crypto-js'` makes
`CJ.AES.encrypt` the `CryptoJS.AES.encrypt` of the tables). The call is listed
as written (`h.md5`).

**Objects.** A method called on an object that a crypto call created (`c =
Cipher.getInstance(..); c.doFinal(d)`, `Fernet(k).encrypt(d)`) is listed as a
method with the algorithm of the object, so every place that encrypts or hashes
shows up, not just the constructor. The object is followed through copies (`b =
a`), lists and loops over them (`xs = [AES.new(..)]`, `xs[0].encrypt(d)`, `for
h in xs`), `xs.append(AES.new(..))`, fields of the same file, through a project
function that returns it (`c = make_cipher()`, also in another file) and into a
project function it is passed to (`encrypt_with(AES.new(..), d)` lists the
`cipher.encrypt(d)` inside `encrypt_with`, with the algorithm of the object
passed in; several callers give several entries). Which function a call reaches
is decided by the call graph (the same one `taintless calls` shows: classes,
overloads, imports and declared types), so two classes with a `build` or `seal`
method are told apart. A call the call graph cannot resolve falls back to the
one project function with that name, if there is exactly one and its name has
four or more characters. An object passed on from one function to another
(`outer(c)` calls `middle(c)` calls `inner(c)`) is followed up to three calls
deep. A variable assigned in several places is not tracked. A parameter or
local declared with a crypto class (`Cipher c`, `HashAlgorithm h`) is an object
of that class, so the methods called on it are listed even where nothing
creates it (with the algorithm the class implies, usually unknown); where a
caller passes a concrete object, that report replaces it.

**Weak algorithms** are marked `[weak: reason]`: MD2/4/5, SHA-1, DES/3DES,
RC2/RC4, Blowfish, ECB mode (`AES.MODE_ECB`, `"AES/ECB/.."`, Java's default for
`"AES"`), RSA/DH keys below 2048 bits, curves below 224 bits (`secp192r1`) and
SSLv2/SSLv3/TLS 1.0/1.1.

**Other issues** are listed in brackets after the call: hardcoded keys,
secrets and passwords, static or all-zero IVs, static salts (by position for
the common functions, and by keyword for any crypto call: `key=`, `iv=`,
`nonce=`, `salt=`, `password=`), PBKDF2 iterations below 10000, bcrypt cost
below 10, constant PRNG seeds, and the use of a non-cryptographic PRNG
(`random.*`, `Math.random`, `rand()`, `java.util.Random`, Go `math/rand`).
A PRNG is only a hint: check that it does not produce secrets.

**Files.** Key material and settings outside the parsed code are listed too:
PEM blocks in any text file, source code included (a committed private key is
reported as `hardcoded private key`; certificates and public keys are listed
without a flag; the algorithm and size are read from the key, so `RSA
1024-bit`, `EC prime192v1` and a certificate with a SHA-1 or MD5 signature are
marked weak), keys in other encodings (binary DER files such as `.der`, `.crt`,
`.key` and `.p8`; one line of base64 DER in a config or `.env` file; JSON Web
Keys, where a `d` or an `oct` key is a secret and the size comes from the
modulus or the key), keystore files (`.jks`, `.p12`, `.pfx`, ...; the key
sizes of the certificates inside a `.jks`, `.jceks` or `.bks`, and the
encryption and MAC of a `.p12`; the libraries and
weak classes named in a `.jar`), weak
protocols and ciphers in configuration files (`.conf`, `.cnf`, `.cfg`, `.ini`,
`.yml`, `.properties`, `.toml`, `.xml` attributes, `.json`, `sshd_config`,
`java.security`), and 1024-bit or smaller keys generated in shell scripts,
Dockerfiles and Makefiles (`openssl genrsa 1024`, `ssh-keygen -b 1024`).
Switched-off entries (`!RC4`, `-SSLv3`) and deny lists
(`jdk.tls.disabledAlgorithms`) are not findings. A setting is only read when
its key names `ssl`, `tls`, `cipher`, `protocol`, `macs`, `kex` or `algorithm`.
In nested formats the key is the whole path, so `min_version` under `tls:`
(YAML, JSON, a TOML or INI `[tls]` section) counts; list items, XML element
text and values continued with a backslash are read as values of their key.
JSON with several keys on a line, YAML flow collections (`tls: {min: 1.0}`),
YAML anchors and aliases, and `include` directives (the included file is read
and reported at its own lines) are followed.

**Disabled verification.** Source files and scripts are searched for switched
off certificate checks and old protocol minimums: `InsecureSkipVerify: true`,
`MinVersion: tls.VersionTLS10`, `verify=False`, `check_hostname = False`,
`ssl.CERT_NONE`, `rejectUnauthorized: false`,
`NODE_TLS_REJECT_UNAUTHORIZED = '0'`, `NoopHostnameVerifier`,
`danger_accept_invalid_certs(true)`, `curl -k` and `wget
--no-check-certificate`. Comment lines are skipped. A key size given to a key
generator (`kpg.initialize(1024)`, `keyGen.init(64)`) is checked like one given
to a constructor.

**Taint.** `taintless security` also reports untrusted input that chooses
the algorithm (`Cipher.getInstance(user)`), or becomes a key or an IV (rules
`crypto-algorithm-from-input`, `crypto-key-from-input`,
`crypto-iv-from-input`; see "What `security` finds"). `taintless crypto`
itself does no taint analysis.

**Embedded implementations.** Hand-rolled or vendored algorithms are found by
their constants, in source files (hex or decimal literals) and in binaries
(either byte order, files up to 4 MB): the initial words of SHA-1, MD5,
SHA-224/256/384/512, SHA-3's round constants, SM3 and Camellia, Blowfish's pi
digits, the SHA-256 round constants, the AES S-box and its inverse, the SM4
S-box, the Twofish, Serpent, Whirlpool and RC2 tables, the Threefish / Skein
constant, the DES permutation table and
ChaCha's `expand 32-byte k`. A file needs all words of an algorithm (SHA-1 and
MD5 share four, so the fifth decides) or the whole start of the table. They are
listed without a flag, except the broken ones (MD5, SHA-1, Blowfish, DES, RC2).

**Compiled programs.** Executables, shared libraries and Java class files
(ELF, Mach-O, PE, `.class`, up to 4 MB) are searched for crypto by their
symbol and import tables (the printable strings when there is no table):
the library functions a C or C++ program imports (`EVP_md5`, `mbedtls_*`,
`crypto_secretbox*`, Mach-O's leading underscore is ignored), the crypto
libraries it links (`libcrypto`, `libsodium`, `bcrypt.dll`, ...), the crypto
packages of a Go program (`crypto/md5`), and the algorithm names in a class
file's constants (`MD5`, `DES/ECB/..`), also inside a `.jar`, and the crypto
crates of a Rust program (from legacy and v0 symbols). Weak functions and
algorithms are flagged like the same calls in source.

**Dependencies.** Manifests under the scanned path are read too: `Cargo.toml`,
`package.json`, `pyproject.toml`, `requirements*.txt`, `setup.py`, `setup.cfg`,
`Pipfile`, `go.mod`, `pom.xml`, `build.gradle(.kts)`, Gradle's
`libs.versions.toml`, Conan (`conanfile.txt` / `.py`), `vcpkg.json` and
`CMakeLists.txt` (`find_package`, imported targets), `Gemfile` / `*.gemspec`,
`composer.json`, `Package.swift` and `Podfile`, and the lock files
`Cargo.lock`, `package-lock.json`, `poetry.lock`, `Pipfile.lock`, `go.sum`,
`Gemfile.lock`, `composer.lock` and `Package.resolved`.
Crypto libraries they declare are listed with file and line, and marked `[not
imported]` when no scanned file imports them (unused, used through another
library, or code that was not scanned) and `[lock file]` when only a lock file
names them, which usually means a transitive dependency.

**Output.** `--format cbom` writes a CycloneDX 1.6 cryptographic bill of
materials (libraries and algorithms with where they are used) and `--format
sarif` a SARIF 2.1.0 report with one result per weak algorithm or problem in
the arguments. Public-key algorithms a quantum computer breaks (RSA, ECC, DH,
DSA) are tagged `[quantum: vulnerable]` and the post-quantum standards (ML-KEM,
ML-DSA, SLH-DSA, ...) `[quantum: safe]`. `--only-weak` lists only weak
algorithms and problems in the arguments, `--min-severity low|medium|high`
keeps those of at least that severity, and `--fail-on-weak` exits with
status 1 when there are any (after the filters), for CI. The JSON output has a
`severity` for every flagged entry: `high` for a disabled certificate check,
committed key material and a hardcoded key or secret; `medium` for weak
algorithms, modes and protocols, static IVs and salts, small keys, low work
factors and constant PRNG seeds; `low` for SHA-1 and a plain non-cryptographic
PRNG.

Matching is by name, using the tables in `src/analysis/crypto/tables.toml`.
A `.taintless.toml` (or `--config`) can add entries under `[crypto]` in the
same shape; they are matched before the built-in ones, so an entry can also
override a built-in one. `lang` is `python`, `javascript` (also TypeScript),
`rust`, `go`, `java` (also Kotlin), `csharp`, `ruby`, `php`, `swift` or `c`
(also C++). A call entry takes an optional `weak = true` and an optional
`library` (it then counts only in files that import that library):

```toml
[[crypto.library]]
lang = "python"
module = "mycorp.crypto"
name = "mycorp"

[[crypto.call]]
lang = "python"
pattern = "mycorp.crypto.seal"
primitive = "cipher"
algorithm = "AES-GCM"
```

The other tables are `dependency` (manifest names that differ from the module),
`secret` (arguments holding keys, IVs, salts), `algorithm` (arguments that name
the algorithm), `limit` (minimum iterations or cost), `prng`, and the plain
lists `constant_prefix` (`kCCAlgorithm`) and `unsigned_literal` (JWT `none`);
see the header of `tables.toml` for the fields. Values that are not literals
(read from the environment, computed, or defined differently in several
files) are not seen, and neither are keys given as struct fields or JS object
properties. This is an inventory, not a vulnerability check: the `weak-crypto`
rule in `security` is separate.

## Cache and stored results

The default database is `.taintless/db.sqlite` in the project root: the
nearest directory above the scanned path (or the working directory) with a
cache, `.git`, or `.taintless.toml`. `--cache <file>` selects another database.
`--no-cache` skips caching during scans; `index` and `security --store` need
the cache. A generated `.gitignore` excludes the local database. Unused parsed
facts and project results are pruned after 30 runs; `cache-status` shows the
database contents.

- **Parsed files:** CFGs, imports and declarations are keyed by language and
  content hash. Unchanged files skip parsing. A change to analysis code
  invalidates these facts.
- **Security results:** an unchanged project, configuration and manifests
  reuse whole-run findings. A change to those inputs invalidates the result.
- **Function summaries:** after an edit, `security` analyzes again only the
  functions the edit can affect (it reports `analyzed N of M functions`): the
  changed ones and, while a summary changes, their callers. Adding, removing
  or renaming a function, or changing a configuration file, analyzes all.
- **Code property graph:** `index` stores it for `query` and `export-graph`.
  Re-run `index` after the project changes; only the files whose rows changed
  are rewritten.
- **Findings history:** `security --store` records findings for `history` and
  `triage`. Triage decisions survive cache clearing and code changes.

`taintless clear-cache` empties everything except the findings history. A warm
run gives exactly the findings of a `--no-cache` run (`tests/cache.rs`).

Where to keep it:

- **Local checkout:** the default; delete the directory to reset.
- **CI:** cache `.taintless/db.sqlite` between runs. Stored results are tied to
  the analysis build and sources; stale entries are ignored. Run from the same
  working directory each time so relative paths match.
- **Triage:** accepted and false-positive findings are hidden by `--store` and
  listed as externally suppressed in SARIF. A finding that returns after being
  fixed is open again.
- **Triage shared by a team:** commit nothing from `.taintless/`. Keep triage
  decisions in a baseline (`--write-baseline`) or share the database through
  your CI artifact store. A shared server database is not supported.

```
taintless index src                          # store the code property graph
taintless query callers run_cmd              # who calls it
taintless query callees main                 # what it calls
taintless query reach 'input()' os.system    # data flow between statements
taintless export-graph --format neo4j --out graph/
# record findings; each prints its id=
taintless security src --store
taintless history                            # list them
taintless triage false-positive <id> --reason "test fixture"
# bulk triage
taintless triage accepted --rule weak-crypto --file tests/
# show the chain of statements as JSON
taintless query reach 'input()' os.system --format json
taintless cache-status
taintless query findings --by-dir
```

## How it works

```
source ──tree-sitter──▶ syntax tree ──lowering──▶ Cfg ──▶ DOT / JSON
```

- `src/lang/`: language detection and lowering. `common.rs` is a shared engine:
  a language implements `Spec` (find functions, map each syntax node to a `Ctl`
  shape such as `If`, `Loop`, `Switch`, `Try`), and the engine builds blocks
  and edges, inlines `finally`, and resolves labeled break/continue and `goto`.
  Every language uses it.
- `src/ir/`: the language-independent IR. A `Cfg` is a petgraph `StableDiGraph`
  of basic blocks (`Block`, holding `Stmt`s) joined by typed edges (`EdgeKind`:
  normal, true, false, back, break, continue, return, exception). `CfgBuilder`
  handles loop targets and terminators, so dead code after a `return` still
  appears in the graph as an unreachable block.
- `src/export/`: `dot.rs`, `json.rs`, `text.rs` (CFGs), `findings.rs` (text,
  JSON, SARIF), `callgraph.rs`, `deps.rs` and `dataflow.rs`.
- `src/analysis/`: `dataflow.rs` (reaching definitions, data flow graph),
  `rules.rs` (source / sink / sanitizer tables), `taint.rs` (data-flow plus
  function summaries), `unreachable.rs`, `callgraph.rs` (name resolution, call
  graph), `deps.rs` (import resolution, file graph).

### What is modeled

All languages: `if`/`else`, `for`/`while`/`do`, `switch`/`match` (fallthrough
where the language has it), `try`/`catch`/`finally` (the `finally` body is
inlined on every path that leaves its `try`), `return`, `throw`/`raise`,
`break`/`continue` with labels, and `goto`. Short-circuit `&&`/`||`/`!` (Python
`and`/`or`/`not`) in conditions become one branch per operand.

Also: Python loop `else`, `try/else`, `with`, comprehensions; Go `defer` (run
on each exit path in reverse order), `fallthrough`, `select`, `recover()` and
`panic`; Rust `?` (also in `if`/`match` heads), `let ... else`, labeled loops,
`async` blocks, `panic!`; Java try-with-resources (`close()` on every path);
`match`/`case` guards; ternaries, `&&`/`||`/`??` and `?.` outside conditions;
`switch`/`match`/`if` used as expressions; `finally` on the exception path of a
`try` without a handler. Top-level script code in Python and JS/TS becomes a
`<module>` CFG (only when it contains more than imports/declarations).
Functions, methods, closures, lambdas and async blocks each get their own CFG,
named like `Class.method`, `Type::method` or `ns::Class::f`. `.h` headers that
use C++ constructs are parsed as C++.

Deliberately not modeled (await/yield, drops, computed goto, `noexcept`): see
"Deliberate limits" in `TODO.md`.

## Development

```sh
cargo test                                # snapshot + unit tests
# accept changed snapshots (review the diff!)
INSTA_UPDATE=always cargo test
cargo clippy --all-targets

# robustness on real code: lower every function, fail on any panic or error
TAINTLESS_CORPUS=/path/to/project:/another/project \
  cargo test --release --test smoke -- --nocapture
```

The default test profile uses optimization level 1 and line-table debug
information, with debug assertions and incremental compilation still enabled.
The first build after a profile change recompiles dependencies; subsequent
test builds reuse them. CLI tests default to two Rayon threads per process to
avoid competing thread pools when tests run concurrently. Set
`RAYON_NUM_THREADS` to override this when checking parallel behavior.

CI (`.github/workflows/ci.yml`) runs the same checks. Its cJSON and fmt corpora
use CMake's compilation database to check translation units with the compiler
and expand macros before scanning. Project headers are included; host SDK
declarations are omitted. Compiler and preprocessing failures fail the job.
For compiler-validated fmt, set `TAINTLESS_CORPUS_RECOVER_CPP=1` to lower
fully parsed C++ functions and report unsupported syntax and skipped function
nodes. Translation units are analyzed separately to avoid merging repeated
header definitions into one synthetic project. Lowering and analysis failures
remain fatal. This mode does not enable partial parsing in the CLI or the
repository's own smoke test.
Fixtures live in `tests/fixtures/<language>/`; each one is snapshot-tested as
DOT in `tests/snapshots/`. The code property graph of the fixture directories
and language fixtures is snapshotted too (node and edge counts per kind, and
function-level calls; `tests/cpg_snapshots.rs`). The ignored
`tests/cpg_corpus.rs` test builds graphs for projects under `SCAN_CORPUS`,
checks their shape and determinism, and can pin counts in a baseline
(`SCAN_CORPUS_BASELINE`, `SCAN_CORPUS_UPDATE=1`). Run it with
`SCAN_CORPUS=/path/to/projects cargo test --release --test cpg_corpus --
--ignored`.

## Adding a language

1. Add the `tree-sitter-<lang>` dependency.
2. Add `src/lang/<lang>.rs` with a `Spec` impl: `is_function`, `function_name`,
   `function_body`, and `classify` (node kind -> `Ctl`).
3. Extend `Language` and `build_cfgs` in `src/lang/mod.rs` (extension detection
   and dispatch).
4. Add fixtures under `tests/fixtures/<lang>/` and a snapshot test.
