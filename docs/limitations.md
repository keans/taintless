# Known limitations

What `taintless` does not do, does only partly, or does by approximation. Read
it together with the [user guide](guide.md), the open work
list (`TODO.md`) and the design notes ([concept.md](concept.md)).

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

- **Thirteen languages only**
  **Kind:** by design
  **Consequence:** Python, JavaScript, TypeScript/TSX, Rust, Go, Java, Kotlin,
  C#, Ruby, PHP, Swift, C, C++.
  Files with other extensions are skipped. Dependencies never cross language
  families (a Python call is never linked to a Rust function).

- **C# is modeled like Java**
  **Kind:** approximation
  **Consequence:** Methods, constructors, destructors, operators, local
  functions, lambdas, anonymous methods and property accessors (`Prop.get`,
  `Prop.set`) are functions; top-level statements form a `<module>` function.
  `using` directives, `using Alias = ...` and `using static` are imports.
  `async` / `await`, `yield`, LINQ, pattern-matching declarations (`is T x`),
  records' primary constructors, extension methods, partial classes spread
  over files and `dynamic` are not modeled beyond their syntax: an awaited
  call is a call, a pattern variable is not a binding, an extension method is
  matched by its name only. ASP.NET action parameters are not sources unless
  configured (`[[entry]]`); `Request.QueryString`, `Request.Form`,
  `Request.Query`, `Request.Headers`, `Console.ReadLine` and the environment
  are. A `using` namespace is matched to files by path suffix only (a
  namespace need not mirror the directory layout), so `deps` lists most
  project namespaces as external.

- **Kotlin is modeled like Java**
  **Kind:** approximation
  **Consequence:** Kotlin and Java are one family: they call each other and
  share the rule tables and the crypto tables (`lang = "java"`). Functions,
  secondary constructors, `init` blocks, lambdas (an implicit `it` is a
  parameter), anonymous functions and property accessors (`Prop.get`) are
  functions; `if`, `when`, `try`, `for`, `while` and `do` are control flow,
  also as expressions. Coroutines (`suspend`, `launch`, `async`), scope
  functions (`let`, `apply`, `also`, `run`: their lambdas are arguments of a
  library call, so data does not flow through them), extension functions,
  delegated properties (`by lazy`), operator overloading, destructuring
  beyond the declaration itself, string templates (`"$x"` joins its parts) and
  callable references (`::sink`) are not modeled beyond their syntax. The
  Kotlin grammar (`tree-sitter-kotlin-ng`) names few fields, so the
  front end relies on child order, which a grammar update may change.

- **Ruby is modeled like Python**
  **Kind:** approximation
  **Consequence:** Methods (`def`, `def self.x`), blocks, `do` blocks and
  lambdas are functions; the top-level statements form a `<module>` function.
  `if` / `unless` (and their modifiers), `while` / `until`, `for`,
  `case` / `when` / `in`, `begin` / `rescue` / `ensure`, `return`, `break`,
  `next` and `raise` are control flow; the last expression of a method or
  block is its value. `@name` is a field of `self`; `Foo.new(x)` calls
  `initialize`. `require` and `require_relative` are imports. A call without
  parentheses or arguments is a call only when it has a receiver (a bare
  `name` is a variable). Metaprogramming (`send`, `define_method`,
  `method_missing`, `instance_variable_get`), backticks and `%x()`, heredocs
  with interpolation, safe navigation, a data flow through the elements a
  block iterates (`items.each { |i| .. }` does not carry what `items` holds to
  `i`), mixins (`include`) and the loop of `loop do` are not modeled beyond
  their syntax.

- **PHP is modeled like Java**
  **Kind:** approximation
  **Consequence:** Functions, methods, closures and arrow functions are
  functions; classes, interfaces and traits name their methods
  (`Class.method`); `$this->field` is a field of `$this`; `new C(..)` calls
  `__construct`; `echo`, `print`, `include` / `require` and backticks are
  calls (sinks for XSS and file inclusion). `use` of a namespace is matched to
  files by path suffix (PSR-4 layouts), `require` / `include` by path. `if`,
  `elseif`, `switch` (with fall-through), loops, `try` / `catch` / `finally`
  and `throw` are control flow. Superglobals (`$_GET`, `$_POST`, `$_REQUEST`,
  `$_COOKIE`, `$_FILES`, `$_SERVER`) are sources. Variable variables
  (`$$x`), `extract`, dynamic calls (`$f()`, `call_user_func` with a name),
  references (`&$x`), `list()` destructuring, `match`, generators, traits'
  `use` inside classes, magic methods other than the constructor, and
  framework routing (Laravel, Symfony request objects) are not modeled beyond
  their syntax.

- **Swift is modeled like Kotlin**
  **Kind:** approximation
  **Consequence:** Functions, `init`, `deinit`, and closures are functions;
  classes, structs, enums, extensions and protocols name their members
  (`Type.method`); bare property names inside a method are fields of `self`;
  `Type(..)` calls `init`; a single-expression function or closure returns its
  value. `if let` / `guard let` bind their names to the values (the
  conditions of `if`, `guard` and `while` are one head statement, so
  `&&` / `||` in them do not short-circuit in the control-flow graph).
  `switch`, `for`, `repeat`, `do` / `catch` and `throw` are control flow;
  `defer` is not; `async` / `await` and actors are calls. A generic call used
  as a statement (`HMAC<SHA256>.authenticationCode(..)`) is parsed by the
  grammar as a comparison and reaches the tables by its method name only.
  Property wrappers, result builders, key paths, operator overloading,
  `@objc` dispatch, subscripts and tuple destructuring are not modeled beyond
  their syntax. `import` names modules, not files, so files in one directory
  see each other and imports never link files.

- **Incremental work is limited**
  **Kind:** gap
  **Consequence:** Parsed files, whole-run security findings and function
  summaries are cached. After a change, functions whose code, environment and
  inputs are unchanged are not analyzed again, but a change to the set of
  functions (one added, removed or renamed), to the class hierarchy, to imports
  or to a configuration file re-analyzes every function. A function is also
  analyzed again when a line above it moves (its position is part of its
  code). `index` still builds the whole graph in memory; it rewrites only the
  files whose rows changed.

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
- Import aliases are resolved from the text of the import statement (`import
  os as o`, `from os import system`, a renamed `require` member, an aliased Go
  package, Rust `use .. as`, Java static imports). Relative Python imports,
  nested Rust `use` groups and aliases created by assignment (`f = os.system`)
  are not, except for the function references the call graph tracks. The CPG
  taint query resolves them the same way.
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
- A stored graph is built as a whole when the project changes (only the rows
  of changed files are rewritten). Queries over the stored graph are
  approximate; `query reach` does not model sanitizers.

## 8. Crypto inventory (`crypto`)

- **An inventory, not a proof.** It lists what the code says it uses, matched
  by name. It does not tell whether a primitive is used correctly as a whole
  (key management, nonce reuse across calls, padding oracles, protocol
  design), and a clean report does not mean the cryptography is sound. The
  `weak-crypto` rule in `security` is a separate, smaller check.
- **Name-based matching (by design).** Libraries, calls and secret-bearing
  arguments come from tables (`src/analysis/crypto/tables.toml`). A library or
  function that is not in them is not reported, and a project function named
  like a crypto call (`MD5`, `sha256`) is reported unless the entry is scoped
  to a library that the file must import. Add entries under `[[crypto.*]]` in
  `.taintless.toml`.
- **Languages.** Only the languages the tool parses are scanned: Python,
  JavaScript / TypeScript, Rust, Go, Java, Kotlin, C#, Ruby, PHP, Swift and
  C / C++ (files of other languages are still checked for key material and
  settings). PHP has no imports for its built-in functions (`openssl_*`,
  `hash`, `md5`, `sodium_*`), which are matched in every file; Ruby's
  `OpenSSL::` and `Digest::` constants are matched the same way. A Swift call
  of a CryptoKit generic as a statement is matched by method name.
- **Arguments are read from source text (approximation).** Literals are not
  kept in the IR, so an argument is read from the text at the call. Only
  literals, and a name with exactly one literal definition in the same file,
  are understood. Values read from the environment, computed, built from
  several parts are missed, and so are secrets set
  through struct fields or JS object properties (`{ key: "..." }`); a number
  inside an argument object, such as
  `modulusLength: 1024`, is read. A name defined twice with different values
  is treated as unknown. A name defined in another file is looked up only
  when it is written like a constant (starts with an upper-case letter) and
  every file of that language that defines it agrees; imports are not followed,
  so an unrelated constant of the same name elsewhere makes it ambiguous.
- **Hardcoded values are literal values.** `hardcoded key`, `static IV` and
  `static salt` mean a literal reaches the argument. A key that is derived from
  a constant, loaded from a file in the repository, or that the code only
  *treats* as secret is not recognized, and test or example keys are reported
  like real ones.
- **Objects are followed by call graph and by name (approximation).** A
  method on a crypto object is listed when the variable is assigned once in
  the same function, or is a field assigned once in the same file, when the
  method is called on the call's result, when a project function returns the
  object, and when it is passed to a project function that calls methods on
  that parameter. Which function a call reaches comes from the call graph, so
  it has the call graph's limits (section 4: reflection, dynamic dispatch,
  unknown receiver types); a call the graph does not resolve falls back to the
  one project function with that simple name (four or more characters, unique
  per language), which may match an unrelated library method of the same
  name. When a call can reach several functions, the object is listed only if
  they all return the same kind of object. Copies (`b = a`), list literals and
  `append` / `add` / `put` of crypto objects, and loops over such a list are
  followed. A list or dictionary of different kinds lists a method call on
  one of its elements once per kind, unless the call names a literal key
  (`d["fast"].encrypt()`), which gets the object stored under that key (in the
  literal or by `d["k"] = ...`). A variable assigned in several places gets,
  at each call, the kinds of the assignments that reach it (branches and loops
  included, by the control-flow graph). Not followed: objects stored under
  computed keys or in a map read with `get`, objects returned conditionally
  from a function, a reassigned object passed to a function (the parameter
  is judged by the one kind a caller passes, if any), and a parameter passed
  on beyond three calls.
- **Values are read from text (approximation).** A constant defined as
  another constant is followed three hops; a parameter takes the literal all
  its callers pass (at most six callers, found by the call graph). String
  literals added together (`"MD" + "5"`) are joined, and a function whose
  returns are all the same literal (`def alg(): return "sha" + "1"`) gives it,
  when it is defined in the same file. A part that is not a literal
  (`"SHA-" + mode`) leaves the algorithm unresolved. A value returned by a
  function of another file is read when every definition of that name in the
  language agrees. Constants interpolated into a string (`f"sha{BITS}"`,
  `` `md${LEVEL}` ``) and entries of a dictionary, list or object the file
  defines (`ALGS["fast"]`, `ALGS.fast`, `ORDER[1]`) are filled in when they
  resolve completely. Strings made by `%`, `.format`, `String.format`,
  `fmt.Sprintf` and `string.Format` are formatted the same way when the
  template is a literal and every value resolves (`%s` / `%d` / `{}` /
  `{0}` / `{name}`, with flags, width and precision; no other
  specifiers). A container filled key by key (`ALGS["k"] = "v"`,
  `ORDER.append("v")`) or defined in another file counts when every
  definition agrees and every stored value is a literal; a key stored with
  different values has none. Function results that are not one literal are
  not read.
- **Aliases (approximation).** Import aliases are resolved from the text of
  the import statement, nested Rust `use` groups included. The default import
  of a library the tables know by another name (`import CJ from 'crypto-js'`)
  resolves to that name for the libraries that have one in `tables.toml`
  (`alias`), not for others. Relative Python imports are not resolved: they
  name project code, which is matched by function name.
- **Weakness is a list of known-bad names (approximation).** MD2/4/5, SHA-1,
  DES / 3DES, RC2 / RC4, Blowfish, ECB, small RSA / DH keys, short curves,
  old TLS versions, low PBKDF2 and bcrypt work factors. Weaker choices that are
  not on the list pass, and the thresholds (2048 bits, 10000 iterations,
  cost 10) are fixed. SHA-1 in an HMAC or as a non-security checksum is
  reported like any other use.
- **Non-cryptographic generators and hashes are hints.** `random.*`,
  `Math.random`, `rand()` and friends are listed with `non-cryptographic PRNG`,
  and xxHash, MurmurHash, CityHash, FarmHash, wyhash, HighwayHash, t1ha,
  SpookyHash, MetroHash, FNV and CRC with `non-cryptographic hash`; whether the
  value protects anything is not known. A constant seed is reported separately.
  Argon2 memory is the only parameter checked, not time or parallelism: the
  OWASP profiles trade them against each other (one pass with 46 MiB is as
  accepted as two with 19 MiB), so no minimum for one alone is right. Memory is
  read from a literal, a product or shift of literals (`8 * 1024`, `1 << 16`),
  a constant of the file, libsodium's `MEMLIMIT_*` presets, and the
  `memoryCost` of a JS options object written in the call or held in a variable
  of the file.
- **Quantum tags are by name.** `vulnerable` and `safe` come from algorithm
  names (RSA, ECC, DH, DSA; ML-KEM, ML-DSA, SLH-DSA), not from the key sizes or
  from how a protocol combines them (hybrid schemes are not recognized).
- **Manifests and lock files.** A declared library is `[not imported]` when no
  scanned file imports it, which is also true for code in an unsupported
  language, in an ignored path, or loaded dynamically. Lock files give
  transitive dependencies only by name: versions, features and which
  dependency pulls in which are not read. Only the manifest formats listed in
  the guide are read, by their text: a `setup.py` that builds its
  requirements in code, Gradle build logic (`libs.<alias>` references are
  resolved only through `libs.versions.toml`), a Maven parent POM outside the
  scanned path, and Conan or CMake dependencies fetched by other means
  (`FetchContent`, `pkg_check_modules`) are not seen.
- **Files (approximation).** PEM blocks are found by their header followed by
  key data. DER files are recognized by their extension (`.der`, `.crt`,
  `.cer`, `.key`, `.p8`) and shape, one-line base64 only when it starts like a
  DER sequence (`MI..`) and is at least 100 characters long, and JSON Web Keys
  only in files that parse as JSON; a key in another encoding (a base64 body
  split over lines in a config file, hex) is missed. Of a keystore only the
  Java `.jks` and `.jceks` and BouncyCastle `.bks` formats are opened, for
  the certificates they hold (a key entry through its certificate chain; the
  keys are encrypted; a secret key entry ends the reading). The BKS layout
  is read from the format description, not checked against files from
  every version. A PKCS#12 file shows the certificates in bags that are not
  encrypted, the algorithm that encrypts the rest (RC2-40, 3DES and RC4 are
  flagged; PBES2 is not) and the MAC digest; what is encrypted stays
  unread without the password. A `.jar` is read by its entry names (the
  libraries its packages belong to and a few broken algorithm classes such as
  `MD5Digest` and `DESEngine`) and by the algorithm names in its classes,
  which are inflated (the first 400 classes of at most 1 MB, not those of
  `org/bouncycastle`).
  Encrypted keys are reported as keys without their size. The size is read for
  RSA and DH parameters, EC keys (curve names only), Ed25519 / X25519 and
  certificates (their public key and signature); other key types and
  certificate chains beyond the first block are listed without details. The
  ASN.1 reader is minimal and does not validate. Settings are read only when
  the key (its whole path in nested formats) names `ssl`, `tls`, `cipher`,
  `protocol`, `macs`, `kex` or `algorithm`; a `min_version` that nothing names
  TLS is missed. Nesting is followed by indentation (YAML), by the brackets
  of the whole document (JSON, any number of keys per line) and by section
  headers. YAML flow collections (`tls: { min_version: 1.0 }`, over several
  lines too) and anchors (`&tls`, `*tls`, `<<: *tls`) are read; a flow
  collection inside a block list item or an anchor on a list is not.
  `include` / `Include` / `IncludeOptional` read the named file, relative to
  the including file, with `*` in the file name, three levels deep; the
  findings are at the included file's own lines, and an include of a file
  outside the scanned tree that does not exist here is skipped. Values spread
  over several lines other than lists, backslash continuations and XML text
  are missed, and XML attributes are read per line. Which of two conflicting
  settings wins (Apache, `sshd_config` `Match` blocks) is not evaluated.
- **Disabled verification is matched by spelling (approximation).** A fixed
  list of settings is searched line by line in source and scripts. A check
  turned off through a variable, a helper, another option name or a different
  line is missed, and a test that disables verification on purpose is reported
  like production code.
- **Embedded implementations (approximation).** Recognized by a fixed set of
  constants (the SHA family, MD5, SM3, Camellia, Blowfish, the AES and SM4
  S-boxes, the Twofish, Serpent (two S-boxes), Whirlpool and RC2 tables, the
  Threefish / Skein key schedule constant, the DES permutation, ChaCha).
  Other algorithms are not found, and constants encoded in another way (signed
  decimals, bytes in a string, compressed or obfuscated data) are missed. A
  file with the constants of a hash may only contain a test vector. Binaries
  are searched as raw bytes, and files over 4 MB are skipped.
- **Compiled programs: tables where there are any (approximation).** The symbol
  and dynamic tables and linked libraries of ELF and Mach-O files (fat
  binaries: the first architecture) and the import table of a PE file are read,
  so a name that only appears in a message is not an import. A file without a
  readable table (a Java class, a file whose tables were removed, an unusual
  layout) is searched by its printable strings instead, which can list a name
  that is only text. Go packages are always found by string. PE imports by
  ordinal are named by the exports of the DLL when that file is in the same
  directory (else only the library is listed), delay-load imports are read, and
  only the library names and the functions in the tables are listed. Rust
  symbols (legacy `_ZN` and v0 `_R`) give the crates they mention (also those
  of the type and trait of an `impl`, and of generic arguments), listed when
  they are crypto crates, and the function when it is a type and method the
  tables know (`<md5::Md5 as Digest>::update` is `Md5.update`); a function that
  is only a name in a generic or closure is not matched. A name built at run
  time and a packed binary are not seen. A Java class shows algorithm names but
  not which call they reach, so a bare `AES` is listed without a verdict. Only
  formats with a known magic number are read.
- **Taint into crypto arguments is only as good as the tables and the
  taint analysis.** The `crypto-*-from-input` rules cover the calls in the
  `algorithm` and `secret` tables, by position, by keyword and by property of
  an object, dictionary or Go struct literal argument (only top-level
  properties with a literal name, up to three levels deep; a spread, a
  computed key and a Rust struct literal are not seen). An options object
  built in a variable (`opts = { algorithm: x }; f(opts)`) is followed, in
  both analyses, when the literal is assigned in the same function. One
  passed to another function (`verify(t, k, { algorithms: [x] })` where
  `verify` hands its `opts` parameter to the sink, also through wrappers) or
  returned by one (`jwt.verify(t, k, build(req))`, `o = build(req)`) is
  followed property by property: another tainted property (`audience`) does
  not make it a finding. The property may be written in a literal
  (`return { algorithms: [x] }`), assigned key by key (`o.algorithms = x`),
  held by a variable the callee reassigns, kept in a field of the class
  (`this.opts = { algorithms: [x] }` in a constructor, used in another
  method) or nested in a literal (`all = { jwt: { algorithms: [x] } }`,
  passed as `all.jwt`). Keys written with a computed name, objects built in
  a loop, and objects stored in a list or a map filled at run time are not
  followed.
  Untrusted data from the environment is ignored on purpose, and a key from
  the request is only `low` because it is sometimes intended. They inherit the
  limits of section 3.
- **Not a source of truth for compliance.** The CycloneDX CBOM and SARIF
  output carry what was found; they leave out fields a full CBOM has (key
  lengths, curves, certificate details, protocol versions) and they are not
  validated against a profile.

## 9. Findings workflow

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

## 10. Performance and scale

- Analysis still holds the project in memory. The cache skips parsing of
  unchanged files, reuses security findings for an unchanged project and
  reuses function summaries after an edit (see the incremental limits above).
- Parsing and per-file work are parallel; the interprocedural phase is parallel
  only across independent groups of the call graph, so one very large strongly
  connected group serializes.
- Large projects can produce `flow` and CPG outputs too big to render or load
  in a viewer; the filters exist for that reason.
- The smoke test scans this repository and any corpora listed in
  `TAINTLESS_CORPUS` (no panic). The large corpora run so far were Go, Python,
  Rust and C++; Java, JavaScript/TypeScript and C are covered by fixtures only.

## 11. How to treat the results

- Treat every finding as a lead, and check the printed origin and call chain.
- Expect misses in code that goes through frameworks, reflection, generated
  code, macros, or dynamically computed names.
- Expect noise from may-analysis in code with shared helper objects, wide
  containers, and name collisions.
- When a result surprises you, `taintless flow --from NAME` and `taintless
  calls` show what the analysis believed about a name; add a `[[source]]` /
  `[[sink]]` / `[[sanitizer]]` entry or a `taintless: ignore` with `until=`
  when the model is wrong for your code base.
