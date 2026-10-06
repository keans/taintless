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

> **Status:** an experimental proof of concept at an early stage, not
> production ready. Review security findings before acting on them.

## Where to start

- The [user guide](guide.md) covers installation, every command, findings,
  the crypto inventory and stored results.
- [Known limitations](limitations.md) lists what is approximated or missing.
- The [design notes](concept.md) explain the architecture and how to add a
  language.

The installation steps, the Docker image and a short tour are in `README.md`
in the repository root. Open work is tracked in `TODO.md` there.
