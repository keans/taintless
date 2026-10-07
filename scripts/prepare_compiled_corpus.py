"""Expand configured C/C++ translation units for the strict corpus test.

Use CMake's compilation database to retain its include paths and defines.
System headers are processed for their macros, but their declarations are
omitted from the corpus so the test covers the project rather than the host SDK.
"""

import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess


LINE_MARKER = re.compile(r'^#\s+\d+\s+("(?:\\.|[^"\\])*")')


def project_source(expanded: str, root: Path, directory: Path) -> str:
    keep = False
    lines = []
    for line in expanded.splitlines(keepends=True):
        marker = LINE_MARKER.match(line)
        if marker:
            filename = json.loads(marker.group(1))
            keep = not filename.startswith("<") and (
                directory / filename
            ).resolve().is_relative_to(root)
        elif keep:
            lines.append(line)
    return "".join(lines)


def prepare(root: Path, database: Path, output: Path) -> int:
    root = root.resolve()
    output = output.resolve()
    if output.is_relative_to(root) or root.is_relative_to(output):
        raise ValueError("the output and source trees must be separate")
    # Refuse stale files from an earlier preparation run.
    output.mkdir(parents=True, exist_ok=False)
    seen = set()
    for entry in json.loads(database.read_text()):
        directory = Path(entry["directory"])
        source = (directory / entry["file"]).resolve()
        relative = source.relative_to(root)
        if relative in seen:
            continue
        seen.add(relative)
        arguments = entry.get("arguments")
        if arguments is None:
            arguments = shlex.split(entry["command"])
        command = []
        args = iter(arguments)
        for arg in args:
            if arg == "-o":
                next(args)
            elif arg != "-c":
                command.append(arg)
        # Recovery in the C++ smoke test is only useful for compiler-valid
        # input. A syntax or configuration error must still fail preparation.
        subprocess.check_call([*command, "-fsyntax-only"], cwd=directory)
        expanded = subprocess.check_output(
            [*command, "-E"], cwd=directory, text=True
        )
        text = project_source(expanded, root, directory)
        if not text.strip():
            raise ValueError(f"no project source emitted for {relative}")
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    if not seen:
        raise ValueError("the compilation database contains no sources")
    return len(seen)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("database", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count = prepare(args.root, args.database, args.output)
    print(f"Prepared {count} translation units in {args.output}")


if __name__ == "__main__":
    main()
