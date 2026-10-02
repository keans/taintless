"""Check that tracked Markdown files fit within 79 characters per line."""

import subprocess
from pathlib import Path


def main() -> int:
    paths = subprocess.check_output(["git", "ls-files", "-z", "--", "*.md"])
    violations = []
    for name in paths.split(b"\0"):
        if not name:
            continue
        path = Path(name.decode())
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if len(line) > 79:
                violations.append(f"{path}:{number}: {len(line)} characters")
    if violations:
        print("\n".join(violations))
        return 1
    print("All tracked Markdown lines are at most 79 characters.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
