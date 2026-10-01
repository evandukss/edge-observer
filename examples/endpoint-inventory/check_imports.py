"""Check the executable's imports without importing or executing its source."""

import ast
from pathlib import Path
import sys


def check(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise ValueError("relative import from the source tree")
            names.append(node.module.split(".")[0])
    if not names:
        raise ValueError("no imports checked")
    for name in names:
        if name not in sys.stdlib_module_names:
            raise ValueError("non-standard import: " + name)
        if (path.parent / (name + ".py")).exists() or (path.parent / name).is_dir():
            raise ValueError("source tree shadows standard library: " + name)
    return names


if __name__ == "__main__":
    try:
        names = check(Path(sys.argv[1]))
    except ValueError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
    print(str(len(names)) + " imports checked: " + ", ".join(names))
