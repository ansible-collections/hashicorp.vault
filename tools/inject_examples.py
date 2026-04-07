# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Inject examples from ``examples/`` into module EXAMPLES blocks.

Reads example YAML files from ``examples/<module>/`` and replaces the
``EXAMPLES`` constant in the corresponding module file under
``plugins/modules/<module>.py``.

The ``examples/`` directory is the source of truth.

Usage:
    python -m tools.inject_examples           # inject all
    python -m tools.inject_examples --check    # check-only (exit 1 if stale)
    python -m tools.inject_examples --diff     # show what would change
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

COLLECTION_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = COLLECTION_ROOT / "plugins" / "modules"
EXAMPLES_DIR = COLLECTION_ROOT / "examples"

FILE_ORDER = ["present", "absent", "action", "info"]

EXAMPLES_PATTERN = re.compile(
    r'(EXAMPLES\s*=\s*(?:r)?""")\n.*?(""")',
    re.DOTALL,
)


def load_examples(example_dir: Path) -> str:
    """Load and concatenate example files from a module's example directory."""
    parts = []
    for name in FILE_ORDER:
        path = example_dir / f"{name}.yml"
        if path.exists():
            content = path.read_text().strip()
            if content.startswith("---"):
                content = content[3:].strip()
            parts.append(content)

    if not parts:
        return ""
    return "\n\n".join(parts)


def inject_into_module(module_path: Path, examples_content: str) -> tuple:
    """Replace the EXAMPLES block in a module file. Returns (new_content, changed)."""
    original = module_path.read_text()

    new_examples = f'EXAMPLES = """\n{examples_content}\n"""'

    match = EXAMPLES_PATTERN.search(original)
    if not match:
        return original, False

    new_content = original[: match.start()] + new_examples + original[match.end() :]
    changed = new_content != original
    return new_content, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check if EXAMPLES are up to date (exit 1 if stale)")
    parser.add_argument("--diff", action="store_true", help="Show what would change without writing")
    args = parser.parse_args()

    if not EXAMPLES_DIR.exists():
        print("No examples/ directory found. Run generate_examples first.")
        sys.exit(1)

    stale = []
    updated = 0

    for example_dir in sorted(EXAMPLES_DIR.iterdir()):
        if not example_dir.is_dir():
            continue
        module_name = example_dir.name
        module_path = MODULES_DIR / f"{module_name}.py"
        if not module_path.exists():
            print(f"  SKIP {module_name}: no module file")
            continue

        examples_content = load_examples(example_dir)
        if not examples_content:
            print(f"  SKIP {module_name}: no example files")
            continue

        new_content, changed = inject_into_module(module_path, examples_content)

        if changed:
            if args.check:
                stale.append(module_name)
                print(f"  STALE {module_name}")
            elif args.diff:
                print(f"  WOULD UPDATE {module_name}")
            else:
                module_path.write_text(new_content)
                updated += 1
                print(f"  Updated {module_name}")
        else:
            if not args.check:
                print(f"  OK {module_name}")

    if args.check and stale:
        print(f"\n{len(stale)} module(s) have stale EXAMPLES. Run: python -m tools.inject_examples")
        sys.exit(1)
    elif not args.check and not args.diff:
        print(f"\nDone. Updated {updated} module(s).")


if __name__ == "__main__":
    main()
